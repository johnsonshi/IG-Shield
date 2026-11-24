"""Closed v1 evidence format. Validate before copying any guest result into the repository."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zlib

HERE = Path(__file__).resolve().parent
PHASES = ("before", "during", "after")
SOCKETS = ("unix", "alg")
OUTCOMES = {"allowed", "EPERM", "EACCES", "EAFNOSUPPORT", "EPROTONOSUPPORT"}


def check(cond, reason):
    if not cond:
        raise ValueError("Invalid receipt: " + reason)


def keys(obj, *expected):
    check(type(obj) is dict and set(obj) == set(expected), "unexpected or missing field")


def uint(value, low=0, high=2_000_000_000):
    check(type(value) is int and low <= value <= high, "integer outside range")


def validate(row, parked=True):
    from datetime import date
    keys(row, "schema", "utc_day", "pins_sha256", "kernel", "os", "packages", "seccomp_mode", "fixture_cpu",
         "af_alg_restrict", "unprivileged_host", "files", "jvm", "sockets", "advice", "timing",
         *(["lifecycle", "azure"] if parked else []))
    uint(row["schema"], 1, 1)
    check(re.fullmatch(r"\d{4}-\d\d-\d\d", row["utc_day"]) and date.fromisoformat(row["utc_day"]), "date")
    check(row["pins_sha256"] == hashlib.sha256((HERE / "pins.json").read_bytes()).hexdigest(), "wrong lock file")
    check(re.fullmatch(r"\d{1,2}\.\d{1,2}\.\d{1,3}-\d{1,5}-azure", row["kernel"]), "stock Azure kernel release")
    check(row["os"] == "26.04", "unexpected OS")
    keys(row["packages"], "libh2-java", "php8.5-fpm", "openjdk-25-jdk-headless")
    for version in row["packages"].values():
        check(re.fullmatch(r"[0-9][0-9a-z.+:~\-]{0,48}", version), "invalid distro package version")
    uint(row["seccomp_mode"], 2, 2)
    uint(row["fixture_cpu"], 0, 0)
    if row["af_alg_restrict"] is not None:
        uint(row["af_alg_restrict"], 0, 2)
    host = row["unprivileged_host"]
    keys(host, *SOCKETS)
    check(host["unix"] == "allowed" and host["alg"] in OUTCOMES, "host socket controls")
    files, jvm, socks = (row[k] for k in ("files", "jvm", "sockets"))
    keys(files, *PHASES, "events")
    keys(jvm, *PHASES, "exec_events")
    keys(socks, *PHASES, "matching_events")
    keys(files["events"], "canary.php", "canary.txt", "ENOENT")
    for count in files["events"].values():
        uint(count, 1, 1)
    uint(jvm["exec_events"], 1, 1)
    for phase in PHASES:
        check(files[phase] == ["written", "written", "ENOENT"], "file outcomes")
        check(jvm[phase] == {"decode": "control", "read": 7, "false_predicate": "empty"}
              and type(jvm[phase]["read"]) is int, "JVM outcomes")
        keys(socks[phase], *SOCKETS)
        for family in SOCKETS:
            obj = socks[phase][family]
            keys(obj, "outcome", "median_ns")
            allowed = OUTCOMES if family == "alg" else {"allowed"}
            check(obj["outcome"] in allowed and obj["outcome"] == socks["before"][family]["outcome"], "socket outcomes")
            uint(obj["median_ns"], 1)
    keys(socks["matching_events"], *SOCKETS)
    for family in SOCKETS:
        count = socks["matching_events"][family]
        uint(count, 0, 18)
        check(count == 18 or (count == 0 and socks["during"][family]["outcome"] != "allowed"), "socket event count")
    advice = row["advice"]
    keys(advice, "default", "allows_openat", "allows_socket", "applied")
    check(advice["default"] == "SCMP_ACT_ERRNO" and advice["allows_openat"] is True and
          advice["allows_socket"] is True and advice["applied"] is False, "advisory evidence")
    t = row["timing"]
    keys(t, "n", "warmups", "clock", "units", "timeout_ns", "off", "on", "first_open_event")
    uint(t["n"], 15, 15)
    uint(t["warmups"], 3, 3)
    uint(t["timeout_ns"], 2_000_000_000, 2_000_000_000)
    check((t["clock"], t["units"]) == ("CLOCK_MONOTONIC", "ns"), "clock")
    for field in ("off", "on", "first_open_event"):
        check(type(t[field]) is list and len(t[field]) == t["n"], "incomplete timing distribution")
        for ns in t[field]:
            uint(ns, 1)
    if parked:
        life = row["lifecycle"]
        keys(life, "power", "original_os_disk", "disk_state")
        check(life["power"] == "deallocated" and life["original_os_disk"] == "retained_and_bound" and
              life["disk_state"] in ("Attached", "Reserved"), "lifecycle receipt")
        check(row["azure"] == {"region": "westus3", "size": "Standard_D4ds_v5",
                               "image": "Canonical:ubuntu-26_04-lts:server:26.04.202611100",
                               "secure_boot": True, "vtpm": True,
                               "inbound": "deny_all", "internet_egress": "tcp_443"}
              and row["azure"]["secure_boot"] is True and row["azure"]["vtpm"] is True, "Azure isolation receipt")
    return row


def decode(blob):
    check(len(blob) <= 4096, "oversized transport")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(blob, validate=True))) as f:
            data = f.read(16_385)
    except (gzip.BadGzipFile, EOFError, zlib.error) as exc:
        raise ValueError("Invalid receipt: damaged transport") from exc
    check(len(data) < 16_385, "oversized document")
    return validate(json.loads(data), parked=False)


if __name__ == "__main__":
    r = validate(json.loads(Path(sys.argv[1]).read_text()))
    print("Verified v1 receipt. Timings in nanoseconds (min / median / max):")
    for label in ("off", "on", "first_open_event"):
        v = sorted(r["timing"][label])
        print(f"  {label}: {v[0]} / {v[len(v)//2]} / {v[-1]} (n={len(v)})")
