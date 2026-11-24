"""Guest-local measurements on a single networkless synthetic workload."""
import base64
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import subprocess
import threading
import time

from fixture import N, WORK, must

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_text())
IG = str(HERE / "ig")
CLOCK = time.monotonic_ns
READY_S = 35
DELIVERY_NS = 2_000_000_000


def output(*cmd, timeout=20):
    return subprocess.check_output(cmd, text=True, timeout=timeout).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def setting():
    path = Path("/proc/sys/crypto/af_alg_restrict")
    return int(path.read_text()) if path.exists() else None


@contextmanager
def workload():
    name = "ig-fixture-" + os.urandom(6).hex()
    mounts = []
    for file in ("fixture.py", "Control.java"):
        p = HERE / file
        p.chmod(0o644)
        mounts += ["--mount", f"type=bind,src={p},dst=/fixture/{file},readonly"]
    cmd = ["docker", "run", "-i", "--name", name, "--pull=never", "--network=none", "--read-only",
                 "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
                 "--pids-limit=192", "--memory=768m", "--cpuset-cpus=0", "--tmpfs=/tmp:rw,nosuid,nodev,size=128m,mode=1777",
                 *mounts, "ig-validation-fixture:1", "python3", "-I", "-u", "/fixture/fixture.py", "pipe"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    def step(action):
        proc.stdin.write((action + "\n").encode())
        proc.stdin.flush()
        must(select.select([proc.stdout], [], [], 20)[0], "fixed workload timed out")
        return json.loads(proc.stdout.readline())
    try:
        must(step("seed") == "seeded", "fixture readiness failure")
        yield name, step
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        finally:
            output("docker", "rm", "-f", name)


class Observer:
    """Never persist event streams. Keep only positive markers with allowlisted fields."""
    def __init__(self, name, gadget):
        self.name, self.gadget = name, gadget
        self.hits = defaultdict(list)
        self.counts = Counter()
        self.advice = ""
        self.failure = None
        self.started = threading.Event()

    def __enter__(self):
        ref = f"{PINS['registry']}/{self.gadget}@{PINS['gadgets'][self.gadget]['index']}"
        cmd = [IG, "run", ref, "--verify-image=true", "-r", "docker", "-c", self.name,
               "--timeout=12" if self.gadget in ("traceloop", "advise_seccomp") else "--timeout=45"]
        if self.gadget == "trace_open":
            cmd += ["-o", "json", "--fields", "fname,fd,error_raw,flags_raw,proc.comm",
                    "--filter", r"fname~^/tmp/ig-control/"]
        elif self.gadget == "trace_exec":
            cmd += ["-o", "json", "--paths", "--fields", "proc.comm,exepath,error_raw"]
        elif self.gadget == "traceloop":
            cmd += ["-o", "json", "--syscall-filters=socket", "--fields", "comm,syscall,parameters,ret"]
        buffered = self.gadget in ("traceloop", "advise_seccomp")
        if buffered:
            cmd.append("-v")
        self.log = (HERE / (self.gadget + ".log")).open("w")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE if buffered else self.log, bufsize=0)
        if buffered:
            threading.Thread(target=self.watch_start, daemon=True).start()
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        return self

    def watch_start(self):
        # v0.58.0 pkg/gadget-context/run.go logs this only after every operator's Start returned.
        # Never persist the verbose stream, which can also contain container metadata.
        import io
        for line in io.BufferedReader(self.proc.stderr):
            if b"running..." in line:
                self.started.set()

    def read(self):
        try:
            # Buffered line reads: timestamp immediately after a complete CLI line arrives.
            import io
            for line in io.BufferedReader(self.proc.stdout):
                received = CLOCK()
                if self.gadget == "advise_seccomp":
                    must(len(self.advice) + len(line) < 32768, "oversized advisor output")
                    self.advice += line.decode()
                    continue
                row = json.loads(line)
                if self.gadget == "trace_open":
                    path = Path(row["fname"])
                    if path.parent != WORK:
                        continue
                    flags = row["flags_raw"]
                    if row["error_raw"] == 0 and row["fd"] >= 0 and flags & os.O_WRONLY:
                        if path.name in ("canary.php", "canary.txt"):
                            if flags & os.O_EXCL and row["proc"]["comm"].startswith("php-fpm"):
                                self.counts[path.name] += 1
                        elif path.name == "ready.txt" or re.fullmatch(r"sample-\d{1,2}\.txt", path.name):
                            self.hits[path.name].append(received)
                    elif path.name == "absent.txt" and row["error_raw"] == 2:
                        self.counts["ENOENT"] += 1
                elif self.gadget == "trace_exec":
                    comm = row["proc"]["comm"]
                    exe = Path(row.get("exepath", "")).name
                    if row["error_raw"] == 0 and (comm, exe) in (("true", "gnutrue"), ("true", "true"), ("java", "java")):
                        self.counts[comm] += 1
                elif row.get("syscall") == "socket" and row.get("comm") in ("igsockprobe", "igsockready"):
                    # Values are integer arguments of socket(), never addresses or buffers.
                    m = re.search(r"(?:family|domain)=(1|38)(?:,|$)", row["parameters"])
                    if m:
                        ret = row["ret"]
                        outcome = "allowed" if re.fullmatch(r"\d+", ret) else ret
                        self.counts[row["comm"], m[1], outcome] += 1
        except Exception as exc:
            self.failure = exc

    def check(self):
        if self.failure:
            raise RuntimeError(f"{self.gadget}: invalid event format") from self.failure
        if self.proc.poll() is not None:
            raise RuntimeError(f"{self.gadget} exited early; see its guest-local diagnostic")

    def ready(self, probe, test):
        end = time.monotonic() + READY_S
        while time.monotonic() < end:
            self.check()
            probe()
            time.sleep(0.15)
            if test():
                return
        raise TimeoutError(self.gadget + " readiness marker not seen")

    def wait(self, test):
        end = CLOCK() + DELIVERY_NS
        while not test() and CLOCK() < end:
            self.check()
            time.sleep(0.01)
        must(test(), self.gadget + " matching event timed out")

    def batch_ready(self):
        # A discovery perf FD can appear before the gadget attaches. Wait for operator readiness;
        # the later positive controls are separately verified on the actual end-of-run flush.
        self.ready(lambda: None, self.started.is_set)

    def __exit__(self, typ, value, tb):
        try:
            buffered = self.gadget in ("traceloop", "advise_seccomp")
            if self.proc.poll() is None and not buffered:
                self.proc.send_signal(signal.SIGINT)
            try:
                rc = self.proc.wait(timeout=20 if buffered else 8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise
            self.thread.join(timeout=3)
            if typ is None:
                must(not self.thread.is_alive() and rc == 0, self.gadget + " unclean stop")
                if self.failure:
                    raise self.failure
        finally:
            self.log.close()


def phase_audit(name):
    proc = output("docker", "exec", name, "cat", "/proc/self/status")
    mode = int(re.search(r"^Seccomp:\s+(\d+)$", proc, re.M)[1])
    must(mode == 2 and re.search(r"^NoNewPrivs:\s+1$", proc, re.M), "runtime safety settings absent")
    must(re.search(r"^Cpus_allowed_list:\s+0$", proc, re.M), "single-CPU fixture affinity changed")
    return mode


def measure(name, fx):
    pkgs = ["openjdk-25-jdk-headless", "libh2-java", "php8.5-fpm"]
    packages = {p: output("docker", "exec", name, "dpkg-query", "-W", "-f=${Version}", p) for p in pkgs}
    mode = phase_audit(name)
    host = json.loads(host_socket())
    original = setting()
    files = {"before": fx("php")}
    jvm = {"before": fx("java")}
    socks = {"before": fx("sockets")}
    off = fx("bench")
    with Observer(name, "trace_open") as o:
        o.ready(lambda: fx("ready"), lambda: bool(o.hits["ready.txt"]))
        on = fx("bench")
        markers = [f"sample-{i}.txt" for i in range(N)]
        o.wait(lambda: all(o.hits[m] for m in markers))
        files["during"] = fx("php")
        try:
            o.wait(lambda: all(o.counts[k] for k in ("canary.php", "canary.txt", "ENOENT")))
        except RuntimeError as exc:
            raise RuntimeError(f"Missing fixed FPM or ENOENT event; matched {dict(o.counts)}") from exc
    must(all(len(o.hits[m]) == 1 for m in markers), "duplicate marker")
    delivery = [o.hits[m][0] - pair[0] for m, pair in zip(markers, on, strict=True)]
    must(all(0 < v <= DELIVERY_NS for v in delivery), "clock mismatch or late delivery")
    files["events"] = dict(o.counts)
    files["after"] = fx("php")
    with Observer(name, "trace_exec") as o:
        o.ready(lambda: fx("true"), lambda: o.counts["true"] > 0)
        jvm["during"] = fx("java")
        o.wait(lambda: o.counts["java"] > 0)
    jvm["exec_events"] = o.counts["java"]
    jvm["after"] = fx("java")
    with Observer(name, "traceloop") as o:
        o.batch_ready()
        fx("sock-ready")
        socks["during"] = fx("sockets")
    must(o.counts["igsockready", "1", "allowed"] == 1, "missing buffered readiness marker")
    events = {}
    for label, domain in [("unix", "1"), ("alg", "38")]:
        result = socks["during"][label]["outcome"]
        expected = "allowed" if result == "allowed" else "-1 (" + os.strerror(getattr(errno, result)).lower() + ")"
        matched = o.counts["igsockprobe", domain, expected]
        total = sum(n for (proc, fam, _), n in o.counts.items() if proc == "igsockprobe" and fam == domain)
        must(matched == total and (matched == 18 or (result != "allowed" and total == 0)),
             "unexpected buffered socket count or return")
        events[label] = matched
    socks["matching_events"] = events
    socks["after"] = fx("sockets")
    with Observer(name, "advise_seccomp") as o:
        o.batch_ready()
        fx("sockets")
        fx("ready")
    comment, text = o.advice.strip().split("\n", 1)
    must(comment.strip() == "// " + name, "advisor profile not scoped to this fixture")
    profile = json.loads(text)
    allowed = {syscall for rule in profile["syscalls"] if rule["action"] == "SCMP_ACT_ALLOW" for syscall in rule["names"]}
    must({"socket", "openat"} <= allowed and profile["defaultAction"] == "SCMP_ACT_ERRNO", "missing advisory controls")
    must(original == setting() and phase_audit(name) == mode, "security settings changed")
    return {"schema": 1, "utc_day": datetime.now(timezone.utc).date().isoformat(),
            "pins_sha256": digest(HERE / "pins.json"), "kernel": platform.release(),
            "os": platform.freedesktop_os_release()["VERSION_ID"],
            "packages": packages, "seccomp_mode": mode, "af_alg_restrict": original,
            "fixture_cpu": 0,
            "unprivileged_host": {k: v["outcome"] for k, v in host.items()},
            "files": files, "jvm": jvm, "sockets": socks,
            "advice": {"default": profile["defaultAction"], "allows_openat": True, "allows_socket": True, "applied": False},
            "timing": {"n": N, "warmups": 3, "clock": "CLOCK_MONOTONIC", "units": "ns",
                       "timeout_ns": DELIVERY_NS, "off": [b-a for a, b in off], "on": [b-a for a, b in on],
                       "first_open_event": delivery}}


def host_socket():
    # Pass just the fixed script on stdin: no private host directory accessible to the unprivileged user.
    return subprocess.check_output(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "python3", "-I",
                                    "-", "sockets"], input=(HERE / "fixture.py").read_bytes(), timeout=5)


def main():
    must(os.getuid() == 0 and digest(Path(IG)) == PINS["ig_sha256"], "released CLI hash mismatch")
    must(not Path("/var/run/reboot-required").exists(), "boot into updated stock kernel before measuring")
    with workload() as (name, fx):
        row = measure(name, fx)
    blob = gzip.compress(json.dumps(row, separators=(",", ":")).encode(), mtime=0)
    print("IG_RECEIPT=" + base64.b64encode(blob).decode())


if __name__ == "__main__":
    main()
