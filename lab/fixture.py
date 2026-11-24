"""Fixed unprivileged fixtures. No input payload, arbitrary command, network peer or algorithm."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import time
import signal

WORK = Path("/tmp/ig-control")
N = 15
CLOCK = time.monotonic_ns


def must(test, message):
    if not test:
        raise RuntimeError(message)


def marker(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        must(os.write(fd, b"x") == 1, "short marker write")
    finally:
        os.close(fd)


def bench():
    rows = []
    for i in range(-3, N):
        path = WORK / f"sample-{i}.txt"
        start = CLOCK()
        marker(path)
        end = CLOCK()
        if i >= 0:
            rows.append([start, end])
        time.sleep(0.01)
    return rows


def start_fpm():
    # No TCP listener. The sole private FastCGI request names a fixed local script.
    conf = WORK / "fpm.conf"
    sock = str(WORK / "fpm.sock")
    conf.write_text(f"[global]\nerror_log={WORK}/fpm.log\n[lab]\nlisten={sock}\npm=static\npm.max_children=1\n")
    page = WORK / "fixture.php"
    page.write_text("""<?php
foreach (['canary.php','canary.txt'] as $name) {
    $f = fopen(__DIR__ . '/' . $name, 'xb');
    if (!$f || fwrite($f, 'control-only') !== 12 || !fclose($f)) exit(1);
}
echo 'FIXED_OK';
""")
    proc = subprocess.Popen(["/usr/sbin/php-fpm8.5", "-n", "-F", "-y", conf], stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(sock):
            return proc
        must(proc.poll() is None, "FPM exited")
        time.sleep(0.025)
    raise TimeoutError("FPM socket not ready")


def php():
    paths = [WORK / "canary.php", WORK / "canary.txt"]
    for p in paths:
        p.unlink(missing_ok=True)
    response = subprocess.check_output(["/usr/bin/cgi-fcgi", "-bind", "-connect", str(WORK / "fpm.sock")],
                                       env={"SCRIPT_FILENAME": str(WORK / "fixture.php"), "REQUEST_METHOD": "GET",
                                            "SCRIPT_NAME": "/fixture.php"}, timeout=3)
    must(response.rstrip().endswith(b"FIXED_OK"), "fixed FPM request failed")
    must(all(p.read_bytes() == b"control-only" for p in paths), "canary write not confirmed")
    try:
        os.close(os.open(WORK / "absent.txt", os.O_RDONLY))
    except FileNotFoundError:
        return ["written", "written", "ENOENT"]
    raise RuntimeError("negative file control unexpectedly existed")


def sockets(ready=False):
    libc = ctypes.CDLL(None)
    must(libc.prctl(15, b"igsockready" if ready else b"igsockprobe", 0, 0, 0) == 0, "comm")
    out = {}
    for label, fam, typ in [("unix", socket.AF_UNIX, socket.SOCK_DGRAM),
                            ("alg", socket.AF_ALG, socket.SOCK_SEQPACKET)]:
        samples, outcomes = [], set()
        for i in range(1 if ready else 18):
            start = CLOCK()
            try:
                socket.socket(fam, typ, 0).close()
            except OSError as e:
                outcome = errno.errorcode[e.errno]
            else:
                outcome = "allowed"
            elapsed = CLOCK() - start
            outcomes.add(outcome)
            if i >= 3:
                samples.append(elapsed)
        must(len(outcomes) == 1, "mixed socket outcomes")
        out[label] = {"outcome": outcomes.pop(), "median_ns": statistics.median(samples) if samples else 0}
    return out


def step(action):
    if action == "sockets":
        return sockets()
    if action == "sock-ready":
        return sockets(True)
    WORK.mkdir(mode=0o700, exist_ok=True)
    if action == "seed":
        for i in range(-3, N):
            marker(WORK / f"sample-{i}.txt")
        return "seeded"
    if action == "ready":
        marker(WORK / "ready.txt")
        return "ready"
    if action == "bench":
        return bench()
    if action == "php":
        return php()
    if action == "true":
        subprocess.run(["/usr/bin/true"], check=True)
        return True
    if action == "java":
        return json.loads(subprocess.check_output(["java", "-Xmx96m", "-cp", "/usr/share/java/h2.jar",
                                                    "/fixture/Control.java"], timeout=15))
    raise ValueError("unknown fixture")


if __name__ == "__main__":
    must(os.geteuid() == 65534, "fixture must be unprivileged")
    if sys.argv[1:] == ["pipe"]:
        signal.alarm(270)
        WORK.mkdir(mode=0o700, exist_ok=True)
        fpm = start_fpm()
        try:
            for command in sys.stdin:
                print(json.dumps(step(command.strip())), flush=True)
        finally:
            fpm.terminate()
            fpm.wait(timeout=5)
    else:
        print(json.dumps(step(sys.argv[1])))
