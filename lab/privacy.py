"""Scan tracked contents and every tree/commit reachable from the candidate, never print matched secrets."""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SEED = "f760b77cc752f788bc40317e15e23443b1fa5ce7"
NOREPLY = re.compile(r"^[0-9A-Za-z_+\-]+@users\.noreply\.github\.com$", re.I)
PRIVATE_PATH = re.compile(r"(^|/)(?:\.env(?:\..+)?|\.state|\.scratch)(?:/|$)|\.(?:log|pem|key|pub)$", re.I)
PATTERNS = [
    re.compile(p, re.I) for p in (
        r"(?:^|[\s\"'=])/(?:Users|home)/[^/\s\"']+/",
        r"/subscriptions/[0-9a-f-]{32,36}/",
        r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/]{40,}",
        r"\b(?:gh[pousr]_[a-z0-9]{30,}|github_pat_[a-z0-9_]{30,}|AKIA[A-Z0-9]{16})",
        r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.+~\-])",
        r"\bigl[0-9a-f]{10}-(?:rg|vm|nic|os|nsg|out|sub|net)\b",
    )
]


def git(*args):
    return subprocess.check_output(["git", "-C", ROOT, *args])


def private_values():
    import json
    values = []
    for src in [ROOT / ".env", ROOT / ".state/owner.json", ROOT / ".state/private-needles.txt"]:
        if src.exists():
            text = src.read_text()
            if src.name == ".env":
                values += [v for k, sep, v in (line.partition("=") for line in text.splitlines())
                           if k.strip() == "AZURE_SUBSCRIPTION" and sep]
            elif src.suffix == ".json":
                values += list(json.loads(text).values())
            else:
                values += text.splitlines()
    return [v.lower() for v in values if type(v) is str and len(v) >= 4 and not v.startswith("REPLACE_")]


def inspect(text, needles):
    # Software versions can have four numeric components. Exempt only the two pinned
    # marketplace/distro version contexts, not arbitrary IP-shaped literals.
    clean = re.sub(r"\b25\.0\.\d{1,2}\.\d{1,2}(?=\+\d)", "JDK_VERSION", text)
    addresses = re.findall(r"[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}", clean)
    return (any(not NOREPLY.fullmatch(a) for a in addresses) or any(p.search(clean) for p in PATTERNS)
            or any(s in text.lower() for s in needles))


def safe_name(name):
    return name == ".env.example" or not PRIVATE_PATH.search(name)


def scan(rev="HEAD"):
    needles = private_values()
    seen = set()
    for commit in git("rev-list", rev).decode().splitlines():
        author, committer, names, msg = git("show", "-s", "--format=%ae%x00%ce%x00%an %cn%x00%B", commit).decode().split("\0", 3)
        if not NOREPLY.fullmatch(author) or not (
            NOREPLY.fullmatch(committer) or (commit == SEED and committer == "noreply" + "@" + "github.com")
        ) or inspect(names + "\n" + msg, needles):
            raise ValueError("Non-private commit metadata")
        if commit != SEED and "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>" not in msg.splitlines():
            raise ValueError("Missing noreply trailer")
        for record in git("ls-tree", "-rz", commit).split(b"\0"):
            if not record:
                continue
            meta, name = record.split(b"\t", 1)
            mode, kind, oid = meta.split()
            name = os.fsdecode(name)
            if kind != b"blob" or mode not in (b"100644", b"100755") or not safe_name(name) or inspect(name, needles):
                raise ValueError("Disallowed tree entry")
            if oid not in seen:
                if inspect(git("cat-file", "blob", oid).decode(), needles):
                    raise ValueError("Privacy match in tracked blob: " + name)
                seen.add(oid)
    print(f"Privacy scan passed: {len(seen)} unique committed blobs and all reachable commit identities.")


if __name__ == "__main__":
    scan(*sys.argv[1:])
