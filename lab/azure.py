"""Operate one explicitly owned, isolated IG VM. No command or resource-name input."""
import argparse
import base64
import gzip
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".state"
OWNER = STATE / "owner.json"
REGION = "westus3"
SIZE = "Standard_D4ds_v5"
IMAGE = "Canonical:ubuntu-26_04-lts:server:26.04.202611100"


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def subscription():
    envfile = ROOT / ".env"
    lines = envfile.read_text().splitlines() if envfile.is_file() else []
    names = [s.partition("=")[2] for s in lines if s.startswith("AZURE_SUBSCRIPTION=")]
    sub = os.getenv("AZURE_SUBSCRIPTION") or (names[0] if len(names) == 1 else "")
    require(sub and not sub.startswith(("REPLACE", "-")), "Set the explicitly authorized subscription in .env")
    return sub


def az(sub, *args):
    with (STATE / "azure.log").open("ab") as log:
        p = subprocess.run(["az", *args, "--subscription", sub, "--only-show-errors", "-o", "json"],
                           stdout=subprocess.PIPE, stderr=log)
        require(p.returncode == 0, f"Azure CLI {args[0]} failed; see ignored .state/azure.log")
    return json.loads(p.stdout) if p.stdout.strip() else None


def save(s, first=False):
    if first:
        with OWNER.open("x") as f:
            json.dump(s, f)
    else:
        tmp = OWNER.with_suffix(".tmp")
        tmp.write_text(json.dumps(s))
        tmp.replace(OWNER)


def tagged(obj, s):
    tags = obj.get("tags") or {}
    return tags.get("lab") == "ig-upstream-validation" and tags.get("ownership") == s["nonce"]


def guard(s, bind=False):
    sub, rg, vm = s["subscription"], s["group"], s["vm"]
    require(az(subscription(), "account", "show")["id"] == sub, "Subscription changed")
    require(tagged(az(sub, "group", "show", "-n", rg), s), "Resource group ownership mismatch")
    obj = az(sub, "vm", "show", "-g", rg, "-n", vm)
    require(tagged(obj, s), "VM ownership mismatch")
    require(obj["hardwareProfile"]["vmSize"] == SIZE and obj["location"] == REGION, "VM shape changed")
    disk = obj["storageProfile"]["osDisk"]
    require(disk["deleteOption"] == "Detach", "Disk retention changed")
    ids = (obj["vmId"], disk["managedDisk"]["id"])
    if bind:
        require("vmId" not in s, "VM identity already bound")
        s["vmId"], s["disk"] = ids
        save(s)
    # ARM may normalize casing (e.g. resourceGroups) on a later VM start.
    require(ids[0] == s["vmId"] and ids[1].lower() == s["disk"].lower(), "VM or OS disk identity changed")
    return obj


def create():
    require(not OWNER.exists(), "Local ownership file exists; refuse to adopt or replace")
    sub = az(subscription(), "account", "show")["id"]
    nonce = secrets.token_hex(16)
    pfx = "igl" + nonce[:10]
    rg, vm = pfx + "-rg", pfx + "-vm"
    require(az(sub, "group", "exists", "-n", rg) is False, "Group already exists")
    s = {"subscription": sub, "group": rg, "vm": vm, "nonce": nonce}
    save(s, first=True)
    tags = ["--tags", "lab=ig-upstream-validation", "ownership=" + nonce]
    az(sub, "group", "create", "-n", rg, "-l", REGION, *tags)
    require(tagged(az(sub, "group", "show", "-n", rg), s), "Failed to establish group ownership")

    def make(kind, *args):
        return az(sub, *kind.split(), "-g", rg, *args)

    nsg, net, subnet, pip, nic = [pfx + tail for tail in ("-nsg", "-net", "-sub", "-out", "-nic")]
    make("network nsg create", "-n", nsg, "-l", REGION, *tags)
    for name, prio, direction, access, proto, dest, port in [
        ("deny-in", "100", "Inbound", "Deny", "*", "*", "*"),
        ("https-out", "100", "Outbound", "Allow", "Tcp", "Internet", "443"),
        ("deny-out", "110", "Outbound", "Deny", "*", "*", "*"),
    ]:
        make("network nsg rule create", "--nsg-name", nsg, "-n", name, "--priority", prio,
             "--direction", direction, "--access", access, "--protocol", proto,
             "--source-address-prefixes", "*", "--source-port-ranges", "*",
             "--destination-address-prefixes", dest, "--destination-port-ranges", port)
    private = f"10.{int(nonce[:2], 16)}.{int(nonce[2:4], 16)}.0"
    make("network vnet create", "-n", net, "-l", REGION, "--address-prefixes", private + "/24", *tags)
    make("network vnet subnet create", "--vnet-name", net, "-n", subnet, "--address-prefixes",
         private + "/27", "--default-outbound-access", "false", "--network-security-group", nsg)
    make("network public-ip create", "-n", pip, "-l", REGION, "--sku", "Standard",
         "--allocation-method", "Static", *tags)
    make("network nic create", "-n", nic, "-l", REGION, "--vnet-name", net, "--subnet", subnet,
         "--public-ip-address", pip, "--network-security-group", nsg, *tags)
    # Azure requires an OS credential; its private half never leaves this temporary directory.
    with tempfile.TemporaryDirectory(dir=STATE) as folder:
        key = Path(folder) / "bootstrap"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "unused", "-f", key], check=True)
        key.unlink()
        make("vm create", "-n", vm, "-l", REGION, "--size", SIZE, "--image", IMAGE, "--nics", nic,
             "--admin-username", pfx + "admin", "--authentication-type", "ssh", "--ssh-key-values", str(key)+".pub",
             "--security-type", "TrustedLaunch", "--enable-secure-boot", "true", "--enable-vtpm", "true",
             "--os-disk-name", pfx + "-os", "--os-disk-delete-option", "Detach",
             "--storage-sku", "StandardSSD_LRS", "--custom-data", str(ROOT / "lab/cloud-init.yml"), *tags)
    guard(s, bind=True)
    print("Created and bound one owned VM; resource names are only in .state/owner.json.")


def power(s):
    iv = az(s["subscription"], "vm", "get-instance-view", "-g", s["group"], "-n", s["vm"])
    states = [v["code"] for v in iv["instanceView"]["statuses"] if v["code"].startswith("PowerState/")]
    require(len(states) == 1, "Ambiguous VM power state")
    return states[0].split("/")[1]


def change(s, verb):
    guard(s)
    az(s["subscription"], "vm", verb, "-g", s["group"], "-n", s["vm"])


def park(s):
    change(s, "deallocate")
    vm = guard(s)
    require(power(s) == "deallocated", "Deallocation not confirmed")
    disk = az(s["subscription"], "disk", "show", "--ids", s["disk"])
    verify_disk(s, vm, disk)
    print("PowerState/deallocated; original OS disk retained and attached.")
    return disk["diskState"]


def verify_disk(s, vm, disk):
    # A deallocated VM's OS disk normally transitions from Attached to Reserved.
    require(disk["id"].lower() == s["disk"].lower() and (disk.get("managedBy") or "").lower() == vm["id"].lower()
            and disk["diskState"] in {"Attached", "Reserved"}, "OS disk no longer bound to this VM")


def verify_rules(rules):
    columns = ("priority", "access", "protocol", "sourceAddressPrefix", "sourcePortRange",
               "destinationAddressPrefix", "destinationPortRange")
    expected = {
        "Inbound": [(100, "Deny", "*", "*", "*", "*", "*")],
        "Outbound": [(100, "Allow", "Tcp", "*", "*", "Internet", "443"),
                     (110, "Deny", "*", "*", "*", "*", "*")],
    }
    for direction, prefix in expected.items():
        order = sorted((r for r in rules if r["direction"] == direction), key=lambda r: r["priority"])
        require(len({r["priority"] for r in order}) == len(order), "Ambiguous rule priority")
        # After the terminal wildcard deny, later organization rules are unreachable. Never edit those rules.
        require([tuple(r.get(k) for k in columns) for r in order[:len(prefix)]] == prefix, "Traffic policy changed")
        for r in order[:len(prefix)]:
            require(not any(r.get(k) for k in ("sourceApplicationSecurityGroups", "destinationApplicationSecurityGroups",
                                                "sourceAddressPrefixes", "destinationAddressPrefixes",
                                                "sourcePortRanges", "destinationPortRanges")), "Rule scope changed")


def isolation(s):
    vm = guard(s)
    image = vm["storageProfile"]["imageReference"]
    require(":".join(image[k] for k in ("publisher", "offer", "sku", "version")).lower() == IMAGE.lower(), "Wrong image")
    uefi = vm["securityProfile"]["uefiSettings"]
    require(uefi["secureBootEnabled"] is True and uefi["vTpmEnabled"] is True, "UEFI protections changed")
    sub = s["subscription"]
    nics = vm["networkProfile"]["networkInterfaces"]
    require(len(nics) == 1, "Expected one NIC")
    nic = az(sub, "network", "nic", "show", "--ids", nics[0]["id"])
    require(tagged(nic, s) and len(nic["ipConfigurations"]) == 1, "NIC ownership or configuration changed")
    conf = nic["ipConfigurations"][0]
    net = az(sub, "network", "vnet", "subnet", "show", "--ids", conf["subnet"]["id"])
    nsgid = nic["networkSecurityGroup"]["id"]
    require(net["networkSecurityGroup"]["id"].lower() == nsgid.lower() and net["defaultOutboundAccess"] is False,
            "Subnet isolation changed")
    nsg = az(sub, "network", "nsg", "show", "--ids", nsgid)
    require(tagged(nsg, s), "NSG ownership changed")
    verify_rules(nsg["securityRules"])
    return {"region": REGION, "size": SIZE, "image": IMAGE, "secure_boot": True, "vtpm": True,
            "inbound": "deny_all", "internet_egress": "tcp_443"}


def guest(s, files, command, marker):
    guard(s)
    lines = ["set -eu", "umask 077", "export PATH=/usr/sbin:/usr/bin:/sbin:/bin",
             "install -dm700 /opt/ig-validation", "cd /opt/ig-validation"]
    for name in files:
        data = base64.b64encode(gzip.compress((ROOT / "lab" / name).read_bytes(), mtime=0)).decode()
        lines.append(f"printf %s '{data}' | base64 -d | gzip -d > '{name}'")
    lines.append(command)
    msg = az(s["subscription"], "vm", "run-command", "invoke", "-g", s["group"], "-n", s["vm"],
             "--command-id", "RunShellScript", "--scripts", "\n".join(lines))
    text = "\n".join(x["message"] for x in msg["value"])
    (STATE / "last-command.log").write_text(text)
    hits = [line.removeprefix(marker) for line in text.splitlines() if line.startswith(marker)]
    require(len(hits) == 1, "Guest command did not complete: see ignored .state/last-command.log")
    return hits[0]


def main():
    os.umask(0o077)
    STATE.mkdir(exist_ok=True, mode=0o700)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=["create", "status", "park", "start", "prepare", "live"])
    act = ap.parse_args().action
    if act == "create":
        return create()
    s = json.loads(OWNER.read_text())
    guard(s)
    if act == "status":
        print("PowerState/" + power(s))
    elif act == "park":
        park(s)
    elif act == "start":
        isolation(s)
        change(s, "start")
        require(power(s) == "running", "Start not confirmed")
    elif act == "prepare":
        isolation(s)
        suffix = guest(s, ["prepare.sh", "pins.json"], "bash prepare.sh", "IG_PREPARED")
        require(suffix in ("", "_REBOOT"), "Unexpected preparation status")
        if suffix == "_REBOOT":
            change(s, "restart")
        print("Verified release and prepared fixtures.")
    else:
        from receipt import decode
        try:
            facts = isolation(s)
            if power(s) == "deallocated":
                change(s, "start")
            require(power(s) == "running", "VM not running")
            result = guest(s, ["measure.py", "fixture.py", "Control.java", "pins.json"],
                           "timeout 240 python3 measure.py", "IG_RECEIPT=")
            receipt = decode(result)
        finally:
            disk_state = park(s)
        receipt["lifecycle"] = {"power": "deallocated", "original_os_disk": "retained_and_bound", "disk_state": disk_state}
        receipt["azure"] = facts
        from receipt import validate
        validate(receipt)
        dst = STATE / "verified.json"
        dst.write_text(json.dumps(receipt, indent=2) + "\n")
        print("Verified receipt: .state/verified.json")


if __name__ == "__main__":
    main()
