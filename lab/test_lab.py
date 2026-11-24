import base64
import copy
import gzip
import json
from pathlib import Path
import subprocess
import tempfile
from unittest import TestCase, main
from unittest.mock import patch

import azure
import privacy
import receipt

RESULT = Path(__file__).resolve().parents[1] / "docs/results/ig-azure.json"


class Evidence(TestCase):
    def setUp(self):
        self.row = json.loads(RESULT.read_text())

    def test_measured_transport(self):
        receipt.validate(self.row)
        del self.row["azure"], self.row["lifecycle"]
        blob = base64.b64encode(gzip.compress(json.dumps(self.row).encode())).decode()
        self.assertEqual(receipt.decode(blob), self.row)
        with self.assertRaises(ValueError):
            receipt.decode(blob[:-4])

    def test_unverified_is_never_promoted(self):
        for path, replacement in [
            (("pins_sha256",), "0"*64), (("schema",), True),
            (("files", "events", "canary.php"), 0), (("files", "during"), ["EACCES", "written", "ENOENT"]),
            (("jvm", "exec_events"), 0), (("jvm", "during", "false_predicate"), "policy-exception"),
            (("sockets", "during", "unix", "outcome"), "EPERM"), (("sockets", "matching_events", "unix"), 0),
            (("timing", "off"), []), (("timing", "first_open_event"), [2_000_000_001]*15),
            (("advice", "applied"), True), (("azure", "inbound"), "permit"), (("lifecycle", "power"), "stopped"),
            (("packages", "hostname"), "not-for-publication"), (("raw_events",), ["not-for-publication"]),
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                row = copy.deepcopy(self.row)
                obj = row
                for key in path[:-1]:
                    obj = obj[key]
                obj[path[-1]] = replacement
                receipt.validate(row)


class Ownership(TestCase):
    def test_guest_inputs_never_follow_worktree_files(self):
        expected = azure.measured_blob("fixture.py")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "test-clone"
            subprocess.run(["git", "clone", "--quiet", "--no-checkout", "--local", str(azure.ROOT), repo], check=True)
            (repo / "lab").mkdir()
            fake = repo / "private-local-data"
            fake.write_text("never transport this")
            (repo / "lab/fixture.py").symlink_to(fake)
            with patch.object(azure, "ROOT", repo):
                self.assertEqual(azure.measured_blob("fixture.py"), expected)
                with self.assertRaises(RuntimeError):
                    azure.measured_blob("../private-local-data")
                with self.assertRaises(RuntimeError):
                    azure.guest({}, "unmeasured")

    def test_reserved_is_bound_not_unattached(self):
        disk = {"id": "disk", "managedBy": "vm", "diskState": "Reserved"}
        azure.verify_disk({"disk": "disk"}, {"id": "vm"}, disk)
        for changed in [dict(disk, managedBy=None), dict(disk, managedBy="someone-else"),
                        dict(disk, id="replacement"), dict(disk, diskState="Unattached")]:
            with self.assertRaises(RuntimeError):
                azure.verify_disk({"disk": "disk"}, {"id": "vm"}, changed)
    def test_nsg_order_and_exact_scopes(self):
        base = dict(direction="Inbound", priority=100, access="Deny", protocol="*", sourceAddressPrefix="*",
                    destinationAddressPrefix="*", sourcePortRange="*", destinationPortRange="*")
        out = dict(base, direction="Outbound")
        https = dict(out, access="Allow", protocol="Tcp", destinationAddressPrefix="Internet", destinationPortRange="443")
        rules = [dict(out, priority=110), dict(base, priority=101, access="Allow"), https, base]
        azure.verify_rules(rules)
        for added in (dict(base, priority=99, access="Allow"), dict(out, priority=104, access="Allow")):
            with self.assertRaises(RuntimeError):
                azure.verify_rules([added] + rules)
        with self.assertRaises(RuntimeError):
            azure.verify_rules([dict(base, destinationAddressPrefix="VirtualNetwork") if r is base else r for r in rules])

    def test_foreign_group_or_replaced_vm_is_never_stopped(self):
        s = dict(subscription="sub", group="group", vm="vm", nonce="expected", vmId="bound", disk="disk")
        tags = {"lab": "ig-upstream-validation", "ownership": "expected"}
        vm = {"tags": tags, "location": azure.REGION, "hardwareProfile": {"vmSize": azure.SIZE},
              "storageProfile": {"osDisk": {"deleteOption": "Detach", "managedDisk": {"id": "disk"}}}, "vmId": "new"}
        for responses in [[{"id": "wrong"}], [{"id": "sub"}, {"tags": {}}],
                          [{"id": "sub"}, {"tags": tags}, vm]]:
            with self.subTest(responses=len(responses)), patch.object(azure, "subscription", return_value="sub"), \
                    patch.object(azure, "az", side_effect=responses) as cli, self.assertRaises(RuntimeError):
                try:
                    azure.park(s)
                finally:
                    self.assertNotIn("deallocate", [arg for c in cli.call_args_list for arg in c.args])

    def test_zero_exit_without_guest_marker_is_failure(self):
        with patch.object(azure, "guard"), patch.object(azure, "az", return_value={"value": [{"message": "Enable succeeded"}]}), \
                patch("pathlib.Path.write_text"), self.assertRaises(RuntimeError):
            azure.guest({"subscription": "s", "group": "g", "vm": "v"}, "prepare")


class Privacy(TestCase):
    def test_positive_and_negative_controls(self):
        forbidden = ["mock" + "-operator-alias"]
        self.assertFalse(privacy.inspect("sha256:" + "c"*64 + " / fixed control", forbidden))
        for text in ["user=" + forbidden[0], "/Users/" + "fixture" + "/repo",
                     "-".join(["abcd1234", "1000", "2000", "3000", "000000000001"]),
                     "ghp_" + "X"*36, ".".join(["192", "0", "2", "1"]),
                     "-----BEGIN " + "OPENSSH" + " PRIVATE KEY-----"]:
            self.assertTrue(privacy.inspect(text, forbidden))
        self.assertTrue(privacy.safe_name(".env.example"))
        for path in [".env", "a/.env.local", ".state/receipt.json", ".scratch/test", "id.key"]:
            self.assertFalse(privacy.safe_name(path))


if __name__ == "__main__":
    main()
