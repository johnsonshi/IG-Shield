# Reproduce the Offline Verification and Live Azure Run

This guide covers three layers:

1. **Offline replay** of the saved results from the Azure run ([`results/ig-azure.json`](results/ig-azure.json)) on any machine with Python 3.10+.
2. **Live Azure provisioning and measurement** in your own authorized Azure subscription.
3. **What is timed and what experimental limits apply** when interpreting the numbers.

---

## 1. Replay the Saved Results Offline (No Azure or Docker Needed)

Start with the saved results from the Azure run in [`results/ig-azure.json`](results/ig-azure.json) (referred to by the validation script as a `v1 receipt`). These commands work in a fresh clone with Python 3.10+ and Git, and do not contact Azure or install Inspektor Gadget:

```sh
git clone https://github.com/johnsonshi/IG-Shield.git
cd IG-Shield
python3 lab/receipt.py docs/results/ig-azure.json
python3 -m unittest discover -s lab -v
python3 lab/privacy.py HEAD
```

Running `python3 lab/receipt.py docs/results/ig-azure.json` prints:

```text
Verified v1 receipt. Timings in nanoseconds (min / median / max):
  off: 10508 / 14722 / 101276 (n=15)
  on: 23407 / 28475 / 102236 (n=15)
  first_open_event: 54052 / 95328 / 152555 (n=15)
```

### How to interpret the offline output

- **Schema and outcome verification (`Verified v1 receipt`):** [`../lab/receipt.py`](../lab/receipt.py) confirms that `pins_sha256` matches [`../lab/pins.json`](../lab/pins.json), that the PHP-FPM worker wrote both `canary.php` and `canary.txt` (`["written", "written", "ENOENT"]`) while `trace_open` logged `1` event for each plus the missing-file baseline `ENOENT`, that the JVM decoded `"control"` and returned `7` and `"empty"` across all phases while `trace_exec` logged `1` JVM launch, that `AF_UNIX` and `AF_ALG` socket calls stayed `allowed` while `traceloop` logged `18` returns per family, that `advise_seccomp` drafted an unapplied `SCMP_ACT_ERRNO` profile (`applied: false`), and that the VM ended in `PowerState/deallocated` with its original OS disk retained (`disk_state: "Reserved"`).
- **Timing lines (`min / median / max` in nanoseconds, where `1,000 ns = 1 µs`):**
  - `off` (`10,508 / 14,722 / 101,276 ns`, median **14.722 µs**): Time for the application to open, write 1 byte to, and close a `tmpfs` file without `trace_open`.
  - `on` (`23,407 / 28,475 / 102,236 ns`, median **28.475 µs**): Time for the application to complete that same `open + write + close` while `trace_open` was attached.
  - `first_open_event` (`54,052 / 95,328 / 152,555 ns`, median **95.328 µs**): Time from when the application started `open()` until the userspace Python reader received the first matching complete JSON line from the `ig` CLI over stdout.

---

## 2. Start or Rerun the Live Experiment on Azure

### Permissions, explicit ownership, and spend

Use a workstation with the Azure CLI (`az`), `ssh-keygen`, a signed-in Azure account, and permission to create resources in **your own authorized subscription**. This repository grants no roles. You need resource-group, network, and compute permissions for setup (`create`) and Azure VM Run Command permission (`Microsoft.Compute/virtualMachines/runCommand/action`) to prepare and run the fixture (`prepare` and `live`). Do not run it against a shared machine.

```sh
cp .env.example .env
# Edit AZURE_SUBSCRIPTION in .env. There is no ambient subscription fallback.
python3 lab/azure.py create
python3 lab/azure.py prepare
python3 lab/azure.py live
```

- **Explicit resource ownership (`.env` and `.state/owner.json`):** For an already prepared VM, the single rerun command is `python3 lab/azure.py live`. It requires the workstation's gitignored `.env` and `.state/owner.json`. **Never commit `.env` or `.state/` to Git.** The runner never discovers other VMs, never adopts an existing resource group, and never logs in over SSH. Before acting, `live` verifies the resource group and VM ownership tags, the immutable `vmId`, the original attached OS disk ID, the NSG bindings and effective rule order, the stock Ubuntu 26.04 image (`26.04.202611100`), Secure Boot, and vTPM.
- **Automatic deallocation and failure handling:** `live` starts the VM if deallocated, runs the fixed experiment, and then **deallocates the VM even if a measurement check fails**. A new result is written to `.state/verified.json` only after confirming `PowerState/deallocated` and the original bound OS disk. A failed run is never evidence of a security block, and an earlier file is not a result for a failed attempt.
- **Ongoing storage and IP spend:** If setup or measurement fails, `.state/azure.log` and `.state/last-command.log` stay local. `python3 lab/azure.py status` checks the bound VM's power state, and `python3 lab/azure.py park` deallocates it. Keep `.state/owner.json` if provisioning fails partway so you can inspect the tagged resource group in the Azure portal instead of creating duplicate resources. Resource-group deletion is intentionally manual, and **while compute billing stops when the VM is deallocated, the retained `StandardSSD_LRS` OS disk and static `Standard` public IP continue to incur small charges until you delete the resource group.**

### Network isolation and guest artifact verification

- **Pinned Git blob transport:** Guest inputs (including `cloud-init.yml`, `prepare.sh`, `measure.py`, `fixture.py`, `Control.java`, and `pins.json`) are read directly from bounded, regular Git blobs at commit `fb131298906015020fef618584bd56ed0c6aa537`. Uncommitted worktree edits and symlinks on the workstation are ignored by `measured_blob()`, so use a full clone that contains that commit.
- **Network lockdown:** `create` generates a disposable `ed25519` keypair solely to satisfy Azure OS provisioning and deletes the private key before `az vm create` runs. The isolated subnet disables default outbound access (`--default-outbound-access false`). Its single guest NIC and subnet share an NSG that denies all inbound traffic at priority `100` (`deny-in`), allows outbound TCP `443` to `Internet` at priority `100` (`https-out`, which is a port rule rather than an FQDN allowlist), and denies all other outbound traffic at priority `110` (`deny-out`). Cloud-init masks `ssh.service` and `ssh.socket`, the workload container runs with `--network=none`, and the PHP-FPM worker listens only on a private Unix socket (`/tmp/ig-control/fpm.sock`). Nothing on the guest needs a GitHub credential.
- **Guest package and binary checks:** `prepare` updates the stock Ubuntu 26.04 guest from signed distribution repositories and reboots if `/var/run/reboot-required` is present. It verifies the pinned Inspektor Gadget release public key (`release_key_sha256`), checks the RSA signature of `SHA256SUMS`, and checks both the release archive (`archive_sha256`) and extracted `ig` binary (`ig_sha256`) against [`../lab/pins.json`](../lab/pins.json). The Docker fixture image (`ig-validation-fixture:1`) is bootstrapped locally from signed Ubuntu archive packages (`php8.5-fpm`, `openjdk-25-jdk-headless`, `libh2-java`, `libfcgi-bin`) rather than copying the host filesystem. At run time, `ig` pulls the four stock gadgets by their pinned multi-arch index digests in [`../lab/pins.json`](../lab/pins.json) with `--verify-image=true`. Do not disable Secure Boot, seccomp, signature verification, or schema checks to force a run to pass.

---

## 3. What Is Timed and Experimental Limits

- **Single-CPU affinity (`vCPU 0`) and attachment boundary:** The networkless workload container is pinned to `vCPU 0` (`--cpuset-cpus=0`) in both untraced and traced phases. Early unpinned trials on this 4-vCPU guest could not reliably correlate every low-volume open and exec event before process exit and failed the strict validator checks. This single-CPU, bounded-rate test is **not** evidence of lossless system-wide tracing under high multi-core load. Also note that the IG fixture starts its PHP-FPM worker before `trace_open` attaches, whereas Shirudo's `app-sandbox` attaches on the first `execve` after the shield is loaded (`first_exec_after_load: true`).
- **File benchmark (`timing.off`, `timing.on`, and `timing.first_open_event`):** Each phase uses 15 pre-created `tmpfs` files (`sample-0.txt` through `sample-14.txt`) after three warmup files (`sample--3.txt` through `sample--1.txt`), with a 10 ms pause between iterations that is excluded from the per-operation timestamps. The unprivileged Python process (`uid 65534`) opens each file with `O_WRONLY | O_CREAT | O_TRUNC`, writes 1 byte (`b"x"`), and closes it, recording guest `CLOCK_MONOTONIC` nanoseconds before `open()` and after `close()`. Before starting the traced phase, `trace_open` must first observe a separate readiness marker file (`ready.txt`). Every measured sample file must produce exactly one matching `trace_open` JSON line within the 2-second delivery bound. `first_open_event` measures from the start of the application's `open()` call to the moment the host userspace reader thread receives the complete matching JSON line from `ig` stdout on the same `CLOCK_MONOTONIC` clock. The `28,475 ns` (`28.475 µs`) application median and the `95,328 ns` (`95.328 µs`) start-to-matching-line median answer separate questions with different endpoints: the workload container is pinned to `vCPU 0`, while the `95.328 µs` figure includes ring-buffer wakeup, userspace JSON formatting in `ig`, and pipe delivery to the host reader; it is not synchronous blocking latency or pure in-kernel BPF execution time. Azure VM Run Command, VM boot, and image pulls happen outside the timed loops.
- **Unbound socket benchmark (`sockets`) and `af_alg_restrict`:** The socket probe (`igsockprobe`) creates and immediately closes an unbound `AF_UNIX` (`SOCK_DGRAM`) or `AF_ALG` (`SOCK_SEQPACKET`) socket (`3` warmups + `15` measured calls per family in each phase). No address bind, socket option, crypto algorithm, payload, or peer is used. `traceloop` runs as a buffered syscall flight recorder whose ring buffer is flushed when the gadget stops, so its `matching_events` count (`18` `AF_UNIX` and `18` `AF_ALG`) includes the `3` warmups plus `15` measured calls and is not timed as streaming line delivery. Note that `crypto.af_alg_restrict` is a Linux sysctl setting that controls who can use part of Linux's kernel crypto socket interface (`AF_ALG`): the stock Azure kernel on the IG guest did not expose that setting (`af_alg_restrict: null`), whereas the companion Shirudo guest had a temporary lab value of `0` during its two control runs (not a recommended default) and restored it to its build default of `1` afterward ([`azure-af-alg-restoration.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-af-alg-restoration.json)).
- **Scenario checks, baseline `seccomp_mode: 2`, and privacy filtering:**
  - In the PHP-FPM check, the worker opens `canary.php` and `canary.txt` with exclusive create flags (`fopen(..., 'xb')`), writes `control-only` (12 bytes), and closes them, and the harness reads back those exact bytes before attempting to open the intentionally missing `absent.txt` (`ENOENT`).
  - In the Java check, a fresh JVM decodes `"Y29udHJvbA=="` to `"control"` and runs `SELECT 7` (`7`) and `SELECT 7 WHERE 8 > 3 AND 4 = 5` (`"empty"`) against an empty in-memory H2 database. `trace_exec` proves that the `java` binary executed (`exec_events: 1`), not what bytecode or SQL ran inside the JVM.
  - In the seccomp advisor check, the container already runs with Docker's normal baseline security restrictions (`seccomp_mode: 2` in `/proc/self/status`). While it runs, `advise_seccomp` prints a candidate JSON profile (`defaultAction: SCMP_ACT_ERRNO`); the harness verifies that `openat` and `socket` are in the allowlist, never turns that new suggested policy on (`applied: false`), and discards the raw syscall list.
  - Only allowlisted outcomes, counts, and nanosecond durations are exported into the final JSON result. Raw event streams, container IDs, hostnames, and absolute timestamps are never persisted to the repository.

