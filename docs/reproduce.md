# Reproduce the Azure VM control run

Start with the [checked-in result](results/ig-azure.json). These commands work in a fresh clone with Python 3.10+ and Git. They do not contact Azure or install IG:

```sh
git clone https://github.com/johnsonshi/IG-Shield.git
cd IG-Shield
python3 lab/receipt.py docs/results/ig-azure.json
python3 -m unittest discover -s lab -v
python3 lab/privacy.py HEAD
```

## Start or rerun the isolated demo

Use a workstation with the Azure CLI, `ssh-keygen`, a signed-in Azure account, and permission to create resources in **your authorized subscription**. This lab grants no roles. The person running it needs resource-group, network and compute permissions for setup and Azure VM Run Command permission to run the fixed fixture. Do not run it against a shared machine.

```sh
cp .env.example .env
# Edit AZURE_SUBSCRIPTION in .env. There is no ambient subscription fallback.
python3 lab/azure.py create
python3 lab/azure.py prepare
python3 lab/azure.py live
```

For the already prepared VM the single live command is `python3 lab/azure.py live`. Use the original workstation's ignored `.env` and `.state/owner.json`, or restore them from your private backup. **Do not copy them to Git.** The tool does not discover other VMs, adopt an existing group, or log in over SSH. `live` checks the group and VM ownership tags, immutable VM ID and original disk, NSG bindings and effective rule order, stock image, Secure Boot and vTPM. It starts the VM if deallocated, runs the fixed experiment, then deallocates it even on a measurement error. A valid result is written to `.state/verified.json` only after confirming `PowerState/deallocated` and the original attached disk. A failed run is not evidence of blocking; an earlier successful file is not a receipt for that failed attempt.

`create` uses one disposable local public key to satisfy OS provisioning. The private half is destroyed before VM creation. The new isolated subnet disables implicit outbound access. Its sole guest has an explicit outbound public IP with inbound denied at priority 100 on **both** NIC and subnet; no load balancer or public application is deployed. Egress to the Internet is TCP 443, not an FQDN allowlist. Azure platform agent/DNS traffic is separate. Cloud-init masks SSH, and the container has no network or published ports. Lower-priority organizational NSG rules are preserved. The fixture's PHP-FPM listener is a private Unix socket. Nothing on the guest needs a private GitHub credential.

`prepare` updates the stock distribution through signed Ubuntu repositories and reboots when needed. It verifies the pinned release public key, checks the RSA signature of `SHA256SUMS`, and checks both the archive and extracted executable against [the lock](../lab/pins.json). This is not a claim of full transparency-log or TPM attestation. The fixture image contains only packages bootstrapped from the signed distribution archives, not a copy of the running host. At run time the pinned CLI uses the official gadget index digests and upstream signature verification; no custom gadget is built or loaded. Distro updates are intentional, so a later package or kernel revision can differ from the recorded one. Do not disable Secure Boot, seccomp, signature verification, kernel restrictions, or the schema checks to make a run pass.

If setup fails, `.state/azure.log` and `.state/last-command.log` stay local. `python3 lab/azure.py status` inspects only the bound VM, and `python3 lab/azure.py park` safely deallocates it. Keep `.state/owner.json` on partial provisioning failure: inspect the named, tagged group with the Azure portal rather than rerunning creation blind. No group deletion is automated. Disk and public IP charges may persist while compute is deallocated.

## What is timed

The networkless workload is pinned to vCPU 0 in **both** phases. Early unpinned trials could not reliably correlate all low-volume opens and execs on this guest. They did not pass the receipt checks. This bounded, affinity-controlled result is not evidence of lossless system-wide tracing. The IG run uses a prestarted PHP-FPM worker; it does not reproduce Shirudo's first-exec attachment boundary.

The file-operation experiment uses 15 pre-created tmpfs files per phase after three warmups. The same unprivileged Python process opens each file with create/truncate flags, writes one byte, and closes it, first without an observer and then with the signed `trace_open` attached. Both timestamps are guest-local `CLOCK_MONOTONIC` nanoseconds. The operation excludes the deliberate pause between samples. A separate successful ready-file event is required before the observed phase. Each distinct sample filename must yield exactly one matching event. `first_open_event` measures from before the application open to the guest reader receiving the first complete matching IG CLI line, on the same clock. The two-second bound applies to each matched event. It includes scheduling, gadget processing and userspace delivery; it is not synchronous denial time, pure BPF cost, or a maximum guarantee. Run Command, VM startup and artifact pulls are outside the samples.

The unbound socket probe creates and immediately closes one AF_UNIX datagram socket or AF_ALG sequenced-packet socket. No bind, option, algorithm, payload or peer is used. Each phase reports the median of 15 attempts per family after three warmups. `traceloop` is a **buffered flight recorder**; matched returns include the three warmups and are inspected at stop, not timed as event delivery. The unprivileged host comparison does not attach a host-wide observer. A preexisting kernel/runtime error is not a denial by IG.

The PHP check validates exclusive creates and the resulting fixed bytes for `canary.php`, then `canary.txt`. A known nonexistent read is an error-path control, not an enforcing policy. The Java check starts a new real JVM, decodes a valid constant, and runs only `SELECT 7` and a fixed false predicate in an empty in-memory H2 database. An exec event proves process execution, not interpretation of bytecode or JDBC. The seccomp advisor prints a candidate syscall allowlist; the harness checks for `socket` and `openat`, never applies the profile, and discards the raw list. All observers select only the disposable container in the kernel; `trace_open` also filters fixture paths in userspace. The release can emit additional JSON fields regardless of `--fields`. Only allowlisted fixture outcomes and durations are retained. No event streams, profiles, identifiers or absolute timestamps are published.
