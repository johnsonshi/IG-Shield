# What Stock Inspektor Gadget Sees (and What Shirudo Blocks) on Azure

By Johnson Shi

I asked a live PHP web worker to write two new files containing the same harmless text: `canary.php` and `canary.txt`. On my Shirudo VM, while its web-sandbox rule was loaded, `canary.php` got "Permission denied" and `canary.txt` was written; after I unloaded that rule, the worker could write both files again. On a second VM running stock Inspektor Gadget, the file tracer named the PHP worker process that opened both `canary.php` and `canary.txt`, and both writes succeeded there. Upstream Inspektor Gadget supplies those open-source file-watching tools, while this `IG-Shield` repository is my Azure experiment testing them alongside Shirudo.

Why is seeing that successful open useful when nothing was blocked? If you run a live web service, workers often need to write plain text or cache files like `canary.txt`, while a new `.php` script appearing in a writable folder is a red flag. Before you turn on a strict blocking rule that denies every `.php` write in production, you need to know whether a legitimate updater, plugin, or cache step in your app is already creating `.php` files. Seeing the live open events first on your existing kernel tells you whether a future blocking rule would protect your service or break it.

---

## Who Built What (and Why I Ran Both Setups)

**[Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget)** is an open-source Linux eBPF toolkit maintained by the upstream [CNCF Sandbox project](https://www.cncf.io/projects/inspektor-gadget/). Its maintainers built it to package kernel tracers and policy advisors as container images called **gadgets** that run on standard distribution kernels.

When I built my earlier [Shirudo-on-Azure experiment](https://github.com/johnsonshi/shirudo-on-azure#readme), I tested [Shirudo](https://github.com/shirudo-dev/shirudo), an open-source runtime mitigation framework that uses kernel security hooks and Java bytecode agents to refuse specific operations in place and record active rules in a virtual TPM register. That work sparked a follow-up question for this independent `IG-Shield` repository: if I point the unmodified upstream Inspektor Gadget `v0.58.0` release and four official stock gadgets (`trace_open`, `trace_exec`, `traceloop`, and `advise_seccomp`) at the same five control areas on an Azure Ubuntu VM, what does a stock observability toolkit show an operator, and does any gadget block an operation?

Take note: `IG-Shield` is an independent Azure experiment, not an official CNCF project, and I did not write a custom blocking gadget. In the saved results from my Azure run ([`../results/ig-azure.json`](../results/ig-azure.json)), **none of the four stock Inspektor Gadget gadgets blocked anything.** Both PHP file writes, the Java Base64 decode, both in-memory database queries, and both socket families succeeded (while a deliberate read of a missing file failed with "No such file or directory" as expected). Putting the saved results from both VMs side by side shows how live observation and inline blocking fit together.

![How Shirudo Inspires IG-Shield: Enforcement vs. Observability](../figures/ig-vs-shirudo-boundaries.svg)

*Figure 1: Shared Linux kernel and JVM control surfaces across upstream Shirudo and stock upstream Inspektor Gadget (`v0.58.0`). Editable Mermaid source: [`../figures/ig-vs-shirudo-boundaries.mmd`](../figures/ig-vs-shirudo-boundaries.mmd).*

---

## Walking Through the Five Scenarios on Both VMs

Before looking at kernel configurations or cryptographic hashes, here is what each test did, what the application saw, and what the logs recorded in the saved results from the Inspektor Gadget Azure run ([`../results/ig-azure.json`](../results/ig-azure.json)) and the companion Shirudo runs ([`azure-controls.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls.json) and [`azure-controls-real-runtimes.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls-real-runtimes.json)).

### 1. Web Worker File Creation (`canary.php` vs. `canary.txt`)

In the file scenario, a real Ubuntu PHP-FPM worker handled a local request and tried to create `canary.php` and `canary.txt` in `/tmp/ig-control`, writing `control-only` (12 bytes) into each. I checked the outcome before turning on the tool, while the tool was active, and after stopping or unloading it:

- **On the Inspektor Gadget VM (with stock `trace_open`):** The PHP worker wrote both `canary.php` and `canary.txt` before starting `trace_open`, while `trace_open` was running, and after stopping `trace_open` (`written`, `written` in all three steps). Nothing was blocked, and `trace_open` logged one open event for `canary.php` and one for `canary.txt`.
- **On the companion Shirudo VM (with Shirudo's `app-sandbox` rule):** The PHP worker wrote both files before loading the rule (`written`, `written`). While `app-sandbox` was loaded, the kernel refused `canary.php` with `Permission denied` (`EACCES`) while allowing `canary.txt` (`written`). After I unloaded `app-sandbox`, the PHP worker wrote both `canary.php` and `canary.txt` again (`written`, `written`), confirming that removing the rule restored normal behavior.

Two details help avoid misreading [`../results/ig-azure.json`](../results/ig-azure.json):
- **An open event in the log is not proof that text was written:** `trace_open` reports when a process opens or creates a file, not what bytes get written afterward. That is why I checked the PHP response and read the 12 bytes (`control-only`) back from disk separately from counting `trace_open` log lines.
- **Why `ENOENT` in the saved results is not a security block:** In each step, I also had the test try to open `/tmp/ig-control/absent.txt`, a file that intentionally does not exist. That call failed with `No such file or directory` (`ENOENT`), so the saved result lists `["written", "written", "ENOENT"]`. That missing-file check only confirms that normal file errors are reported accurately; it is not a policy block.

### 2. Live JVM Continuity (`trace_exec` vs. Shirudo `java-base64`)

Separately, I ran a Java program on OpenJDK 25 that decoded the valid Base64 string `"Y29udHJvbA=="` into `"control"`.

- **On the Inspektor Gadget VM:** The Java program decoded `"control"` before, during, and after tracing. While `trace_exec` was running, it logged `1` process-start event when the `java` binary launched (`exec_events: 1`). Because `trace_exec` watches OS process starts at the kernel boundary, its log shows that `java` started, while the decoded `"control"` string comes from the Java program's own output.
- **On the companion Shirudo VM:** This scenario tested whether attaching a pre-existing sealed Java agent (`/run/shirudo-java/java-base64.jar`) disrupted a running process (`scope: "continuity_only"`). One long-lived JVM decoded `"Y29udHJvbA=="` to `"control"` before attach, had the sealed agent explicitly attached to that running process, and decoded `"Y29udHJvbA=="` to `"control"` again while keeping the exact same PID and process start time (`same_pid_and_jvm_start: true`).

### 3. In-Memory Database Queries (`trace_exec` vs. Shirudo `java-sql-inj`)

Inside the same Java program, I opened an empty in-memory database via JDBC and ran two fixed queries: a scalar read (`SELECT 7`) and a harmless false arithmetic condition (`SELECT 7 WHERE 8 > 3 AND 4 = 5`).

- **On the Inspektor Gadget VM:** Using Ubuntu's H2 database package, `SELECT 7` returned `7` and the harmless false condition returned `"empty"` (zero rows) before, during, and after tracing. `trace_exec` logged the single `java` process launch (`exec_events: 1`), and no query inside the JVM was blocked.
- **On the companion Shirudo VM:** In both Shirudo runs (first with a mock SQLite JDBC statement in [`azure-controls.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls.json), then with the real Ubuntu H2 JDBC package in [`azure-controls-real-runtimes.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls-real-runtimes.json)), the scalar read `SELECT 7` still returned `7` in every step. Meanwhile, the harmless policy-matching query (`SELECT 7 WHERE 8 > 3 AND 4 = 5`) returned `"empty"` before loading the rule, was refused with `"policy-exception"` (`SecurityException`) inside a newly started JVM while the sealed Byte Buddy agent (`/run/shirudo-java/java-sql-inj.jar`) was loaded, and returned `"empty"` again in a new JVM after I unloaded the rule.

### 4. Unbound Socket Creation (`traceloop` vs. Shirudo `cve-2026-31431-af-alg-block`)

Next, an unprivileged Python probe created and immediately closed unbound local Unix datagram sockets (`AF_UNIX`) and Linux kernel crypto sockets (`AF_ALG`), running `3` warmups followed by `15` measured calls (`18` total per socket family).

- **On the Inspektor Gadget VM:** Both `AF_UNIX` and `AF_ALG` socket calls succeeded (`allowed`) before, during, and after tracing. When I stopped `traceloop` (Inspektor Gadget's system-call flight recorder), it reported all `18` `AF_UNIX` and `18` `AF_ALG` successful `socket()` syscall returns.
- **On the companion Shirudo VM:** Shirudo's `cve-2026-31431-af-alg-block` rule checks only the socket address family (`AF_ALG`). Before loading the rule, both `AF_UNIX` and `AF_ALG` succeeded (`allowed`). While the rule was loaded, `AF_ALG` was refused inline with `EPERM` (`Operation not permitted`) while `AF_UNIX` stayed `allowed`. After I unloaded the rule, both `AF_UNIX` and `AF_ALG` succeeded again.

### 5. Seccomp Policy Suggestion vs. Signed BPF Lifecycle (`advise_seccomp` vs. Shirudo `basic`)

- **On the Inspektor Gadget VM (`advise_seccomp`):** While the container ran its file and socket probes, `advise_seccomp` watched the system calls and printed a suggested seccomp syscall allowlist (allowing `openat` and `socket`). **Nobody applied that suggested list, and it did not block anything.**
- **On the companion Shirudo VM (`basic`):** Shirudo's `basic` control loaded and unloaded a signed kernel BPF program (`fentry/do_nanosleep`), confirming that the kernel verified the signature, transitioned the program from `absent` to `loaded_and_measured` and back to `absent`, and extended the VM's virtual TPM register on both transitions.

---

## Under the Hood: How the Catalog, Trust Layers, and VMs Work

### 1. How Upstream Inspektor Gadget and Its OCI Catalog Work

Meanwhile as a refresher, Inspektor Gadget packages every gadget as an OCI image in a container registry:

- **What is inside a gadget image:** A compiled eBPF object (`program.bpf.c`), a metadata manifest (`gadget.yaml`) declaring fields and operators, and an optional WebAssembly (`.wasm`) module for userspace formatting or filtering.
- **Official stock gadgets vs. third-party community gadgets:** Upstream maintains its stock gadgets in-tree under [`gadgets/`](https://github.com/inspektor-gadget/inspektor-gadget/tree/v0.58.0/gadgets) and publishes them to `ghcr.io/inspektor-gadget/gadget/<name>:<tag>`. Community authors can also build third-party gadgets with `ig image build` and list them on Artifact Hub (which indexes Inspektor Gadget repositories under repository kind `22`). Note that Artifact Hub catalog metadata is separate from the GHCR release images: when I queried the Artifact Hub API for `inspektor-gadget/gadgets/trace-open`, the catalog record reported `verified_publisher: true`, `official: false`, and version `0.57.0` (lagging the `v0.58.0` GHCR images pinned in [`../../lab/pins.json`](../../lab/pins.json)).
- **Observation vs. enforcement in `v0.58.0`:** None of the four stock `v0.58.0` gadgets pinned in [`../../lab/pins.json`](../../lab/pins.json) deny system calls. Even if you inspect upstream's other stock `v0.58.0` security-related gadgets (`audit_seccomp` and `trace_lsm`), `audit_seccomp` only logs hits from an existing seccomp filter, and `trace_lsm` hooks `file_open` (omitting `socket_create` and `socket_connect`, with no address-family or `errno` field) and ends every handler with `return 0;`. That is specific to these stock `v0.58.0` gadgets, not a blanket claim that no third-party eBPF gadget could ever block.

![How Upstream Inspektor Gadget Works: OCI Catalog & Control Matrix](../figures/ig-community-gadget-workflow.svg)

*Figure 2: OCI gadget catalog taxonomy and the three-bucket capability split across the five control surfaces for stock `v0.58.0` Inspektor Gadget. Editable Mermaid source: [`../figures/ig-community-gadget-workflow.mmd`](../figures/ig-community-gadget-workflow.mmd).*

### 2. Separating the Four Layers of Trust

When comparing how Shirudo and Inspektor Gadget verify what runs on a VM, four separate layers are at play:

1. **Release archive attestation (`release/v0.2`):** Running `gh release verify-asset v0.58.0 ig-linux-amd64-v0.58.0.tar.gz -R inspektor-gadget/inspektor-gadget` verified GitHub's immutable release attestation (`https://in-toto.io/attestation/release/v0.2`) for the `v0.58.0` archive whose SHA-256 matches [`../../lab/pins.json`](../../lab/pins.json). That proves the archive came from the official GitHub release, not which gadgets are running on a VM.
2. **Publisher signature verification:** Inspektor Gadget verifies OCI gadget signatures in userspace by default (`--verify-image=true`) using `cosign` against the embedded official Inspektor Gadget public key. Shirudo verifies kernel BPF `.upatch` programs inside the Linux kernel against an initrd-sealed `.bpf` keyring (while `lsm/bpf` rejects unsigned BPF loads) and verifies Java `.upatch` agents in `/run/shirudo/runtime/usr/bin/shirudo`, sealing the JARs under `/run/shirudo-java`.
3. **Artifact digest pinning:** [`../../lab/pins.json`](../../lab/pins.json) pins the exact SHA-256 digests for `trace_open`, `trace_exec`, `traceloop`, and `advise_seccomp`. Shirudo binds every `.upatch` unload to the loaded artifact's `payload_sha256`.
4. **Hardware vTPM state attestation:** Shirudo binds TPM NV register `0x01818E00` in the initrd and extends it synchronously on every signed load and unload (`727.428 ms` to `800.637 ms` per one-shot signed CLI load or unload including vTPM work). Stock Inspektor Gadget runs on a Trusted Launch VM with Secure Boot and vTPM on, but does not seal kernel `.bpf` keyrings or extend a TPM register when gadgets start or stop.

### 3. Comparison Limits and How the Two Azure VMs Differ

Both phases used isolated Azure West US 3 `Standard_D4ds_v5` VMs provisioned from the same Canonical Ubuntu 26.04 LTS base image (`26.04.202611100`), but they are **distinct VMs** with different kernels, boot policies, and fixture details:

- **Kernel and boot policy:** The Inspektor Gadget VM runs the stock Azure Ubuntu kernel (`7.0.0-1021-azure`) with **Secure Boot on** and **vTPM on**, and ends deallocated (`power: "deallocated"`) with its original OS disk retained (`disk_state: "Reserved"`). The Shirudo target VM runs a custom kernel (`7.4-shirudo-azure-20261124` built from `bpf-next` commit `2bf3351c5f894697e8443eeef5333d4c4ce90cab` with `CONFIG_LSM="bpf"`), **vTPM on**, and **Secure Boot off** (`secure_boot: false` for its unsigned custom Unified Kernel Image), plus two disclosed Azure compatibility patches (`0001-tpm-size-the-NV-writer-key-for-vTPMs-without-RSA-307.patch` and `0002-init-retry-boot-image-teardown-while-udev-probes-the.patch`), paired with a separate `Standard_D32ds_v5` signing VM.
- **PHP-FPM attachment boundary:** On the Inspektor Gadget VM, the PHP-FPM worker is already running inside the networkless container (pinned to `vCPU 0`) before `trace_open` attaches. On the Shirudo VM, `app-sandbox` tags `php-fpm` when the worker first executes after the shield is loaded (`first_exec_after_load: true`).
- **Why [`../results/ig-azure.json`](../results/ig-azure.json) says `seccomp_mode: 2` even though `advise_seccomp` was not applied (`applied: false`):** Linux reports `Seccomp: 2` (`seccomp_mode: 2`) whenever a process runs under a seccomp filter, and Docker starts containers with its normal default seccomp profile enabled. The new seccomp policy that `advise_seccomp` suggested (`defaultAction: SCMP_ACT_ERRNO`, allowing `openat` and `socket`) was only printed as text and was **never turned on** (`applied: false`).
- **Linux crypto socket setting (`af_alg_restrict`):** `crypto.af_alg_restrict` is a setting that controls who can use part of Linux's kernel crypto socket interface (`AF_ALG`). The stock Azure kernel on the Inspektor Gadget VM did not expose that setting (`af_alg_restrict: null`). On the Shirudo VM, both control runs executed while `crypto.af_alg_restrict` had a temporary lab value of `0` (which is not a recommended default); post-run housekeeping ([`azure-af-alg-restoration.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-af-alg-restoration.json)) verified that `crypto/af_alg.c:32` defaults to `1` and restored `crypto.af_alg_restrict` from `0` to `1` without re-running the socket probe (`probe_rerun_after_restoration: false`).

---

## Plain-English Guide to the Timing Numbers

### 1. File Benchmark on the IG Guest (`14.722 µs` vs. `28.475 µs` vs. `95.328 µs`)

In [`../results/ig-azure.json`](../results/ig-azure.json), an unprivileged Python loop inside the container (pinned to `vCPU 0`) opened a pre-existing file on `tmpfs`, truncated and wrote 1 byte to it, and closed it (`n = 15` measured iterations after `3` warmups on `CLOCK_MONOTONIC`):

- **Without `trace_open` (`timing.off`):** The application's `open + write + close` took a median of **14.722 µs** (`14,722 ns`; min `10.508 µs` / `10,508 ns`, max `101.276 µs` / `101,276 ns`).
- **With `trace_open` attached (`timing.on`):** The application's `open + write + close` took a median of **28.475 µs** (`28,475 ns`; min `23.407 µs` / `23,407 ns`, max `102.236 µs` / `102,236 ns`).
- **Application start to first matching CLI line (`timing.first_open_event`):** From the start of the application's `open()` call until the host CLI reader received the first matching complete JSON line from the `ig` CLI took a median of **95.328 µs** (`95,328 ns`; min `54.052 µs` / `54,052 ns`, max `152.555 µs` / `152,555 ns`).

**Why that distinction matters:**
- `14.722 µs` vs. `28.475 µs` and `95.328 µs` answer two separate questions with different endpoints.
- `14.722 µs` vs. `28.475 µs` measures what the **application** (pinned to `vCPU 0` inside the workload container) waits for its own `open + write + close` to finish; it does not wait for a security verdict.
- `95.328 µs` measures from the start of `open()` until the **host CLI reader** receives the first matching formatted JSON line from `ig` stdout, which includes kernel ring-buffer delivery, JSON formatting inside `ig`, and pipe read time.
- Because this is an `n = 15` (after `3` warmups) single-vCPU workload test spanning `open + write + close`, it is **not** pure in-kernel eBPF overhead, **not** attack detection latency, and **not** a platform ranking.

### 2. Unbound Socket Medians (`AF_UNIX` and `AF_ALG`, `n = 15` after `3` warmups)

- **On the Inspektor Gadget VM ([`../results/ig-azure.json`](../results/ig-azure.json)):** Both families stayed `allowed`. `AF_UNIX` medians were **2.964 µs** (`2,964 ns` before), **9.751 µs** (`9,751 ns` during `traceloop`), and **2.989 µs** (`2,989 ns` after). `AF_ALG` medians were **2.483 µs** (`2,483 ns` before), **9.347 µs** (`9,347 ns` during `traceloop`), and **2.848 µs** (`2,848 ns` after).
- **On the Shirudo VM ([`azure-controls.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls.json) and [`azure-controls-real-runtimes.json`](https://github.com/johnsonshi/shirudo-on-azure/blob/a989c9e7551be2059f9bb3f8ee16b3965e7bd373/docs/results/azure-controls-real-runtimes.json)):** `AF_ALG` went from `allowed` (**1,890 ns** in Run 1 / **1,952 ns** in Run 2) to inline `EPERM` refusal (**1,446 ns** in Run 1 / **1,442 ns** in Run 2) while loaded, and back to `allowed` (**1,886 ns** / **1,929 ns**) after unload, while `AF_UNIX` stayed `allowed` (**2,058 / 2,122 / 1,985 ns** in Run 1; **2,096 / 2,124 / 2,111 ns** in Run 2). Because an immediate `-EPERM` return inside `lsm/socket_create` skips socket allocation and `close(fd)`, `1,442 ns` vs. `1,952 ns` compares two different code paths and is not a speedup.

For the full side-by-side reference tables, see [`../comparison.md`](../comparison.md). To replay the saved results offline (`python3 lab/receipt.py docs/results/ig-azure.json`) or run the live Azure workflow, see [`../reproduce.md`](../reproduce.md).

---

## Closing Forecast

Looking at both projects side by side, their roles are complementary rather than overlapping. Stock upstream Inspektor Gadget (`v0.58.0`) gives operators immediate, OCI-packaged visibility (`trace_open`, `trace_exec`, `traceloop`) and seccomp profile drafting (`advise_seccomp`) on unmodified distribution kernels with Secure Boot enabled. Upstream Shirudo takes on the heavier requirements of a custom `CONFIG_LSM="bpf"` kernel, initrd keyring sealing, and synchronous vTPM `NV_Extend` accounting so that it can refuse vulnerable kernel paths (`-EACCES`, `-EPERM`) and enforce sealed JVM bytecode guards inline.

I think future cloud defense workflows will pair both patterns in a two-stage loop: using stock OCI observability gadgets on standard nodes to see which processes open files, launch binaries, or use niche socket families across a fleet, and reserving signed, TPM-attested LSM shields or container-runtime seccomp profiles for the specific boundaries that require synchronous inline refusal. Perhaps upstream gadget catalogs will eventually standardize read-only capability metadata in `gadget.yaml` so operators can see at a glance whether an OCI artifact is a passive ring-buffer tracer, a policy advisor, or an active LSM enforcer.

