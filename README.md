# IG-Shield

IG-Shield is an Azure lab inspired by [Shirudo](https://github.com/shirudo-dev/shirudo) and built with [Inspektor Gadget (IG)](https://github.com/inspektor-gadget/inspektor-gadget). It borrows the before-and-after test design from [Shirudo on Azure](https://github.com/johnsonshi/shirudo-on-azure#readme). The Shirudo demos show what a security rule can block. IG-Shield runs comparable workloads on a stock Ubuntu VM to show what four ready-made IG tools, called *gadgets*, can observe.

In the PHP demo, a web worker tries to create two files. On the Shirudo VM, a rule allows `canary.txt` but denies `canary.php`. On the IG-Shield VM, both writes succeed, and the tracer names the worker that opened each file. That gives an operator a way to check which programs create `.php` files before deciding where to block those writes.

## Quick start: inspect the results offline

From the repository root, with Python 3.10 or later:

```sh
python3 lab/receipt.py docs/results/ig-azure.json
```

The command checks the outcomes in the [saved result](docs/results/ig-azure.json) and confirms that it references the [pinned tool versions](lab/pins.json). Look for `Verified v1 receipt` followed by three timing rows. No Azure account, Docker installation, or running tracer is needed.

## What the gadgets show

| Upstream gadget | Workload and observation |
| --- | --- |
| `trace_open` | The tracer reported the worker and the paths it opened. The test also read the text back from both files: an open event alone cannot prove the write succeeded. |
| `trace_exec` | The tracer recorded the Java program starting. The program itself confirmed that it decoded a valid Base64 value and ran two fixed queries in an in-memory H2 database. The trace did not reveal the query text or its result. |
| `traceloop` | The flight recorder captured successful calls to create local Unix sockets and Linux crypto sockets. The test closed each socket without connecting or sending data. |
| `advise_seccomp` | The advisor generated a suggested list of system calls to allow, including file opens and socket creation. The lab did not apply that list; the container kept its existing security settings. |

## What the timings mean

The offline command reports nanoseconds. The medians below are converted to microseconds. Each comes from 15 measured file operations after three warmups, with the test workload pinned to one virtual CPU.

| Output row | Measured interval | Median |
| --- | --- | ---: |
| `off` | Application opens a file, writes one byte, and closes it without `trace_open`. | 14.722 µs |
| `on` | The same operation while `trace_open` is active. | 28.475 µs |
| `first_open_event` | Start of the application's file operation to the first matching line received from the IG command-line tool. | 95.328 µs |

The first two rows measure application work. The third measures when an observer can see the event, including scheduling and output processing. It is not time to block an operation or a performance ranking against Shirudo.

## Run on Azure

The [reproduction guide](docs/reproduce.md) covers prerequisites, cost, deployment, and reruns. The runner uses Azure VM Run Command; the workload container needs no inbound application port. On an already prepared lab, `python3 lab/azure.py live` starts the owned VM if necessary, runs the checks, and deallocates it. The retained OS disk and public IP can still incur charges.

The measured configuration used [Inspektor Gadget v0.58.0](https://github.com/inspektor-gadget/inspektor-gadget/releases/tag/v0.58.0) with Secure Boot enabled. IG-Shield is an independent project built with upstream Inspektor Gadget, a [CNCF Sandbox project](https://www.cncf.io/projects/inspektor-gadget/). See the [side-by-side results](docs/comparison.md) for the differences between the two VMs and the [illustrated article](docs/blog/inspektor-gadget-and-shirudo-on-azure.md) for the background on community gadgets.
