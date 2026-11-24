# IG-Shield

This Azure lab compares **what Inspektor Gadget observed** with **what Shirudo enforced** on fixed, harmless workloads. It runs the [upstream IG release](https://github.com/inspektor-gadget/inspektor-gadget/releases/tag/v0.58.0) and four signed, digest-pinned gadgets. It does not implement a custom shield.

The IG guest reported both PHP-FPM file creates, a real JVM exec and successful unbound socket calls. The file writes, H2 reads and socket creates still succeeded. In the [Shirudo comparison](docs/comparison.md), a denied operation is counted only when the application itself saw the error and the control recovered.

Start with the [illustrated walkthrough](docs/blog/inspektor-gadget-and-shirudo-on-azure.md), or go straight to the [measured receipt](docs/results/ig-azure.json), [artifact lock](lab/pins.json), and [setup and measurement method](docs/reproduce.md). To verify the result and replay its timing summary **offline**:

```sh
python3 lab/receipt.py docs/results/ig-azure.json
```

For a **live Azure rerun**, use `python3 lab/azure.py live` from the workstation with the [prepared guest's private ownership state](docs/reproduce.md#start-or-rerun-the-isolated-demo). It starts the owned guest, verifies all controls, and deallocates it while keeping its OS disk.
