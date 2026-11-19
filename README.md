# lantern-boot

The **boot path** for LanternOS, and the system image it starts. It brings the machine up, places the kernel, builds the
first confined programs from their ELF images, hands each exactly the capabilities it needs, and then gets out of the way.

- **Layer:** TCB (it runs before anything is confined).
- **Language:** Rust.
- **System context:** [wiki/Hardware](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Hardware.md), [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md).

> **Phase 4** ([RFC-0036](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0036-phase-3-to-phase-4-transition.md)): hardware and assurance. The interactive system boots from its own disk through UEFI on QEMU `virt` (riscv64): see
> [`STATUS.md`](./STATUS.md). It is a research system: its keys are public demo keys, and nothing below the kernel is
> verified yet ([RFC-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0023-hardware-key-custody-in-phase-4.md)'s checklist). Real hardware is
> Phase 4's bring-up.

## Run LanternOS

You need a Rust toolchain with the `riscv64gc-unknown-none-elf` target, `qemu-system-riscv64` (10.x), and EDK2's RISC-V
firmware (`qemu-efi-riscv64` on Debian and Ubuntu).

```sh
# Build the boot image, the EFI loader, and an installable disk: lantern.img. The first time, this downloads the
# language model (61 MB, MIT-licensed) into ~/.cache/lantern and checks it; LANTERN_NO_MODEL=1 leaves it out.
scripts/make-image.sh lantern.img

# Boot it: the firmware finds the loader on the disk, which starts LanternOS. No -kernel.
cp /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd vars.fd
qemu-system-riscv64 -machine virt,acpi=off -m 256M -nographic \
  -drive if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
  -drive if=pflash,unit=1,format=raw,file=vars.fd \
  -global virtio-mmio.force-legacy=false \
  -drive if=none,format=raw,file=lantern.img,id=disk -device virtio-blk-device,drive=disk \
  -device virtio-rng-device -netdev user,id=net -device virtio-net-device,netdev=net
```

The last line gives LanternOS randomness and a network card. Without it, everything else works, and the wallet refuses
every network identity.

At the console, `help` lists the commands. `apps` lists the apps on the disk, and `run confined-fs-probe` starts one: it
asks for what it needs, and you decide. What it writes, and what you decide, stays on `lantern.img` across reboots.

To try the local AI agent ([RFC-0034](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0034-local-inference-and-a-file-assistant.md)):

```text
> write 1 Once upon a time, there was a little dog named
> run file-assistant        (it asks for file 1, file 2 and the language model: answer each)
> read 2                    the model's continuation, written by the assistant
> files                     who wrote each file
> audit 20                  every use of each grant, including which model ran and whose it was
> archive                   audit history kept after the log retired it, sealed on the disk
```

The model is small (15 million parameters, trained on children's stories), so it continues text rather than following
instructions. It runs on the CPU inside a confined service and never leaves the machine.

To try network identities ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)), start two test peers
on the host first, in another terminal: QEMU's network reaches the host at `10.0.2.2`, where the greeter's two peers are.

```sh
(cd tools/peer && cargo run -q --target "$(rustc -vV | sed -n 's/^host: //p')" -- --name alice.test --port 7001 --log peers.log) &
(cd tools/peer && cargo run -q --target "$(rustc -vV | sed -n 's/^host: //p')" -- --name bob.test --port 7002 --log peers.log) &
```

```text
> run greeter               (it asks for alice.test and for bob.test: answer each)
> identities                which identity it presented to each: two different keys
> audit 20                  every connect, send and receive, with the key it used
```

`tools/peer/peers.log` shows the identity each peer saw. They're unrelated, and the same again after a reboot.

**Installing** is writing that image to a disk: a VM uses `lantern.img` as its disk, as above, and a machine has it
written whole to its own ([RFC-0032](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0032-installing-a-bootable-disk.md)). On real hardware, that's
the roadmap's next step.

`acpi=off` is needed because QEMU gives ACPI tables by default, and EDK2 then omits the device tree LanternOS reads.

## In this repo
- `src/` — the boot image's entry, the loader that builds programs (`launch.rs`), and each boot image (`system/` is the
  interactive system; the others are demos).
- `efi-loader/` — the UEFI application that starts the boot image from the disk.
- `blk-driver/`, `volume/`, `keystore-service/`, `store-service/`, `inference-service/`, `rng-driver/`, `net-driver/`,
  `net/`, `wallet/` — confined system programs; `virtio/` is the newer drivers' shared virtio code. The archiver, which
  keeps audit history, is in `lantern-shell`.
- `tools/mkdisk/`, `tools/elf2efi/`, `tools/mkmodel/`, `tools/peer/` — host tools that write the disk, build the EFI
  loader, convert the model, and stand in for a network peer.
- `scripts/` — the QEMU suites, `make-image.sh`, and `get-model.sh`.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Why this matters
If boot is subverted, every later guarantee is void. The boot path is therefore as security-critical as the kernel: small,
auditable, and eventually anchored in a hardware root of trust with **measured boot**, so the system can *prove* what it is
running. Today the chain is firmware, loader, kernel, with nothing verified: Phase 4's work.
