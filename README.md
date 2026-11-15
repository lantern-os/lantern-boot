# lantern-boot

The **boot path** for LanternOS, and the system image it starts. It brings the machine up, places the kernel, builds the
first confined programs from their ELF images, hands each exactly the capabilities it needs, and then gets out of the way.

- **Layer:** TCB (it runs before anything is confined).
- **Language:** Rust.
- **System context:** [wiki/Hardware](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Hardware.md), [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md).

> **Phase 3**, on QEMU `virt` (riscv64). The interactive system boots from its own disk through UEFI: see
> [`STATUS.md`](./STATUS.md). It is a research system: its keys are public demo keys, and nothing below the kernel is
> verified yet ([RFC-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0023-hardware-key-custody-in-phase-4.md)'s checklist).

## Run LanternOS

You need a Rust toolchain with the `riscv64gc-unknown-none-elf` target, `qemu-system-riscv64` (10.x), and EDK2's RISC-V
firmware (`qemu-efi-riscv64` on Debian and Ubuntu).

```sh
# Build the boot image, the EFI loader, and an installable disk: lantern.img.
scripts/make-image.sh lantern.img

# Boot it: the firmware finds the loader on the disk, which starts LanternOS. No -kernel.
cp /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd vars.fd
qemu-system-riscv64 -machine virt,acpi=off -m 256M -nographic \
  -drive if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
  -drive if=pflash,unit=1,format=raw,file=vars.fd \
  -global virtio-mmio.force-legacy=false \
  -drive if=none,format=raw,file=lantern.img,id=disk -device virtio-blk-device,drive=disk
```

At the console, `help` lists the commands. `apps` lists the apps on the disk, and `run confined-fs-probe` starts one: it
asks for what it needs, and you decide. What it writes, and what you decide, stays on `lantern.img` across reboots.

**Installing** is writing that image to a disk: a VM uses `lantern.img` as its disk, as above, and a machine has it
written whole to its own ([RFC-0032](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0032-installing-a-bootable-disk.md)). On real hardware, that's
the roadmap's next step.

`acpi=off` is needed because QEMU gives ACPI tables by default, and EDK2 then omits the device tree LanternOS reads.

## In this repo
- `src/` — the boot image's entry, the loader that builds programs (`launch.rs`), and each boot image (`system/` is the
  interactive system; the others are demos).
- `efi-loader/` — the UEFI application that starts the boot image from the disk.
- `blk-driver/`, `volume/`, `keystore-service/`, `store-service/` — confined system programs.
- `tools/mkdisk/`, `tools/elf2efi/` — host tools that write the disk and build the EFI loader.
- `scripts/` — the QEMU suites, and `make-image.sh`.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Why this matters
If boot is subverted, every later guarantee is void. The boot path is therefore as security-critical as the kernel: small,
auditable, and eventually anchored in a hardware root of trust with **measured boot**, so the system can *prove* what it is
running. Today the chain is firmware, loader, kernel, with nothing verified: Phase 4's work.
