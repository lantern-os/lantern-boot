# lantern-boot — Architecture

Companion to [wiki/Hardware](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Hardware.md). Establishes the trust chain
that the [kernel](https://github.com/lantern-os/lantern-kernel) and everything above it depend on.

## Boot flow

```
  power-on
    │
  hardware root of trust (immutable/first-stage; enclave-anchored where available)
    │  measure & verify
  platform/supervisor firmware (prefer open: OpenSBI-class on RISC-V)
    │  measure & verify
  lantern-boot loader
    │  verify kernel image signature; record measurement
  lantern-kernel  ──▶  kernel takes physical memory as untyped, starts root task
```

## Responsibilities
- **Measured boot:** hash each stage into a hardware register/enclave before executing it, so
  the running configuration is attestable later ([Cryptography](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Cryptography.md)).
- **Verification:** check the kernel image signature against a trust anchor before loading.
- **Handoff:** pass a clean machine description (memory map, device tree/ACPI) to the kernel
  and transfer to the root task with the initial capability set.
- **Minimalism:** do the least necessary; the loader is part of the TCB.

## Portability
Per-platform bring-up (entry, memory discovery, firmware interface) is shared with
[`lantern-hal`](https://github.com/lantern-os/lantern-hal). Targets: `riscv64` (strategic) and x86-64 (development),
initially under QEMU.

## Open questions
- Minimum hardware root of trust we require; behaviour on hardware that lacks one.
- Attestation vs. privacy (attestation can fingerprint a device — see
  [Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)).
- Recovery/anti-bricking when verification fails.
- Reproducible firmware builds and supply-chain provenance.
