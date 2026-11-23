# lantern-boot — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). Boot integrity is
the foundation of all other guarantees; threats here are top severity (system threat T7).

## Assets
- The trust chain (each stage's integrity).
- The kernel-image trust anchor / verification keys.
- Measured-boot records used for attestation.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| B1 | Tampered firmware/loader/kernel image | Verify signatures against a hardware-anchored trust root; refuse unverified images. **Not yet:** since [ADR-0037](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0037-installing-a-bootable-disk.md), the firmware runs the disk's EFI loader, which runs the disk's boot image, and neither is verified. On RFC-0023's checklist. |
| B2 | Evil-maid / persistence below the OS | Measured boot makes tampering detectable via attestation. |
| B3 | Rollback to a vulnerable signed version | Monotonic version counters / anti-rollback (hardware dependent). |
| B4 | Trust-anchor compromise | Keys held in enclave; rotation policy; defence in depth. |
| B5 | Attestation abused as a tracker | Mediate who can request attestation; minimise linkable detail ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)). |
| B6 | A model on the disk that isn't one a trusted publisher signed ([RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md)) | `inference-service` checks the package's signature against the trusted publishers, the binder's list for apps, before parsing it, and refuses every call otherwise. **Not yet:** the keys live in the boot image, which B1 says nothing verifies, so whoever can rewrite the disk can replace both. On RFC-0023's checklist. |
| B7 | A device tree or firmware hand-off that misdescribes the machine ([RFC-0039](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0039-bring-up-on-the-k3-pico-itx.md)) | Both are untrusted input: the reader is bounded (depth, cell sizes, every offset checked) and refuses what it can't parse rather than guessing, with host tests over real trees and corrupted copies; the loader's reserved-memory table is accepted only as one page inside RAM. **Not mitigated:** firmware that lies consistently (it is trusted, as EDK2 and OpenSBI are under QEMU), until secure and measured boot (B1, B2). |
| B8 | DMA that reads stale memory, or a device overwriting the kernel's | DMA frames are mapped non-cacheable where the CPU has `Svpbmt`, and flushed after the kernel zeroes them where it has `Zicbom`; a non-coherent machine lacking either is refused. Which frames are DMA frames is a capability property. **Not mitigated:** a driver programming any address into its device: no IOMMU confinement yet (RFC-0039's stream D; RFC-0023's DMA row). |

## Non-goals
- Defeating a malicious hardware root of trust or implanted silicon (system non-goal).
- Sophisticated physical attacks (bus probing, decapping) at Phase 0.
