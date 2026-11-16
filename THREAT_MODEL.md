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
| B6 | A model on the disk that isn't the one the system was built with ([RFC-0034](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0034-local-inference-and-a-file-assistant.md)) | `inference-service` checks the whole file's BLAKE3 digest against `assets/model.digest`, compiled in, before parsing it, and refuses every call otherwise. **Not yet:** the digest lives in the boot image, which B1 says nothing verifies, so whoever can rewrite the disk can replace both. On RFC-0023's checklist. |

## Non-goals
- Defeating a malicious hardware root of trust or implanted silicon (system non-goal).
- Sophisticated physical attacks (bus probing, decapping) at Phase 0.
