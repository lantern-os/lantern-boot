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
| B1 | Tampered firmware/loader/kernel image | Verify signatures against a hardware-anchored trust root; refuse unverified images. |
| B2 | Evil-maid / persistence below the OS | Measured boot makes tampering detectable via attestation. |
| B3 | Rollback to a vulnerable signed version | Monotonic version counters / anti-rollback (hardware dependent). |
| B4 | Trust-anchor compromise | Keys held in enclave; rotation policy; defence in depth. |
| B5 | Attestation abused as a tracker | Mediate who can request attestation; minimise linkable detail ([Identity](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)). |

## Non-goals
- Defeating a malicious hardware root of trust or implanted silicon (system non-goal).
- Sophisticated physical attacks (bus probing, decapping) at Phase 0.
