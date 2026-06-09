# lantern-boot

The **root of trust** and boot path for LanternOS. It brings the machine up, establishes and
*measures* the trust chain, verifies and loads the kernel, and hands off the initial
capabilities — then gets out of the way.

- **Layer:** TCB (firmware / highest assurance).
- **Language:** Rust (Zig permitted for small freestanding pieces per ADR-0001).
- **System context:** [wiki/Hardware](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Hardware.md), [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md).

> ⚠️ **Phase 0.** Design only; no code. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — boot flow and the trust chain.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — boot-integrity threats.
- [`STATUS.md`](./STATUS.md).

## Why this matters
If boot is subverted, every later guarantee is void. The boot path is therefore as
security-critical as the kernel: small, auditable, and where possible anchored in a hardware
root of trust with **measured boot** so the system can *prove* what it is running.
