# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0004-phase-0-to-phase-1-transition.md); design complete, no code merged yet.

## Done
- Boot flow and trust chain sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Boot-integrity threat model drafted and reviewed.

## Next
- Decide the minimum required hardware root of trust.
- Phase 1: minimal loader that boots the kernel prototype under QEMU (`riscv64`/x86-64).

## Blocked on
- HAL platform bring-up contract ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)) —
  `riscv64`/`x86-64` trap entries are implemented; platform discovery/early-console
  bring-up is not.
- Nothing on crypto currently — the verification primitives (Ed25519 signatures,
  BLAKE3/SHA-256 hashing for measured boot) are fixed by
  [RFC-0007](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0007-cryptographic-primitive-set.md)/
  [ADR-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0011-cryptographic-primitive-set.md).
  `lantern-crypto` itself has no implementation yet (still Phase 0), so boot's own loader
  code will need to call these primitives directly or via a minimal shim until the crypto
  service exists.
