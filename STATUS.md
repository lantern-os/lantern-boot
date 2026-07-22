# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0004-phase-0-to-phase-1-transition.md); design complete, no code merged yet.

## Done
- Boot flow and trust chain sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Boot-integrity threat model drafted and reviewed.

## Next
- Decide the minimum required hardware root of trust.
- Phase 1: minimal loader that boots the kernel prototype under QEMU (`riscv64`/x86-64).

## Blocked on
- HAL platform bring-up contract ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)).
- Crypto verification primitives ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
