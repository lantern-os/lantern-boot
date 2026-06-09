# lantern-boot — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Boot flow and trust chain sketched ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Boot-integrity threat model drafted.

## Next
- Decide the minimum required hardware root of trust.
- Phase 1: minimal loader that boots the kernel prototype under QEMU (`riscv64`/x86-64).

## Blocked on
- HAL platform bring-up contract ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)).
- Crypto verification primitives ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
