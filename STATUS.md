# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0004-phase-0-to-phase-1-transition.md); `riscv64` loader boots and runs a real kernel IPC demo under QEMU.

## Done
- Boot flow and trust chain sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Boot-integrity threat model drafted and reviewed.
- **First loader code merged and running under real QEMU** (`src/`, `riscv64` only —
  `x86-64` boot deferred, see "Next"): a linker script placing the kernel at
  `0x8020_0000` (OpenSBI's default payload address on QEMU's `virt` machine), a hand-written
  `_start` (stack setup, BSS clear, parks any hart other than the boot hart), a raw
  boot-internal ns16550a UART driver (`src/uart.rs` — **not** `lantern-hal`'s not-yet-built
  "early console" HAL item; hardcoded to QEMU `virt`'s fixed UART0 address, kept clearly
  separate), and `boot_main` installing `lantern-kernel`'s trap handler via
  `lantern_hal::Hardware::install_trap_handler`.
- **A real two-thread "hello service" demo** (`src/demo.rs`) directly populates
  `lantern-kernel`'s `KernelState` (an endpoint capability, two threads each with their own
  CSpace) and cold-starts the first thread. The client `Call`s the server over the
  endpoint; the server doubles the payload and `Reply`s. Confirmed under
  `qemu-system-riscv64 -machine virt -bios default`, debug and release, stable over a 10s
  run:
  ```
  boot: entering client thread
  server: received 21
  client: called with 21, got reply 42
  ```
  This is the first real, hardware-level (QEMU) validation of the entire syscall/IPC
  pipeline — `lantern-hal` trap entry → `lantern-kernel` dispatch → trap exit — not just
  unit tests against a fabricated `TrapFrame`.
- Both "threads" run in the same address space at kernel privilege — Phase 1 has no
  VSpace/paging yet, so there is no real isolation. This demonstrates the IPC *mechanism*,
  not yet RFC-0004's "**confined** hello service."
- Extended `lantern_hal::Hal` with `initial_trap_frame`/`enter_thread` — primitives for
  starting a thread that has never trapped before, which didn't previously exist (only
  save/restore *around* a trap did). Implemented for `riscv64`, verified by disassembly and
  now by the real QEMU run above; stubbed (`unimplemented!()`) for `x86-64`, consistent with
  deferring `x86-64` boot.
- **Found and fixed a real bug in `lantern-hal`'s `riscv64` trap trampoline** while getting
  this demo running: it only ever wrote back `mr0..mr3`/the tag to real registers, and
  advanced `sepc` *after* the handler ran — both silently discarded every context switch
  `lantern-kernel` performs (which replaces the *entire* saved register state, `sepc`
  included). No unit test could have caught this, since none of `lantern-hal`'s or
  `lantern-kernel`'s tests exercise the actual trap-entry assembly. See
  `lantern-hal/STATUS.md`.
- `wfi` crashes under this QEMU/OpenSBI setup (logged as "Invalid opcode for CSR
  read/write instruction" shortly after) — not fully root-caused (plausibly
  `sstatus.SIE` ending up enabled after the first `sret`, then a timer interrupt firing
  into a trap handler with no interrupt/timer support to do anything about it, but that's
  a hypothesis). Moot either way, since Phase 1 has no interrupt/timer handling yet — all
  idle loops in this crate use a busy-loop (`core::hint::spin_loop()`) instead, documented
  at each site.

## Next
- `x86-64` boot: a separate, harder bring-up problem (real → protected → long mode, GDT/TSS
  setup) — deferred, matching how `lantern-hal`'s trap entries were sequenced.
- Measured boot / kernel-image signature verification (RFC-0007/ADR-0011 primitives are
  ready) — deferred: Phase 1 links `lantern-kernel` directly as a library rather than
  loading/verifying a separate signed image, since there's no separate image and no exit
  criterion needing that trust chain yet.
- Decide the minimum required hardware root of trust (unchanged open question).
- Root-cause the `wfi` crash properly, once there's a reason to need real `wfi`/interrupt
  handling (i.e. once `lantern-hal` gains timer/interrupt-controller support).
- Real physical memory discovery (from the DTB `boot_main` already receives) to back
  `lantern-kernel`'s `UntypedRetype` with actual memory instead of a count-based budget.

## Blocked on
- Nothing for further `riscv64` loader work. `x86-64` boot and measured-boot/verification
  are deferred by choice, not blocked.
