# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); `riscv64` loader boots and runs a real kernel IPC demo under QEMU.

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
  `qemu-system-riscv64 -machine virt -bios default`, debug and release:
  ```
  boot: entering client thread (own page table, U-mode)
  boot: client Call'd with payload 21
  boot: a Recv rendezvoused; receiver now has payload 21
  boot: server Reply'd 42; caller now resumed with reply 42
  ```
  This is the first real, hardware-level (QEMU) validation of the entire syscall/IPC
  pipeline — `lantern-hal` trap entry → `lantern-kernel` dispatch → trap exit — not just
  unit tests against a fabricated `TrapFrame`. The thread bodies themselves can't
  `println!` (see the next bullet), so `main.rs`'s `boot_trap_handler` narrates each
  syscall from S-mode instead.
- **Each thread now runs under its own Sv39 page table, in real U-mode** (`src/paging.rs`,
  `src/pmm.rs`), using `lantern-hal`'s new `riscv64_paging` primitives
  (`lantern-hal/STATUS.md`). Genuinely real: real address-space switching
  (`activate_address_space` on every context switch), real U-mode execution (`sret` with
  `sstatus.SPP/SPIE` cleared, verified by the demo's `ecall`s actually trapping from U-mode),
  and real per-thread stack isolation (each thread's stack lives in its own region, mapped
  only in its own table — confirmed absent from the other thread's). Not yet RFC-0004's
  finish line: the shared *kernel* code is still mapped identically in both tables (no
  separate user-program loader exists yet to keep it out) — see `paging.rs`'s module doc.
  Two real bugs found and fixed getting here, both invisible to any unit test (neither
  `lantern-hal`'s nor `lantern-kernel`'s host tests exercise a real hardware MMU):
  - **S-mode can never fetch instructions from a U-accessible page** (RISC-V, unconditionally
    — unlike loads/stores, `sstatus.SUM` doesn't override this for fetches). An earlier
    revision mapped the *entire* kernel image U-accessible (for the threads' benefit), which
    made every S-mode instruction fetch fault immediately after activating a thread's table,
    including the trap vector re-faulting on its own entry forever. Fixed by splitting the
    image: kernel code (trap vector, `lantern-kernel` dispatch, the `sret` cold-start path)
    stays S-mode-only; only `demo.rs`'s thread bodies (`.user_text`, `linker.ld`) are
    U-accessible.
  - **A QEMU environment limitation with full 3-level Sv39 walks** — see
    `lantern-hal/STATUS.md`'s entry for the full debugging record and `paging.rs`'s module
    doc for the workaround (2 MiB megapages instead of 4 KiB pages) this crate now uses
    throughout.
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
- A real ELF loader for a separate user program, so the shared-kernel-code caveat above can
  actually go away — the natural next step toward RFC-0004's "confined hello service."
- Switch back to 4 KiB pages (`lantern-hal`'s `map`, already correct and host-tested) once
  the QEMU 3-level-walk limitation is resolved — `map_megapage`'s 2 MiB granularity is a
  documented environment workaround, not the intended long-term page size.

## Blocked on
- Nothing for further `riscv64` loader work. `x86-64` boot and measured-boot/verification
  are deferred by choice, not blocked.
