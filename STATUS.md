# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); `riscv64` loader boots and, via a real ELF loader (RFC-0008/ADR-0012), runs two mutually confined, independently-built programs exchanging IPC under QEMU — RFC-0004's Phase 1 exit criterion.

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
- **A real two-thread "hello service" demo, first with both threads compiled directly into
  `lantern-boot`, later replaced entirely by a real ELF loader** (see below) — the earlier
  revision directly populated `lantern-kernel`'s `KernelState` (an endpoint capability, two
  threads each with their own CSpace) and cold-started the first thread; superseded, not
  extended, once `src/loader.rs` landed. This is still the first real, hardware-level (QEMU)
  validation of the entire syscall/IPC pipeline — `lantern-hal` trap entry → `lantern-kernel`
  dispatch → trap exit — not just unit tests against a fabricated `TrapFrame`.
- **Each loaded program now runs under its own Sv39 page table, in real U-mode**, using
  `lantern-hal`'s `riscv64_paging` primitives (`lantern-hal/STATUS.md`). Genuinely real: real
  address-space switching (`activate_address_space` on every context switch), real U-mode
  execution (`sret` with `sstatus.SPP/SPIE` cleared), and real per-program stack isolation.
  Two real bugs found and fixed getting here, both invisible to any unit test (neither
  `lantern-hal`'s nor `lantern-kernel`'s host tests exercise a real hardware MMU) — since
  superseded by the RFC-0008 work below but recorded here since they're still true:
  - **S-mode can never fetch instructions from a U-accessible page** (RISC-V, unconditionally
    — unlike loads/stores, `sstatus.SUM` doesn't override this for fetches). Every loaded
    program's VSpace maps the shared kernel megapage S-mode-only (`loader.rs`'s
    `map_kernel_shared`); only that program's own retyped Frames are U-accessible.
  - **A QEMU environment limitation with full 3-level Sv39 walks** — see
    `lantern-hal/STATUS.md`'s entry for the full debugging record. This crate uses 2 MiB
    megapages (`FrameSize::Mega`, RFC-0008/ADR-0012) exclusively as the documented workaround.
- **A real ELF loader** (`src/loader.rs`, `src/elf.rs` — [RFC-0008](../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
  [ADR-0012](../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)) replaces
  the old demo entirely: `hello-service/` is a genuinely standalone riscv64 binary (its own
  crate, own linker script, zero dependency on `lantern-hal`/`lantern-kernel` — it only ever
  issues raw `ecall`s), embedded via `include_bytes!` (`assets/hello-service.elf` — rebuild
  with `cd hello-service && cargo build --release`, then copy
  `target/riscv64gc-unknown-none-elf/release/lantern-hello-service` over the checked-in
  copy; not built automatically, see "Next"). `elf.rs` is a minimal, hand-written ELF64
  parser (`PT_LOAD` only, strict header/bounds validation, a small explicit skip-list for
  harmless-but-common segment types like `PT_GNU_STACK`, everything else rejected — no
  external ELF-parsing crate, per RFC-0008's TCB-impact reasoning). `loader.rs` retypes real
  VSpace/Frame capabilities (RFC-0008), maps each `PT_LOAD` segment and a stack Frame via
  the real `FrameInvoke::Map` syscall path, and grants each loaded program's CSpace
  *exactly* the shared endpoint capability it needs and nothing else — the actual "confined
  hello service reachable only via a granted capability" RFC-0004 names as Phase 1's exit
  criterion, loading the *same* binary twice (as server, then client, chosen by `arg0`) into
  two mutually confined programs. Confirmed under `qemu-system-riscv64 -machine virt -bios
  default`, from a clean rebuild, release profile:
  ```
  boot: entering client (loaded ELF, own VSpace, U-mode)
  boot: client Call'd with payload 21
  boot: a Recv rendezvoused; receiver now has payload 21
  boot: server Reply'd 42; caller now resumed with reply 42
  ```
  `main.rs`'s `boot_trap_handler` narrates each syscall from S-mode, since the loaded
  program itself can't `println!` (U-mode can't reach S-mode-only `fmt`/UART code any more
  than S-mode can fetch from a U-accessible page).
- **`src/main.rs`'s `#![no_std]`/`#![no_main]` are now conditional on `not(test)`**, and
  every `riscv64`-only module is `#[cfg(target_arch = "riscv64")]`-gated (matching
  `lantern-hal`/`lantern-kernel`'s existing pattern) — this crate's own build still defaults
  to `riscv64gc-unknown-none-elf` (`.cargo/config.toml`), but `elf.rs` (portable, no
  hardware dependency) now has real host-test coverage via
  `cargo test --target <host triple>`.
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
  `lantern-kernel`'s `Untyped` with a real memory map instead of one hardcoded
  `pmm::GENERAL_MEMORY_BASE..GENERAL_MEMORY_END` range.
- Automate rebuilding/embedding `assets/hello-service.elf` (a `build.rs` invoking `cargo
  build` for `hello-service/` was considered and deliberately deferred — real, meaningful
  nested-cross-compilation complexity for a manual step that's simple and rare today; revisit
  if `hello-service/` starts changing often) — currently a documented manual step (see
  "Done").
- Switch back to 4 KiB pages (`lantern-hal`'s `map`, already correct and host-tested) once
  the QEMU 3-level-walk limitation is resolved — `map_megapage`'s 2 MiB granularity is a
  documented environment workaround, not the intended long-term page size.
- A real cross-CNode capability-transfer primitive (`cnode::invoke`'s `Copy`/`Move` only
  operate within a single CNode today) would let `loader.rs` grant the shared endpoint via a
  real capability invocation instead of the one remaining direct pool write it still has —
  a pre-existing Phase 1 gap RFC-0008 didn't touch, not new from this round.
- A real root-task crate, and/or loading from a real block device instead of
  `include_bytes!`, once `lantern-boot` needs to load more than one fixed program
  (RFC-0008's "Future possibilities").

## Blocked on
- Nothing for further `riscv64` loader work. `x86-64` boot and measured-boot/verification
  are deferred by choice, not blocked.
