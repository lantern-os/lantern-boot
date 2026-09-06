# lantern-boot — Status

**Phase:** 1 (Microkernel prototype) — opened per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md), **closed** per [RFC-0009](../lantern-rfcs/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](../lantern-rfcs/adr/0014-phase-1-complete-phase-2-opened.md); `riscv64` loader boots and, via a real ELF loader (RFC-0008/ADR-0012), runs two mutually confined, independently-built programs exchanging IPC under QEMU, with IPC latency benchmarked ([ADR-0013](../lantern-rfcs/adr/0013-ipc-latency-benchmark.md)). This crate's own remaining "Next" items below (`x86-64` boot, DTB memory discovery, ...) continue as ordinary engineering work — the Roadmap's phase gate has moved on to Phase 3 (RFC-0017/ADR-0021), this crate's Phase 1 backlog hasn't.

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
  the old demo entirely: `hello-service/` is a standalone riscv64 binary (its own crate, own
  linker script), embedded via `include_bytes!` (`assets/hello-service.elf` — rebuild with
  `cd hello-service && cargo build --release`, then copy
  `target/riscv64gc-unknown-none-elf/release/lantern-hello-service` over the checked-in
  copy; not built automatically, see "Next"). **Since 2026-09-01 it (and
  `broker-service`/`broker-client`) issue syscalls through [`lantern-abi`](../lantern-abi)**
  ([RFC-0018](../lantern-rfcs/rfcs/0018-confined-execution-port.md)/[ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md))
  — the one non-TCB crate that owns the `ecall` asm, the message-tag packing, the
  `#[panic_handler]`, and `_start` (`lantern_abi::entry!`) — instead of each hand-rolling its
  own. Their `Cargo.toml` `path` dep on `../../lantern-abi` needs the usual
  path→`git` rewrite when pushing `lantern-boot` standalone (same as `lantern-kernel` →
  `lantern-hal`). The broker demo and the hello-service benchmark produce identical output
  under QEMU after the switch (benchmark `instret/round-trip min` unchanged within TCG
  run-to-run variance). `elf.rs` is a minimal, hand-written ELF64
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
- **IPC latency benchmarked, closing RFC-0004's remaining exit-criterion item**
  ([ADR-0013](../lantern-rfcs/adr/0013-ipc-latency-benchmark.md)). `hello-service`
  (`hello-service/src/main.rs`) now repeats its Call/Recv+Reply round trip
  `BENCH_ROUND_TRIPS` (2000) + 1 (untimed warm-up) + `BENCH_SAFETY_MARGIN` (8, see
  "IPC round-trip loss" below) times; `main.rs`'s `boot_trap_handler` reads the riscv64
  `cycle`/`instret` counters (`rdcycle`/`rdinstret`, S-mode, no `lantern-hal` primitive
  needed) around each timed round trip and reports min/avg/max. Confirmed under real QEMU,
  release profile:
  ```
  boot: IPC benchmark done (2000 timed Call+Reply round trips, direct-switch fast path):
  boot:   cycles/round-trip  min=26477 avg=27035 max=129804
  boot:   instret/round-trip min=26507 avg=27074 max=129923
  ```
  (Run-to-run variance under QEMU/TCG is real and expected — a repeat run measured
  min=26872 avg=32081 max=179226 — see ADR-0013's fixed target for how that's handled.)
  `cycles` and `instret` tracking almost exactly 1:1 confirms this environment's QEMU/TCG
  `cycle` counter is an instruction-count proxy, not real-hardware cycle timing — see
  ADR-0013 for the full scope/methodology discussion and the Phase 1 target this sets.
- **IPC round-trip loss — a real, reproducible, unresolved bug found while building the
  above benchmark.** The *first* `Call` a thread issues immediately after being resumed via
  `ipc::reply`'s direct `state.switch_to` occasionally never completes its switch to the
  receiver: `lantern-kernel`'s own bookkeeping says it switched (`block_current` returns
  `true`, `scheduler.current` genuinely becomes the receiver — confirmed with a hard
  `assert!` in place of the normal `debug_assert!`, which never fired) and there is no
  panic, no unexpected `scause` in QEMU's own `-d int` trace (every trap is a plain
  `user_ecall`, no spurious interrupt), yet execution resumes the *original caller* anyway,
  silently dropping that one message. Observed **exactly once per run so far, always
  immediately after the untimed warm-up round trip** (i.e. the second time the client-side
  `block_current`/direct-switch path runs), never again in the following ~2000 round trips.
  Investigated and ruled out this session: `ipc::call`/`block_current`'s own logic (a
  host-side unit test replaying the identical dispatch sequence against portable
  `KernelState` — no real paging — passes cleanly, see
  `lantern-kernel/src/syscall.rs`'s `two_call_reply_round_trips_in_a_row_client_runs_first`);
  a spurious/timer interrupt (QEMU's own trace shows none); `sfence.vma`/TLB staleness on
  VSpace reactivation (adding `fence.i` after `activate()`'s `sfence.vma` made no
  difference); and stack overflow from the diagnostic instrumentation itself (the bug
  reproduces identically with all narration/diagnostics silenced, including in the
  *original*, pre-diagnostic minimal benchmark code). Not root-caused. Worked around for
  now with `BENCH_SAFETY_MARGIN` (both `hello-service` and `boot_trap_handler` tolerate a
  few extra round trips beyond the target; `Bench::done` ignores anything after the target
  is reached) rather than blocking the benchmark on it — this is exactly the kind of
  QEMU/hardware-level mystery the Sv39-walk bug above also was, and may turn out to be
  related or may not.
  **A second, distinct-looking manifestation found 2026-08-20** while building the
  `broker_demo/` demo below: a thread parked mid-`Reply` (made ready via
  `ipc::reply`'s own `state.make_ready(current)`, then only resumable later via a
  *different* thread's own `block_current`/`Yield` — a path this project's existing
  benchmark never actually exercises, since its server always re-enters `Recv` itself
  immediately after being naturally rescheduled) never resumed at all, with no panic
  and no further trap — confirmed via `[diag]` instrumentation showing the full
  `Recv`→`Mint`→`Reply` sequence succeeding, then nothing further from that thread,
  ever. Not investigated further (out of scope for that session's goal); the demo was
  redesigned to route around it instead — see `broker_demo/main.rs`'s own trap-handler
  doc for how and why. Recorded here because it's a new, real data point on the same
  underlying class of bug, not because it's been root-caused.
- **`loader.rs`'s direct pool write is gone** — it now places each loaded program's shared
  endpoint capability via `lantern-kernel`'s new `CNodeInvoke::CopyCross`
  ([RFC-0010](../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md),
  see `lantern-kernel/STATUS.md`), a real, capability-checked cross-CNode invocation instead
  of a raw slot poke. Required giving root its own founding self-CNode capability
  ([`SELF_CNODE_CPTR`]) so it can name itself as `CopyCross`'s source argument, and retyping
  + minting the shared endpoint as a real capability (`ObjectType::Endpoint` retype, then
  `CNodeInvoke::Mint` for its badge) rather than constructing a `Capability::Endpoint` value
  by hand. **This was originally attempted with RFC-0010's *other* new mechanism (live
  `extra_caps == 1` IPC transfer) and abandoned partway through**: that needs an
  already-running receiver to `Recv` with a registered destination slot, but a program's
  very first capability can't be bootstrapped that way — there's nothing to rendezvous on
  before it has *any* capability (chicken-and-egg). `CopyCross` is the administrative
  primitive that actually fits; `lantern-kernel/STATUS.md` has the full reasoning. Confirmed
  under real QEMU, clean rebuild, release profile — same two mutually confined programs,
  same full 2000-round-trip benchmark, unchanged behavior end to end:
  ```
  boot: entering client (loaded ELF, own VSpace, U-mode)
  boot: client Call'd with payload 21
  boot: a Recv rendezvoused; receiver now has payload 21
  boot: server Reply'd 42; caller now resumed with reply 42
  boot: warm-up round trip confirmed correct; benchmarking 2000 more IPC round trips...
  boot: IPC benchmark done (2000 timed Call+Reply round trips, direct-switch fast path):
  boot:   cycles/round-trip  min=26732 avg=27537 max=132939
  boot:   instret/round-trip min=26754 avg=27549 max=133076
  ```
  `cargo clippy -D warnings` clean on host and `riscv64gc-unknown-none-elf` (debug and
  release); the 8 host-side `elf.rs` tests (`cargo test --target <host triple>`) unaffected.
- **A real, confined [RFC-0010](../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)
  capability-broker demo**, in a **second, fully isolated binary**
  (`lantern-boot-broker-demo`, `src/broker_demo/`) — proving
  [`lantern_capabilities::Broker`](../lantern-capabilities/src/lib.rs) for real from confined
  U-mode under QEMU, not just against a direct `KernelState`. Two standalone programs
  (`broker-service/`, `broker-client/`, same shape as `hello-service/` — since 2026-09-01
  all three issue syscalls through [`lantern-abi`](../lantern-abi), not hand-rolled
  `ecall`s): `broker-client` `Call`s `broker-service` registering its own reply-leg
  destination slot (`tag.extra_caps == 2`); `broker-service` `Recv`s, then **runs the real
  `lantern_capabilities::Broker`** (since 2026-09-05, via that crate's `Abi` backend,
  `default-features = false` so nothing from the TCB is linked): `Broker::mint` (its own
  `Rights::GRANT` policy check + a real `CNodeInvoke::Mint` + badge bookkeeping) then
  `Broker::grant_via_reply` (`Reply` with the capability attached, `tag.extra_caps == 1`);
  `broker-client` then `Signal`s the granted capability — the real proof, since only a
  genuinely transferred, `WRITE`-rights capability can succeed there.
  Confirmed under real QEMU, 3/3 reproducible runs:
  ```
  broker-demo: client Call'd the broker, registering its reply destination
  broker-demo: broker Recv'd the client's request -- ok=true
  broker-demo: broker Mint'd an attenuated, badged copy of its resource -- ok=true
  broker-demo: broker Reply'd with the capability attached (extra_caps == 1) -- ok=true
  broker-demo: client Signal'd the granted capability -- ok=true (the real proof: only a
    genuinely transferred, WRITE-rights capability can succeed here)
  ```
  **Deliberately a second, isolated binary, not a third program merged into the existing
  two-thread benchmark** (`lantern-boot`'s own `[[bin]]`) — that benchmark's trap handler
  and cycle-counting narration are keyed only on syscall number, not which program issued
  it, so an interleaved `Call`/`Reply` from this demo would have misattributed timing data
  into its global `Bench` state. The two binaries share only the genuinely portable pieces
  (`elf.rs`, `pmm.rs`, `uart.rs`, `entry.rs`) via `#[path]`, each compiled fresh into its
  own separate crate root — real Cargo multi-`[[bin]]`, not code duplicated by hand.
  `load()` in `broker_demo/loader.rs` generalises `../loader.rs`'s own (which only ever
  grants one hardcoded capability) into an arbitrary `grants: &[(CPtr, CPtr)]` list, plus a
  `self_cnode_dest` case that needed its own fix: granting a loaded program a capability to
  *its own* CNode must source from *root's* freshly-retyped `cnode_cptr` (which names that
  program's CNode), not from root's own unrelated self-reference — an actual bug caught and
  fixed via the QEMU run itself (`Mint`/`Reply` both failed until corrected). See "Known
  Phase 1 gaps" above for a new, real manifestation of the IPC round-trip-loss bug found
  while building this, and how the demo's own design routes around it. `cargo clippy -D
  warnings` clean on both binaries; existing `lantern-boot` binary's own build, clippy, host
  tests, and full QEMU benchmark run all reconfirmed unaffected.

## Next
- **Root-cause the IPC round-trip-loss bug above — now with a second, real manifestation
  to compare against.** Candidates not yet tried: QEMU's GDB stub single-stepping across
  the exact failing trap (entry assembly → Rust dispatch → exit assembly) to see directly
  where the resumed context diverges from what `lantern-kernel` computed; testing against
  a different QEMU version/`-cpu` flag the same way the Sv39-walk bug was differentially
  tested; inspecting `RAW_FRAME`'s actual memory contents via the QEMU monitor at the
  moment of the bad resume; comparing the two manifestations' actual trigger conditions
  (this one's "parked mid-`Reply`, resumed via a *different* thread's `block_current`"
  shape, vs. the original's "first `Call` right after a warm-up round trip") for anything
  in common.
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
  `pmm::GENERAL_MEMORY_BASE..GENERAL_MEMORY_END` range. Named a prerequisite by
  [RFC-0018](../lantern-rfcs/rfcs/0018-confined-execution-port.md)/[ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
  (Accepted): the launcher spawning several programs — each with its own VSpace, heap, and
  Wasm memories — needs a real memory map.
- Automate rebuilding/embedding `assets/hello-service.elf` (a `build.rs` invoking `cargo
  build` for `hello-service/` was considered and deliberately deferred — real, meaningful
  nested-cross-compilation complexity for a manual step that's simple and rare today; revisit
  if `hello-service/` starts changing often) — currently a documented manual step (see
  "Done").
- Switch back to 4 KiB pages (`lantern-hal`'s `map`, already correct and host-tested) once
  the QEMU 3-level-walk limitation is resolved — `map_megapage`'s 2 MiB granularity is a
  documented environment workaround, not the intended long-term page size.
- A real root-task crate, and/or loading from a real block device instead of
  `include_bytes!`, once `lantern-boot` needs to load more than one fixed program
  (RFC-0008's "Future possibilities") — `broker_demo/loader.rs`'s own generalised `load()`
  is a step in that direction but is still a second, separate, `include_bytes!`-based
  loader, not a unification of the two. [RFC-0018](../lantern-rfcs/rfcs/0018-confined-execution-port.md)/[ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
  (Accepted) makes this Phase 3's foundational work: the narrowing-waterfall loader gains
  the ability to load N programs and place exactly the capabilities named by a launch
  description into each CSpace via `CNodeInvoke::CopyCross`.
- ~~Wire `lantern_capabilities::Broker`'s actual Rust API into a real confined program~~ —
  **done 2026-09-05.** `Broker` now has a `BrokerBackend` trait with an `Abi` (confined,
  `lantern-abi`-only) and a `KernelBackend` (`&mut KernelState`) impl;
  [RFC-0018](../lantern-rfcs/rfcs/0018-confined-execution-port.md)/[ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md).
  `broker-service` constructs a real `Broker` with the `Abi` backend and runs its `mint` /
  `grant_via_reply` under QEMU. `Keystore`/`Store` still thread a `KernelBackend` internally
  — moving *their* logic (and request/reply wire protocols) into confined programs is the
  remaining ADR-0022 Part 1 work.

## Blocked on
- Nothing for further `riscv64` loader work. `x86-64` boot and measured-boot/verification
  are deferred by choice, not blocked.
