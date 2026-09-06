//! `lantern-boot` — Phase 1 prototype loader ([RFC-0004](../../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md)).
//!
//! **Scope of this first slice:** get real control from QEMU/OpenSBI, prove it with
//! UART output, and install `lantern-kernel`'s trap handler via `lantern-hal`. This
//! is deliberately *not yet* the full boot flow `lantern-boot/ARCHITECTURE.md`
//! describes — no measured boot, no kernel-image signature verification. Phase 1
//! links `lantern-kernel` directly as a library rather than loading/verifying a
//! separate signed image: RFC-0004's Phase 1 exit criterion (one confined "hello
//! service", benchmarked IPC) doesn't need that trust chain yet, and there is no
//! separate image to verify without it. See `lantern-boot/STATUS.md`.
//!
//! `riscv64` only for now (the strategic target, ADR-0002) — `x86-64` boot is a
//! separate, harder bring-up problem (real → protected → long mode) left as
//! follow-up work, matching how `lantern-hal`'s trap entries were sequenced.
//!
//! `#![no_std]`/`#![no_main]` are conditional on `not(test)`, and every
//! `riscv64`-only module/item below is gated on `target_arch = "riscv64"`
//! (raw `ecall`/MMIO/linker-section code that simply cannot build for any other
//! target) — the same pattern `lantern-hal`/`lantern-kernel` already use, applied
//! here so [`elf`] (portable, hand-written ELF64 parsing — RFC-0008/ADR-0012) has
//! real host-test coverage via `cargo test --target <host triple>` (this crate's
//! own `.cargo/config.toml` still defaults *builds* to `riscv64gc-unknown-none-elf`,
//! so the real boot binary is unaffected).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

mod elf;
mod fdt;

#[cfg(target_arch = "riscv64")]
mod entry;
#[cfg(target_arch = "riscv64")]
mod loader;
#[cfg(target_arch = "riscv64")]
mod pmm;
#[cfg(target_arch = "riscv64")]
mod uart;

#[cfg(target_arch = "riscv64")]
use core::fmt::Write;
#[cfg(target_arch = "riscv64")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv64")]
use lantern_hal::{Hal, TrapFrame};
#[cfg(target_arch = "riscv64")]
use lantern_kernel::syscall::SyscallNumber;

#[cfg(target_arch = "riscv64")]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = writeln!(uart::Uart, "PANIC: {info}");
    loop {
        // Not `wfi`: empirically (under QEMU/OpenSBI) it crashes here rather than
        // idling, and Phase 1 has no interrupt/timer handling to wake into safely
        // regardless (`lantern-hal/STATUS.md`) — see `demo.rs`'s identical choice
        // for the full explanation.
        core::hint::spin_loop();
    }
}

/// Timed round trips the benchmark below expects — must match
/// `hello-service/src/main.rs`'s `BENCH_ROUND_TRIPS` (duplicated by
/// convention, not shared code; see that module's doc).
///
/// `hello-service` actually attempts this many + 1 + a small safety margin
/// (its own `BENCH_SAFETY_MARGIN`) round trips, to tolerate a real,
/// reproducible Phase 1 bug: the *first* `Call` a thread issues immediately
/// after being resumed via `ipc::reply`'s direct `state.switch_to`
/// occasionally never completes its switch to the receiver —
/// `lantern-kernel`'s own bookkeeping (`scheduler.current`, the
/// `block_current` return value) says it switched, but execution resumes the
/// caller anyway, silently dropping that one message. Root cause not
/// isolated (see `lantern-kernel/STATUS.md`'s "IPC round-trip loss" entry —
/// ruled out: endpoint/queue logic, scheduler state, `sfence.vma`/TLB
/// staleness, and stack overflow from added instrumentation, via a passing
/// host-side reproduction of the same call sequence and a hard `assert!` that
/// never fired). Observed exactly once per run so far, always immediately
/// after the warm-up round trip, never again afterward. This side doesn't
/// need the margin's exact value — see [`Bench::done`] for how it's absorbed.
#[cfg(target_arch = "riscv64")]
const BENCH_ROUND_TRIPS: u32 = 2000;

/// Reads the riscv64 `cycle` counter (the `rdcycle` pseudo-instruction,
/// unprivileged CSR `0xC00`). No `lantern-hal` primitive exists for this —
/// Phase 1 has no timer/perf-counter HAL surface (`lantern-hal/STATUS.md`'s
/// "Next") — and this benchmark is deliberately narrow, throwaway
/// instrumentation for RFC-0004's exit criterion, not a general timing API.
/// S-mode-only: relies on OpenSBI's default `mcounteren` granting S-mode read
/// access to the hardware counters under this project's `-bios default` QEMU
/// setup (confirmed empirically — see `lantern-boot/STATUS.md`); never read
/// from U-mode here, which would additionally need `scounteren`, unset in
/// Phase 1.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn rdcycle() -> u64 {
    let value: u64;
    // SAFETY: `cycle` is a read-only unprivileged counter CSR; reading it has
    // no side effect beyond the value returned.
    unsafe {
        core::arch::asm!("csrr {}, cycle", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Reads the riscv64 `instret` counter (`rdinstret`, CSR `0xC02`) — instructions
/// retired since boot. Cross-checks [`rdcycle`]'s reading against a metric that
/// stays meaningful even in a QEMU/TCG environment where `cycle` may not track
/// real hardware cycle timing (see the benchmark summary's caveat below and
/// `lantern-boot/STATUS.md`).
#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn rdinstret() -> u64 {
    let value: u64;
    // SAFETY: as `rdcycle` above.
    unsafe {
        core::arch::asm!("csrr {}, instret", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Accumulates the IPC latency benchmark across trap-handler invocations.
/// Single-hart, single-stack, run-to-completion (ADR-0010) — no concurrent
/// access is possible, so a `static mut` is sound without further locking.
#[cfg(target_arch = "riscv64")]
struct Bench {
    call_start_cycle: u64,
    call_start_instret: u64,
    /// Round trips finished so far, *including* the untimed warm-up one at
    /// index 0 — matches `hello-service`'s `0..=(BENCH_ROUND_TRIPS +
    /// BENCH_SAFETY_MARGIN)` loop. Stops advancing past the target (see
    /// `done`) so a safety-margin round trip made necessary by the dropped-
    /// message bug can't double-count or reprint the summary.
    completed: u32,
    /// Set once `completed` reaches the real target, so any further Reply
    /// traps (the safety-margin round trips, if the known bug didn't
    /// actually drop anything this run) are silently ignored rather than
    /// re-triggering the summary or skewing the stats.
    done: bool,
    cycles_sum: u64,
    cycles_min: u64,
    cycles_max: u64,
    instret_sum: u64,
    instret_min: u64,
    instret_max: u64,
}

#[cfg(target_arch = "riscv64")]
static mut BENCH: Bench = Bench {
    call_start_cycle: 0,
    call_start_instret: 0,
    completed: 0,
    done: false,
    cycles_sum: 0,
    cycles_min: u64::MAX,
    cycles_max: 0,
    instret_sum: 0,
    instret_min: u64::MAX,
    instret_max: 0,
};

/// Wraps [`lantern_kernel::kernel_trap_handler`] to narrate the demo's first
/// syscalls on the console, and to benchmark the [`BENCH_ROUND_TRIPS`] timed
/// round trips that follow (RFC-0004's Phase 1 exit criterion: "a confined
/// hello service... with IPC latency benchmarked and within target"). Entirely
/// S-mode code (every trap runs in S-mode, regardless of which privilege the
/// interrupted thread was in) — unlike the thread bodies in `demo.rs`, it's
/// free to use `println!`; see `demo.rs`'s module doc for why they can't.
///
/// Timing scope: `rdcycle`/`rdinstret` are read here, at the very top of the
/// Rust trap handler for the `Call` that starts a round trip, and again right
/// after `kernel_trap_handler` finishes dispatching the matching `Reply` (the
/// direct-switch fast path — `ipc::call`/`ipc::reply`'s `state.switch_to` —
/// means that single `Reply` dispatch is what resumes the client). This
/// measures **kernel-side IPC dispatch latency**: capability lookup, endpoint
/// rendezvous, and the direct context switch in both directions. It excludes
/// the fixed hardware trap-entry/exit assembly (`lantern-hal`'s riscv64
/// trampoline) on either end, which is small, symmetric, and shared by every
/// syscall alike, not specific to IPC.
#[cfg(target_arch = "riscv64")]
fn boot_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming_mr1 = frame.mr(1);

    if syscall == Some(SyscallNumber::Call) {
        // SAFETY: single-hart, run-to-completion; no concurrent access.
        unsafe {
            BENCH.call_start_cycle = rdcycle();
            BENCH.call_start_instret = rdinstret();
        }
    }

    lantern_kernel::kernel_trap_handler(frame);

    // SAFETY: single-hart, run-to-completion; no concurrent access.
    let (warming_up, done) = unsafe { (BENCH.completed == 0, BENCH.done) };

    match syscall {
        Some(SyscallNumber::Call) if warming_up => {
            println!("boot: client Call'd with payload {incoming_mr1}")
        }
        Some(SyscallNumber::Recv) if warming_up => {
            println!("boot: a Recv rendezvoused; receiver now has payload {}", frame.mr(1))
        }
        Some(SyscallNumber::Reply) if done => {
            // A safety-margin round trip (see `BENCH_SAFETY_MARGIN`) completed
            // after the real target was already reached and reported — ignore
            // it, it exists only to absorb the known dropped-message bug.
        }
        Some(SyscallNumber::Reply) => {
            let end_cycle = rdcycle();
            let end_instret = rdinstret();
            if warming_up {
                println!(
                    "boot: server Reply'd {incoming_mr1}; caller now resumed with reply {}",
                    frame.mr(1)
                );
                println!(
                    "boot: warm-up round trip confirmed correct; benchmarking {BENCH_ROUND_TRIPS} more IPC round trips..."
                );
            } else {
                // SAFETY: single-hart, run-to-completion; no concurrent access.
                unsafe {
                    let cycles = end_cycle.wrapping_sub(BENCH.call_start_cycle);
                    let instret = end_instret.wrapping_sub(BENCH.call_start_instret);
                    BENCH.cycles_sum += cycles;
                    BENCH.cycles_min = BENCH.cycles_min.min(cycles);
                    BENCH.cycles_max = BENCH.cycles_max.max(cycles);
                    BENCH.instret_sum += instret;
                    BENCH.instret_min = BENCH.instret_min.min(instret);
                    BENCH.instret_max = BENCH.instret_max.max(instret);
                }
            }
            // SAFETY: single-hart, run-to-completion; no concurrent access.
            unsafe { BENCH.completed += 1 };
            if unsafe { BENCH.completed } == BENCH_ROUND_TRIPS + 1 {
                let n = BENCH_ROUND_TRIPS as u64;
                // Read every field into locals inside one unsafe block, then
                // print from the locals — taking `&BENCH.field` (what a
                // `println!` argument does implicitly) is UB-shaped once a
                // `static mut` exists (Rust 2024's `static_mut_refs` lint),
                // even though nothing here is actually concurrent.
                // SAFETY: single-hart, run-to-completion; no concurrent access.
                let (cycles_min, cycles_avg, cycles_max, instret_min, instret_avg, instret_max) = unsafe {
                    BENCH.done = true;
                    (
                        BENCH.cycles_min,
                        BENCH.cycles_sum / n,
                        BENCH.cycles_max,
                        BENCH.instret_min,
                        BENCH.instret_sum / n,
                        BENCH.instret_max,
                    )
                };
                println!(
                    "boot: IPC benchmark done ({n} timed Call+Reply round trips, direct-switch fast path):"
                );
                println!("boot:   cycles/round-trip  min={cycles_min} avg={cycles_avg} max={cycles_max}");
                println!("boot:   instret/round-trip min={instret_min} avg={instret_avg} max={instret_max}");
                println!(
                    "boot:   (QEMU/TCG software emulation, kernel-side dispatch latency only — see ADR-0013)"
                );
            }
        }
        _ => {}
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot -- Phase 1 prototype");
    println!("hartid={hartid} dtb={dtb:#x}");

    // Real physical-memory discovery from the device tree OpenSBI handed us in
    // `a1` (`src/fdt.rs`), replacing `pmm.rs`'s hardcoded QEMU-`virt` guess. The
    // loader's memory-backed `Untyped` spans `pmm::GENERAL_MEMORY_BASE` (fixed,
    // tied to `linker.ld`'s kernel/`.user_text` placement) up to the end of the
    // RAM the tree reports. If the tree is unreadable, fall back to the guess.
    // SAFETY: `dtb` is the pointer OpenSBI passed in `a1` — a valid FDT blob.
    let mem_end = match unsafe { fdt::ram_region(dtb as *const u8) } {
        Some((base, size)) => {
            let end = base.saturating_add(size);
            println!("boot: DTB reports RAM {base:#x}..{end:#x}");
            end as usize
        }
        None => {
            println!("boot: DTB unreadable, using the hardcoded RAM end {:#x}", pmm::GENERAL_MEMORY_END);
            pmm::GENERAL_MEMORY_END
        }
    };

    // SAFETY: called exactly once, here, before any trap can occur — the required
    // precondition on `install_trap_handler`.
    unsafe {
        lantern_hal::Hardware::install_trap_handler(boot_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the trap
    // handler and before anything else could trap.
    unsafe { loader::run(mem_end) }
}
