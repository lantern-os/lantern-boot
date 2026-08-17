//! A minimal, genuinely standalone riscv64 ELF binary -- **not** part of
//! `lantern-boot`'s own build, not linked against `lantern-hal`/`lantern-kernel`
//! at all. Loaded from its own independently compiled bytes by `lantern-boot`'s
//! ELF loader (`../src/elf.rs`, `../src/loader.rs` --
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)).
//! That's the entire point of this crate's existence: `lantern-boot` never sees
//! this source, only the compiled ELF bytes it embeds via `include_bytes!` and
//! walks exactly as it would if they'd come from a disk image.
//!
//! Plays *both* halves of RFC-0004's Phase 1 exit-criterion demo, chosen by
//! `arg0` (the loader picks which): `arg0 == 0` is the server (`Recv`s a
//! request, doubles it, `Reply`s), `arg0 != 0` is the client (`Call`s with
//! `21`). One binary, loaded twice into two separate, mutually confined
//! programs -- simpler than a second source crate, and just as real an ELF
//! load each time. Both use CPtr `1` for the shared endpoint by convention; the
//! loader is what actually decides which program's CSpace gets a capability to
//! which endpoint, not anything ambient here.
//!
//! Each side repeats its half [`BENCH_ROUND_TRIPS`] + 1 + [`BENCH_SAFETY_MARGIN`]
//! times (one untimed warm-up round trip, matching this crate's original
//! single-shot behaviour exactly, then that many timed ones, plus a few spare)
//! -- `lantern-boot/src/main.rs`'s `boot_trap_handler` is what actually
//! measures and reports the IPC latency benchmark (RFC-0004's Phase 1 exit
//! criterion), by reading the riscv64 `cycle`/`instret` counters from S-mode
//! around each round trip; this binary just needs to *make* that many round
//! trips happen. Both constants are duplicated there by the same convention as
//! `ENDPOINT_CPTR`/`ARG0_SERVER` (`../src/loader.rs`'s module doc) -- neither
//! side reads the other's source. `BENCH_SAFETY_MARGIN` exists because of a
//! real, reproducible Phase 1 bug — see its doc on the `lantern-boot` side.
//!
//! Issues raw `ecall`s directly, matching `lantern-boot`'s own `demo.rs`
//! `syscall()` helper's register convention exactly (`lantern-hal`'s riscv64
//! trap entry, `mr0..mr3` = `a0..a3`, tag = `a4`, syscall number = `a7`) --
//! duplicated here rather than depending on `lantern-hal` because this binary
//! must build and link with *zero* dependency on this project's own crates to
//! be a genuine "separate program" a loader parses from bytes, not source.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const ENDPOINT_CPTR: usize = 1;

const SYSCALL_CALL: usize = 4;
const SYSCALL_RECV: usize = 3;
const SYSCALL_REPLY: usize = 5;

/// Timed round trips per run, after the one untimed warm-up round trip -- see
/// the module doc. Chosen to give a statistically stable min/avg/max under
/// QEMU TCG emulation without making a manual benchmark run slow to wait for.
const BENCH_ROUND_TRIPS: usize = 2000;

/// Extra round trips beyond `BENCH_ROUND_TRIPS` + 1 -- see the module doc and
/// `lantern-boot/src/main.rs`'s matching constant for why.
const BENCH_SAFETY_MARGIN: usize = 8;

/// Issues one syscall via `ecall`. `tag` is the raw packed `MessageTag` word;
/// `0` is the all-zero tag (label/length/extra_caps/flags all zero) every call
/// here needs, so this binary never needs to duplicate `lantern-hal`'s
/// `MessageTag` packing logic to construct one.
///
/// # Safety
/// Caller upholds whatever precondition the syscall itself has.
unsafe fn syscall(
    num: usize,
    cptr: usize,
    mr1: usize,
    mr2: usize,
    mr3: usize,
) -> (usize, usize, usize, usize) {
    let (r0, r1, r2, r3): (usize, usize, usize, usize);
    // SAFETY: forwarded from this function's own contract; register mapping
    // matches `lantern-hal`'s riscv64 trap trampoline exactly.
    unsafe {
        asm!(
            "ecall",
            inout("a0") cptr => r0,
            inout("a1") mr1 => r1,
            inout("a2") mr2 => r2,
            inout("a3") mr3 => r3,
            in("a4") 0usize, // empty MessageTag, packed
            in("a7") num,
            options(nostack),
        );
    }
    (r0, r1, r2, r3)
}

#[unsafe(no_mangle)]
extern "C" fn _start(arg0: usize) -> ! {
    if arg0 == 0 {
        for _ in 0..=(BENCH_ROUND_TRIPS + BENCH_SAFETY_MARGIN) {
            let (_r0, request, _r2, _r3) = unsafe { syscall(SYSCALL_RECV, ENDPOINT_CPTR, 0, 0, 0) };
            let reply_value = request * 2;
            // Reply takes no explicit CPtr; `cptr` here is unused.
            let _ = unsafe { syscall(SYSCALL_REPLY, 0, reply_value, 0, 0) };
        }
    } else {
        for _ in 0..=(BENCH_ROUND_TRIPS + BENCH_SAFETY_MARGIN) {
            let _ = unsafe { syscall(SYSCALL_CALL, ENDPOINT_CPTR, 21, 0, 0) };
        }
    }
    loop {
        // Not `wfi` -- see `lantern-boot/demo.rs`'s identical choice for why.
        core::hint::spin_loop();
    }
}
