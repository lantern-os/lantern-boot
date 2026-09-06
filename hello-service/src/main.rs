//! A minimal, genuinely standalone riscv64 ELF binary -- loaded from its own
//! independently compiled bytes by `lantern-boot`'s ELF loader (`../src/elf.rs`,
//! `../src/loader.rs` --
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)).
//! `lantern-boot` never sees this source, only the compiled ELF bytes it embeds
//! via `include_bytes!` and walks exactly as it would if they'd come from a disk
//! image.
//!
//! Plays *both* halves of RFC-0004's Phase 1 exit-criterion demo, chosen by
//! `arg0` (the loader picks which): `arg0 == 0` is the server (`Recv`s a
//! request, doubles it, `Reply`s), `arg0 != 0` is the client (`Call`s with
//! `21`). One binary, loaded twice into two separate, mutually confined
//! programs. Both use CPtr `1` for the shared endpoint by convention; the loader
//! decides which program's CSpace gets a capability to which endpoint.
//!
//! Each side repeats its half [`BENCH_ROUND_TRIPS`] + 1 + [`BENCH_SAFETY_MARGIN`]
//! times (one untimed warm-up round trip, then that many timed ones, plus a few
//! spare) -- `lantern-boot/src/main.rs`'s `boot_trap_handler` measures and
//! reports the IPC latency benchmark (RFC-0004's Phase 1 exit criterion) by
//! reading the riscv64 `cycle`/`instret` counters from S-mode around each round
//! trip; this binary just needs to *make* that many round trips happen. Both
//! constants are duplicated on the `lantern-boot` side by the same convention as
//! `ENDPOINT_CPTR`/`ARG0_SERVER` -- neither side reads the other's source.
//! `BENCH_SAFETY_MARGIN` exists because of a real, reproducible Phase 1 bug --
//! see its doc on the `lantern-boot` side.
//!
//! **Now built on [`lantern_abi`]** ([RFC-0018](../../lantern-rfcs/rfcs/0018-confined-execution-port.md) /
//! [ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)):
//! `sys::{recv, reply, call}` and `_start` replace the hand-rolled `ecall`
//! helper. The benchmark's 2000+ round trips per side are, incidentally, a
//! stress test of those wrappers against the real kernel.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys;

lantern_abi::entry!(run);

const ENDPOINT_CPTR: usize = 1;

/// Timed round trips per run, after the one untimed warm-up round trip -- see
/// the module doc. Chosen to give a statistically stable min/avg/max under QEMU
/// TCG emulation without making a manual benchmark run slow to wait for.
const BENCH_ROUND_TRIPS: usize = 2000;

/// Extra round trips beyond `BENCH_ROUND_TRIPS` + 1 -- see the module doc and
/// `lantern-boot/src/main.rs`'s matching constant for why.
const BENCH_SAFETY_MARGIN: usize = 8;

fn run(arg0: usize) -> ! {
    if arg0 == 0 {
        for _ in 0..=(BENCH_ROUND_TRIPS + BENCH_SAFETY_MARGIN) {
            let request = sys::recv(ENDPOINT_CPTR).map(|r| r.msg[0]).unwrap_or(0);
            let _ = sys::reply([request * 2, 0, 0]);
        }
    } else {
        for _ in 0..=(BENCH_ROUND_TRIPS + BENCH_SAFETY_MARGIN) {
            let _ = sys::call(ENDPOINT_CPTR, [21, 0, 0]);
        }
    }
    loop {
        // Not `wfi` -- see `lantern-boot/demo.rs`'s identical choice for why.
        core::hint::spin_loop();
    }
}
