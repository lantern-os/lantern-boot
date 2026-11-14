//! `lantern-sleeper` — [RFC-0028](../../lantern-rfcs/rfcs/0028-deadlines-and-a-capability-clock.md)'s proof that a confined
//! program can sleep, and read the time, through `Deadline`s and nothing else.
//!
//! It holds two deadlines, each bound to its one notification under its own bit. Three times, it arms the first for a
//! step after the start, and the second for half a step earlier, which it cancels at once. It then waits. The wake must
//! come from the first deadline alone, no earlier than its time. Then a deadline already past must fire at once. It
//! reports the worst lateness, in microseconds, and how many checks passed.
//!
//! `arg0` is the step in milliseconds.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys::{self, deadline};

const FIRST_CPTR: usize = 1;
const SECOND_CPTR: usize = 2;
const NOTIFY_CPTR: usize = 3;
const FIRST_BIT_CPTR: usize = 4;
const SECOND_BIT_CPTR: usize = 5;
const DONE_CPTR: usize = 6;
const FAILURE_CPTR: usize = 7;
const FIRST_BIT: u64 = 1;

lantern_abi::entry!(run);

fn run(step_ms: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);
    let step = step_ms as u64 * 1_000_000;
    if deadline::set_notification(FIRST_CPTR, FIRST_BIT_CPTR).is_err() || deadline::set_notification(SECOND_CPTR, SECOND_BIT_CPTR).is_err() {
        fail(1, 0);
    }
    let start = now();
    let mut worst = 0;
    let mut checks = 0;
    for round in 1..=3 {
        let at = start + round * step;
        if deadline::arm(FIRST_CPTR, at).is_err() || deadline::arm(SECOND_CPTR, at - step / 2).is_err() {
            fail(2, round as usize);
        }
        let _ = deadline::cancel(SECOND_CPTR);
        let bits = sys::wait(NOTIFY_CPTR).unwrap_or(0);
        if bits != FIRST_BIT {
            fail(3, bits as usize);
        }
        let woke = now();
        if woke < at {
            fail(4, round as usize);
        }
        worst = worst.max(woke - at);
        checks += 1;
    }
    // A time already past fires on the way out of `arm` itself.
    let _ = deadline::arm(FIRST_CPTR, now().saturating_sub(1));
    if sys::wait(NOTIFY_CPTR).unwrap_or(0) != FIRST_BIT {
        fail(5, 0);
    }
    checks += 1;
    let _ = sys::signal_with(DONE_CPTR, (worst / 1000) as usize, checks);
    park()
}

fn now() -> u64 {
    deadline::now(FIRST_CPTR).unwrap_or_else(|_| fail(6, 0))
}

fn fail(step: usize, detail: usize) -> ! {
    let _ = sys::signal_with(FAILURE_CPTR, step, detail);
    park()
}

fn park() -> ! {
    loop {
        let _ = sys::wait(DONE_CPTR);
    }
}
