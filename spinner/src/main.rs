//! `lantern-spinner` — [RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)'s adversary.
//!
//! With `arg0` 0 it spins forever and never makes a system call. Before RFC-0027 that stopped every other program;
//! now the timer preempts it. With `arg0` 1 it waits forever on a notification nothing signals, so that with the
//! driver also waiting, no thread is ready and the kernel must idle.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

const PARK_CPTR: usize = 1;

lantern_abi::entry!(run);

fn run(arg0: usize) -> ! {
    if arg0 == 0 {
        loop {
            core::hint::spin_loop();
        }
    }
    loop {
        let _ = lantern_abi::sys::wait(PARK_CPTR);
    }
}
