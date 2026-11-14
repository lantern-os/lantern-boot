//! `lantern-lifecycle-child` — [RFC-0030](../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md)'s
//! child. The nursery builds it again and again, each time from memory the last one used.
//!
//! `arg0` is how it ends:
//!
//! | `arg0` | It | `scause` |
//! |---|---|---|
//! | 0 | checks its memory, and signals `CLEAN` if it was, `BAD` if not | (none) |
//! | 1 | loads from an unmapped address | 13, load page fault |
//! | 2 | runs an illegal instruction | 2 |
//! | 3 | stores to its own code, which is mapped read-and-execute only | 15, store page fault |
//! | 4 | jumps to an unmapped address | 12, instruction page fault |
//!
//! Kind 0's check: its `.bss` and its 2 MiB heap must read as zero and its `.data` as the ELF says, which only the
//! kernel's clearing makes true, since the last child's pages are the same physical memory and it left them dirty. Then
//! it dirties them itself.
//! A fault that somehow didn't fault signals `BAD`. The two capabilities differ only in badge, which is all a
//! notification carries.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys;

const CLEAN_CPTR: usize = 1;
const PARK_CPTR: usize = 2;
const BAD_CPTR: usize = 3;
/// What `.data` starts as.
const MAGIC: usize = 0x11fe;
const BSS_WORDS: usize = 512;
/// The nursery maps 2 MiB here, read-write.
const HEAP: usize = 0x8800_0000;
const HEAP_BYTES: usize = 2 << 20;
/// One word in each 4 KiB page of the heap.
const HEAP_STRIDE: usize = 4096;

static mut BSS: [usize; BSS_WORDS] = [0; BSS_WORDS];
/// In `.data`, so its page is writable and starts with something the ELF says.
static mut DATA: usize = MAGIC;

lantern_abi::entry!(run);

fn run(kind: usize) -> ! {
    match kind {
        0 => {
            // SAFETY: single-threaded; nothing else refers to `BSS` or `DATA`.
            let clean = unsafe {
                let bss = core::ptr::addr_of_mut!(BSS);
                let heap = (HEAP..HEAP + HEAP_BYTES).step_by(HEAP_STRIDE).map(|a| a as *mut usize);
                let clean = (0..BSS_WORDS).all(|i| core::ptr::read_volatile(&(*bss)[i]) == 0)
                    && core::ptr::read_volatile(core::ptr::addr_of!(DATA)) == MAGIC
                    && heap.clone().all(|w| core::ptr::read_volatile(w) == 0);
                for i in 0..BSS_WORDS {
                    core::ptr::write_volatile(&mut (*bss)[i], 0xa5a5_a5a5);
                }
                heap.for_each(|w| core::ptr::write_volatile(w, 0xa5a5_a5a5));
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DATA), 0);
                clean
            };
            let _ = sys::signal(if clean { CLEAN_CPTR } else { BAD_CPTR });
            loop {
                let _ = sys::wait(PARK_CPTR);
            }
        }
        // SAFETY (each arm below): deliberately faulting is this program's whole job. The kernel ends it at the fault.
        1 => {
            let _ = unsafe { core::ptr::read_volatile(0x10 as *const usize) };
        }
        2 => unsafe { core::arch::asm!("unimp") },
        3 => unsafe { core::ptr::write_volatile(run as *const () as *mut usize, 0) },
        4 => unsafe {
            let unmapped: extern "C" fn() = core::mem::transmute(0x4000_0000usize);
            unmapped()
        },
        _ => {}
    };
    // A fault that didn't fault.
    let _ = sys::signal(BAD_CPTR);
    loop {
        let _ = sys::wait(PARK_CPTR);
    }
}
