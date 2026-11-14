//! `lantern-nursery` — [RFC-0030](../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md)'s proof that
//! a process can be built, can fail, and can be reclaimed, entirely from user space, again and again.
//!
//! It holds an `Untyped` and nothing of the boot loader's beyond its own CNode and VSpace, a notification, a `Deadline`
//! for the clock, and its two report notifications. It carves one child `Untyped` (a launcher's "slot"), and then
//! `ROUNDS` times:
//!
//! 1. builds the embedded child from the slot: a VSpace, one 4 KiB Frame per page of the ELF, copied in through a scratch
//!    mapping of its own, a stack, a 2 MiB heap, a CNode, a scheduling context and a TCB, with `SetEntry` and a fault
//!    notification. A child fills the slot, so a slot that `Reset` didn't empty can't hold the next one;
//! 2. waits for it to end, in one of five ways (`lifecycle-child`'s table), and checks it ended that way, with
//!    `ReadFault`'s cause and address;
//! 3. `Reset`s the slot, timing it, and checks that every capability it made is gone from its own CNode.
//!
//! Every `RECURSE_EVERY` rounds it resets its whole `Untyped` instead, which must take the slot and everything made from
//! it, and carves the slot again. `ROUNDS` children need far more TCBs, VSpaces, Frames and page tables than the kernel
//! has, so without reclamation it fails within a few rounds.
//!
//! Reports `DONE(worst slot Reset, worst whole-memory Reset)`, in µs, once all `ROUNDS` pass, or `FAILURE(step, detail)`.
//! The first `Reset` of a boot isn't counted: under QEMU it is many times slower than any later one, which looks like the
//! emulator's first translation of that kernel code rather than the kernel's own work.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

#[path = "../../src/elf.rs"]
mod elf;

use lantern_abi::sys::{self, cnode, deadline, frame, retype, tcb, untyped};
use lantern_abi::wire::{MapPerms, Rights};

const CHILD_ELF: &[u8] = include_bytes!("../../assets/lifecycle-child.elf");

// Granted by the loader (`src/lifecycle_demo/loader.rs`).
const MEMORY: usize = 1;
const SELF_CNODE: usize = 2;
const SELF_VSPACE: usize = 3;
const NOTIFY: usize = 4;
const CLOCK: usize = 7;
const DONE: usize = 8;
const FAILURE: usize = 9;

// Its own.
const CHILD_CLEAN: usize = 5;
const CHILD_FAULT: usize = 6;
const CHILD_BAD: usize = 10;
const SLOT: usize = 11;
const SCRATCH_SLOT: usize = 12;
const VSPACE: usize = 20;
const CNODE: usize = 21;
const SCHED: usize = 22;
const TCB: usize = 23;
const PARK: usize = 24;
const STACK: usize = 25;
const PAGES: usize = 26;
const MAX_PAGES: usize = 16;
const HEAP: usize = PAGES + MAX_PAGES;
/// Every slot a child's objects occupy. After a `Reset`, each must be empty.
const CHILD_SLOTS: core::ops::Range<usize> = VSPACE..HEAP + 1;

const CLEAN_BIT: u64 = 1;
const FAULT_BIT: u64 = 2;
const BAD_BIT: u64 = 4;

const MEGA: usize = 2 << 20;
const PAGE: usize = 4096;
/// The child's small pages, then its heap at the next 2 MiB boundary: exactly full.
const SLOT_BYTES: usize = 2 * MEGA;
/// Where the nursery maps a child's page to fill it. Nothing else of its own is here.
const SCRATCH_VADDR: usize = 0x9800_0000;
const CHILD_STACK_VADDR: usize = 0x8600_0000;
const CHILD_HEAP_VADDR: usize = 0x8800_0000;

const ROUNDS: usize = 40;
const RECURSE_EVERY: usize = 10;

lantern_abi::entry!(run);

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    for (dest, badge) in [(CHILD_CLEAN, CLEAN_BIT), (CHILD_FAULT, FAULT_BIT), (CHILD_BAD, BAD_BIT)] {
        check(cnode::mint(SELF_CNODE, NOTIFY, dest, badge, Rights::WRITE), 1, dest);
    }
    check(untyped::child(MEMORY, SLOT, SLOT_BYTES), 2, 0);
    let mut worst_ns = [0; 2];
    for round in 0..ROUNDS {
        let kind = round % 5;
        let entry = build(kind);
        let bits = sys::wait(NOTIFY).unwrap_or_else(|_| fail(3, round));
        let (cause, value) = tcb::read_fault(TCB).unwrap_or_else(|_| fail(4, round));
        let expected = match kind {
            0 => bits == CLEAN_BIT && cause == 0,
            1 => bits == FAULT_BIT && cause == 13 && value == 0x10,
            2 => bits == FAULT_BIT && cause == 2,
            3 => bits == FAULT_BIT && cause == 15 && value & !(PAGE - 1) == entry & !(PAGE - 1),
            _ => bits == FAULT_BIT && cause == 12 && value == 0x4000_0000,
        };
        if !expected {
            fail(5, round << 16 | (bits as usize) << 8 | cause);
        }

        let recurse = (round + 1) % RECURSE_EVERY == 0;
        let start = now();
        check(untyped::reset(SELF_CNODE, if recurse { MEMORY } else { SLOT }), 6, round);
        if round > 0 {
            worst_ns[recurse as usize] = worst_ns[recurse as usize].max(now() - start);
        }
        // Nothing it made survives: copying from any of those slots must find nothing there.
        for slot in CHILD_SLOTS.chain(if recurse { SLOT..SLOT + 1 } else { 0..0 }) {
            if cnode::copy(SELF_CNODE, slot, SCRATCH_SLOT).is_ok() {
                fail(7, round << 16 | slot);
            }
        }
        if recurse {
            check(untyped::child(MEMORY, SLOT, SLOT_BYTES), 8, round);
        }
    }
    let _ = sys::signal_with(DONE, (worst_ns[0] / 1000) as usize, (worst_ns[1] / 1000) as usize);
    park()
}

/// Builds and starts a child of `kind` from the slot, and returns its entry point.
fn build(kind: usize) -> usize {
    let header = elf::parse_header(CHILD_ELF).unwrap_or_else(|_| fail(10, 0));
    check(retype::vspace(SLOT, VSPACE), 11, 0);

    // Each page the segments touch, with the union of their permissions.
    let mut pages = [(0usize, 0usize); MAX_PAGES];
    let mut count = 0;
    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(CHILD_ELF, &header, i).unwrap_or_else(|_| fail(12, i.into())) else { continue };
        let mut perms = MapPerms::USER.bits();
        for (flag, perm) in [(elf::PF_R, MapPerms::READ), (elf::PF_W, MapPerms::WRITE), (elf::PF_X, MapPerms::EXECUTE)] {
            if ph.flags & flag != 0 {
                perms |= perm.bits();
            }
        }
        let mut v = ph.vaddr as usize & !(PAGE - 1);
        while v < ph.vaddr as usize + ph.memsz as usize {
            match pages[..count].iter_mut().find(|(pv, _)| *pv == v) {
                Some((_, p)) => *p |= perms,
                None if count < MAX_PAGES => {
                    pages[count] = (v, perms);
                    count += 1;
                }
                None => fail(13, v),
            }
            v += PAGE;
        }
    }

    // Fill each page through the scratch mapping, then hand it to the child.
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    for (n, &(v, perms)) in pages[..count].iter().enumerate() {
        let cap = PAGES + n;
        check(retype::frame_small(SLOT, cap), 14, n);
        check(frame::map(cap, SELF_VSPACE, SCRATCH_VADDR, rw), 15, n);
        for i in 0..header.phnum {
            let Some(ph) = elf::program_header(CHILD_ELF, &header, i).ok().flatten() else { continue };
            let (file_start, file_end) = (ph.vaddr as usize, ph.vaddr as usize + ph.filesz as usize);
            let (from, to) = (v.max(file_start), (v + PAGE).min(file_end));
            if from < to {
                let src = &CHILD_ELF[ph.offset as usize + (from - file_start)..][..to - from];
                // SAFETY: the scratch page is this Frame, mapped read-write just above and nowhere else; `from - v` and
                // the length keep the copy inside its 4 KiB.
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (SCRATCH_VADDR + (from - v)) as *mut u8, src.len()) };
            }
        }
        check(frame::unmap(cap, SELF_VSPACE), 16, n);
        check(frame::map(cap, VSPACE, v, MapPerms(perms)), 17, n);
    }
    check(retype::frame_small(SLOT, STACK), 18, 0);
    check(frame::map(STACK, VSPACE, CHILD_STACK_VADDR, rw), 19, 0);
    check(retype::frame_mega(SLOT, HEAP), 28, 0);
    check(frame::map(HEAP, VSPACE, CHILD_HEAP_VADDR, rw), 29, 0);

    check(retype::cnode(SLOT, CNODE), 20, 0);
    check(retype::notification(SLOT, PARK), 21, 0);
    for (src, dest) in [(CHILD_CLEAN, 1), (PARK, 2), (CHILD_BAD, 3)] {
        check(cnode::copy_cross(CNODE, SELF_CNODE, src, dest), 22, dest);
    }
    check(retype::sched_context(SLOT, SCHED), 23, 0);
    check(retype::tcb(SLOT, TCB), 24, 0);
    check(tcb::set_fault_notification(TCB, CHILD_FAULT), 25, 0);
    check(tcb::set_entry(TCB, header.entry as usize, CHILD_STACK_VADDR + PAGE, kind), 26, 0);
    check(sys::tcb_configure(TCB, CNODE, SCHED, VSPACE), 27, 0);
    header.entry as usize
}

fn now() -> u64 {
    deadline::now(CLOCK).unwrap_or_else(|_| fail(30, 0))
}

fn check<E>(result: Result<(), E>, step: usize, detail: usize) {
    if result.is_err() {
        fail(step, detail);
    }
}

fn fail(step: usize, detail: usize) -> ! {
    let _ = sys::signal_with(FAILURE, step, detail);
    park()
}

fn park() -> ! {
    loop {
        let _ = sys::wait(NOTIFY);
    }
}
