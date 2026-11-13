//! Boots RFC-0028's deadline demo: a **tenth, isolated boot image**, with two confined programs.
//!
//! - `../../sleeper/` holds two `Deadline`s, each bound to its one notification under its own bit, and `DONE`/`FAILURE`
//!   notifications. It sleeps three times, checks every wake against the clock, which only a `Deadline` lets it read, and
//!   reports the worst lateness.
//! - `../../spinner/` (RFC-0027's) runs first and never makes a system call, so every wake depends on the timer firing a
//!   deadline and then preempting the spinner. With the `deadline-idle` feature it parks instead, the sleeps are a second
//!   each, and the kernel must idle between wakes with the timer armed for the next deadline.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const SLEEPER_ELF: &[u8] = include_bytes!("../../assets/sleeper.elf");
const SPINNER_ELF: &[u8] = include_bytes!("../../assets/spinner.elf");

/// `sleeper/src/main.rs`'s slots.
const FIRST_CPTR: CPtr = 1;
const SECOND_CPTR: CPtr = 2;
const NOTIFY_CPTR: CPtr = 3;
const FIRST_BIT_CPTR: CPtr = 4;
const SECOND_BIT_CPTR: CPtr = 5;
pub const DONE_CPTR: CPtr = 6;
pub const FAILURE_CPTR: CPtr = 7;
const SPINNER_PARK_CPTR: CPtr = 1;

const IDLE: bool = cfg!(feature = "deadline-idle");
/// The sleeper's step, in ms: long enough while idle to measure that the hart rests.
const STEP_MS: usize = if IDLE { 1000 } else { 100 };

/// # Safety
/// Must be called at most once, before any trap has occurred.
pub unsafe fn run(mem_end: usize) -> ! {
    // SAFETY: forwarded from this function's own contract.
    let state = unsafe { lantern_kernel::state::kernel_state() };
    let root_cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    let root = TcbId(state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted") as u16);
    state.tcbs.get_mut(root.0 as usize).unwrap().cspace = Some(CNodeId(root_cnode_idx as u16));
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(SELF_CNODE_CPTR).unwrap() =
        Capability::CNode(CNodeId(root_cnode_idx as u16));
    let mem_end = mem_end.max(pmm::GENERAL_MEMORY_BASE + lantern_hal::RISCV64_MEGAPAGE_SIZE)
        & !(lantern_hal::RISCV64_MEGAPAGE_SIZE - 1);
    let untyped = Untyped::with_memory(1000, pmm::GENERAL_MEMORY_BASE, mem_end - pmm::GENERAL_MEMORY_BASE);
    let untyped_idx = state.untypeds.alloc(untyped).expect("untyped pool exhausted");
    let untyped_cptr: CPtr = 1;
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
        Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };
    let mut next_slot: CPtr = 2;
    let mut slot = || {
        let s = next_slot;
        next_slot += 1;
        s
    };
    let (first, second, notify, first_bit, second_bit, done, failure, park) =
        (slot(), slot(), slot(), slot(), slot(), slot(), slot(), slot());
    launch::deadline(state, root, first);
    launch::deadline(state, root, second);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, notify);
    launch::mint(state, root, notify, first_bit, Rights::WRITE, 1);
    launch::mint(state, root, notify, second_bit, Rights::WRITE, 2);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, done);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, park);

    let specs = [
        ProgramSpec {
            elf_bytes: SPINNER_ELF,
            arg0: if IDLE { 1 } else { 0 },
            grants: &[(park, SPINNER_PARK_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: SLEEPER_ELF,
            arg0: STEP_MS,
            grants: &[
                (first, FIRST_CPTR),
                (second, SECOND_CPTR),
                (notify, NOTIFY_CPTR),
                (first_bit, FIRST_BIT_CPTR),
                (second_bit, SECOND_BIT_CPTR),
                (done, DONE_CPTR),
                (failure, FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
    ];
    let [spinner, _sleeper] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    crate::println!(
        "deadline-demo: the sleeper sleeps 3 x {STEP_MS} ms beside a spinner that {}",
        if IDLE { "parks, so the kernel idles between wakes" } else { "never yields" }
    );
    // SAFETY: called once, after every program's capabilities, address space and context were populated above.
    unsafe { lantern_kernel::enter_first_thread(spinner.tcb) }
}
