//! Boots RFC-0030's lifecycle demo: an **eleventh, isolated boot image**, with two confined programs.
//!
//! - `../../nursery/` holds an 8 MiB child `Untyped` and builds `../../lifecycle-child/` from it again and again, through
//!   system calls alone. Each child finishes or faults on purpose; the nursery checks how, `Reset`s, and checks that
//!   nothing it made survives. It runs more children than any kernel pool has room for, so reclamation must work.
//! - `../../spinner/` (RFC-0027's) runs first and never makes a system call. Every child's fault must end only that child:
//!   before RFC-0030 the first fault parked the hart.
//!
//! The nursery gets nothing the boot loader made for anything else: its `Untyped` is a child of the loader's, so a `Reset`
//! of it can reach only what the nursery made.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const NURSERY_ELF: &[u8] = include_bytes!("../../assets/nursery.elf");
const SPINNER_ELF: &[u8] = include_bytes!("../../assets/spinner.elf");

/// `nursery/src/main.rs`'s slots.
const MEMORY_CPTR: CPtr = 1;
const SELF_CNODE_DEST: CPtr = 2;
const SELF_VSPACE_DEST: CPtr = 3;
const NOTIFY_CPTR: CPtr = 4;
const CLOCK_CPTR: CPtr = 7;
pub const DONE_CPTR: CPtr = 8;
pub const FAILURE_CPTR: CPtr = 9;
const SPINNER_PARK_CPTR: CPtr = 1;

/// Room for two of the nursery's 4 MiB slots, so a whole-memory `Reset` that didn't empty it fails within two.
const NURSERY_MEMORY: usize = 4 * lantern_hal::RISCV64_MEGAPAGE_SIZE;

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
    let (memory, notify, clock, done, failure, park) = (slot(), slot(), slot(), slot(), slot(), slot());
    launch::retype_untyped(state, root, untyped_cptr, memory, NURSERY_MEMORY);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, notify);
    launch::deadline(state, root, clock);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, done);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure);
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, park);

    let specs = [
        ProgramSpec {
            elf_bytes: SPINNER_ELF,
            arg0: 0,
            grants: &[(park, SPINNER_PARK_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: NURSERY_ELF,
            arg0: 0,
            grants: &[
                (memory, MEMORY_CPTR),
                (notify, NOTIFY_CPTR),
                (clock, CLOCK_CPTR),
                (done, DONE_CPTR),
                (failure, FAILURE_CPTR),
            ],
            self_cnode_dest: Some(SELF_CNODE_DEST),
            heap_megapages: 0,
            arena: Some(ArenaGrant { megapages: 0, self_vspace_dest: SELF_VSPACE_DEST, frame_dest_base: 0 }),
        },
    ];
    let [spinner, _nursery] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    // The loader keeps no capability to the nursery's memory.
    launch::delete(state, root, memory);
    crate::println!("lifecycle-demo: the nursery builds, loses and reclaims children beside a spinner that never yields");
    // SAFETY: called once, after every program's capabilities, address space and context were populated above.
    unsafe { lantern_kernel::enter_first_thread(spinner.tcb) }
}
