//! Boots the [RFC-0019](../../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)/
//! [ADR-0024](../../../lantern-rfcs/adr/0024-confined-service-call-protocol.md)
//! shared-`Frame` framing demo — a **third, isolated boot image**, same
//! scoping reasoning `broker_demo/loader.rs`'s module doc gives for its own
//! separateness from `../loader.rs`.
//!
//! Two programs, `../../frame-service/` and `../../frame-client/`, share the
//! usual endpoint *and*, new here, one 4 KiB `Frame`
//! ([`launch::map_shared_frame`],
//! [ADR-0022](../../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
//! Part 2) mapped at [`FRAME_VADDR`] in both — the first time this crate maps
//! a Frame into more than one VSpace. The client also gets two plain
//! `Notification`s (`SUCCESS_CPTR`/`FAILURE_CPTR`, matching its own
//! constants) to signal its self-checked verdict on.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const FRAME_SERVICE_ELF: &[u8] = include_bytes!("../../assets/frame-service.elf");
const FRAME_CLIENT_ELF: &[u8] = include_bytes!("../../assets/frame-client.elf");

/// Matches both loaded programs' own `ENDPOINT_CPTR`.
const ENDPOINT_CPTR: CPtr = 1;
/// Matches `frame-client/src/main.rs`'s own `SUCCESS_CPTR`/`FAILURE_CPTR` —
/// `pub` so `../main.rs`'s trap handler can narrate by comparing against
/// them.
pub const CLIENT_SUCCESS_CPTR: CPtr = 2;
pub const CLIENT_FAILURE_CPTR: CPtr = 3;

/// Where the shared Frame is mapped in *both* programs' VSpaces — matches
/// `frame-service`/`frame-client`'s own `FRAME_VADDR` constant. Not required
/// to be the same address in both (each VSpace is independent); kept
/// identical here only because it's simpler to write down once.
const FRAME_VADDR: usize = 0x9000_0000;

const ARG0_SERVICE: usize = 0;
const ARG0_CLIENT: usize = 1;

/// Sets up the loader's own privileged root identity, retypes the shared
/// endpoint and the client's two proof notifications, loads both confined
/// programs, maps the shared `Frame` into both, and cold-starts the client.
/// Never returns.
///
/// `mem_end` is the end of usable RAM (`src/fdt.rs`'s device-tree read, or
/// `pmm::GENERAL_MEMORY_END` on failure) — see `../loader.rs`'s `run`.
///
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

    let mut next_slot: CPtr = 2; // slot 0 is SELF_CNODE_CPTR, slot 1 is untyped_cptr.

    let endpoint_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, endpoint_root_cptr);

    let success_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, success_root_cptr);
    let failure_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root_cptr);

    let specs = [
        ProgramSpec {
            elf_bytes: FRAME_SERVICE_ELF,
            arg0: ARG0_SERVICE,
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: FRAME_CLIENT_ELF,
            arg0: ARG0_CLIENT,
            grants: &[
                (endpoint_root_cptr, ENDPOINT_CPTR),
                (success_root_cptr, CLIENT_SUCCESS_CPTR),
                (failure_root_cptr, CLIENT_FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
    ];
    let [service, client] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    // ADR-0022 Part 2: one shared Frame, mapped read/write into both
    // programs' own VSpaces — the actual thing this demo exists to prove.
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        service.vspace_cptr,
        FRAME_VADDR,
        client.vspace_cptr,
        FRAME_VADDR,
        &mut next_slot,
    );

    state.make_ready(service.tcb);

    crate::println!("frame-demo: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and
    // address space were both fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(client.tcb) }
}
