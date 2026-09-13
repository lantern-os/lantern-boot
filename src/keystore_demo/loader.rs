//! Boots the confined [`lantern_crypto::Keystore`] demo — a **fourth,
//! isolated boot image** (same separateness reasoning `broker_demo/loader.rs`'s
//! module doc gives for its own independence from `../loader.rs`).
//!
//! Two programs, `../../keystore-service/` and `../../keystore-client/`,
//! share the usual endpoint *and* one shared `Frame`
//! ([`launch::map_shared_frame`],
//! [ADR-0022](../../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
//! Part 2) — the same shape `frame_demo/loader.rs` already proved, now
//! carrying a real
//! [RFC-0019](../../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)
//! `keystore` exchange instead of a toy transform. The client also gets two
//! plain `Notification`s (`SUCCESS_CPTR`/`FAILURE_CPTR`) to signal its
//! self-checked verdict on.
//!
//! Unlike `frame_demo`, the keystore-service's own access grant (which
//! client gets ENCRYPT|DECRYPT on which key) is **not** pre-wired by this
//! loader — the service mints and hands it over live, over real IPC, via its
//! own confined `Broker` (see `../../keystore-service/src/main.rs`'s module
//! doc). This loader only grants the shared endpoint and the shared `Frame`,
//! the same "narrowing waterfall" authority `../loader.rs` grants
//! `hello-service`.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const KEYSTORE_CLIENT_ELF: &[u8] = include_bytes!("../../assets/keystore-client.elf");

/// Matches both loaded programs' own `ENDPOINT_CPTR`.
const ENDPOINT_CPTR: CPtr = 1;
/// Matches `keystore-service/src/main.rs`'s own `SELF_CNODE_CPTR` — the
/// destination slot *in the service's own CSpace* for its self-CNode grant,
/// coincidentally also `0` (same convention `broker_demo/loader.rs`'s
/// `BROKER_SELF_CNODE_CPTR` documents) but a distinct concept from
/// `launch::SELF_CNODE_CPTR` (root's own, in root's CSpace).
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
/// Matches `keystore-client/src/main.rs`'s own `SUCCESS_CPTR`/`FAILURE_CPTR`
/// — `pub` so `../main.rs`'s trap handler can narrate by comparing against
/// them.
pub const CLIENT_SUCCESS_CPTR: CPtr = 3;
pub const CLIENT_FAILURE_CPTR: CPtr = 4;

/// Where the shared Frame is mapped in both programs' VSpaces — matches
/// `keystore-service`/`keystore-client`'s own `FRAME_VADDR` constant.
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
            elf_bytes: KEYSTORE_SERVICE_ELF,
            arg0: ARG0_SERVICE,
            // The service's own retained authority is exactly its endpoint
            // capability, granted with Rights::ALL (matching every other
            // demo's shared-endpoint convention) so it can mint attenuated,
            // badged copies of it via CNodeInvoke::Mint (Rights::GRANT
            // required) as well as Recv/Reply on it.
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: KEYSTORE_CLIENT_ELF,
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
    // programs' own VSpaces.
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

    crate::println!("keystore-demo: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and
    // address space were both fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(client.tcb) }
}
