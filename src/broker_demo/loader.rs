//! Boots the [RFC-0010](../../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)
//! confined-broker demo — a **separate, isolated boot image** from
//! `../loader.rs`'s existing two-thread IPC benchmark, per the scoping
//! decision recorded in `STATUS.md`: merging a third/fourth confined program
//! into that boot image risked corrupting its already-QEMU-validated,
//! timing-sensitive benchmark (its trap handler's narration and cycle
//! counters are keyed only on syscall number, not which program issued it —
//! an interleaved `Call`/`Reply` from this demo's own programs would
//! misattribute timing data). This loader, `../broker_demo/main.rs`'s own
//! trap handler, and the two confined programs it loads
//! (`../../broker-service/`, `../../broker-client/`) are entirely
//! independent of that demo; nothing here is shared except the genuinely
//! portable pieces (`../elf.rs`, `../pmm.rs`, `../uart.rs`, `../entry.rs`,
//! `../launch.rs`, shared via `#[path]` in `main.rs`).
//!
//! The actual "take an ELF, build it a VSpace/CNode/Tcb, wire in its
//! capabilities" work lives in [`crate::launch`] — this file just does this
//! demo's own bootstrap (root's founding identity, the shared endpoint and
//! the `Notification` "resource" `broker-service` administers) and builds
//! the two-entry launch description: `broker-service` gets the shared
//! endpoint, a capability to its own CNode (so it can `Mint` on itself), and
//! the resource; `broker-client` gets only the shared endpoint.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const BROKER_SERVICE_ELF: &[u8] = include_bytes!("../../assets/broker-service.elf");
const BROKER_CLIENT_ELF: &[u8] = include_bytes!("../../assets/broker-client.elf");

/// Matches both loaded programs' own `ENDPOINT_CPTR` (their own module docs —
/// neither reads this loader's source, this is the ABI between them, same
/// convention `../loader.rs`'s own `ENDPOINT_CPTR` documents).
const ENDPOINT_CPTR: CPtr = 1;
/// Matches `broker-service/src/main.rs`'s own `SELF_CNODE_CPTR`.
const BROKER_SELF_CNODE_CPTR: CPtr = 0;
/// Matches `broker-service/src/main.rs`'s own `RESOURCE_CPTR`.
const BROKER_RESOURCE_CPTR: CPtr = 2;
/// Matches `broker-client/src/main.rs`'s own `DEST_CPTR` — not granted by
/// this loader at all (the whole point of the demo: it arrives later, via a
/// real RFC-0010 transfer), listed here only so the two numbering choices
/// are visibly non-colliding at a glance.
#[allow(dead_code)]
const CLIENT_DEST_CPTR: CPtr = 2;

const ARG0_BROKER: usize = 0;
const ARG0_CLIENT: usize = 1;

/// Sets up the loader's own privileged root identity, retypes the shared
/// endpoint and the `Notification` "resource" `broker-service` administers,
/// loads both confined programs granting each exactly what RFC-0010's demo
/// needs, and cold-starts the client. Never returns.
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

    // The resource broker-service administers and mints attenuated, badged
    // copies of -- a Notification, standing in for whatever a real Phase 2
    // service would hold. Retyped with full rights, same as the endpoint.
    let resource_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, resource_root_cptr);

    let specs = [
        ProgramSpec {
            elf_bytes: BROKER_SERVICE_ELF,
            arg0: ARG0_BROKER,
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR), (resource_root_cptr, BROKER_RESOURCE_CPTR)],
            self_cnode_dest: Some(BROKER_SELF_CNODE_CPTR),
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: BROKER_CLIENT_ELF,
            arg0: ARG0_CLIENT,
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
    ];
    let [broker, client] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    state.make_ready(broker);

    crate::println!("broker-demo: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and
    // address space were both fully populated by `launch::load_all` above.
    unsafe { lantern_kernel::enter_first_thread(client) }
}
