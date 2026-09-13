//! Boots the confined [`lantern_filesystem::Store`] demo — a **fifth,
//! isolated boot image** (same separateness reasoning `broker_demo/loader.rs`'s
//! module doc gives for its own independence from `../loader.rs`).
//!
//! **Three programs, not two** — the first demo in this crate with that
//! shape: `../../keystore-service/` (unchanged, reused verbatim — it doesn't
//! care whether its "client" is a human-facing demo or another confined
//! service), `../../store-service/`, and `../../store-client/`. Two
//! independent shared `Frame`s ([`launch::map_shared_frame`], called twice):
//! one between `keystore-service`/`store-service` (the store's own
//! `ChannelCipher` leg), one between `store-service`/`store-client` (the
//! RFC-0019 `store` READ/WRITE leg). `store-service` maps *both* into its own
//! single VSpace at two different virtual addresses — see its own module doc.
//!
//! Neither grant chain is pre-wired by this loader: `store-service` gets its
//! own keystore access live over real IPC from `keystore-service` (exactly
//! `store-client`/`keystore-service`'s own dance, replayed one layer down),
//! and `store-client` gets its file access live from `store-service` — this
//! loader only grants the two shared endpoints, the two shared `Frame`s, and
//! the two `self_cnode_dest` grants each service needs to `Broker::mint`
//! against itself.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const STORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/store-service.elf");
const STORE_CLIENT_ELF: &[u8] = include_bytes!("../../assets/store-client.elf");

/// Matches `keystore-service/src/main.rs`'s own `ENDPOINT_CPTR` and
/// `store-service/src/main.rs`'s own `KS_ENDPOINT_CPTR` — coincidentally the
/// same slot number in both programs' own CSpaces, but two independent
/// grants of the same root-level resource (see `grants` below), not shared
/// state.
const KS_ENDPOINT_CPTR: CPtr = 1;
/// Matches `store-service/src/main.rs`'s own `CLIENT_ENDPOINT_CPTR` — where
/// *store-service itself* keeps its retained authority/mint source for the
/// endpoint `store-client` reaches it on.
const STORE_SERVICE_OWN_ENDPOINT_CPTR: CPtr = 3;
/// Matches `store-client/src/main.rs`'s own `ENDPOINT_CPTR` — a *different*
/// slot number than [`STORE_SERVICE_OWN_ENDPOINT_CPTR`] even though both name
/// the same underlying endpoint object, exactly the same "each program picks
/// its own slot" shape `KS_ENDPOINT_CPTR` above and `keystore-client`'s own
/// `ENDPOINT_CPTR` already established.
const STORE_CLIENT_ENDPOINT_CPTR: CPtr = 1;
/// Matches both services' own `SELF_CNODE_CPTR` — see
/// `keystore_demo/loader.rs`'s `KEYSTORE_SELF_CNODE_CPTR` for why this is a
/// distinct concept from `launch::SELF_CNODE_CPTR` (root's own).
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
const STORE_SELF_CNODE_CPTR: CPtr = 0;
/// Matches `store-client/src/main.rs`'s own `SUCCESS_CPTR`/`FAILURE_CPTR` —
/// `pub` so `../main.rs`'s trap handler can narrate by comparing against
/// them.
pub const CLIENT_SUCCESS_CPTR: CPtr = 3;
pub const CLIENT_FAILURE_CPTR: CPtr = 4;

/// Where `keystore-service` and `store-service` each map their shared
/// `Frame` — matches both programs' own `KS_FRAME_VADDR`/`FRAME_VADDR`
/// constant (independent VSpaces, no need for the *other* frame below to
/// avoid this address in a different program's own mapping).
const KS_FRAME_VADDR: usize = 0x9000_0000;
/// Where `store-service` maps its half of the *second* shared `Frame` (with
/// `store-client`) — a different virtual address than [`KS_FRAME_VADDR`]
/// since both are mapped into `store-service`'s own single VSpace at once.
/// Matches `store-service/src/main.rs`'s own `CLIENT_FRAME_VADDR`.
const CLIENT_FRAME_VADDR_ON_STORE: usize = 0x9001_0000;
/// Where `store-client` maps its own half of that second `Frame` — matches
/// `store-client/src/main.rs`'s own `FRAME_VADDR`. Free to differ numerically
/// from [`CLIENT_FRAME_VADDR_ON_STORE`] (independent VSpaces); kept the same
/// here purely for readability.
const CLIENT_FRAME_VADDR: usize = 0x9000_0000;

const ARG0_KEYSTORE: usize = 0;
const ARG0_STORE: usize = 1;
const ARG0_CLIENT: usize = 2;

/// Sets up the loader's own privileged root identity, retypes both shared
/// endpoints and the client's two proof notifications, loads all three
/// confined programs, maps both shared `Frame`s, and cold-starts the client.
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

    let ks_endpoint_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, ks_endpoint_root_cptr);

    let ss_endpoint_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, ss_endpoint_root_cptr);

    let success_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, success_root_cptr);
    let failure_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root_cptr);

    let specs = [
        ProgramSpec {
            elf_bytes: KEYSTORE_SERVICE_ELF,
            arg0: ARG0_KEYSTORE,
            grants: &[(ks_endpoint_root_cptr, KS_ENDPOINT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: STORE_SERVICE_ELF,
            arg0: ARG0_STORE,
            // store-service's own retained authority is its endpoint to
            // store-client (STORE_SERVICE_OWN_ENDPOINT_CPTR, its own
            // Broker::mint source — keystore-service's identical convention);
            // its endpoint to keystore-service is just an ordinary granted
            // capability, never minted from.
            grants: &[(ks_endpoint_root_cptr, KS_ENDPOINT_CPTR), (ss_endpoint_root_cptr, STORE_SERVICE_OWN_ENDPOINT_CPTR)],
            self_cnode_dest: Some(STORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: STORE_CLIENT_ELF,
            arg0: ARG0_CLIENT,
            grants: &[
                (ss_endpoint_root_cptr, STORE_CLIENT_ENDPOINT_CPTR),
                (success_root_cptr, CLIENT_SUCCESS_CPTR),
                (failure_root_cptr, CLIENT_FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
    ];
    let [keystore, store, client] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    // ADR-0022 Part 2: two independent shared Frames — see the module doc.
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        keystore.vspace_cptr,
        KS_FRAME_VADDR,
        store.vspace_cptr,
        KS_FRAME_VADDR,
        &mut next_slot,
    );
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        store.vspace_cptr,
        CLIENT_FRAME_VADDR_ON_STORE,
        client.vspace_cptr,
        CLIENT_FRAME_VADDR,
        &mut next_slot,
    );

    state.make_ready(keystore.tcb);
    state.make_ready(store.tcb);

    crate::println!("store-demo: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; all three programs' contexts
    // and address spaces were fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(client.tcb) }
}
