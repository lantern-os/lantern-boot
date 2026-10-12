//! Boots the RFC-0018 **filesystem** integration demo — an **eighth,
//! isolated boot image** (same separateness reasoning `broker_demo/loader.rs`'s
//! module doc gives).
//!
//! `store_demo`'s three-program topology with its client swapped for a real
//! runtime, the way `runtime_demo` did for `keystore_demo`:
//! `../../keystore-service/` (AEAD profile) ← `../../store-service/` ←
//! `lantern-runtime/confined-runtime`'s `lantern-confined-runtime-fs`, a
//! confined `lantern-runtime` process hosting `confined-fs-guest` whose
//! `filesystem` slot 0 is `IpcFilesystem` over the second shared `Frame`.
//! Every guest `read`/`write` crosses three confined programs, and the
//! store-service seals each block through its own grant on the
//! keystore-service — a key neither the runtime nor the guest can name.
//!
//! As in `store_demo`, neither grant chain is pre-wired: store-service gets
//! its AEAD access live from keystore-service, and the runtime gets its
//! READ|WRITE file access live from store-service.
//!
//! **This demo sits at two of the kernel's fixed limits.** `MAX_FRAMES` (16):
//! the runtime's image (2) + stack (1) + heap (1) + arena (4), each service's
//! image (2) + stack (1), and the two shared `Frame`s — exactly 16. Root's
//! `CNODE_SLOTS` (32): 31 used, which fits only because `launch::load` now
//! reuses one root scratch slot for an `ArenaGrant`'s whole pool. A fourth
//! program, or any growth here, needs those limits raised — a kernel decision,
//! not a launcher one.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const STORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/store-service.elf");
const CONFINED_RUNTIME_FS_ELF: &[u8] = include_bytes!("../../assets/confined-runtime-fs.elf");

/// As `store_demo/loader.rs`'s constants of the same names.
const KS_ENDPOINT_CPTR: CPtr = 1;
const STORE_SERVICE_OWN_ENDPOINT_CPTR: CPtr = 3;
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
const STORE_SELF_CNODE_CPTR: CPtr = 0;
const KS_FRAME_VADDR: usize = 0x9000_0000;
const CLIENT_FRAME_VADDR_ON_STORE: usize = 0x9001_0000;

/// Matches `confined-runtime/src/lib.rs`'s `ENDPOINT_CPTR`, `SUCCESS_CPTR`/
/// `FAILURE_CPTR` and `FRAME_VADDR` — `pub` where `main.rs`'s trap handler
/// narrates by comparing against them.
const RUNTIME_ENDPOINT_CPTR: CPtr = 1;
pub const RUNTIME_SUCCESS_CPTR: CPtr = 3;
pub const RUNTIME_FAILURE_CPTR: CPtr = 4;
const RUNTIME_FRAME_VADDR: usize = 0x9000_0000;

/// As `runtime_demo/loader.rs`'s constants of the same names
/// (`lantern-runtime/src/platform.rs`'s launcher contract).
const RUNTIME_SELF_VSPACE_CPTR: CPtr = 6;
const RUNTIME_ARENA_FRAME_CPTR_BASE: CPtr = 7;
const RUNTIME_ARENA_MEGAPAGES: usize = 4;
const RUNTIME_HEAP_MEGAPAGES: usize = 1;

/// `keystore-service`'s `PROFILE_AEAD`: the store's sealing key.
const ARG0_KEYSTORE_AEAD: usize = 0;
const ARG0_STORE: usize = 1;
const ARG0_RUNTIME: usize = 2;

/// Sets up the loader's own privileged root identity, retypes both shared
/// endpoints and the runtime's two proof notifications, loads all three
/// confined programs, maps both shared `Frame`s, and cold-starts the runtime.
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
            arg0: ARG0_KEYSTORE_AEAD,
            grants: &[(ks_endpoint_root_cptr, KS_ENDPOINT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: STORE_SERVICE_ELF,
            arg0: ARG0_STORE,
            // store-service's own retained authority is its endpoint to
            // the runtime (STORE_SERVICE_OWN_ENDPOINT_CPTR, its own
            // Broker::mint source — keystore-service's identical convention);
            // its endpoint to keystore-service is just an ordinary granted
            // capability, never minted from.
            grants: &[(ks_endpoint_root_cptr, KS_ENDPOINT_CPTR), (ss_endpoint_root_cptr, STORE_SERVICE_OWN_ENDPOINT_CPTR)],
            self_cnode_dest: Some(STORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: CONFINED_RUNTIME_FS_ELF,
            arg0: ARG0_RUNTIME,
            grants: &[
                (ss_endpoint_root_cptr, RUNTIME_ENDPOINT_CPTR),
                (success_root_cptr, RUNTIME_SUCCESS_CPTR),
                (failure_root_cptr, RUNTIME_FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: RUNTIME_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant {
                megapages: RUNTIME_ARENA_MEGAPAGES,
                self_vspace_dest: RUNTIME_SELF_VSPACE_CPTR,
                frame_dest_base: RUNTIME_ARENA_FRAME_CPTR_BASE,
            }),
        },
    ];
    let [keystore, store, runtime] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

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
        runtime.vspace_cptr,
        RUNTIME_FRAME_VADDR,
        &mut next_slot,
    );

    state.make_ready(keystore.tcb);
    state.make_ready(store.tcb);

    crate::println!("runtime-fs-demo: entering the confined runtime (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; all three programs' contexts
    // and address spaces were fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(runtime.tcb) }
}
