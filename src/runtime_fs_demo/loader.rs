//! Boots the RFC-0018 **filesystem** integration demo — an **eighth,
//! isolated boot image** (same separateness reasoning `broker_demo/loader.rs`'s
//! module doc gives).
//!
//! `store_demo`'s three-program topology with its client swapped for a real
//! runtime, the way `runtime_demo` did for `keystore_demo`:
//! `../../keystore-service/` (AEAD profile) ← `../../store-service/` ←
//! `lantern-runtime/confined-runtime`, a confined `lantern-runtime` process
//! hosting `confined-fs-guest` whose `filesystem` slot 0 is `IpcFilesystem`
//! over the second shared `Frame`. The guest arrives as the signed package
//! `assets/fs-probe.lpkg`, mapped read-only (see `runtime_demo/loader.rs`'s
//! module doc). It is the same runtime ELF as `runtime_demo`'s: the package's
//! own manifest is what selects `filesystem` over `keystore`.
//! Every guest `read`/`write` crosses three confined programs, and the
//! store-service seals each block through its own grant on the
//! keystore-service — a key neither the runtime nor the guest can name.
//!
//! As in `store_demo`, neither grant chain is pre-wired: store-service gets
//! its AEAD access live from keystore-service, and the runtime gets its
//! READ|WRITE file access live from store-service.
//!
//! The launch binder ([RFC-0020](../../../lantern-rfcs/rfcs/0020-launch-binder.md))
//! sits between the runtime and store-service, as in `runtime_demo`: the runtime
//! holds no endpoint to store-service until the binder decides it should. The
//! store-service's own grant from keystore-service is launcher-fixed infrastructure
//! rather than an app's request, and it stays a first-caller grant.
//!
//! `lantern-shell/grant-control/` holds the binder's control capability
//! ([RFC-0021](../../../lantern-rfcs/rfcs/0021-grant-ledger-and-revocation.md)) and revokes the
//! runtime's file grant midway through its run. A test script, not a user interface.
//!
//! `lantern-shell/policy-store/` ([RFC-0022](../../../lantern-rfcs/rfcs/0022-persistent-revocation-store.md))
//! makes that revocation outlive a reboot, on `virt.flash1`. **This demo needs that flash attached:**
//! `-drive if=pflash,format=raw,unit=1,file=<32 MiB image of 0xFF bytes>`. Without it, or on a second boot
//! of the same image, the role is declined.
//!
//! **This is the largest demo, and what `lantern-kernel/src/limits.rs` is sized
//! from.** Frames: the runtime's image (2) + stack (1) + heap (1) + arena (3),
//! the shared package (1), each service's image (2) + stack (1), the binder's
//! image (2) + stack (1) + heap (1), grant-control's image (2) + stack (1), policy-store's image (2) + stack (1) + flash (1),
//! and the two shared `Frame`s: 27. Six programs is also the most `MAX_VSPACES` allows.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const STORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/store-service.elf");
const CONFINED_RUNTIME_ELF: &[u8] = include_bytes!("../../assets/confined-runtime.elf");
const LAUNCH_BINDER_ELF: &[u8] = include_bytes!("../../assets/launch-binder.elf");
const GRANT_CONTROL_ELF: &[u8] = include_bytes!("../../assets/grant-control.elf");
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store.elf");
/// `confined-fs-guest`'s signed package, built by `lantern-sdk build` from
/// `lantern-runtime/confined-fs-guest/` (see that crate's
/// `lantern.capabilities.toml`).
const FS_PROBE_LPKG: &[u8] = include_bytes!("../../assets/fs-probe.lpkg");

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
const RUNTIME_ARENA_MEGAPAGES: usize = 3;
const RUNTIME_HEAP_MEGAPAGES: usize = 1;

/// `keystore-service`'s `PROFILE_AEAD`: the store's sealing key.
const ARG0_KEYSTORE_AEAD: usize = 0;
const ARG0_STORE: usize = 1;

/// Matches `confined-runtime/src/lib.rs`'s `REVOKE_REQUEST_CPTR`/`REVOKE_DONE_CPTR`.
const RUNTIME_REVOKE_REQUEST_CPTR: CPtr = 10;
const RUNTIME_REVOKE_DONE_CPTR: CPtr = 11;

/// What `grant-control` expects to find: `lantern_abi::grant::INTERFACE_FILESYSTEM`, with
/// `FileOps::READ | FileOps::WRITE`'s bits above it.
const ARG0_GRANT_CONTROL: usize = 2 | (launch::FILE_OPS_READ_WRITE << 8);

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

    // RFC-0020: only the binder can ask the service for a grant, and it asks
    // under a badge the kernel delivers. The runtime gets only a way to ask
    // the binder.
    let granter_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, ss_endpoint_root_cptr, granter_root_cptr, Rights::WRITE, launch::GRANTER_BADGE);
    let binder_endpoint_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, binder_endpoint_root_cptr);
    let binder_client_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, binder_endpoint_root_cptr, binder_client_root_cptr, Rights::WRITE, 0);
    // RFC-0021: the same endpoint under another badge is what lists and revokes.
    let binder_control_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, binder_endpoint_root_cptr, binder_control_root_cptr, Rights::WRITE, launch::CONTROL_BADGE);
    let stranger_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, ss_endpoint_root_cptr, stranger_root_cptr, Rights::WRITE, 0);

    let success_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, success_root_cptr);
    let failure_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root_cptr);
    // RFC-0022: only the binder can reach the policy store.
    let policy_endpoint_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, policy_endpoint_root_cptr);
    let policy_client_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, policy_endpoint_root_cptr, policy_client_root_cptr, Rights::WRITE, 0);

    let revoke_request_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, revoke_request_root_cptr);
    let revoke_done_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, revoke_done_root_cptr);

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
            arg0: ARG0_STORE | launch::BINDER_LAUNCHED,
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
            elf_bytes: LAUNCH_BINDER_ELF,
            // The binder's `arg0` is the package's exact length, as the runtime's.
            arg0: FS_PROBE_LPKG.len(),
            grants: &[
                (binder_endpoint_root_cptr, launch::BINDER_ENDPOINT_CPTR),
                (policy_client_root_cptr, launch::BINDER_POLICY_STORE_CPTR),
                (granter_root_cptr, launch::BINDER_STORE_GRANTER_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: launch::BINDER_HEAP_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: CONFINED_RUNTIME_ELF,
            // The runtime's `arg0` is its package's exact length.
            arg0: FS_PROBE_LPKG.len(),
            grants: &[
                (binder_client_root_cptr, RUNTIME_ENDPOINT_CPTR),
                (success_root_cptr, RUNTIME_SUCCESS_CPTR),
                (failure_root_cptr, RUNTIME_FAILURE_CPTR),
                (revoke_request_root_cptr, RUNTIME_REVOKE_REQUEST_CPTR),
                (revoke_done_root_cptr, RUNTIME_REVOKE_DONE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: RUNTIME_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant {
                megapages: RUNTIME_ARENA_MEGAPAGES,
                self_vspace_dest: RUNTIME_SELF_VSPACE_CPTR,
                frame_dest_base: RUNTIME_ARENA_FRAME_CPTR_BASE,
            }),
        },
        ProgramSpec {
            elf_bytes: GRANT_CONTROL_ELF,
            arg0: ARG0_GRANT_CONTROL,
            grants: &[
                (binder_control_root_cptr, launch::GRANT_CONTROL_CONTROL_CPTR),
                (stranger_root_cptr, launch::GRANT_CONTROL_STRANGER_CPTR),
                (failure_root_cptr, RUNTIME_FAILURE_CPTR),
                (revoke_request_root_cptr, launch::GRANT_CONTROL_REQUEST_CPTR),
                (revoke_done_root_cptr, launch::GRANT_CONTROL_DONE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: POLICY_STORE_ELF,
            arg0: 0,
            grants: &[
                (policy_endpoint_root_cptr, launch::POLICY_STORE_ENDPOINT_CPTR),
                (failure_root_cptr, RUNTIME_FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
    ];
    let [keystore, store, binder, runtime, control, policy_store] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    launch::map_device_frame(
        state,
        root,
        launch::POLICY_FLASH_PADDR,
        policy_store.vspace_cptr,
        launch::POLICY_FLASH_VADDR,
        &mut next_slot,
    );

    launch::map_package(state, root, untyped_cptr, FS_PROBE_LPKG, &[binder.vspace_cptr, runtime.vspace_cptr], &mut next_slot);

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
    state.make_ready(binder.tcb);
    state.make_ready(control.tcb);
    state.make_ready(policy_store.tcb);

    crate::println!("runtime-fs-demo: entering the confined runtime (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; all three programs' contexts
    // and address spaces were fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(runtime.tcb) }
}
