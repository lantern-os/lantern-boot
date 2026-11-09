//! Boots the RFC-0018 integration demo — a **seventh, isolated boot image**
//! (same separateness reasoning `broker_demo/loader.rs`'s module doc gives).
//!
//! Five confined programs, the `keystore_demo` topology with its client
//! swapped for a real runtime, and a launch binder between them
//! ([RFC-0020](../../../lantern-rfcs/rfcs/0020-launch-binder.md)):
//!
//! - `../../keystore-service/`, launched with `arg0 = PROFILE_SIGNING |
//!   BINDER_LAUNCHED`: one Ed25519 key, which it grants (via its own confined
//!   `Broker`, live over IPC) only over `GRANT`, from the binder.
//! - `lantern-shell/launch-binder/`: holds the only `GRANTER_BADGE`d copy of the
//!   service's endpoint, verifies the package, and decides each request.
//! - `lantern-runtime/confined-runtime/`: a confined `lantern-runtime` process
//!   (Wasmtime `no_std` + Pulley) holding **no** service endpoint. It asks the
//!   binder for its grant, backs a guest component's `lantern:host/keystore`
//!   slot 0 with `IpcKeystore` over the shared `Frame`, and runs
//!   `confined-probe-guest`'s `probe` export. The guest is not in the runtime's
//!   image: it arrives as the signed package `assets/probe.lpkg`, one `Frame`
//!   mapped read-only at `launch::PACKAGE_VADDR` in both the runtime and the
//!   binder, each of which verifies it. Its manifest is what selects `keystore`
//!   as the wiring.
//! - `lantern-shell/grant-control/`: holds the binder's control capability
//!   ([RFC-0021](../../../lantern-rfcs/rfcs/0021-grant-ledger-and-revocation.md)) and revokes the
//!   runtime's grant midway through its run. A test script, not a user interface.
//!
//! `lantern-shell/policy-store/` ([RFC-0022](../../../lantern-rfcs/rfcs/0022-persistent-revocation-store.md))
//! makes that revocation outlive a reboot, on `virt.flash1`. **This demo needs that flash attached:**
//! `-drive if=pflash,format=raw,unit=1,file=<32 MiB image of 0xFF bytes>`. Without it, or on a second boot
//! of the same image, the role is declined.
//!
//! The runtime gets more than any earlier client: a 2 MiB private heap
//! (Wasmtime bookkeeping, the Pulley interpreter stack; ~640 KiB measured) and an
//! [`ArenaGrant`] of three unmapped `FrameMega`s plus its own VSpace, which
//! `lantern_runtime::platform` maps on demand for the deserialized `.cwasm`
//! (one) and the guest's linear memory (two). Three is the measured minimum:
//! with two, Wasmtime's `mmap` runs out and the runtime reports a panic. Neither is shared with, or visible to, the
//! keystore-service.
//!
//! `lantern-kernel`'s `MAX_FRAMES` is system-wide. This demo uses 23: the
//! runtime's image (2) + stack (1) + heap (1) + arena (3), the shared package
//! (1), the keystore-service's image (2) + stack (1), the binder's image (2) +
//! stack (1) + heap (1), grant-control's image (2) + stack (1), policy-store's image (2) +
//! stack (1) + flash (1), and the shared `Frame` (1).

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const CONFINED_RUNTIME_ELF: &[u8] = include_bytes!("../../assets/confined-runtime.elf");
const LAUNCH_BINDER_ELF: &[u8] = include_bytes!("../../assets/launch-binder.elf");
const GRANT_CONTROL_ELF: &[u8] = include_bytes!("../../assets/grant-control.elf");
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store.elf");
/// `confined-probe-guest`'s signed package, built by `lantern-sdk build` from
/// `lantern-runtime/confined-probe-guest/` (see that crate's
/// `lantern.capabilities.toml`).
const PROBE_LPKG: &[u8] = include_bytes!("../../assets/probe.lpkg");

/// Matches the keystore-service's own `ENDPOINT_CPTR`, and the runtime's slot
/// for the binder's endpoint.
const ENDPOINT_CPTR: CPtr = 1;
/// Matches `keystore-service`'s own `SELF_CNODE_CPTR` (see
/// `keystore_demo/loader.rs`'s `KEYSTORE_SELF_CNODE_CPTR`).
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
/// Matches `confined-runtime/src/lib.rs`'s own `SUCCESS_CPTR`/`FAILURE_CPTR`
/// — `pub` so `main.rs`'s trap handler can narrate by comparing against them.
pub const RUNTIME_SUCCESS_CPTR: CPtr = 3;
pub const RUNTIME_FAILURE_CPTR: CPtr = 4;

/// Matches `lantern-runtime/src/platform.rs`'s `SELF_VSPACE_CPTR`,
/// `ARENA_FRAME_CPTR_BASE`, and `REGIONS` (that module's launcher contract).
const RUNTIME_SELF_VSPACE_CPTR: CPtr = 6;
const RUNTIME_ARENA_FRAME_CPTR_BASE: CPtr = 7;
const RUNTIME_ARENA_MEGAPAGES: usize = 3;
/// Matches `confined-runtime/src/lib.rs`'s `HEAP_LEN` (one 2 MiB megapage).
const RUNTIME_HEAP_MEGAPAGES: usize = 1;

/// Where the shared Frame is mapped in both programs' VSpaces — matches
/// `keystore-service`/`confined-runtime`'s own `FRAME_VADDR`.
const FRAME_VADDR: usize = 0x9000_0000;

/// `keystore-service`'s `PROFILE_SIGNING`: an Ed25519 key, granted SIGN-only.
const ARG0_KEYSTORE_SIGNING: usize = 1;

/// Matches `confined-runtime/src/lib.rs`'s `REVOKE_REQUEST_CPTR`/`REVOKE_DONE_CPTR`.
const RUNTIME_REVOKE_REQUEST_CPTR: CPtr = 10;
const RUNTIME_REVOKE_DONE_CPTR: CPtr = 11;

/// What `grant-control` expects to find: `lantern_abi::grant::INTERFACE_KEYSTORE`, with
/// `KeyOps::SIGN`'s bits above it.
const ARG0_GRANT_CONTROL: usize = 1 | (launch::KEY_OP_SIGN << 8);

/// Sets up the loader's own privileged root identity, retypes the shared
/// endpoint and the runtime's two proof notifications, loads both confined
/// programs, maps the shared `Frame` into both, and cold-starts the runtime.
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

    // RFC-0020: only the binder can ask the service for a grant, and it asks
    // under a badge the kernel delivers. The runtime gets only a way to ask
    // the binder.
    let granter_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, endpoint_root_cptr, granter_root_cptr, Rights::WRITE, launch::GRANTER_BADGE);
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
    launch::mint(state, root, endpoint_root_cptr, stranger_root_cptr, Rights::WRITE, 0);

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
    // RFC-0024: and grant-control reads the audit log through its own read-only copy.
    let policy_reader_root_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, policy_endpoint_root_cptr, policy_reader_root_cptr, Rights::WRITE, launch::READER_BADGE);

    let revoke_request_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, revoke_request_root_cptr);
    let revoke_done_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, revoke_done_root_cptr);

    let specs = [
        ProgramSpec {
            elf_bytes: KEYSTORE_SERVICE_ELF,
            arg0: ARG0_KEYSTORE_SIGNING | launch::BINDER_LAUNCHED,
            // Rights::ALL, as in keystore_demo: the service mints each
            // attenuated, badged copy from this.
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: LAUNCH_BINDER_ELF,
            // The binder's `arg0` is the package's exact length, as the runtime's.
            arg0: PROBE_LPKG.len(),
            grants: &[
                (binder_endpoint_root_cptr, launch::BINDER_ENDPOINT_CPTR),
                (policy_client_root_cptr, launch::BINDER_POLICY_STORE_CPTR),
                (granter_root_cptr, launch::BINDER_KEYSTORE_GRANTER_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: launch::BINDER_HEAP_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: CONFINED_RUNTIME_ELF,
            // The runtime's `arg0` is its package's exact length.
            arg0: PROBE_LPKG.len(),
            grants: &[
                (binder_client_root_cptr, ENDPOINT_CPTR),
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
                (policy_reader_root_cptr, launch::GRANT_CONTROL_READER_CPTR),
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
    let [service, binder, runtime, control, policy_store] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    launch::map_device_frame(
        state,
        root,
        launch::POLICY_FLASH_PADDR,
        policy_store.vspace_cptr,
        launch::POLICY_FLASH_VADDR,
        &mut next_slot,
    );

    launch::map_package(state, root, untyped_cptr, PROBE_LPKG, &[binder.vspace_cptr, runtime.vspace_cptr], &mut next_slot);

    // ADR-0022 Part 2: one shared Frame, mapped read/write into both
    // programs' own VSpaces.
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        service.vspace_cptr,
        FRAME_VADDR,
        runtime.vspace_cptr,
        FRAME_VADDR,
        &mut next_slot,
    );

    state.make_ready(service.tcb);
    state.make_ready(binder.tcb);
    state.make_ready(control.tcb);
    state.make_ready(policy_store.tcb);

    crate::println!("runtime-demo: entering the confined runtime (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the runtime's context and
    // address space were both fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(runtime.tcb) }
}
