//! Boots the RFC-0018 integration demo — a **seventh, isolated boot image**
//! (same separateness reasoning `broker_demo/loader.rs`'s module doc gives).
//!
//! Two confined programs, the `keystore_demo` topology with its client
//! swapped for a real runtime:
//!
//! - `../../keystore-service/`, launched with `arg0 = PROFILE_SIGNING`: one
//!   Ed25519 key, which it grants SIGN-only (via its own confined `Broker`,
//!   live over IPC) to whoever `Call`s first.
//! - `lantern-runtime/confined-runtime/`: a confined `lantern-runtime` process
//!   (Wasmtime `no_std` + Pulley) that takes that grant, backs a guest
//!   component's `lantern:host/keystore` slot 0 with `IpcKeystore` over the
//!   shared `Frame`, and runs `confined-probe-guest`'s `probe` export. The
//!   guest is not in the runtime's image: it arrives as the signed package
//!   `assets/probe.lpkg`, mapped read-only at `launch::PACKAGE_VADDR`, which
//!   the runtime verifies against its own trusted publisher key before
//!   deserializing.
//!
//! The runtime gets more than any earlier client: a 2 MiB private heap
//! (Wasmtime bookkeeping, the Pulley interpreter stack; ~640 KiB measured) and an
//! [`ArenaGrant`] of three unmapped `FrameMega`s plus its own VSpace, which
//! `lantern_runtime::platform` maps on demand for the deserialized `.cwasm`
//! (one) and the guest's linear memory (two). Three is the measured minimum:
//! with two, Wasmtime's `mmap` runs out and the runtime reports a panic. Neither is shared with, or visible to, the
//! keystore-service. Only the endpoint, the shared `Frame`, and the two proof
//! notifications are.
//!
//! `lantern-kernel`'s `MAX_FRAMES` is 16 system-wide. This demo uses 12: the
//! runtime's image (2) + stack (1) + heap (1) + arena (3) + package (1), the
//! keystore-service's image (2) + stack (1), and the shared `Frame` (1).

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const CONFINED_RUNTIME_ELF: &[u8] = include_bytes!("../../assets/confined-runtime.elf");
/// `confined-probe-guest`'s signed package, built by `lantern-sdk build` from
/// `lantern-runtime/confined-probe-guest/` (see that crate's
/// `lantern.capabilities.toml`).
const PROBE_LPKG: &[u8] = include_bytes!("../../assets/probe.lpkg");

/// Matches both loaded programs' own `ENDPOINT_CPTR`.
const ENDPOINT_CPTR: CPtr = 1;
/// Matches `keystore-service`'s own `SELF_CNODE_CPTR` (see
/// `keystore_demo/loader.rs`'s `KEYSTORE_SELF_CNODE_CPTR`).
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
/// Matches `confined-runtime/src/main.rs`'s own `SUCCESS_CPTR`/`FAILURE_CPTR`
/// — `pub` so `main.rs`'s trap handler can narrate by comparing against them.
pub const RUNTIME_SUCCESS_CPTR: CPtr = 3;
pub const RUNTIME_FAILURE_CPTR: CPtr = 4;

/// Matches `lantern-runtime/src/platform.rs`'s `SELF_VSPACE_CPTR`,
/// `ARENA_FRAME_CPTR_BASE`, and `REGIONS` (that module's launcher contract).
const RUNTIME_SELF_VSPACE_CPTR: CPtr = 6;
const RUNTIME_ARENA_FRAME_CPTR_BASE: CPtr = 7;
const RUNTIME_ARENA_MEGAPAGES: usize = 3;
/// Matches `confined-runtime/src/main.rs`'s `HEAP_LEN` (one 2 MiB megapage).
const RUNTIME_HEAP_MEGAPAGES: usize = 1;

/// Where the shared Frame is mapped in both programs' VSpaces — matches
/// `keystore-service`/`confined-runtime`'s own `FRAME_VADDR`.
const FRAME_VADDR: usize = 0x9000_0000;

/// `keystore-service`'s `PROFILE_SIGNING`: an Ed25519 key, granted SIGN-only.
const ARG0_KEYSTORE_SIGNING: usize = 1;

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

    let success_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, success_root_cptr);
    let failure_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root_cptr);

    let specs = [
        ProgramSpec {
            elf_bytes: KEYSTORE_SERVICE_ELF,
            arg0: ARG0_KEYSTORE_SIGNING,
            // Rights::ALL, as in keystore_demo: the service mints the
            // runtime's attenuated, badged copy from this.
            grants: &[(endpoint_root_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
            package: None,
        },
        ProgramSpec {
            elf_bytes: CONFINED_RUNTIME_ELF,
            // The runtime's `arg0` is its package's exact length.
            arg0: PROBE_LPKG.len(),
            grants: &[
                (endpoint_root_cptr, ENDPOINT_CPTR),
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
            package: Some(PROBE_LPKG),
        },
    ];
    let [service, runtime] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

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

    crate::println!("runtime-demo: entering the confined runtime (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the runtime's context and
    // address space were both fully populated by `launch::load_all` and
    // `launch::map_shared_frame` above.
    unsafe { lantern_kernel::enter_first_thread(runtime.tcb) }
}
