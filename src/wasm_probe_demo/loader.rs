//! Boots the Wasmtime/Pulley `riscv64` link-proof demo — a **sixth, isolated
//! boot image**, and this crate's first demo needing only **one** confined
//! program, not two or three (this probe is entirely self-contained: it runs
//! a trivial embedded Pulley component in-process and self-checks the
//! result, with no IPC to anyone else).
//!
//! `WASM_PROBE_ELF` is `lantern-runtime/riscv64-probe`'s own `--features bin`
//! binary ([RFC-0018](../../../lantern-rfcs/rfcs/0018-confined-execution-port.md)
//! Part 3 / [ADR-0023](../../../lantern-rfcs/adr/0023-wasmtime-no-std-pulley-hosting.md)) —
//! that crate's own doc previously said it "cannot be loaded by
//! `lantern-boot`'s current... loader (the image plus its 64 MiB `.bss` arena
//! is far larger than that)". It still can't, *at that size*: `lantern-kernel`'s
//! `MAX_FRAMES` is a hard 16 system-wide (`lantern-kernel/src/limits.rs`), and
//! a 64 MiB arena alone needs ~32 `FrameMega`s. Shrinking the arena (and the
//! probe's own heap) to what the trivial embedded component actually needs —
//! 256 KiB and 2 MiB respectively, found by bisection — brought the whole
//! program down to ~4 `FrameMega`s total (image + stack + heap), closing the
//! "loader integration" gap Part 3's own STATUS.md named as outstanding.
//!
//! **This probe now gets an [`ArenaGrant`]** — a bounded pool of unmapped
//! `FrameMega` capabilities plus a capability to its own VSpace, which it
//! maps/unmaps itself via real `FrameInvoke::Map`/`Unmap`
//! (`riscv64-probe/src/platform.rs`), replacing the old `.bss` static array.
//! Wiring this up for real found a genuine, previously-unexercised
//! `lantern-kernel` bug — a confined program's own `FrameInvoke::Map`, the
//! first real `ecall` into `FrameInvoke` after `enter_first_thread`, hung
//! dereferencing its own VSpace's root table — fixed by
//! `lantern_kernel::object::KernelPageTables` (see that type's doc, and this
//! crate's own `STATUS.md`, for the full record). **4/4 reproducible `probe
//! Signal'd SUCCESS`** with the real Frame-backed arena live end-to-end.
//! **What this demo still does not prove**: a real (non-trivial) guest
//! component, or host imports (`IpcKeystore`/`IpcFilesystem`) — see
//! `lantern-runtime/STATUS.md`'s "Next" for what's outstanding on the way to
//! the full RFC-0018 integration demo (keystore + store + a confined runtime
//! together). This demo's job stays narrower and concrete: prove the loader
//! can actually place and run a Wasmtime+Pulley binary under the real
//! kernel at all, with its Wasm-linear-memory backing store made of real,
//! self-mapped capabilities.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const WASM_PROBE_ELF: &[u8] = include_bytes!("../../assets/wasm-probe.elf");

/// Matches `lantern-runtime/riscv64-probe/src/main.rs`'s own
/// `SUCCESS_CPTR`/`FAILURE_CPTR` — `pub` so `../main.rs`'s trap handler can
/// narrate by comparing against them.
pub const PROBE_SUCCESS_CPTR: CPtr = 4;
pub const PROBE_FAILURE_CPTR: CPtr = 5;

/// Matches `riscv64-probe/src/platform.rs`'s own `SELF_VSPACE_CPTR` — the
/// same "duplicated shared constant" convention `../main.rs`'s
/// `HEAP_BASE`/`HEAP_LEN` already established.
const PROBE_SELF_VSPACE_CPTR: CPtr = 6;
/// Matches `platform.rs`'s own `ARENA_FRAME_CPTR_BASE`.
const PROBE_ARENA_FRAME_CPTR_BASE: CPtr = 7;
/// Matches `platform.rs`'s own `REGIONS` — two unmapped `FrameMega`s (4 MiB),
/// comfortable headroom over the 256 KiB the old static arena used, well
/// within `lantern-kernel`'s `MAX_FRAMES = 16` budget alongside this demo's
/// existing ~4 (image + stack + heap).
const PROBE_ARENA_MEGAPAGES: usize = 2;

const ARG0_PROBE: usize = 0;

/// Sets up the loader's own privileged root identity, retypes the probe's two
/// proof notifications, loads the one confined program (with a 2 MiB private
/// heap — `ProgramSpec::heap_megapages` — and a `Frame`-backed arena pool —
/// `ProgramSpec::arena`), and cold-starts it. Never returns.
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

    let success_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, success_root_cptr);
    let failure_root_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root_cptr);

    let specs = [ProgramSpec {
        elf_bytes: WASM_PROBE_ELF,
        arg0: ARG0_PROBE,
        grants: &[(success_root_cptr, PROBE_SUCCESS_CPTR), (failure_root_cptr, PROBE_FAILURE_CPTR)],
        self_cnode_dest: None,
        // One FrameMega (2 MiB) at `launch::HEAP_VADDR` — must match
        // `lantern-runtime-riscv64-probe`'s own `HEAP_BASE`/`HEAP_LEN`.
        heap_megapages: 1,
        arena: Some(ArenaGrant {
            megapages: PROBE_ARENA_MEGAPAGES,
            self_vspace_dest: PROBE_SELF_VSPACE_CPTR,
            frame_dest_base: PROBE_ARENA_FRAME_CPTR_BASE,
        }),
    }];
    let [probe] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    crate::println!("wasm-probe-demo: entering the probe (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the probe's context and
    // address space were fully populated by `launch::load_all` above.
    unsafe { lantern_kernel::enter_first_thread(probe.tcb) }
}
