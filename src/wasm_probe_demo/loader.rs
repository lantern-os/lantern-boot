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
//! **What this demo does not yet prove**: a real (non-trivial) guest
//! component, host imports (`IpcKeystore`/`IpcFilesystem`), or a `Frame`-backed
//! platform layer (the arena is still a `static`, not real `Untyped`→`Frame`
//! retyping) — see `lantern-runtime/STATUS.md`'s "Next" for what's still
//! outstanding on the way to the full RFC-0018 integration demo (keystore +
//! store + a confined runtime together). This demo's job is narrower and
//! concrete: prove the loader can actually place and run a Wasmtime+Pulley
//! binary under the real kernel at all.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const WASM_PROBE_ELF: &[u8] = include_bytes!("../../assets/wasm-probe.elf");

/// Matches `lantern-runtime/riscv64-probe/src/main.rs`'s own
/// `SUCCESS_CPTR`/`FAILURE_CPTR` — `pub` so `../main.rs`'s trap handler can
/// narrate by comparing against them.
pub const PROBE_SUCCESS_CPTR: CPtr = 4;
pub const PROBE_FAILURE_CPTR: CPtr = 5;

const ARG0_PROBE: usize = 0;

/// Sets up the loader's own privileged root identity, retypes the probe's two
/// proof notifications, loads the one confined program (with a 2 MiB private
/// heap — `ProgramSpec::heap_megapages`), and cold-starts it. Never returns.
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
    }];
    let [probe] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);

    crate::println!("wasm-probe-demo: entering the probe (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the probe's context and
    // address space were fully populated by `launch::load_all` above.
    unsafe { lantern_kernel::enter_first_thread(probe.tcb) }
}
