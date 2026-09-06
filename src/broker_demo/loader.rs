//! Loader for the [RFC-0010](../../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)
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
//! shared via `#[path]` in `main.rs`).
//!
//! Loads two programs, granting each only what RFC-0010's demo actually
//! needs:
//! - `broker-service`: the shared endpoint, a capability to its own CNode
//!   (so it can `Mint` on itself), and a `Notification` "resource" it mints
//!   attenuated, badged copies of.
//! - `broker-client`: only the shared endpoint.
//!
//! Every grant is a real `CNodeInvoke::CopyCross` (RFC-0010) — the same
//! administrative, capability-checked mechanism `../loader.rs` uses for its
//! own single endpoint grant, generalised here into [`load`]'s `grants`
//! parameter since this demo needs more than one per program.

use lantern_hal::TrapFrame;
use lantern_kernel::admin;
use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId, VSpaceId};
use lantern_kernel::cnode;
use lantern_kernel::frame::{self as frame_invoke, LABEL_MAP};
use lantern_kernel::object::{SavedContext, Tcb, Untyped};
use lantern_kernel::state::KernelState;

use crate::elf;
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

/// Root's own CNode capability, in its own CSpace — see
/// `../loader.rs`'s `SELF_CNODE_CPTR` doc for the full reasoning; identical
/// role here.
const SELF_CNODE_CPTR: CPtr = 0;

/// Retypes one object from `untyped_cptr` into `root`'s CSpace at `dest`,
/// returning the resulting capability. Panics on failure — trusted,
/// privileged boot-time setup, same reasoning as `../loader.rs`'s identical
/// helper.
fn retype(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, object_type: ObjectType, dest: CPtr) -> Capability {
    let mut frame = TrapFrame::zeroed();
    frame.set_mr(1, object_type as usize);
    frame.set_mr(2, dest);
    admin::untyped_retype(state, root, untyped_cptr, &mut frame).expect("loader retype must succeed");
    let cspace = state.tcbs.get(root.0 as usize).unwrap().cspace.unwrap();
    state.cnodes.get(cspace.0 as usize).unwrap().get(dest).unwrap()
}

/// Copies the capability at `source_slot` in the CNode named by
/// `source_cnode` (a CPtr in `root`'s own CSpace) into `dest_slot` of the
/// CNode named by `dest_cnode` (also a CPtr in `root`'s own CSpace) — a real
/// `CNodeInvoke::CopyCross` (RFC-0010). Identical to `../loader.rs`'s own
/// helper of the same name and purpose.
fn copy_cross(state: &mut KernelState, root: TcbId, source_cnode: CPtr, source_slot: CPtr, dest_cnode: CPtr, dest_slot: CPtr) {
    let mut frame = TrapFrame::zeroed();
    frame.set_tag(lantern_hal::MessageTag { label: cnode::LABEL_COPY_CROSS, length: 0, extra_caps: 0, flags: 0 });
    frame.set_mr(1, source_cnode);
    frame.set_mr(2, source_slot);
    frame.set_mr(3, dest_slot);
    cnode::invoke(state, root, dest_cnode, &mut frame).expect("loader copy_cross must succeed");
}

const KERNEL_MEGAPAGE_BASE: usize = 0x8020_0000;
const UART_MEGAPAGE_BASE: usize = 0x1000_0000;

/// Identical to `../loader.rs`'s own `map_kernel_shared` — see its doc for
/// the full reasoning (every loaded program's VSpace needs the kernel image
/// and UART mapped S-mode-only, for the trap vector/`sret` cold-start path).
fn map_kernel_shared(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, vspace_id: VSpaceId) {
    let Capability::Untyped { id: untyped_id, .. } =
        state.lookup_cap(root, untyped_cptr).expect("loader's own Untyped cap must resolve")
    else {
        panic!("expected an Untyped capability");
    };
    let vspace_root = state.vspaces.get(vspace_id.0 as usize).unwrap().root as *mut lantern_hal::Riscv64PageTable;

    let kernel_flags = lantern_hal::Riscv64PteFlags::READ
        .union(lantern_hal::Riscv64PteFlags::WRITE)
        .union(lantern_hal::Riscv64PteFlags::EXECUTE);
    let mmio_flags = lantern_hal::Riscv64PteFlags::READ.union(lantern_hal::Riscv64PteFlags::WRITE);

    for &(vaddr, paddr, flags) in
        &[(KERNEL_MEGAPAGE_BASE, KERNEL_MEGAPAGE_BASE, kernel_flags), (UART_MEGAPAGE_BASE, UART_MEGAPAGE_BASE, mmio_flags)]
    {
        let spare = state
            .untypeds
            .get_mut(untyped_id.0 as usize)
            .unwrap()
            .bump(lantern_hal::RISCV64_PAGE_SIZE, lantern_hal::RISCV64_PAGE_SIZE)
            .expect("loader's own Untyped must have room for kernel-shared L1 tables");
        let mut alloc = move || spare;
        // SAFETY: `vspace_root` is this VSpace's own freshly built,
        // exclusively owned root table; `vaddr`/`paddr` are megapage-aligned
        // machine constants.
        unsafe { lantern_hal::riscv64_map_megapage(vspace_root, vaddr, paddr, flags, &mut alloc) };
    }
}

/// Identical to `../loader.rs`'s own `map` helper.
fn map(state: &mut KernelState, root: TcbId, frame_cptr: CPtr, vspace_cptr: CPtr, vaddr: usize, perms: usize) {
    let mut invoke_frame = TrapFrame::zeroed();
    invoke_frame.set_tag(lantern_hal::MessageTag { label: LABEL_MAP, length: 0, extra_caps: 0, flags: 0 });
    invoke_frame.set_mr(1, vspace_cptr);
    invoke_frame.set_mr(2, vaddr);
    invoke_frame.set_mr(3, perms);
    frame_invoke::invoke(state, root, frame_cptr, &mut invoke_frame).expect("loader map must succeed");
}

const PERM_R: usize = 1 << 0;
const PERM_W: usize = 1 << 1;
const PERM_X: usize = 1 << 2;
const PERM_U: usize = 1 << 3;

fn round_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

fn round_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

const STACK_VADDR: usize = 0x8600_0000;

/// Loads `elf_bytes` into a fresh VSpace and TCB, granting each `(root_slot,
/// dest_slot)` pair in `grants` — a real `CNodeInvoke::CopyCross` per pair,
/// copying whatever capability sits at `root_slot` in root's own CSpace into
/// `dest_slot` of the new program's CSpace — then admits it to the
/// scheduler. Generalises `../loader.rs`'s own `load` (which only ever grants
/// one, hardcoded, capability) since this demo's `broker-service` needs
/// three.
///
/// `self_cnode_dest`, if `Some`, additionally grants the new program a
/// capability to *its own* CNode at that slot — **not** expressible as an
/// ordinary `grants` entry, since the source (root's own freshly-retyped
/// `cnode_cptr`, naming the very CNode being constructed) doesn't exist until
/// partway through this function. Root already holds a real capability to
/// it (from retyping it below), so this is a genuine `CopyCross`, not a
/// pool write — the loaded-program equivalent of the one pool write
/// `run()` still needs for *root's own* founding self-reference, which
/// (unlike this) has no earlier capability to copy from at all.
#[allow(clippy::too_many_arguments)]
fn load(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    elf_bytes: &[u8],
    arg0: usize,
    grants: &[(CPtr, CPtr)],
    self_cnode_dest: Option<CPtr>,
    next_slot: &mut CPtr,
) -> TcbId {
    let header = elf::parse_header(elf_bytes).expect("broker demo ELF must parse");

    let vspace_cptr = *next_slot;
    *next_slot += 1;
    let Capability::VSpace { id: vspace_id, .. } =
        retype(state, root, untyped_cptr, ObjectType::VSpace, vspace_cptr)
    else {
        panic!("expected a VSpace capability");
    };
    map_kernel_shared(state, root, untyped_cptr, vspace_id);

    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(elf_bytes, &header, i).expect("broker demo ELF program header") else {
            continue;
        };
        let seg_start = round_down(ph.vaddr as usize, lantern_hal::RISCV64_MEGAPAGE_SIZE);
        let seg_end = round_up(ph.vaddr as usize + ph.memsz as usize, lantern_hal::RISCV64_MEGAPAGE_SIZE);
        assert_eq!(
            seg_end - seg_start,
            lantern_hal::RISCV64_MEGAPAGE_SIZE,
            "broker demo ELF segment spans more than one megapage -- loader.rs only handles one Frame per segment"
        );

        let frame_cptr = *next_slot;
        *next_slot += 1;
        let Capability::Frame { id: frame_id, .. } =
            retype(state, root, untyped_cptr, ObjectType::FrameMega, frame_cptr)
        else {
            panic!("expected a Frame capability");
        };
        let paddr = state.frames.get(frame_id.0 as usize).unwrap().paddr;

        let within_frame = ph.vaddr as usize - seg_start;
        // SAFETY: `paddr` is this thread's own freshly retyped, exclusively
        // owned, zeroed Frame, identity-mapped in *this* (the loader's own)
        // address space -- same reasoning as `../loader.rs`'s identical copy.
        unsafe {
            let dst = (paddr + within_frame) as *mut u8;
            let src = &elf_bytes[ph.offset as usize..(ph.offset + ph.filesz) as usize];
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }

        let mut perms = 0usize;
        if ph.flags & elf::PF_R != 0 {
            perms |= PERM_R;
        }
        if ph.flags & elf::PF_W != 0 {
            perms |= PERM_W;
        }
        if ph.flags & elf::PF_X != 0 {
            perms |= PERM_X;
        }
        perms |= PERM_U;
        map(state, root, frame_cptr, vspace_cptr, seg_start, perms);
    }

    let stack_cptr = *next_slot;
    *next_slot += 1;
    let Capability::Frame { .. } = retype(state, root, untyped_cptr, ObjectType::FrameMega, stack_cptr) else {
        panic!("expected a Frame capability");
    };
    map(state, root, stack_cptr, vspace_cptr, STACK_VADDR, PERM_R | PERM_W | PERM_U);
    let stack_top = STACK_VADDR + lantern_hal::RISCV64_MEGAPAGE_SIZE;

    let cnode_cptr = *next_slot;
    *next_slot += 1;
    let Capability::CNode(_) = retype(state, root, untyped_cptr, ObjectType::CNode, cnode_cptr) else {
        panic!("expected a CNode capability");
    };
    for &(root_slot, dest_slot) in grants {
        copy_cross(state, root, SELF_CNODE_CPTR, root_slot, cnode_cptr, dest_slot);
    }
    if let Some(dest_slot) = self_cnode_dest {
        // Source: root's own CNode (SELF_CNODE_CPTR), slot `cnode_cptr` --
        // which holds the `Capability::CNode` this function just retyped,
        // naming the *new* program's own CNode. Copying that into the new
        // program's own `dest_slot` gives it a real capability to itself.
        copy_cross(state, root, SELF_CNODE_CPTR, cnode_cptr, cnode_cptr, dest_slot);
    }

    let sched_cptr = *next_slot;
    *next_slot += 1;
    let Capability::SchedContext { .. } = retype(state, root, untyped_cptr, ObjectType::SchedContext, sched_cptr)
    else {
        panic!("expected a SchedContext capability");
    };

    let tcb_cptr = *next_slot;
    *next_slot += 1;
    let Capability::Tcb { id: tcb_id, .. } = retype(state, root, untyped_cptr, ObjectType::Tcb, tcb_cptr) else {
        panic!("expected a Tcb capability");
    };
    {
        let tcb = state.tcbs.get_mut(tcb_id.0 as usize).unwrap();
        tcb.context = SavedContext::initial(header.entry as usize, stack_top, arg0);
    }

    let mut configure_frame = TrapFrame::zeroed();
    configure_frame.set_mr(1, cnode_cptr);
    configure_frame.set_mr(2, sched_cptr);
    configure_frame.set_mr(3, vspace_cptr);
    admin::configure(state, root, tcb_cptr, &mut configure_frame).expect("loader configure must succeed");

    tcb_id
}

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
    let untyped = Untyped::with_memory(
        1000,
        pmm::GENERAL_MEMORY_BASE,
        mem_end - pmm::GENERAL_MEMORY_BASE,
    );
    let untyped_idx = state.untypeds.alloc(untyped).expect("untyped pool exhausted");
    let untyped_cptr: CPtr = 1;
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
        Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };

    let mut next_slot: CPtr = 2; // slot 0 is SELF_CNODE_CPTR, slot 1 is untyped_cptr.

    let endpoint_root_cptr = next_slot;
    next_slot += 1;
    retype(state, root, untyped_cptr, ObjectType::Endpoint, endpoint_root_cptr);

    // The resource broker-service administers and mints attenuated, badged
    // copies of -- a Notification, standing in for whatever a real Phase 2
    // service would hold. Retyped with full rights, same as the endpoint.
    let resource_root_cptr = next_slot;
    next_slot += 1;
    retype(state, root, untyped_cptr, ObjectType::Notification, resource_root_cptr);

    let broker = load(
        state,
        root,
        untyped_cptr,
        BROKER_SERVICE_ELF,
        ARG0_BROKER,
        &[(endpoint_root_cptr, ENDPOINT_CPTR), (resource_root_cptr, BROKER_RESOURCE_CPTR)],
        Some(BROKER_SELF_CNODE_CPTR),
        &mut next_slot,
    );
    let client = load(
        state,
        root,
        untyped_cptr,
        BROKER_CLIENT_ELF,
        ARG0_CLIENT,
        &[(endpoint_root_cptr, ENDPOINT_CPTR)],
        None,
        &mut next_slot,
    );
    state.make_ready(broker);

    crate::println!("broker-demo: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and
    // address space were both fully populated by `load` above.
    unsafe { lantern_kernel::enter_first_thread(client) }
}
