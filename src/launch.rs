//! A unified, data-driven confined-program launcher —
//! [RFC-0018](../../lantern-rfcs/rfcs/0018-confined-execution-port.md)/
//! [ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)'s
//! Part 1 launcher, replacing the two structurally identical, hand-duplicated
//! loaders `loader.rs` and `broker_demo/loader.rs` used to each carry (see
//! `STATUS.md`'s "Next"). Each binary's own `run()` still does its own
//! demo-specific root/Untyped/CNode bootstrap and mints whatever resources
//! its own demo needs (a plain endpoint here, a `Notification` there) —
//! genuinely different per demo — but "take an ELF, build a VSpace/CNode/Tcb
//! for it, wire in exactly the capabilities it needs, admit it to the
//! scheduler" is identical, and now lives here once.
//!
//! **[`ProgramSpec`] is the launch description**: an ELF image, its `arg0`,
//! the `(root_slot, dest_slot)` grants to `CopyCross` into its CSpace, and
//! (optionally) a slot to grant it a capability to its own CNode. [`load`]
//! loads exactly one program; [`load_all`] is the actual "N programs,
//! data-driven" entry point most callers want — a fixed-size array of specs
//! in, a fixed-size array of the resulting [`TcbId`]s out (this crate has no
//! allocator; `N` is a compile-time launch-description size, not a dynamic
//! list, same discipline `lantern-kernel`'s own fixed-capacity object pools
//! already use — `lantern-kernel/src/limits.rs`).
//!
//! **A segment may now span more than one megapage.** [`load`] loops,
//! retyping and mapping one `FrameMega` per 2 MiB step across
//! `[seg_start, seg_end)` and copying only the file bytes that actually land
//! in each step, rather than the single-Frame-per-segment `assert_eq!` both
//! predecessor loaders carried — a real, if so-far unhit, fragility: either
//! loader would have panicked the instant a loaded binary's segment crossed
//! 2 MiB.
//!
//! **Still out of scope here: a shared `Frame` mapped into two VSpaces at
//! once**, which the RFC-0019 service-call transport needs. `lantern-kernel`'s
//! `Frame` object is capped at exactly one mapping
//! (`lantern-kernel/src/object.rs`'s `Frame::mapped_at` doc: "Phase 1 has no
//! shared-frame IPC yet, so a Frame has at most one mapping, full stop"). That
//! is a kernel object-model change, not a loader one — ADR-0022's Part 2, left
//! for its own round. This module's `load` does gain a per-program **heap**
//! region (an ordinary, non-shared private Frame range, same as the stack) —
//! generalizing "give a loaded program its own scratch memory" beyond just a
//! stack, which every future confined service will want regardless of Part 2.

use lantern_hal::TrapFrame;
use lantern_kernel::admin;
use lantern_kernel::cap::{Capability, CPtr, ObjectType, Rights, TcbId, VSpaceId};
use lantern_kernel::cnode;
use lantern_kernel::frame::{self as frame_invoke, LABEL_MAP};
use lantern_kernel::object::SavedContext;
use lantern_kernel::state::KernelState;

use crate::elf;

/// Where every loaded program's own stack gets mapped — arbitrary, just
/// required not to collide with any loaded ELF's own linked address range.
/// Both predecessor loaders hardcoded this identically; kept as the one
/// shared convention.
pub const STACK_VADDR: usize = 0x8600_0000;

/// Where a loaded program's optional heap (see [`ProgramSpec::heap_megapages`])
/// gets mapped — one megapage above the stack, so the two never collide
/// regardless of how large either grows within its own reserved range.
pub const HEAP_VADDR: usize = STACK_VADDR + lantern_hal::RISCV64_MEGAPAGE_SIZE;

pub const PERM_R: usize = 1 << 0;
pub const PERM_W: usize = 1 << 1;
pub const PERM_X: usize = 1 << 2;
pub const PERM_U: usize = 1 << 3;

fn round_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

fn round_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

/// One program to load — see the module doc.
pub struct ProgramSpec<'a> {
    pub elf_bytes: &'a [u8],
    pub arg0: usize,
    /// `(root_slot, dest_slot)` pairs — each `CopyCross`'d from `root`'s own
    /// CSpace slot `root_slot` into this program's own CSpace slot
    /// `dest_slot`.
    pub grants: &'a [(CPtr, CPtr)],
    /// If `Some(slot)`, additionally grants this program a capability to its
    /// own CNode at that slot — **not** expressible as an ordinary `grants`
    /// entry, since the source (root's own freshly retyped CNode capability
    /// naming the very CNode being constructed) doesn't exist until partway
    /// through [`load`]. See `broker_demo/loader.rs`'s original doc for the
    /// full reasoning (unchanged, just relocated here).
    pub self_cnode_dest: Option<CPtr>,
    /// If nonzero, this program additionally gets `heap_megapages` contiguous
    /// `FrameMega`s mapped read/write at [`HEAP_VADDR`] — ordinary private
    /// memory, not shared with anything (see the module doc's "still out of
    /// scope" note for why this isn't the RFC-0019 shared `Frame`).
    pub heap_megapages: usize,
}

/// Root's own CNode capability slot, in its own CSpace — every caller of this
/// module uses slot 0 for it, by convention established when `loader.rs`
/// first needed to name itself as `CopyCross`'s source-CNode argument.
pub const SELF_CNODE_CPTR: CPtr = 0;

/// Retypes one object from `untyped_cptr` (in `root`'s own CSpace, per
/// `admin::untyped_retype`'s contract) into `root`'s CSpace at `dest`, and
/// returns the resulting capability. Panics on failure — trusted, privileged
/// boot-time setup with a hardcoded, generously sized budget/memory range; a
/// failure here is a configuration bug worth an immediate, loud failure, not
/// a silently misconfigured system (ADR-0008's "no syscall panics" rule
/// governs real syscalls reachable from unprivileged code, not this).
pub fn retype(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, object_type: ObjectType, dest: CPtr) -> Capability {
    let mut frame = TrapFrame::zeroed();
    frame.set_mr(1, object_type as usize);
    frame.set_mr(2, dest);
    admin::untyped_retype(state, root, untyped_cptr, &mut frame).expect("launcher retype must succeed");
    let cspace = state.tcbs.get(root.0 as usize).unwrap().cspace.unwrap();
    state.cnodes.get(cspace.0 as usize).unwrap().get(dest).unwrap()
}

/// Mints an attenuated copy of `root`'s own capability at `src` (in its own
/// CSpace) into `dest` (also its own CSpace), with `rights`/`badge` — a real
/// `CNodeInvoke::Mint`, via [`SELF_CNODE_CPTR`], same trust tier as [`retype`].
/// `#[allow(dead_code)]`: this module is compiled fresh into each binary that
/// shares it via `#[path]` (same convention as `elf.rs`/`fdt.rs`), and only
/// `loader.rs`'s demo badges its own endpoint this way — `broker_demo/loader.rs`
/// mints nothing itself (`lantern_capabilities::Broker` does its own minting,
/// confined, over `Abi`).
#[allow(dead_code)]
pub fn mint(state: &mut KernelState, root: TcbId, src: CPtr, dest: CPtr, rights: Rights, badge: u64) {
    let packed = ((badge as usize) << 8) | rights.bits() as usize;
    let mut frame = TrapFrame::zeroed();
    frame.set_tag(lantern_hal::MessageTag { label: cnode::LABEL_MINT, length: 0, extra_caps: 0, flags: 0 });
    frame.set_mr(1, src);
    frame.set_mr(2, dest);
    frame.set_mr(3, packed);
    cnode::invoke(state, root, SELF_CNODE_CPTR, &mut frame).expect("launcher mint must succeed");
}

/// Copies the capability at `source_slot` in the CNode named by
/// `source_cnode` (a CPtr in `root`'s own CSpace) into `dest_slot` of the
/// CNode named by `dest_cnode` (also a CPtr in `root`'s own CSpace) — a real
/// `CNodeInvoke::CopyCross`
/// ([RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)).
pub fn copy_cross(state: &mut KernelState, root: TcbId, source_cnode: CPtr, source_slot: CPtr, dest_cnode: CPtr, dest_slot: CPtr) {
    let mut frame = TrapFrame::zeroed();
    frame.set_tag(lantern_hal::MessageTag { label: cnode::LABEL_COPY_CROSS, length: 0, extra_caps: 0, flags: 0 });
    frame.set_mr(1, source_cnode);
    frame.set_mr(2, source_slot);
    frame.set_mr(3, dest_slot);
    cnode::invoke(state, root, dest_cnode, &mut frame).expect("launcher copy_cross must succeed");
}

/// Where OpenSBI loads/enters this image (`linker.ld`'s `BASE_ADDRESS`) — the
/// one megapage every loaded program's VSpace needs mapped, S-mode-only, for
/// the trap vector/kernel dispatch/`sret` cold-start path to keep working once
/// that program's own table is active (RISC-V traps don't switch page
/// tables).
const KERNEL_MEGAPAGE_BASE: usize = 0x8020_0000;
const UART_MEGAPAGE_BASE: usize = 0x1000_0000;

/// Maps [`KERNEL_MEGAPAGE_BASE`] and the UART megapage into `vspace_id`'s root
/// table, S-mode-only (no `USER` flag) — **not** through `FrameInvoke::Map`:
/// these aren't retyped `Frame` objects, and `lantern-kernel` itself has no
/// business knowing `lantern-boot`'s own kernel-image layout. See
/// `loader.rs`'s original doc (unchanged reasoning, just relocated here).
pub fn map_kernel_shared(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, vspace_id: VSpaceId) {
    let Capability::Untyped { id: untyped_id, .. } =
        state.lookup_cap(root, untyped_cptr).expect("launcher's own Untyped cap must resolve")
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
        // Pre-allocate the one page `map_megapage` might need for a fresh L1
        // table, same reasoning as `lantern_kernel::frame::map`'s identical
        // pattern (its own doc comment has the full explanation).
        let spare = state
            .untypeds
            .get_mut(untyped_id.0 as usize)
            .unwrap()
            .bump(lantern_hal::RISCV64_PAGE_SIZE, lantern_hal::RISCV64_PAGE_SIZE)
            .expect("launcher's own Untyped must have room for kernel-shared L1 tables");
        let mut alloc = move || spare;
        // SAFETY: `vspace_root` is this VSpace's own freshly built, exclusively
        // owned root table; `vaddr`/`paddr` are megapage-aligned machine
        // constants.
        unsafe { lantern_hal::riscv64_map_megapage(vspace_root, vaddr, paddr, flags, &mut alloc) };
    }
}

/// Maps `frame_cptr` (in `root`'s CSpace) into `vspace_cptr`'s (also `root`'s
/// CSpace) VSpace at `vaddr`, with `perms` (see `PERM_*` above).
pub fn map(state: &mut KernelState, root: TcbId, frame_cptr: CPtr, vspace_cptr: CPtr, vaddr: usize, perms: usize) {
    let mut invoke_frame = TrapFrame::zeroed();
    invoke_frame.set_tag(lantern_hal::MessageTag { label: LABEL_MAP, length: 0, extra_caps: 0, flags: 0 });
    invoke_frame.set_mr(1, vspace_cptr);
    invoke_frame.set_mr(2, vaddr);
    invoke_frame.set_mr(3, perms);
    frame_invoke::invoke(state, root, frame_cptr, &mut invoke_frame).expect("launcher map must succeed");
}

/// Loads `spec.elf_bytes` into a fresh VSpace and TCB, wires in every
/// capability `spec.grants`/`spec.self_cnode_dest` name, maps a stack (and
/// optionally a heap), then admits it to the scheduler. `root`/`untyped_cptr`
/// are the launcher's own privileged identity; `next_slot` hands out fresh
/// CSpace slots in `root`'s own CNode for this program's retyped objects
/// (VSpace/Frames/CNode/Tcb/SchedContext all transiently live there).
pub fn load(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, spec: &ProgramSpec, next_slot: &mut CPtr) -> TcbId {
    let header = elf::parse_header(spec.elf_bytes).expect("loaded ELF must parse");

    let vspace_cptr = *next_slot;
    *next_slot += 1;
    let Capability::VSpace { id: vspace_id, .. } = retype(state, root, untyped_cptr, ObjectType::VSpace, vspace_cptr)
    else {
        panic!("expected a VSpace capability");
    };
    map_kernel_shared(state, root, untyped_cptr, vspace_id);

    let mega = lantern_hal::RISCV64_MEGAPAGE_SIZE;

    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(spec.elf_bytes, &header, i).expect("loaded ELF program header") else {
            continue; // A harmless-to-skip segment type (elf.rs's module doc).
        };
        let seg_start = round_down(ph.vaddr as usize, mega);
        let seg_end = round_up(ph.vaddr as usize + ph.memsz as usize, mega);
        let file_start = ph.vaddr as usize;
        let file_end = file_start + ph.filesz as usize;

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

        // One `FrameMega` per 2 MiB step across the segment's range — not
        // just one, so a segment spanning more than one megapage loads
        // correctly instead of tripping an `assert_eq!` (see the module doc).
        let mut frame_vaddr = seg_start;
        while frame_vaddr < seg_end {
            let frame_cptr = *next_slot;
            *next_slot += 1;
            let Capability::Frame { id: frame_id, .. } =
                retype(state, root, untyped_cptr, ObjectType::FrameMega, frame_cptr)
            else {
                panic!("expected a Frame capability");
            };
            let paddr = state.frames.get(frame_id.0 as usize).unwrap().paddr;

            // Copy only the file bytes that actually land within this step's
            // byte range; anything outside `[file_start, file_end)` (BSS, or
            // simply a step this segment's `filesz` doesn't reach) is left as
            // the Frame's own zeroed-on-retype contents.
            let frame_end = frame_vaddr + mega;
            let copy_start = frame_vaddr.max(file_start);
            let copy_end = frame_end.min(file_end);
            if copy_start < copy_end {
                let within_frame = copy_start - frame_vaddr;
                let file_offset = ph.offset as usize + (copy_start - file_start);
                // SAFETY: `paddr` is this thread's own freshly retyped,
                // exclusively owned, zeroed Frame (per `Untyped::bump`'s "no
                // reclaim" guarantee) — identity-mapped in *this* (the
                // launcher's own) address space, since it came from the
                // shared kernel megapage's identity-mapped range.
                unsafe {
                    let dst = (paddr + within_frame) as *mut u8;
                    let src = &spec.elf_bytes[file_offset..file_offset + (copy_end - copy_start)];
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                }
            }

            map(state, root, frame_cptr, vspace_cptr, frame_vaddr, perms);
            frame_vaddr += mega;
        }
    }

    let stack_cptr = *next_slot;
    *next_slot += 1;
    let Capability::Frame { .. } = retype(state, root, untyped_cptr, ObjectType::FrameMega, stack_cptr) else {
        panic!("expected a Frame capability");
    };
    map(state, root, stack_cptr, vspace_cptr, STACK_VADDR, PERM_R | PERM_W | PERM_U);
    let stack_top = STACK_VADDR + mega;

    for i in 0..spec.heap_megapages {
        let heap_cptr = *next_slot;
        *next_slot += 1;
        let Capability::Frame { .. } = retype(state, root, untyped_cptr, ObjectType::FrameMega, heap_cptr) else {
            panic!("expected a Frame capability");
        };
        map(state, root, heap_cptr, vspace_cptr, HEAP_VADDR + i * mega, PERM_R | PERM_W | PERM_U);
    }

    let cnode_cptr = *next_slot;
    *next_slot += 1;
    let Capability::CNode(_) = retype(state, root, untyped_cptr, ObjectType::CNode, cnode_cptr) else {
        panic!("expected a CNode capability");
    };
    for &(root_slot, dest_slot) in spec.grants {
        copy_cross(state, root, SELF_CNODE_CPTR, root_slot, cnode_cptr, dest_slot);
    }
    if let Some(dest_slot) = spec.self_cnode_dest {
        // Source: root's own CNode (SELF_CNODE_CPTR), slot `cnode_cptr` --
        // which holds the `Capability::CNode` this function just retyped,
        // naming the *new* program's own CNode. Copying that into the new
        // program's own `dest_slot` gives it a real capability to itself.
        copy_cross(state, root, SELF_CNODE_CPTR, cnode_cptr, cnode_cptr, dest_slot);
    }

    let sched_cptr = *next_slot;
    *next_slot += 1;
    let Capability::SchedContext { .. } = retype(state, root, untyped_cptr, ObjectType::SchedContext, sched_cptr) else {
        panic!("expected a SchedContext capability");
    };

    let tcb_cptr = *next_slot;
    *next_slot += 1;
    let Capability::Tcb { id: tcb_id, .. } = retype(state, root, untyped_cptr, ObjectType::Tcb, tcb_cptr) else {
        panic!("expected a Tcb capability");
    };
    {
        let tcb = state.tcbs.get_mut(tcb_id.0 as usize).unwrap();
        tcb.context = SavedContext::initial(header.entry as usize, stack_top, spec.arg0);
    }

    let mut configure_frame = TrapFrame::zeroed();
    configure_frame.set_mr(1, cnode_cptr);
    configure_frame.set_mr(2, sched_cptr);
    configure_frame.set_mr(3, vspace_cptr);
    admin::configure(state, root, tcb_cptr, &mut configure_frame).expect("launcher configure must succeed");

    tcb_id
}

/// The actual "N programs, data-driven" entry point: loads every spec in
/// `specs`, in order, via [`load`], returning each resulting [`TcbId`] in the
/// same order. `N` is fixed at compile time (this crate has no allocator) —
/// callers destructure the result with a matching-length array pattern, e.g.
/// `let [server, client] = load_all(state, root, untyped_cptr, &specs, &mut next_slot);`.
pub fn load_all<const N: usize>(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    specs: &[ProgramSpec; N],
    next_slot: &mut CPtr,
) -> [TcbId; N] {
    let mut out = [TcbId(0); N];
    for (slot, spec) in out.iter_mut().zip(specs.iter()) {
        *slot = load(state, root, untyped_cptr, spec, next_slot);
    }
    out
}
