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
//! **[`map_shared_frame`] is ADR-0022 Part 2**: one 4 KiB `Frame`, mapped
//! read/write into two already-loaded programs' VSpaces at once — the
//! RFC-0019 shared `(runtime, service)` channel. `lantern-kernel`'s `Frame`
//! object used to cap out at exactly one mapping; `MAX_FRAME_MAPPINGS == 2`
//! (`lantern-kernel/src/object.rs`) now allows exactly this case and no more.
//! Neither program needs a capability to the Frame itself — this project's
//! memory model needs none to *use* an already-mapped page (RFC-0008): the
//! launcher (root) retains the one `Capability::Frame` throughout and invokes
//! `Map` on it twice, once per target VSpace; each program just reads/writes
//! its own mapped virtual address, exactly like its stack. [`load`] returns
//! each program's `vspace_cptr` (via [`LoadedProgram`]) so a caller has
//! something to pass here after loading.
//!
//! This module's `load` also gained a per-program **heap** region (an
//! ordinary, non-shared private Frame range, same as the stack) — generalizing
//! "give a loaded program its own scratch memory" beyond just a stack, which
//! every future confined service wants regardless of the shared `Frame`.
//!
//! **[`ArenaGrant`] is RFC-0018 Part 3's "retype `Untyped` → `Frame`,
//! `FrameInvoke::Map`/`Unmap` into the runtime's VSpace at a reserved virtual
//! range" (`rfcs/0018-confined-execution-port.md`'s Part 3 table).** Unlike
//! the stack/heap above, these `FrameMega`s are granted **unmapped** — the
//! program maps/unmaps them itself, on demand, as its own custom-platform
//! `wasmtime_mmap_new`/`wasmtime_munmap` are called
//! (`lantern-runtime/riscv64-probe/src/platform.rs`). That needs two things
//! no earlier grant did: a capability to the program's *own* VSpace (so it
//! can name itself as `FrameInvoke::Map`'s target — the same
//! `self_cnode_dest` "chicken-and-egg... CopyCross" reasoning, sourced from
//! `vspace_cptr` instead of `cnode_cptr`), and the unmapped Frame
//! capabilities themselves. Deliberately **not** an Untyped grant: this
//! kernel has no bounded/sub-Untyped retype (`admin::untyped_retype` rejects
//! `ObjectType::Untyped` as a target), so an Untyped grant would hand the
//! program the *same* unbounded retype authority the launcher itself holds —
//! a real trust-boundary regression the "can an agent use this capability
//! without being unnecessarily trusted?" question (`CLAUDE.md`) rules out. A
//! fixed, launcher-sized pool of pre-retyped Frame capabilities keeps the
//! program's authority bounded exactly the way every other grant in this
//! module already is, while still exercising the real `FrameInvoke::Map`/
//! `Unmap` syscalls from inside the confined program itself, on demand.

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

/// Where a loaded program's optional arena `Frame` pool (see [`ArenaGrant`])
/// gets *reserved* — the program itself chooses when/whether to map each
/// megapage within this range. Fixed well clear of [`HEAP_VADDR`]'s own
/// growth (16 megapages above it) rather than computed from any one spec's
/// `heap_megapages`, so a spec's heap size can change without silently
/// moving this. `#[allow(dead_code)]`: this module is compiled fresh into
/// each binary that shares it via `#[path]` (same convention as [`mint`]'s
/// identical note) — the *value* is what every `arena`-granted program's own
/// platform code must duplicate (`riscv64-probe/src/platform.rs`'s own
/// `ARENA_VADDR`), never read by `launch.rs` itself, so only serves as the
/// one documented source of truth.
#[allow(dead_code)]
pub const ARENA_VADDR: usize = HEAP_VADDR + 16 * lantern_hal::RISCV64_MEGAPAGE_SIZE;

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
    /// If `Some`, this program additionally gets a bounded pool of *unmapped*
    /// `FrameMega` capabilities plus a capability to its own VSpace, so it
    /// can `FrameInvoke::Map`/`Unmap` them itself — see [`ArenaGrant`] and
    /// the module doc.
    pub arena: Option<ArenaGrant>,
}

/// See the module doc's `ArenaGrant` paragraph.
pub struct ArenaGrant {
    /// How many (initially unmapped) `FrameMega`s to retype and grant, at
    /// consecutive `frame_dest_base..` slots in the program's own CSpace.
    pub megapages: usize,
    /// The program's own CSpace slot to grant a capability to *its own*
    /// VSpace at.
    pub self_vspace_dest: CPtr,
    /// The first of `megapages` consecutive destination slots for the
    /// granted (unmapped) Frame capabilities.
    pub frame_dest_base: CPtr,
}

/// Root's own CNode capability slot, in its own CSpace — every caller of this
/// module uses slot 0 for it, by convention established when `loader.rs`
/// first needed to name itself as `CopyCross`'s source-CNode argument.
pub const SELF_CNODE_CPTR: CPtr = 0;

/// What [`load`] hands back: the new program's [`TcbId`] (to `make_ready` or
/// `enter_first_thread`) and its `vspace_cptr` (in `root`'s own CSpace) — the
/// latter needed only by a caller that goes on to [`map_shared_frame`] this
/// program into a shared channel with another one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LoadedProgram {
    pub tcb: TcbId,
    pub vspace_cptr: CPtr,
}

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
///
/// Its own branch-table spares now come from `lantern-kernel`'s
/// `KernelPageTables` (`state.kernel_page_tables`), not a caller-supplied
/// Untyped — see that type's doc for why: it's the fix for a real bug found
/// while adding [`ArenaGrant`]'s self-mapping (a confined program's own
/// `FrameInvoke::Map`, after its own paging is active, couldn't dereference a
/// `VSpace` root bump-allocated from general memory). `lantern-boot/STATUS.md`
/// has the full writeup.
pub fn map_kernel_shared(state: &mut KernelState, vspace_id: VSpaceId) {
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
            .kernel_page_tables
            .alloc()
            .expect("the kernel's own page-table arena must have room for kernel-shared L1 tables");
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
pub fn load(state: &mut KernelState, root: TcbId, untyped_cptr: CPtr, spec: &ProgramSpec, next_slot: &mut CPtr) -> LoadedProgram {
    let header = elf::parse_header(spec.elf_bytes).expect("loaded ELF must parse");

    let vspace_cptr = *next_slot;
    *next_slot += 1;
    let Capability::VSpace { id: vspace_id, .. } = retype(state, root, untyped_cptr, ObjectType::VSpace, vspace_cptr)
    else {
        panic!("expected a VSpace capability");
    };
    map_kernel_shared(state, vspace_id);

    let mega = lantern_hal::RISCV64_MEGAPAGE_SIZE;

    /// Generous for a small, hand-linked demo binary: a handful of segments
    /// (.text/.rodata/.data), each at most a couple of megapages.
    const MAX_PROGRAM_MEGAPAGES: usize = 8;

    fn segment_perms(ph: &elf::ProgramHeader) -> usize {
        let mut perms = PERM_U;
        if ph.flags & elf::PF_R != 0 {
            perms |= PERM_R;
        }
        if ph.flags & elf::PF_W != 0 {
            perms |= PERM_W;
        }
        if ph.flags & elf::PF_X != 0 {
            perms |= PERM_X;
        }
        perms
    }

    // Pass 1: the *set* of unique megapages this ELF's segments touch, each
    // with the union of every segment's own permission bits that lands in
    // it. Two segments sharing one megapage is real and common (a small
    // binary's .text and .rodata are often only a few KiB apart, well within
    // the same 2 MiB page) — mapping the same virtual address twice would
    // fail (`FrameInvoke::Map` refuses re-mapping an occupied address), and
    // mapping it once under only the *first* segment's permissions could
    // under-permission whatever the second segment needed.
    let mut megapage_vaddr = [0usize; MAX_PROGRAM_MEGAPAGES];
    let mut megapage_perms = [0usize; MAX_PROGRAM_MEGAPAGES];
    let mut megapage_count = 0usize;
    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(spec.elf_bytes, &header, i).expect("loaded ELF program header") else {
            continue; // A harmless-to-skip segment type (elf.rs's module doc).
        };
        let seg_start = round_down(ph.vaddr as usize, mega);
        let seg_end = round_up(ph.vaddr as usize + ph.memsz as usize, mega);
        let perms = segment_perms(&ph);

        let mut v = seg_start;
        while v < seg_end {
            match megapage_vaddr[..megapage_count].iter().position(|&mv| mv == v) {
                Some(idx) => megapage_perms[idx] |= perms,
                None => {
                    assert!(
                        megapage_count < MAX_PROGRAM_MEGAPAGES,
                        "loaded ELF needs more distinct megapages than this loader's fixed table"
                    );
                    megapage_vaddr[megapage_count] = v;
                    megapage_perms[megapage_count] = perms;
                    megapage_count += 1;
                }
            }
            v += mega;
        }
    }

    // Pass 2: retype and map exactly one `FrameMega` per unique megapage
    // (not one per segment — see pass 1), with its unioned permissions.
    let mut megapage_paddr = [0usize; MAX_PROGRAM_MEGAPAGES];
    for slot in 0..megapage_count {
        let frame_cptr = *next_slot;
        *next_slot += 1;
        let Capability::Frame { id: frame_id, .. } =
            retype(state, root, untyped_cptr, ObjectType::FrameMega, frame_cptr)
        else {
            panic!("expected a Frame capability");
        };
        megapage_paddr[slot] = state.frames.get(frame_id.0 as usize).unwrap().paddr;
        map(state, root, frame_cptr, vspace_cptr, megapage_vaddr[slot], megapage_perms[slot]);
    }

    // Pass 3: copy each segment's file bytes into whichever already-mapped
    // megapage(s) it overlaps, at the right offset within each.
    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(spec.elf_bytes, &header, i).expect("loaded ELF program header") else {
            continue;
        };
        let seg_start = round_down(ph.vaddr as usize, mega);
        let seg_end = round_up(ph.vaddr as usize + ph.memsz as usize, mega);
        let file_start = ph.vaddr as usize;
        let file_end = file_start + ph.filesz as usize;

        let mut v = seg_start;
        while v < seg_end {
            let idx = megapage_vaddr[..megapage_count]
                .iter()
                .position(|&mv| mv == v)
                .expect("every segment megapage was recorded in pass 1");
            let paddr = megapage_paddr[idx];

            // Copy only the file bytes that actually land within this step's
            // byte range; anything outside `[file_start, file_end)` (BSS, or
            // simply a step this segment's `filesz` doesn't reach) is left as
            // the Frame's own zeroed-on-retype contents.
            let step_end = v + mega;
            let copy_start = v.max(file_start);
            let copy_end = step_end.min(file_end);
            if copy_start < copy_end {
                let within_frame = copy_start - v;
                let file_offset = ph.offset as usize + (copy_start - file_start);
                // SAFETY: `paddr` names a Frame retyped in pass 2 above,
                // exclusively owned by this launcher and zeroed on retype
                // (`Untyped::bump`'s "no reclaim" guarantee) — identity-mapped
                // in *this* (the launcher's own) address space, since it came
                // from the shared kernel megapage's identity-mapped range.
                // Two segments sharing a megapage write disjoint byte ranges
                // within it (their own `[file_start, file_end)`), never the
                // same bytes twice.
                unsafe {
                    let dst = (paddr + within_frame) as *mut u8;
                    let src = &spec.elf_bytes[file_offset..file_offset + (copy_end - copy_start)];
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                }
            }
            v += mega;
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
    if let Some(arena) = &spec.arena {
        // The program's own VSpace, so it can invoke `FrameInvoke::Map`/
        // `Unmap` naming itself — same "source doesn't exist until partway
        // through `load`... CopyCross" reasoning as `self_cnode_dest` just
        // above, just sourced from `vspace_cptr` instead of `cnode_cptr`.
        copy_cross(state, root, SELF_CNODE_CPTR, vspace_cptr, cnode_cptr, arena.self_vspace_dest);
        for i in 0..arena.megapages {
            let frame_cptr = *next_slot;
            *next_slot += 1;
            let Capability::Frame { .. } = retype(state, root, untyped_cptr, ObjectType::FrameMega, frame_cptr) else {
                panic!("expected a Frame capability");
            };
            // Deliberately no `map` call here — granted unmapped; the
            // program itself decides when/where within `ARENA_VADDR` to map
            // each one (see the module doc).
            copy_cross(state, root, SELF_CNODE_CPTR, frame_cptr, cnode_cptr, arena.frame_dest_base + i);
        }
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

    LoadedProgram { tcb: tcb_id, vspace_cptr }
}

/// The actual "N programs, data-driven" entry point: loads every spec in
/// `specs`, in order, via [`load`], returning each resulting [`LoadedProgram`]
/// in the same order. `N` is fixed at compile time (this crate has no
/// allocator) — callers destructure the result with a matching-length array
/// pattern, e.g.
/// `let [server, client] = load_all(state, root, untyped_cptr, &specs, &mut next_slot);`.
pub fn load_all<const N: usize>(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    specs: &[ProgramSpec; N],
    next_slot: &mut CPtr,
) -> [LoadedProgram; N] {
    let mut out = [LoadedProgram { tcb: TcbId(0), vspace_cptr: 0 }; N];
    for (slot, spec) in out.iter_mut().zip(specs.iter()) {
        *slot = load(state, root, untyped_cptr, spec, next_slot);
    }
    out
}

/// ADR-0022 Part 2: retypes one 4 KiB `Frame` and maps it read/write into
/// both `(vspace_a, vaddr_a)` and `(vspace_b, vaddr_b)` — the RFC-0019 shared
/// `(runtime, service)` channel. Neither loaded program receives a capability
/// to the Frame itself (see the module doc); each just gets a live mapping at
/// its own chosen virtual address, exactly like its stack. Panics on failure,
/// same trust tier as [`load`] — this runs before either program's first
/// instruction, with root's full privilege.
/// `#[allow(dead_code)]`: this module is compiled fresh into each binary
/// that shares it via `#[path]` (see [`mint`]'s identical note) — only
/// `frame_demo/loader.rs` calls this today.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn map_shared_frame(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    vspace_a: CPtr,
    vaddr_a: usize,
    vspace_b: CPtr,
    vaddr_b: usize,
    next_slot: &mut CPtr,
) {
    let frame_cptr = *next_slot;
    *next_slot += 1;
    let Capability::Frame { .. } = retype(state, root, untyped_cptr, ObjectType::FrameSmall, frame_cptr) else {
        panic!("expected a Frame capability");
    };
    map(state, root, frame_cptr, vspace_a, vaddr_a, PERM_R | PERM_W | PERM_U);
    map(state, root, frame_cptr, vspace_b, vaddr_b, PERM_R | PERM_W | PERM_U);
}
