//! A minimal ELF loader — [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md).
//! Replaces the earlier `demo.rs`, which compiled both demo threads' bodies
//! directly into `lantern-boot` and wired their capabilities together by hand —
//! this loads a genuinely separate, independently built riscv64 binary
//! (`hello-service/`, embedded via `include_bytes!`), parsed with [`crate::elf`],
//! into two mutually confined programs, granting each only the one capability it
//! actually needs.
//!
//! **This is the "root task"** RFC-0002's narrowing waterfall describes: it
//! starts with (nearly) unlimited authority — one big memory-backed `Untyped`,
//! seeded from `pmm`'s hardcoded physical-memory facts — and spends it
//! explicitly, retyping and mapping through `lantern-kernel`'s *real*,
//! capability-checked `admin`/`frame` functions (not a raw `ecall`: this runs
//! before any thread exists to trap from, so it calls them directly, the same
//! way `demo.rs`'s old `spawn` called kernel functions directly — but *these*
//! calls go through the actual capability checks a real syscall would, unlike
//! the old direct-field-poke `Tcb.address_space` approach RFC-0008 retired).
//!
//! **What's still a direct pool poke, not a capability invocation:** placing the
//! shared endpoint capability into each loaded program's own CSpace.
//! `CNodeInvoke`'s `Copy`/`Move` only operate on slots *within a single CNode*
//! (`cnode.rs`'s own module doc) — there is no cross-CNode transfer primitive
//! yet, a pre-existing Phase 1 gap RFC-0008 didn't touch. Matches `demo.rs`'s
//! old approach for exactly this one step; everything RFC-0008 actually
//! introduced (VSpace/Frame retype, `FrameInvoke::Map`, `TCBConfigure`'s VSpace
//! argument) goes through the real thing.
//!
//! **Per-segment memory is never identity-mapped** — a real, and until this
//! session unexamined, consequence of loading two *separate* programs at the
//! *same* linked virtual address (`hello-service/linker.ld`'s fixed
//! `BASE_ADDRESS`): they cannot both physically live there. Each segment's
//! `Frame` gets whatever physical page the source `Untyped` bump-allocates next
//! (wherever that is), and `FrameInvoke::Map` places it at the *virtual* address
//! the ELF actually asked for — genuine virtual memory, not the
//! paddr-always-equals-vaddr convention this crate's *own* kernel-image mapping
//! still uses (that convention was only ever true for a single, uniquely-placed
//! shared mapping, never a hard requirement of the mapping mechanism itself).

use lantern_hal::TrapFrame;
use lantern_kernel::admin;
use lantern_kernel::cap::{
    Capability, CNode, CNodeId, CPtr, EndpointId, ObjectType, Rights, TcbId, UntypedId, VSpaceId,
};
use lantern_kernel::frame::{self as frame_invoke, LABEL_MAP};
use lantern_kernel::object::{Endpoint, SavedContext, Tcb, Untyped};
use lantern_kernel::state::KernelState;

use crate::elf;
use crate::pmm;

/// The standalone hello-service binary's own compiled bytes — see
/// `hello-service/src/main.rs`'s module doc for what it does and why this is a
/// real, independent ELF load rather than a repeat of the old `demo.rs`.
/// Rebuild with `cd hello-service && cargo build --release`, then copy
/// `target/riscv64gc-unknown-none-elf/release/lantern-hello-service` to
/// `assets/hello-service.elf` (checked in rather than built automatically —
/// `STATUS.md` has the full reasoning).
const HELLO_SERVICE_ELF: &[u8] = include_bytes!("../assets/hello-service.elf");

/// The endpoint capability's slot in each loaded program's own CSpace — matches
/// `hello-service/src/main.rs`'s own `ENDPOINT_CPTR` constant by convention
/// (neither side reads the other's source; this is the ABI between them).
const ENDPOINT_CPTR: CPtr = 1;

/// Where each loaded program's stack gets mapped — arbitrary, just required not
/// to collide with `hello-service/linker.ld`'s own `BASE_ADDRESS`
/// (`0x8400_0000`) plus its one megapage of headroom.
const STACK_VADDR: usize = 0x8600_0000;

/// `arg0` values `hello-service/src/main.rs` dispatches on.
const ARG0_SERVER: usize = 0;
const ARG0_CLIENT: usize = 1;

/// Retypes one object from `untyped_cptr` (in `root`'s own CSpace, per
/// `admin::untyped_retype`'s contract) into `root`'s CSpace at `dest`, and
/// returns the resulting capability. Panics on failure — this is trusted,
/// privileged boot-time setup with a hardcoded, generously sized budget/memory
/// range (`pmm::GENERAL_MEMORY_BASE`/`GENERAL_MEMORY_END`); a failure here is a
/// configuration bug worth an immediate, loud failure, not a silently
/// misconfigured system (ADR-0008's "no syscall panics" rule governs real
/// syscalls reachable from unprivileged code, not this).
fn retype(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    object_type: ObjectType,
    dest: CPtr,
) -> Capability {
    let mut frame = TrapFrame::zeroed();
    frame.set_mr(1, object_type as usize);
    frame.set_mr(2, dest);
    admin::untyped_retype(state, root, untyped_cptr, &mut frame).expect("loader retype must succeed");
    let cspace = state.tcbs.get(root.0 as usize).unwrap().cspace.unwrap();
    state.cnodes.get(cspace.0 as usize).unwrap().get(dest).unwrap()
}

/// Where OpenSBI loads/enters this image (`linker.ld`'s `BASE_ADDRESS`) — the
/// one megapage every loaded program's VSpace needs mapped, S-mode-only, for
/// the trap vector/kernel dispatch/`sret` cold-start path to keep working once
/// that program's own table is active (RISC-V traps don't switch page tables —
/// `linker.ld`'s module doc has the full story).
const KERNEL_MEGAPAGE_BASE: usize = 0x8020_0000;

const UART_MEGAPAGE_BASE: usize = 0x1000_0000;

/// Maps [`KERNEL_MEGAPAGE_BASE`] and the UART megapage into `vspace_id`'s root
/// table, S-mode-only (no `USER` flag) — **not** through `FrameInvoke::Map`:
/// these aren't retyped `Frame` objects (a `Frame` has at most one mapping,
/// `lantern-kernel/src/object.rs`'s doc — but *every* loaded program's VSpace
/// needs this one mapped, by design), and `lantern-kernel` itself has no
/// business knowing `lantern-boot`'s own kernel-image layout (per
/// `lantern-kernel/ARCHITECTURE.md`'s HAL-seam discipline, ISA/image-layout
/// specifics stay out of the portable core). This is boot-privileged code doing
/// something only it — the thing that built and knows the layout of its own
/// kernel image — can correctly do, the same category of trusted-caller
/// responsibility `Hal::activate_address_space`'s own safety contract already
/// places on whoever builds a table ("must map the code currently executing").
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
        // Pre-allocate the one page `map_megapage` might need for a fresh L1
        // table, same reasoning as `lantern_kernel::frame::map`'s identical
        // pattern (its own doc comment has the full explanation).
        let spare = state
            .untypeds
            .get_mut(untyped_id.0 as usize)
            .unwrap()
            .bump(lantern_hal::RISCV64_PAGE_SIZE, lantern_hal::RISCV64_PAGE_SIZE)
            .expect("loader's own Untyped must have room for kernel-shared L1 tables");
        let mut alloc = move || spare;
        // SAFETY: `vspace_root` is this VSpace's own freshly built, exclusively
        // owned root table; `vaddr`/`paddr` are megapage-aligned machine
        // constants.
        unsafe { lantern_hal::riscv64_map_megapage(vspace_root, vaddr, paddr, flags, &mut alloc) };
    }
}

/// Maps `frame_cptr` (in `root`'s CSpace) into `vspace_cptr`'s (also `root`'s
/// CSpace) VSpace at `vaddr`, with `perms` (see
/// `lantern_kernel::frame::PermFlags`'s doc — read/write/execute/user bits).
fn map(
    state: &mut KernelState,
    root: TcbId,
    frame_cptr: CPtr,
    vspace_cptr: CPtr,
    vaddr: usize,
    perms: usize,
) {
    let mut invoke_frame = TrapFrame::zeroed();
    invoke_frame.set_tag(lantern_hal::MessageTag { label: LABEL_MAP, length: 0, extra_caps: 0, flags: 0 });
    invoke_frame.set_mr(1, vspace_cptr);
    invoke_frame.set_mr(2, vaddr);
    invoke_frame.set_mr(3, perms);
    frame_invoke::invoke(state, root, frame_cptr, &mut invoke_frame).expect("loader map must succeed");
}

/// Permission bits for [`map`] — see `lantern_kernel::frame`'s `PermFlags`
/// (private to that crate; duplicated here as the same small, documented
/// kernel-internal convention `crate::abi`'s general mr0-is-CPtr note doesn't
/// cover, matching how that module itself documents it).
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

/// Loads `elf_bytes` into a fresh VSpace and TCB, granting `endpoint` at
/// [`ENDPOINT_CPTR`] and nothing else, then admits it to the scheduler.
/// `root`/`untyped_cptr` are the loader's own privileged identity (see the
/// module doc); `next_slot` hands out fresh CSpace slots in `root`'s own
/// CNode for this program's retyped objects (VSpace/Frames/CNode/Tcb/
/// SchedContext all transiently live there — see the module doc's "still a
/// direct pool poke" note for why the endpoint alone needs different handling).
#[allow(clippy::too_many_arguments)]
fn load(
    state: &mut KernelState,
    root: TcbId,
    untyped_cptr: CPtr,
    elf_bytes: &[u8],
    arg0: usize,
    endpoint: Capability,
    next_slot: &mut CPtr,
) -> TcbId {
    let header = elf::parse_header(elf_bytes).expect("hello-service.elf must parse");

    let vspace_cptr = *next_slot;
    *next_slot += 1;
    let Capability::VSpace { id: vspace_id, .. } =
        retype(state, root, untyped_cptr, ObjectType::VSpace, vspace_cptr)
    else {
        panic!("expected a VSpace capability");
    };
    map_kernel_shared(state, root, untyped_cptr, vspace_id);

    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(elf_bytes, &header, i).expect("hello-service.elf program header") else {
            continue; // A harmless-to-skip segment type (elf.rs's module doc).
        };
        let seg_start = round_down(ph.vaddr as usize, lantern_hal::RISCV64_MEGAPAGE_SIZE);
        let seg_end = round_up(ph.vaddr as usize + ph.memsz as usize, lantern_hal::RISCV64_MEGAPAGE_SIZE);
        assert_eq!(
            seg_end - seg_start,
            lantern_hal::RISCV64_MEGAPAGE_SIZE,
            "hello-service.elf segment spans more than one megapage -- loader.rs only handles one Frame per segment"
        );

        let frame_cptr = *next_slot;
        *next_slot += 1;
        let Capability::Frame { id: frame_id, .. } =
            retype(state, root, untyped_cptr, ObjectType::FrameMega, frame_cptr)
        else {
            panic!("expected a Frame capability");
        };
        let paddr = state.frames.get(frame_id.0 as usize).unwrap().paddr;

        // Copy this segment's file bytes into the Frame at the right offset
        // within it (the segment's vaddr may not start exactly at `seg_start`),
        // zero-filling the memsz-filesz BSS tail and anything else in the Frame
        // this segment doesn't cover.
        let within_frame = ph.vaddr as usize - seg_start;
        // SAFETY: `paddr` is this thread's own freshly retyped, exclusively
        // owned, zeroed Frame (per `Untyped::bump`'s "no reclaim" guarantee) —
        // identity-mapped in *this* (the loader's own) address space, since it
        // came from `pmm::GENERAL_MEMORY_BASE`'s range, which is part of the
        // shared kernel megapage's identity mapping.
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
    let Capability::CNode(cnode_id) = retype(state, root, untyped_cptr, ObjectType::CNode, cnode_cptr) else {
        panic!("expected a CNode capability");
    };
    // Direct pool write for the endpoint capability -- see the module doc.
    *state.cnodes.get_mut(cnode_id.0 as usize).unwrap().slot_mut(ENDPOINT_CPTR).unwrap() = endpoint;

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

/// Sets up the loader's own privileged root identity (one CNode, one TCB never
/// actually scheduled, one memory-backed Untyped spanning
/// `pmm::GENERAL_MEMORY_BASE..GENERAL_MEMORY_END`), loads the hello-service ELF
/// twice (server, then client — see the module doc), grants the shared endpoint
/// to each, and cold-starts the client. Never returns.
///
/// # Safety
/// Must be called at most once, before any trap has occurred (this crate's boot
/// code has exclusive access to kernel state at that point).
pub unsafe fn run() -> ! {
    // SAFETY: forwarded from this function's own contract.
    let state = unsafe { lantern_kernel::state::kernel_state() };

    let root_cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    let root = TcbId(state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted") as u16);
    state.tcbs.get_mut(root.0 as usize).unwrap().cspace = Some(CNodeId(root_cnode_idx as u16));

    let untyped = Untyped::with_memory(
        1000,
        pmm::GENERAL_MEMORY_BASE,
        pmm::GENERAL_MEMORY_END - pmm::GENERAL_MEMORY_BASE,
    );
    let untyped_idx = state.untypeds.alloc(untyped).expect("untyped pool exhausted");
    let untyped_cptr: CPtr = 1;
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
        Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };

    let ep_idx = state.endpoints.alloc(Endpoint::new()).expect("endpoint pool exhausted");
    let endpoint =
        Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 42, rights: Rights::ALL };

    let mut next_slot: CPtr = 2; // slot 1 is `untyped_cptr`.
    let server =
        load(state, root, untyped_cptr, HELLO_SERVICE_ELF, ARG0_SERVER, endpoint, &mut next_slot);
    let client =
        load(state, root, untyped_cptr, HELLO_SERVICE_ELF, ARG0_CLIENT, endpoint, &mut next_slot);
    state.make_ready(server);

    crate::println!("boot: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and address
    // space were both fully populated by `load` above.
    unsafe { lantern_kernel::enter_first_thread(client) }
}
