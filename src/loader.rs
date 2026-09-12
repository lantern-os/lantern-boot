//! Boots the two-thread "hello service" IPC-latency demo —
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md).
//! The actual "take an ELF, build it a VSpace/CNode/Tcb, wire in its
//! capabilities" work now lives in [`crate::launch`] — this file just does
//! this demo's own bootstrap (root's founding identity, the one shared
//! endpoint both programs need) and builds the two-entry launch description.
//!
//! **This is the "root task"** RFC-0002's narrowing waterfall describes: it
//! starts with (nearly) unlimited authority — one big memory-backed
//! `Untyped`, seeded from `pmm`'s hardcoded physical-memory facts — and
//! spends it explicitly, retyping and mapping through `lantern-kernel`'s
//! *real*, capability-checked `admin`/`frame` functions (not a raw `ecall`:
//! this runs before any thread exists to trap from, so it calls them
//! directly, the same way the old `demo.rs`'s `spawn` called kernel functions
//! directly — but *these* calls go through the actual capability checks a
//! real syscall would).
//!
//! Root needs a capability to its own CNode to use `CopyCross`
//! ([`crate::launch::SELF_CNODE_CPTR`]), seeded by the one remaining direct
//! pool write left in this file: root's own founding identity, which — like
//! its Untyped and TCB below — necessarily precedes any capability mechanism
//! that could grant it one instead.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
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

/// `arg0` values `hello-service/src/main.rs` dispatches on.
const ARG0_SERVER: usize = 0;
const ARG0_CLIENT: usize = 1;

/// Sets up the loader's own privileged root identity (one CNode, one TCB never
/// actually scheduled, one memory-backed Untyped spanning
/// `pmm::GENERAL_MEMORY_BASE..mem_end`), loads the hello-service ELF twice
/// (server, then client), grants the shared endpoint to each, and cold-starts
/// the client. Never returns.
///
/// `mem_end` is the end of usable RAM — from `src/fdt.rs`'s device-tree read
/// (`boot_main`), or `pmm::GENERAL_MEMORY_END` if the tree was unreadable.
///
/// # Safety
/// Must be called at most once, before any trap has occurred (this crate's boot
/// code has exclusive access to kernel state at that point).
pub unsafe fn run(mem_end: usize) -> ! {
    // SAFETY: forwarded from this function's own contract.
    let state = unsafe { lantern_kernel::state::kernel_state() };

    let root_cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    let root = TcbId(state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted") as u16);
    state.tcbs.get_mut(root.0 as usize).unwrap().cspace = Some(CNodeId(root_cnode_idx as u16));

    // Root's own founding identity: a capability to its own CNode (so it can
    // administer itself via real CNodeInvoke calls — see SELF_CNODE_CPTR's
    // doc), and a memory-backed Untyped to retype everything else from. Both
    // are direct pool writes, unavoidably — nothing capability-mediated could
    // have granted root its very first capabilities either (the module doc's
    // "necessarily precedes any capability mechanism" note).
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(SELF_CNODE_CPTR).unwrap() =
        Capability::CNode(CNodeId(root_cnode_idx as u16));

    // Clamp defensively: `mem_end` must be above the fixed low boundary and
    // megapage-aligned down (`Untyped::with_memory`'s range requirement).
    let mem_end = mem_end.max(pmm::GENERAL_MEMORY_BASE + lantern_hal::RISCV64_MEGAPAGE_SIZE)
        & !(lantern_hal::RISCV64_MEGAPAGE_SIZE - 1);
    let untyped = Untyped::with_memory(1000, pmm::GENERAL_MEMORY_BASE, mem_end - pmm::GENERAL_MEMORY_BASE);
    let untyped_idx = state.untypeds.alloc(untyped).expect("untyped pool exhausted");
    let untyped_cptr: CPtr = 1;
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
        Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };

    let mut next_slot: CPtr = 2; // slot 0 is SELF_CNODE_CPTR, slot 1 is `untyped_cptr`.

    // A real, retyped Endpoint capability -- not a manually constructed value
    // -- minted into a second, badged slot for this demo's own bookkeeping
    // (the badge is never actually checked by anything on the receiving side,
    // see `hello-service`'s own source, but a nonzero badge is more honest
    // than the plain retype's default of 0).
    let endpoint_plain_cptr = next_slot;
    next_slot += 1;
    launch::retype(state, root, untyped_cptr, ObjectType::Endpoint, endpoint_plain_cptr);
    let endpoint_badged_cptr = next_slot;
    next_slot += 1;
    launch::mint(state, root, endpoint_plain_cptr, endpoint_badged_cptr, Rights::ALL, 42);

    let specs = [
        ProgramSpec {
            elf_bytes: HELLO_SERVICE_ELF,
            arg0: ARG0_SERVER,
            grants: &[(endpoint_badged_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
        ProgramSpec {
            elf_bytes: HELLO_SERVICE_ELF,
            arg0: ARG0_CLIENT,
            grants: &[(endpoint_badged_cptr, ENDPOINT_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
        },
    ];
    let [server, client] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    state.make_ready(server.tcb);

    crate::println!("boot: entering client (loaded ELF, own VSpace, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and address
    // space were both fully populated by `launch::load_all` above.
    unsafe { lantern_kernel::enter_first_thread(client.tcb) }
}
