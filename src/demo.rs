//! A minimal two-thread "hello service" demo (RFC-0004's Phase 1 exit criterion):
//! a client thread `Call`s a server thread over an endpoint, the server doubles
//! the payload and `Reply`s. Proves the full syscall/IPC pipeline (`lantern-hal`
//! trap entry -> `lantern-kernel` dispatch -> trap exit) end to end, for real,
//! under QEMU — not just against a unit test's fabricated `TrapFrame`. `main.rs`'s
//! `boot_trap_handler` prints what's happening on each trap (see its doc) —
//! *not* the thread bodies themselves, which run in real U-mode and so can't
//! reach `println!`'s machinery (S-mode-only; see below).
//!
//! Each thread now runs under its own Sv39 page table in real U-mode (see
//! `paging.rs`) — a genuine step toward RFC-0004's "confined hello service," not
//! yet the finish line: the shared *kernel* code is still mapped identically in
//! both tables (no separate user-program loading mechanism exists yet to keep it
//! out). What *is* real: each thread's own stack is private to its own table,
//! and — new in this revision — [`client_thread`]/[`server_thread`] themselves
//! (plus [`syscall`]/[`empty_tag`]) live in the `.user_text` linker section
//! (`linker.ld`), the *only* range `paging.rs` maps with Sv39's U bit set.
//! Everything else (the trap vector, `lantern-kernel`'s dispatch,
//! `activate_address_space`'s `csrw satp`/`sfence.vma`/`sret` cold-start path)
//! stays S-mode-only, on purpose: RISC-V never allows S-mode to *fetch*
//! instructions from a U-accessible page (loads/stores can be permitted via
//! `sstatus.SUM`; fetches can't, unconditionally) — mapping the *whole* kernel
//! image U-accessible, as an earlier revision of this file did, made every
//! instruction fetch after activating a thread's table fault immediately,
//! including the trap vector's own entry (a real bug this session hit and
//! root-caused under real QEMU, not caught by any unit test). See `paging.rs`'s
//! module doc for the full mapping picture.

use core::arch::asm;

use lantern_hal::MessageTag;
use lantern_kernel::cap::{CNode, CNodeId, Capability, CPtr, EndpointId, Rights, TcbId};
use lantern_kernel::object::{Endpoint, SavedContext, Tcb};
use lantern_kernel::syscall::SyscallNumber;

use crate::{paging, pmm};

/// The endpoint capability's slot — slot 1 in both threads' own (separate)
/// CSpaces; slot 0 is left free by convention (matching `lantern-kernel`'s
/// `cnode.rs` tests, which reserve slot 0 for a self-CNode capability threads
/// administering their own CSpace would need — unused by this demo, but keeping
/// the same convention avoids a trap for anyone extending it later).
const ENDPOINT_CPTR: CPtr = 1;

/// Issues a Phase 1 syscall directly via `ecall`, per `lantern-hal`'s riscv64
/// register mapping (`a0..a3` = `mr0..mr3`, `a4` = tag, `a7` = syscall number,
/// `riscv64.rs`) and `lantern-kernel`'s mr0-is-CPtr convention (`src/abi.rs`).
///
/// Lives in `.user_text` (see the module doc) — only called from the real
/// U-mode thread bodies below.
///
/// # Safety
/// Caller upholds whatever precondition the syscall itself has (a valid `cptr` for
/// operations that need one).
#[unsafe(link_section = ".user_text")]
unsafe fn syscall(
    num: SyscallNumber,
    cptr: usize,
    mr1: usize,
    mr2: usize,
    mr3: usize,
    tag: MessageTag,
) -> (usize, usize, usize, usize, MessageTag) {
    let (r0, r1, r2, r3, rtag_raw): (usize, usize, usize, usize, usize);
    // SAFETY: forwarded from this function's own contract; the register mapping
    // matches `lantern-hal`'s riscv64 trap trampoline exactly.
    unsafe {
        asm!(
            "ecall",
            inout("a0") cptr => r0,
            inout("a1") mr1 => r1,
            inout("a2") mr2 => r2,
            inout("a3") mr3 => r3,
            inout("a4") tag.into_raw() => rtag_raw,
            in("a7") num as usize,
            options(nostack),
        );
    }
    (r0, r1, r2, r3, MessageTag::from_raw(rtag_raw))
}

#[unsafe(link_section = ".user_text")]
fn empty_tag() -> MessageTag {
    MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 }
}

/// Real U-mode code (see the module doc) — no `println!`: `core::fmt`'s
/// machinery and the UART driver are S-mode-only (`.text`, not `.user_text`),
/// and U-mode can no more fetch from a non-U page than S-mode can fetch from a
/// U one. `main.rs`'s `boot_trap_handler` narrates what each syscall did
/// instead, from S-mode, where it's free to print.
#[unsafe(link_section = ".user_text")]
extern "C" fn client_thread(_arg: usize) -> ! {
    let (_r0, _reply, _r2, _r3, _tag) =
        unsafe { syscall(SyscallNumber::Call, ENDPOINT_CPTR, 21, 0, 0, empty_tag()) };
    loop {
        // Not `wfi`: it crashes here (QEMU logs "Invalid opcode for CSR
        // read/write instruction" shortly after) — confirmed by swapping it for
        // this busy-loop and watching the crash disappear. Not fully root-caused
        // (plausibly `sstatus.SIE` ending up enabled after our first `sret`, an
        // OpenSBI timer interrupt then firing into a trap handler that has no
        // interrupt/timer support to do anything with it — but that's a
        // hypothesis, not confirmed). Moot either way: Phase 1 has no
        // interrupt/timer handling yet (`lantern-hal/STATUS.md`), so `wfi` would
        // be premature here even if it worked.
        core::hint::spin_loop();
    }
}

/// Real U-mode code — see [`client_thread`]'s doc for why there's no `println!`.
#[unsafe(link_section = ".user_text")]
extern "C" fn server_thread(_arg: usize) -> ! {
    let (_r0, request, _r2, _r3, _tag) =
        unsafe { syscall(SyscallNumber::Recv, ENDPOINT_CPTR, 0, 0, 0, empty_tag()) };

    let reply_value = request * 2;
    // Reply takes no explicit CPtr (see `abi.rs`); `cptr` here is unused.
    let _ = unsafe { syscall(SyscallNumber::Reply, 0, reply_value, 0, 0, empty_tag()) };

    loop {
        // Not `wfi` — see `client_thread`'s identical loop for why.
        core::hint::spin_loop();
    }
}

/// Allocates a private, megapage-sized stack region (see `paging.rs`'s module
/// doc for why a whole 2 MiB, not 4 KiB) and a page table mapping the shared
/// kernel image plus that region, then configures a fresh TCB to run `entry`
/// under it.
fn spawn(
    state: &mut lantern_kernel::state::KernelState,
    entry: extern "C" fn(usize) -> !,
    endpoint: Capability,
) -> TcbId {
    let cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(ENDPOINT_CPTR).unwrap() = endpoint;

    let stack_base = pmm::alloc_stack_region();
    let stack_top = stack_base + lantern_hal::RISCV64_MEGAPAGE_SIZE;
    let address_space = paging::build_table(stack_base);

    let tcb_idx = state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted");
    let id = TcbId(tcb_idx as u16);
    let tcb = state.tcbs.get_mut(tcb_idx).unwrap();
    tcb.cspace = Some(CNodeId(cnode_idx as u16));
    // Two-step cast avoids `function_casts_as_integer`: coerce to a function
    // pointer first, then take its address.
    let pc = (entry as *const ()) as usize;
    crate::println!("spawn: entry pc={pc:#x} stack_base={stack_base:#x} address_space={address_space:#x}");
    tcb.context = SavedContext::initial(pc, stack_top, 0);
    tcb.address_space = Some(address_space);
    id
}

/// Sets up the client/server threads (each under its own page table and address
/// space) and capabilities, then cold-starts the client — never returns.
///
/// # Safety
/// Must be called at most once, before any trap has occurred (this crate's boot
/// code has exclusive access to kernel state at that point).
pub unsafe fn run() -> ! {
    // SAFETY: forwarded from this function's own contract.
    let state = unsafe { lantern_kernel::state::kernel_state() };

    let ep_idx = state.endpoints.alloc(Endpoint::new()).expect("endpoint pool exhausted");
    let endpoint =
        Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 42, rights: Rights::ALL };

    let client = spawn(state, client_thread, endpoint);
    let server = spawn(state, server_thread, endpoint);
    state.make_ready(server);

    crate::println!("boot: entering client thread (own page table, U-mode)");
    // SAFETY: first and only call on this hart; the client's context and address
    // space were both just fully populated above.
    unsafe { lantern_kernel::enter_first_thread(client) }
}
