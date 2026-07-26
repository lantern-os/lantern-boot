//! A minimal two-thread "hello service" demo (RFC-0004's Phase 1 exit criterion):
//! a client thread `Call`s a server thread over an endpoint, the server doubles
//! the payload and `Reply`s, the client prints the result. Proves the full
//! syscall/IPC pipeline (`lantern-hal` trap entry -> `lantern-kernel` dispatch ->
//! trap exit) end to end, for real, under QEMU — not just against a unit test's
//! fabricated `TrapFrame`.
//!
//! Both "threads" run in the same address space at the same privilege level as
//! the kernel itself — Phase 1 has no VSpace/paging yet (`lantern-kernel/STATUS.md`),
//! so there is no real isolation here. This demonstrates the IPC *mechanism*, not
//! yet the confinement RFC-0004's "confined hello service" ultimately calls for.

use core::arch::asm;
use core::cell::UnsafeCell;

use lantern_hal::MessageTag;
use lantern_kernel::cap::{CNode, CNodeId, Capability, CPtr, EndpointId, Rights, TcbId};
use lantern_kernel::object::{Endpoint, SavedContext, Tcb};
use lantern_kernel::syscall::SyscallNumber;

const STACK_SIZE: usize = 4096;

#[repr(align(16))]
struct Stack(UnsafeCell<[u8; STACK_SIZE]>);
// SAFETY: each stack is used by exactly one thread for its whole lifetime; Phase 1
// is single-hart and non-reentrant (ADR-0010), so there's no concurrent access.
unsafe impl Sync for Stack {}

impl Stack {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; STACK_SIZE]))
    }

    fn top(&self) -> usize {
        self.0.get() as usize + STACK_SIZE
    }
}

static CLIENT_STACK: Stack = Stack::new();
static SERVER_STACK: Stack = Stack::new();

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
/// # Safety
/// Caller upholds whatever precondition the syscall itself has (a valid `cptr` for
/// operations that need one).
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

fn empty_tag() -> MessageTag {
    MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 }
}

extern "C" fn client_thread(_arg: usize) -> ! {
    let (_r0, reply, _r2, _r3, tag) =
        unsafe { syscall(SyscallNumber::Call, ENDPOINT_CPTR, 21, 0, 0, empty_tag()) };
    if tag.is_error() {
        crate::println!("client: Call failed, error code {reply}");
    } else {
        crate::println!("client: called with 21, got reply {reply}");
    }
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

extern "C" fn server_thread(_arg: usize) -> ! {
    let (_r0, request, _r2, _r3, _tag) =
        unsafe { syscall(SyscallNumber::Recv, ENDPOINT_CPTR, 0, 0, 0, empty_tag()) };
    crate::println!("server: received {request}");

    let reply_value = request * 2;
    // Reply takes no explicit CPtr (see `abi.rs`); `cptr` here is unused.
    let _ = unsafe { syscall(SyscallNumber::Reply, 0, reply_value, 0, 0, empty_tag()) };
    crate::println!("server: replied with {reply_value}");

    loop {
        // Not `wfi` — see `client_thread`'s identical loop for why.
        core::hint::spin_loop();
    }
}

fn spawn(
    state: &mut lantern_kernel::state::KernelState,
    entry: extern "C" fn(usize) -> !,
    stack: &Stack,
    endpoint: Capability,
) -> TcbId {
    let cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(ENDPOINT_CPTR).unwrap() = endpoint;

    let tcb_idx = state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted");
    let id = TcbId(tcb_idx as u16);
    let tcb = state.tcbs.get_mut(tcb_idx).unwrap();
    tcb.cspace = Some(CNodeId(cnode_idx as u16));
    // Two-step cast avoids `function_casts_as_integer`: coerce to a function
    // pointer first, then take its address.
    let pc = (entry as *const ()) as usize;
    tcb.context = SavedContext::initial(pc, stack.top(), 0);
    id
}

/// Sets up the client/server threads and capabilities, then cold-starts the
/// client — never returns.
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

    let client = spawn(state, client_thread, &CLIENT_STACK, endpoint);
    let server = spawn(state, server_thread, &SERVER_STACK, endpoint);
    state.make_ready(server);

    crate::println!("boot: entering client thread");
    // SAFETY: first and only call on this hart; the client's context was just
    // fully populated above.
    unsafe { lantern_kernel::enter_first_thread(client) }
}
