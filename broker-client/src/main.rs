//! A minimal, genuinely standalone riscv64 ELF binary — **not** part of
//! `lantern-boot`'s own build, not linked against `lantern-hal`/`lantern-kernel`
//! at all. Loaded from its own independently compiled bytes by
//! `lantern-boot`'s broker demo (`../src/broker_demo/loader.rs`).
//!
//! Plays the **client** half of [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
//! confined-capability-broker demo: `Call`s `../broker-service/`, registering
//! its own destination slot for a capability the `Reply` might attach
//! (`tag.extra_caps == 2` — `lantern_kernel::ipc::call`'s reply-leg
//! convention), then — the actual proof this is a *real*, functional
//! capability and not just bytes that landed in a CSpace slot — invokes
//! `Signal` on it. A forged or empty slot would fail that `Signal` with
//! `InvalidCapability`; only a genuinely transferred, `WRITE`-rights
//! `Notification` capability succeeds.
//!
//! Issues raw `ecall`s directly, same convention and same reasoning as
//! `hello-service`/`broker-service`'s own module docs.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// The endpoint this program and `broker-service` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// Where this program registers the granted capability should land — its own
/// choice, unrelated to `broker-service`'s own `SCRATCH_CPTR`/`RESOURCE_CPTR`
/// numbering (different CSpaces).
const DEST_CPTR: usize = 2;

const SYSCALL_CALL: usize = 4;
const SYSCALL_SIGNAL: usize = 6;

/// Packs a `lantern_hal::MessageTag` the same way `broker-service`'s own
/// helper does (see its module doc) — `label`/`length`/`flags` always `0`
/// here, only `extra_caps` ever varies.
const fn pack_tag(extra_caps: u8) -> usize {
    ((extra_caps & 0xF) as usize) << 16
}

/// # Safety
/// Caller upholds whatever precondition the syscall itself has.
unsafe fn syscall(num: usize, a0: usize, a1: usize, a2: usize, a3: usize, tag: usize) {
    // SAFETY: forwarded from this function's own contract; register mapping
    // matches `lantern-hal`'s riscv64 trap trampoline exactly.
    unsafe {
        asm!(
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") tag,
            in("a7") num,
            options(nostack),
        );
    }
}

#[unsafe(no_mangle)]
extern "C" fn _start(_arg0: usize) -> ! {
    // Call the broker, registering DEST_CPTR as our own reply-leg
    // destination (tag.extra_caps == 2 -- no outbound transfer this call,
    // just "here's where a capability the Reply attaches should land").
    let call_tag = pack_tag(2);
    unsafe { syscall(SYSCALL_CALL, ENDPOINT_CPTR, DEST_CPTR, 0, 0, call_tag) };

    // Prove the granted capability is real and functional, not just bytes
    // that happened to land in DEST_CPTR: Signal it. This only succeeds if
    // DEST_CPTR genuinely holds a WRITE-rights Notification capability --
    // `lantern-boot`'s broker-demo trap handler narrates the real result
    // straight from S-mode as this dispatches (see its own module doc).
    unsafe { syscall(SYSCALL_SIGNAL, DEST_CPTR, 0, 0, 0, 0) };

    loop {
        core::hint::spin_loop();
    }
}
