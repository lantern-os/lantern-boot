//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s keystore demo
//! (`../src/keystore_demo/loader.rs`).
//!
//! Plays the client half of the confined
//! [`lantern_crypto::Keystore`] demo — a stand-in for a real
//! `lantern-runtime` reaching a keystore-service, using exactly the wire
//! codecs `lantern_crypto::wire` already exposes (`encode_encrypt_request`/
//! `decode_encrypt_reply`/etc.), not a hand-rolled duplicate of them.
//!
//! 1. `Call`s `../keystore-service/`, registering `DEST_CPTR` as its
//!    reply-leg destination (`broker-client`'s exact convention) — the
//!    keystore-service mints and hands back a badged capability scoped to
//!    ENCRYPT|DECRYPT on its one demo key.
//! 2. Uses that granted capability to `Channel::call` an ENCRYPT, then a
//!    DECRYPT, over the shared `Frame` — a real round trip through a
//!    confined keystore, not an in-process call.
//! 3. Independently verifies the decrypted result matches what it encrypted
//!    (the real proof, same shape as `frame-client`'s bitwise-NOT check) and
//!    signals one of two distinguishable notifications.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel};
use lantern_abi::sys;
use lantern_crypto::aead::NONCE_LEN;
use lantern_crypto::wire;

lantern_abi::entry!(run);

/// The endpoint this program and `keystore-service` both hold a capability
/// to.
const ENDPOINT_CPTR: usize = 1;
/// Where the keystore-service's granted, badged capability lands.
const DEST_CPTR: usize = 2;
/// Signalled iff the ENCRYPT→DECRYPT round trip matched what this client
/// itself encrypted.
const SUCCESS_CPTR: usize = 3;
/// Signalled otherwise, so a mismatch is an observable, differentiated
/// outcome rather than silence.
const FAILURE_CPTR: usize = 4;
/// Where the loader mapped this program's half of the shared `Frame` — must
/// match `keystore-service`'s own constant.
const FRAME_VADDR: usize = 0x9000_0000;

const PLAINTEXT: &[u8] = b"a confined keystore secret";

fn run(_arg0: usize) -> ! {
    // Phase 1: ask for access, registering DEST_CPTR as the reply-leg
    // destination for the badged capability the keystore-service grants.
    let _ = sys::call_with_reply_slot(ENDPOINT_CPTR, DEST_CPTR, [0, 0]);

    // Phase 2: use the granted, badged capability to reach the same
    // keystore-service over the RFC-0019 wire protocol.
    //
    // SAFETY: the loader mapped `FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran.
    let mut channel = unsafe { Channel::new(DEST_CPTR, FRAME_VADDR as *mut u8) };

    let matched = round_trip(&mut channel).unwrap_or(false);
    let _ = sys::signal(if matched { SUCCESS_CPTR } else { FAILURE_CPTR });

    loop {
        core::hint::spin_loop();
    }
}

/// ENCRYPTs [`PLAINTEXT`], then DECRYPTs the result back, both through the
/// confined keystore-service — `None` on any wire-level error (a malformed
/// buffer, a `Channel` failure); `Some(false)` on a clean but mismatched
/// round trip.
fn round_trip(channel: &mut Channel) -> Option<bool> {
    let nonce = [6u8; NONCE_LEN];
    let aad = b"keystore-demo";

    let mut encrypt_request = [0u8; 128];
    let req_len = wire::encode_encrypt_request(&nonce, aad, PLAINTEXT, &mut encrypt_request)?;

    let mut encrypt_reply = [0u8; 128];
    let (enc_status, enc_len) = channel.call(wire::OP_ENCRYPT, &encrypt_request[..req_len], &mut encrypt_reply).ok()?;
    if enc_status != status::OK {
        return Some(false);
    }
    let (tag, ciphertext) = wire::decode_encrypt_reply(&encrypt_reply[..enc_len])?;
    if ciphertext == PLAINTEXT {
        return Some(false); // real encryption must have changed the bytes
    }

    let mut decrypt_request = [0u8; 128];
    let req_len = wire::encode_decrypt_request(&nonce, aad, &tag, ciphertext, &mut decrypt_request)?;

    let mut decrypt_reply = [0u8; 128];
    let (dec_status, dec_len) = channel.call(wire::OP_DECRYPT, &decrypt_request[..req_len], &mut decrypt_reply).ok()?;
    if dec_status != status::OK {
        return Some(false);
    }
    let decrypted = wire::decode_decrypt_reply(&decrypt_reply[..dec_len]);

    Some(decrypted == PLAINTEXT)
}
