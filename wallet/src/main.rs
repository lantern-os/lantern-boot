//! `lantern-wallet` — [RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)'s OS wallet.
//!
//! 1. **One root.** 32 random bytes from `rng-driver`, made on the first start, sealed under the wallet's own keystore
//!    key, and kept on the disk's wallet partition. On every later start it's unsealed; a sector that doesn't unseal is
//!    never overwritten, and the wallet then refuses every session.
//! 2. **A pairwise identity per (app, peer).** `lantern_crypto::pairwise`: keyed BLAKE3 of the root over the app's
//!    principal, which the binder names, and the peer's name. No two contexts' keys can be linked without the root.
//! 3. **Sessions.** `CONNECT` runs a Noise `XX` handshake (`lantern_crypto::noise`) as that identity, with a fresh
//!    ephemeral key, to the context's peer over `net`; `SEND` and `RECV` move messages over it. The app holds a badge,
//!    never a key, and the wallet holds every key and every session's state.
//! 4. **Recorded first.** Each op is in the audit log before it runs: the grant, the context, the identity's public key
//!    prefix, the length. Never the content.
//!
//! It holds no console, no store, and on the network only its badge on `net`.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::block::{Client, SECTOR};
use lantern_abi::frame::{self, status, Channel, Interloper};
use lantern_abi::grant::{self, Incoming, APP_SLOTS};
use lantern_abi::identity::{self, MESSAGE_MAX, REFUSED, UNREACHABLE};
use lantern_abi::net::{self as netproto, Peer};
use lantern_abi::policy::{self, AuditEntry};
use lantern_abi::sys::{self, Received};
use lantern_abi::wire::Rights;
use lantern_crypto::noise::{Handshake, Transport, TAG_LEN};
use lantern_crypto::{pairwise, wire as kswire};
use lantern_wallet::{context, Grant, Grants, Log, Sector, MAX_GRANTS, PORT_BASE, PROLOGUE, ROOT_AAD};

lantern_abi::entry!(run);

// Granted by the loader (`src/system/loader.rs`).
const SELF_CNODE: usize = 0;
const ENDPOINT: usize = 1;
const SCRATCH: usize = 2;
const AUDIT: usize = 3;
const VOLUME: usize = 4;
const RNG: usize = 5;
const NET: usize = 6;
const KEYSTORE: usize = 7;
/// Where the keystore's grant of the wallet's sealing key lands.
const KEYSTORE_DEST: usize = 8;
const FAILURE: usize = 9;

const CLIENT_VADDR: usize = 0x9001_0000;
const VOLUME_VADDR: usize = 0x9002_0000;
const NET_VADDR: usize = 0x9003_0000;
const KEYSTORE_VADDR: usize = 0x9004_0000;
const CHANNEL_STRIDE: usize = 0x1000;

/// How long a peer has to answer each handshake message, and each `RECV`.
const ANSWER_MS: u32 = 3000;

struct Wallet {
    root: Option<[u8; 32]>,
    grants: Grants,
    sessions: [Option<Transport>; MAX_GRANTS],
    log: Log,
    net: Channel,
}

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // SAFETY: the loader mapped each channel read/write at its address, for this program's whole life.
    let (volume, keystore, net) = unsafe {
        (
            Channel::new(VOLUME, VOLUME_VADDR as *mut u8),
            Channel::new(KEYSTORE_DEST, KEYSTORE_VADDR as *mut u8),
            Channel::new(NET, NET_VADDR as *mut u8),
        )
    };
    let mut volume = Client { channel: volume };
    let mut keystore = keystore;
    // The keystore grants this badge the wallet's own sealing key, once.
    let sealing = sys::call_with_reply_slot(KEYSTORE, KEYSTORE_DEST, [0, 0]).is_ok();
    let root = if sealing { load_root(&mut volume, &mut keystore) } else { None };
    let mut wallet = Wallet {
        root,
        grants: Grants::default(),
        sessions: core::array::from_fn(|_| None),
        log: Log::default(),
        net,
    };
    // SAFETY: the loader mapped each app slot's channel read/write, one page apart, from CLIENT_VADDR.
    let mut clients: [Channel; APP_SLOTS] =
        core::array::from_fn(|c| unsafe { Channel::new(ENDPOINT, (CLIENT_VADDR + c * CHANNEL_STRIDE) as *mut u8) });
    let mut request = [0u8; MESSAGE_MAX];
    let mut reply = [0u8; MESSAGE_MAX];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge == identity::READER_BADGE {
            serve_reader(&wallet.log, &received);
            continue;
        }
        if grant::classify(&received) != Incoming::Data {
            Others { grants: &mut wallet.grants, sessions: &mut wallet.sessions }.serve(received);
            continue;
        }
        let badge = received.badge;
        let Some((place, grant)) = wallet.grants.live(badge) else {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        };
        let client = &mut clients[grant.channel as usize];
        let mut others = Others { grants: &mut wallet.grants, sessions: &mut wallet.sessions };
        let Ok((op, len)) = client.recv_request(received, &mut request, &mut others) else { continue };
        let (outcome, reply_len) = wallet.serve(place, grant, op, &request[..len], &mut reply);
        let mut others = Others { grants: &mut wallet.grants, sessions: &mut wallet.sessions };
        let _ = client.reply(outcome, &reply[..reply_len], badge, &mut others);
    }
}

impl Wallet {
    fn serve(&mut self, place: usize, grant: Grant, op: u16, request: &[u8], reply: &mut [u8]) -> (u16, usize) {
        let Some(root) = self.root else { return (UNREACHABLE, 0) };
        let ctx = context(grant.context).expect("admitted only for a known context");
        let secret = pairwise::secret(&root, grant.principal, ctx.peer.as_bytes());
        let public = lantern_crypto::noise::public_key(secret);
        let key = u32::from_be_bytes([public[0], public[1], public[2], public[3]]);
        let bit = match op {
            identity::OP_CONNECT => identity::CONNECT,
            identity::OP_SEND => identity::SEND,
            identity::OP_RECV => identity::RECV,
            _ => return (status::INVALID, 0),
        };
        let using = AuditEntry {
            object: grant.context,
            ops: bit,
            subject: [grant.badge, identity::audit_subject(key, request.len())],
            ..AuditEntry::default()
        };
        let peer = Peer { ip: ctx.ip, port: ctx.port };
        let port = PORT_BASE + place as u16;
        let run = || match op {
            identity::OP_CONNECT => {
                self.sessions[place] = None;
                match connect(&mut self.net, secret, peer, port) {
                    Ok(transport) => {
                        self.sessions[place] = Some(transport);
                        self.log.record(grant.principal, grant.context, key);
                        (status::OK, 0)
                    }
                    Err(s) => (s, 0),
                }
            }
            identity::OP_SEND => match self.sessions[place].as_mut() {
                Some(t) => (send(&mut self.net, t, peer, port, request), 0),
                None => (UNREACHABLE, 0),
            },
            _ => match self.sessions[place].as_mut() {
                Some(t) => recv(&mut self.net, t, peer, port, reply),
                None => (UNREACHABLE, 0),
            },
        };
        policy::audited(AUDIT, &using, run).unwrap_or((status::FAILED, 0))
    }
}

/// The handshake, as the initiator: `-> e`, `<- e, ee, s, es`, `-> s, se`. A peer that doesn't answer is `UNREACHABLE`; one
/// whose answer doesn't authenticate is `REFUSED`.
fn connect(net: &mut Channel, secret: [u8; 32], peer: Peer, port: u16) -> Result<Transport, u16> {
    let mut ephemeral = [0u8; 32];
    if !netproto::fill_random(RNG, &mut ephemeral) {
        return Err(status::FAILED);
    }
    let mut hs = Handshake::new(true, secret, ephemeral, PROLOGUE);
    let mut msg = [0u8; 256];
    let n = hs.write_message(&[], &mut msg).map_err(|_| status::FAILED)?;
    netproto::send(net, peer, port, &msg[..n]).map_err(|_| UNREACHABLE)?;
    let mut answer = [0u8; 6 + netproto::DATAGRAM_MAX];
    let len = from_peer(net, peer, port, &mut answer)?;
    let mut payload = [0u8; netproto::DATAGRAM_MAX];
    hs.read_message(&answer[..len], &mut payload).map_err(|_| REFUSED)?;
    let n = hs.write_message(&[], &mut msg).map_err(|_| status::FAILED)?;
    netproto::send(net, peer, port, &msg[..n]).map_err(|_| UNREACHABLE)?;
    hs.into_transport().map_err(|_| status::FAILED)
}

/// The next datagram from `peer` to `port`, within the answer limit; others are dropped.
fn from_peer(net: &mut Channel, peer: Peer, port: u16, out: &mut [u8]) -> Result<usize, u16> {
    for _ in 0..8 {
        match netproto::recv(net, port, ANSWER_MS, out) {
            Ok((from, len)) if from == peer => return Ok(len),
            Ok(_) => continue,
            Err(_) => return Err(UNREACHABLE),
        }
    }
    Err(UNREACHABLE)
}

fn send(net: &mut Channel, t: &mut Transport, peer: Peer, port: u16, message: &[u8]) -> u16 {
    if message.len() > MESSAGE_MAX {
        return status::INVALID;
    }
    let mut buf = [0u8; MESSAGE_MAX + TAG_LEN];
    buf[..message.len()].copy_from_slice(message);
    let Ok(n) = t.write(&mut buf, message.len()) else { return status::FAILED };
    match netproto::send(net, peer, port, &buf[..n]) {
        Ok(()) => status::OK,
        Err(_) => UNREACHABLE,
    }
}

fn recv(net: &mut Channel, t: &mut Transport, peer: Peer, port: u16, out: &mut [u8]) -> (u16, usize) {
    let mut buf = [0u8; 6 + netproto::DATAGRAM_MAX];
    let len = match from_peer(net, peer, port, &mut buf) {
        Ok(len) => len,
        Err(s) => return (s, 0),
    };
    match t.read(&mut buf[..len]) {
        Ok(n) if n <= out.len() => {
            out[..n].copy_from_slice(&buf[..n]);
            (status::OK, n)
        }
        Ok(_) => (status::INVALID, 0),
        // A datagram that doesn't authenticate isn't from the peer, or was altered: the session's nonce hasn't moved, so
        // the session stays usable.
        Err(_) => (REFUSED, 0),
    }
}

/// The root from the wallet's partition, unsealed, or a new one, sealed and written, if the partition is empty. `None`
/// if there's no partition, the sector holds something else, or it doesn't unseal: the wallet then refuses every session,
/// and never overwrites what's there.
fn load_root(volume: &mut Client, keystore: &mut Channel) -> Option<[u8; 32]> {
    let mut sector = [0u8; SECTOR];
    volume.read(0, &mut sector).ok()?;
    match lantern_wallet::read_sector(&sector) {
        Sector::Sealed { nonce, tag, ciphertext } => {
            let mut request = [0u8; 256];
            let len = kswire::encode_decrypt_request(&nonce, ROOT_AAD, &tag, &ciphertext, &mut request)?;
            let mut reply = [0u8; 256];
            match keystore.call(kswire::OP_DECRYPT, &request[..len], &mut reply) {
                Ok((kswire::status::OK, n)) => kswire::decode_decrypt_reply(&reply[..n]).try_into().ok(),
                _ => None,
            }
        }
        Sector::Unknown => None,
        Sector::Empty => {
            let mut root = [0u8; 32];
            let mut nonce = [0u8; lantern_wallet::NONCE_LEN];
            if !netproto::fill_random(RNG, &mut root) || !netproto::fill_random(RNG, &mut nonce) {
                return None;
            }
            let mut request = [0u8; 256];
            let len = kswire::encode_encrypt_request(&nonce, ROOT_AAD, &root, &mut request)?;
            let mut reply = [0u8; 256];
            let (tag, ciphertext) = match keystore.call(kswire::OP_ENCRYPT, &request[..len], &mut reply) {
                Ok((kswire::status::OK, n)) => kswire::decode_encrypt_reply(&reply[..n])?,
                _ => return None,
            };
            lantern_wallet::write_sector(&nonce, &tag, ciphertext.try_into().ok()?, &mut sector);
            volume.write(0, &sector).ok()?;
            Some(root)
        }
    }
}

/// The shell's `IDENTITY { index }`.
fn serve_reader(log: &Log, received: &Received) {
    let (op, index) = (received.msg[1], received.msg[2]);
    let _ = match (op, log.get(index)) {
        (identity::OP_IDENTITY, Some(p)) => {
            let (first, second) = identity::encode(p);
            sys::reply([first, status::OK as usize, second])
        }
        _ => sys::reply([0, status::INVALID as usize, 0]),
    };
}

/// Grants and revocations, served whether this program is idle or mid-request.
struct Others<'a> {
    grants: &'a mut Grants,
    sessions: &'a mut [Option<Transport>; MAX_GRANTS],
}

impl Interloper for Others<'_> {
    fn serve(&mut self, received: Received) {
        match grant::classify(&received) {
            Incoming::Grant { object, ops, channel, principal } => self.grant(object, ops, channel, principal),
            Incoming::Revoke { badge } => {
                let place = self.grants.live(badge).map(|(i, _)| i);
                let revoked = self.grants.revoke(badge);
                // A revoked grant's session ends with it: its keys are dropped now.
                if let Some(i) = place {
                    self.sessions[i] = None;
                }
                let _ = grant::reply_status(if revoked { status::OK } else { status::INVALID });
            }
            Incoming::ForgedGrant => {
                let _ = grant::reply_status(status::ACCESS);
            }
            Incoming::Data => frame::reply_busy(),
        }
    }

    fn still_allowed(&self, badge: u64) -> bool {
        self.grants.live(badge).is_some()
    }
}

impl Others<'_> {
    fn grant(&mut self, object: usize, ops: usize, channel: Option<usize>, principal: u64) {
        let (place, grant) = match self.grants.admit(object, ops, channel, principal) {
            Ok(admitted) => admitted,
            Err(refused) => {
                let _ = grant::reply_status(refused);
                return;
            }
        };
        // `GRANT` too: the kernel only moves a capability that has it.
        if sys::cnode::mint(SELF_CNODE, ENDPOINT, SCRATCH, grant.badge, Rights::WRITE.union(Rights::GRANT)).is_err() {
            let _ = grant::reply_status(status::FAILED);
            return;
        }
        self.grants.record(place, grant);
        self.sessions[place] = None;
        if sys::reply_with_cap(SCRATCH, [status::OK as usize, grant.badge as usize]).is_err() {
            self.grants.revoke(grant.badge);
            let _ = grant::reply_status(status::FAILED);
        }
        let _ = sys::cnode::delete(SELF_CNODE, SCRATCH);
    }
}
