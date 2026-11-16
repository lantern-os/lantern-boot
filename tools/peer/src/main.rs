//! `lantern-peer --name <peer> --port <n> --log <file> [--forge]`: [RFC-0035](../../../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)'s
//! test peer, standing in for `alice.test` or `bob.test` on the host QEMU's user network reaches at `10.0.2.2`.
//!
//! It answers each Noise `XX` handshake as the responder, with `snow`, an implementation independent of the wallet's,
//! and a static key of its own. When one completes, it logs `identity <name> <the initiator's static key, in hex>`: the
//! identity the wallet presented. Each message it then receives is answered `welcome to <name>, <key prefix>`.
//!
//! With `--forge`, it answers every handshake with a message that can't authenticate, as someone who isn't the peer would.

use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"lantern-identity-v1";

enum State {
    Handshake(Box<snow::HandshakeState>),
    Transport(snow::TransportState, String),
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let (Some(name), Some(port), Some(log)) = (arg("--name"), arg("--port"), arg("--log")) else {
        eprintln!("usage: lantern-peer --name <peer> --port <n> --log <file> [--forge]");
        std::process::exit(2);
    };
    let forge = args.iter().any(|a| a == "--forge");
    let socket = UdpSocket::bind(("0.0.0.0", port.parse::<u16>().expect("a port"))).expect("bind");
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&log).expect("open the log");
    // The peer's own static key: fixed per name, so a peer is the same peer across runs.
    let builder = || snow::Builder::new(PATTERN.parse().unwrap());
    let secret = {
        let mut s = [0u8; 32];
        for (i, b) in name.bytes().enumerate() {
            s[i % 32] = s[i % 32].wrapping_mul(31).wrapping_add(b);
        }
        s
    };
    let mut sessions: HashMap<SocketAddr, State> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    writeln!(log, "listening {name} {port}").unwrap();
    loop {
        let (n, from) = socket.recv_from(&mut buf).expect("recv");
        let msg = &buf[..n];
        // A message the size of a first handshake message starts a new session from that address.
        let starting = n == 32 && !matches!(sessions.get(&from), Some(State::Handshake(_)));
        if starting {
            let hs = builder().local_private_key(&secret).prologue(PROLOGUE).build_responder().unwrap();
            sessions.insert(from, State::Handshake(Box::new(hs)));
        }
        let Some(state) = sessions.remove(&from) else { continue };
        match state {
            State::Handshake(mut hs) => {
                let mut payload = [0u8; 1024];
                if hs.read_message(msg, &mut payload).is_err() {
                    writeln!(log, "refused {name} {from}").unwrap();
                    continue;
                }
                if hs.is_handshake_finished() {
                    let key: String = hs.get_remote_static().unwrap().iter().map(|b| format!("{b:02x}")).collect();
                    writeln!(log, "identity {name} {key}").unwrap();
                    log.flush().unwrap();
                    sessions.insert(from, State::Transport(hs.into_transport_mode().unwrap(), key));
                    continue;
                }
                let len = if forge {
                    // As long as a real answer, and nothing a key made.
                    out[..96].fill(0x5a);
                    96
                } else {
                    hs.write_message(&[], &mut out).unwrap()
                };
                socket.send_to(&out[..len], from).expect("send");
                sessions.insert(from, State::Handshake(hs));
            }
            State::Transport(mut t, key) => {
                let mut plain = [0u8; 1024];
                match t.read_message(msg, &mut plain) {
                    Ok(_) => {
                        let reply = format!("welcome to {name}, {}", &key[..8]);
                        let len = t.write_message(reply.as_bytes(), &mut out).unwrap();
                        socket.send_to(&out[..len], from).expect("send");
                        writeln!(log, "message {name} {key}").unwrap();
                    }
                    Err(_) => writeln!(log, "garbled {name} {from}").unwrap(),
                }
                log.flush().unwrap();
                sessions.insert(from, State::Transport(t, key));
            }
        }
    }
}
