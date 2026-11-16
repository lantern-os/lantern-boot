//! `lantern-net` — [RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)'s network service: IPv4 and
//! UDP (`lantern_network`) between `net-driver` and one client, the wallet.
//!
//! It parses everything the network sends, so it's the most exposed program in the system, and it holds nothing worth
//! stealing: no key, no DMA, no store, no console. Compromised, it can read encrypted traffic and drop or forge datagrams,
//! which the wallet's Noise sessions detect.
//!
//! - A static address: QEMU's user network gives `10.0.2.15`, behind `10.0.2.2`. DHCP is future work.
//! - It answers ARP for its address, and asks it for the next hop.
//! - It keeps datagrams only for the wallet's ports, [`PORTS`], up to [`QUEUED`] at a time, dropping the oldest.
//! - It sleeps on one notification: the device's interrupt (`BIT_RX`, bound by the driver) and its own deadline
//!   (`BIT_TIMER`), so waiting for a reply costs nothing.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel, RefuseInterlopers};
use lantern_abi::net::{self, driver, Peer, DATAGRAM_MAX};
use lantern_abi::sys;
use lantern_network::{self as stack, ArpCache, Incoming, Ip, Mac, Route};

// Granted by the loader (`src/system/loader.rs`).
const ENDPOINT: usize = 1;
const DRIVER: usize = 2;
const NOTIFY: usize = 3;
const DEADLINE: usize = 4;
/// Its own notification, badged `BIT_TIMER`, for the deadline.
const TIMER_BIT: usize = 5;
const FAILURE: usize = 6;

const DRIVER_VADDR: usize = 0x9000_0000;
const CLIENT_VADDR: usize = 0x9001_0000;

const IP: Ip = [10, 0, 2, 15];
const GATEWAY: Ip = [10, 0, 2, 2];
/// The wallet's ports: one per session.
const PORTS: core::ops::Range<u16> = 40000..41000;
/// Datagrams kept for the wallet while it isn't asking.
const QUEUED: usize = 8;
/// The wallet's badge, its only client.
const WALLET: u64 = 1;
/// How long to wait for the next hop to answer ARP.
const ARP_WAIT_MS: u64 = 1000;

lantern_abi::entry!(run);

#[derive(Clone, Copy)]
struct Datagram {
    from: Peer,
    to_port: u16,
    len: usize,
    bytes: [u8; DATAGRAM_MAX],
}

struct Net {
    driver: Channel,
    mac: Mac,
    arp: ArpCache,
    queue: [Option<Datagram>; QUEUED],
    id: u16,
    /// Notification bits seen but not yet acted on.
    bits: u64,
    frame: [u8; stack::FRAME_MAX],
}

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // SAFETY: the loader mapped the channel shared with the driver read/write at DRIVER_VADDR.
    let driver = unsafe { Channel::new(DRIVER, DRIVER_VADDR as *mut u8) };
    let mut net = Net { driver, mac: [0; 6], arp: ArpCache::default(), queue: [None; QUEUED], id: 1, bits: 0, frame: [0; stack::FRAME_MAX] };
    let mut mac = [0u8; 6];
    let ready = matches!(net.driver.call(driver::OP_MAC, &[], &mut mac), Ok((status::OK, 6)))
        && sys::deadline::set_notification(DEADLINE, TIMER_BIT).is_ok();
    net.mac = mac;
    // SAFETY: the loader mapped the channel shared with the wallet read/write at CLIENT_VADDR.
    let mut client = unsafe { Channel::new(ENDPOINT, CLIENT_VADDR as *mut u8) };
    let mut request = [0u8; net::SEND_HEADER + DATAGRAM_MAX];
    let mut reply = [0u8; 6 + DATAGRAM_MAX];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge != WALLET {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        }
        let Ok((op, len)) = client.recv_request(received, &mut request, &mut RefuseInterlopers) else { continue };
        let (outcome, reply_len) = match (ready, op) {
            (false, _) => (status::FAILED, 0),
            (true, net::OP_SEND) => match net::decode_send(&request[..len]) {
                Some((to, from_port, payload)) if PORTS.contains(&from_port) => (net.send(to, from_port, payload), 0),
                _ => (status::INVALID, 0),
            },
            (true, net::OP_RECV) => match net::decode_recv(&request[..len]) {
                Some((port, wait_ms)) if PORTS.contains(&port) => net.recv(port, wait_ms as u64, &mut reply),
                _ => (status::INVALID, 0),
            },
            _ => (status::INVALID, 0),
        };
        let _ = client.reply(outcome, &reply[..reply_len], received.badge, &mut RefuseInterlopers);
    }
}

impl Net {
    /// Takes every frame the driver has, after letting the device interrupt again, so none is missed between the two.
    fn drain(&mut self) {
        let _ = self.driver.call(driver::OP_ACK, &[], &mut []);
        loop {
            let mut frame = [0u8; stack::FRAME_MAX];
            let len = match self.driver.call(driver::OP_RECV, &[], &mut frame) {
                Ok((status::OK, len)) if len > 0 => len,
                _ => return,
            };
            match stack::parse(&frame[..len], self.mac, IP) {
                Some(Incoming::ArpRequest { mac, ip }) => {
                    let n = stack::arp_reply(self.mac, IP, mac, ip, &mut self.frame);
                    let _ = self.driver.call(driver::OP_SEND, &self.frame[..n], &mut []);
                }
                Some(Incoming::ArpReply { mac, ip }) => self.arp.insert(ip, mac),
                Some(Incoming::Udp { from, from_port, to_port, payload }) if PORTS.contains(&to_port) => {
                    let mut d = Datagram { from: Peer { ip: from, port: from_port }, to_port, len: payload.len(), bytes: [0; DATAGRAM_MAX] };
                    d.bytes[..payload.len()].copy_from_slice(payload);
                    match self.queue.iter_mut().find(|q| q.is_none()) {
                        Some(free) => *free = Some(d),
                        None => {
                            self.queue.rotate_left(1);
                            self.queue[QUEUED - 1] = Some(d);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Waits until a frame may have arrived or `until` passes; `false` once it has passed.
    fn wait_until(&mut self, until: u64) -> bool {
        if self.bits & driver::BIT_RX != 0 {
            self.bits &= !driver::BIT_RX;
            return true;
        }
        if sys::deadline::arm(DEADLINE, until).is_err() {
            return false;
        }
        let bits = sys::wait(NOTIFY).unwrap_or(driver::BIT_TIMER);
        let _ = sys::deadline::cancel(DEADLINE);
        // A timer bit from a deadline that fired after this wait ended is stale: drop it, keeping any frame bit.
        self.bits |= sys::poll(NOTIFY).unwrap_or(0) & driver::BIT_RX;
        bits & driver::BIT_RX != 0 || now() < until
    }

    fn send(&mut self, to: Peer, from_port: u16, payload: &[u8]) -> u16 {
        let hop = stack::next_hop(IP, GATEWAY, to.ip);
        let until = now().saturating_add(ARP_WAIT_MS * 1_000_000);
        let mac = loop {
            self.drain();
            if let Some(mac) = self.arp.get(hop) {
                break mac;
            }
            let n = stack::arp_request(self.mac, IP, hop, &mut self.frame);
            let _ = self.driver.call(driver::OP_SEND, &self.frame[..n], &mut []);
            if !self.wait_until(until.min(now().saturating_add(200_000_000))) && now() >= until {
                return status::FAILED;
            }
        };
        let route = Route { mac: self.mac, ip: IP, port: from_port, to_mac: mac, to_ip: to.ip, to_port: to.port };
        self.id = self.id.wrapping_add(1);
        let Some(n) = stack::udp(route, self.id, payload, &mut self.frame) else { return status::INVALID };
        match self.driver.call(driver::OP_SEND, &self.frame[..n], &mut []) {
            Ok((status::OK, _)) => status::OK,
            _ => status::FAILED,
        }
    }

    fn recv(&mut self, port: u16, wait_ms: u64, out: &mut [u8]) -> (u16, usize) {
        let until = now().saturating_add(wait_ms.min(60_000) * 1_000_000);
        loop {
            self.drain();
            if let Some(i) = self.queue.iter().position(|q| q.is_some_and(|d| d.to_port == port)) {
                let d = self.queue[i].take().expect("found above");
                self.queue[i..].rotate_left(1);
                let n = net::encode_datagram(d.from, &d.bytes[..d.len], out).unwrap_or(0);
                return (status::OK, n);
            }
            if !self.wait_until(until) {
                return (net::TIMED_OUT, 0);
            }
        }
    }
}

fn now() -> u64 {
    sys::deadline::now(DEADLINE).unwrap_or(u64::MAX)
}
