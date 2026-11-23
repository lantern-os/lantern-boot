#!/usr/bin/env bash
# RFC-0035's proof: a network identity presented without cross-context linkage. Two test peers run on the host, stand-ins
# for alice.test and bob.test, which QEMU's user network reaches at 10.0.2.2; each answers the wallet's Noise handshakes
# with `snow`, an implementation independent of the wallet's, and logs every identity it sees (`tools/peer`). The
# `greeter` app says hello to each, through the wallet, as a person allows it at the console.
#
# What it checks:
#   - each peer sees a 32-byte identity, and the two are different: nothing but QEMU's one address links them;
#   - each peer sees the same identity again on the next run, and after a reboot: the root is kept, sealed, on the disk;
#   - a peer the person declines is never contacted;
#   - a peer that answers with a forged handshake is refused, and the app learns only that;
#   - without network devices, the wallet refuses, and nothing else changes;
#   - a sealed root that's been changed on the disk, or a sector the wallet doesn't recognise, isn't used or overwritten.
set -u
cd "$(dirname "$0")/.." || exit 2
TARGET=target/riscv64gc-unknown-none-elf/release
HOST=$(rustc -vV | sed -n 's/^host: //p')
WORK=$(mktemp -d)
QEMU_PID=
PEERS=()
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    for p in "${PEERS[@]}"; do kill "$p" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

(cd tools/mkdisk && cargo build -q --target "$HOST") || exit 2
(cd tools/peer && cargo build -q --target "$HOST") || exit 2
MKDISK="tools/mkdisk/target/$HOST/debug/lantern-mkdisk"
PEER="tools/peer/target/$HOST/debug/lantern-peer"
cargo build -q --release --bin lantern-boot-system || exit 2
DISK="$WORK/disk.img"
LOG="$WORK/peers.log"
# `lantern-mkdisk`'s layout without a model or an EFI partition: the wallet's partition's first sector.
WALLET_SECTOR=106496

failures=0
fail() {
    printf 'FAIL  %-58s %s\n' "$CASE" "$1"
    failures=$((failures + 1))
}
case_() {
    CASE=$1
    BEFORE=$failures
}
ok() {
    [ "$failures" = "$BEFORE" ] && printf 'ok    %s\n' "$CASE"
}

# peers [--forge-bob]: (re)starts both test peers, logging to $LOG.
peers() {
    for p in "${PEERS[@]}"; do kill "$p" 2>/dev/null; done
    PEERS=()
    sleep 0.2
    "$PEER" --name alice.test --port 7001 --log "$LOG" &
    PEERS+=($!)
    if [ "${1:-}" = --forge-bob ]; then
        "$PEER" --name bob.test --port 7002 --log "$LOG" --forge &
    else
        "$PEER" --name bob.test --port 7002 --log "$LOG" &
    fi
    PEERS+=($!)
    sleep 0.3
    for p in "${PEERS[@]}"; do
        kill -0 "$p" 2>/dev/null || { echo "a test peer couldn't start: is something else on UDP 7001 or 7002?"; exit 2; }
    done
}

# boot [no-net]: starts the system on $DISK, a new one unless KEEP is set.
boot() {
    if [ -z "${KEEP:-}" ]; then
        "$MKDISK" --out "$DISK" --package assets/greeter.lpkg >/dev/null || exit 2
    fi
    local devices=(-device virtio-rng-device -netdev user,id=net -device virtio-net-device,netdev=net)
    [ "${1:-}" = no-net ] && devices=()
    rm -f "$WORK/in"
    mkfifo "$WORK/in"
    qemu-system-riscv64 -machine "${MACHINE:-virt}" ${SMP:+-smp "$SMP"} ${CPU:+-cpu "$CPU"} -bios default -nographic -m 256M "${devices[@]}" \
        -global virtio-mmio.force-legacy=false -drive "if=none,format=raw,file=$DISK,id=disk" -device virtio-blk-device,drive=disk \
        -kernel "$TARGET/lantern-boot-system" <"$WORK/in" >"$WORK/out" 2>&1 &
    QEMU_PID=$!
    exec 3>"$WORK/in"
    expect 'Type help for commands.'
}

stop() {
    exec 3>&-
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=
}

# expect <text> [n]: waits up to 60 s for the n-th occurrence of fixed text on the console.
expect() {
    local n=${2:-1}
    for _ in $(seq 1 600); do
        [ "$(grep -aoF -- "$1" "$WORK/out" | wc -l)" -ge "$n" ] && return 0
        sleep 0.1
    done
    fail "no \"$1\" on the console"
    return 1
}

type_line() {
    printf '%s\r' "$1" >&3
}

PROMPT='allow? [y]es once, [a]lways, [n]o, n[e]ver >'
DONE='lantern: "greeter" finished.'
FAILED='lantern: "greeter" stopped with an error.'

# greet <answer for alice> <answer for bob>: runs the greeter and answers each request once it's asked.
greet() {
    local asked
    asked=$(grep -aoF -- "$PROMPT" "$WORK/out" | wc -l)
    type_line 'run greeter' && expect 'lantern: "greeter" started.'
    for answer in "$@"; do
        asked=$((asked + 1))
        expect "$PROMPT" "$asked" && type_line "$answer"
    done
}

# key <peer>: the identity that peer saw most recently, or nothing.
key() {
    awk -v p="$1" '$1 == "identity" && $2 == p { k = $3 } END { print k }' "$LOG"
}

count() {
    grep -c "^identity $1 " "$LOG"
}

peers

case_ 'each peer sees an identity of its own, unrelated to the other'
boot
greet y y
expect "$DONE"
alice=$(key alice.test)
bob=$(key bob.test)
[ "${#alice}" = 64 ] || fail "alice.test saw no 32-byte identity: \"$alice\""
[ "${#bob}" = 64 ] || fail "bob.test saw no 32-byte identity: \"$bob\""
[ "$alice" != "$bob" ] || fail 'both peers saw the same identity'
type_line identities && expect "to alice.test: key ${alice:0:8}.., 1 session" && expect "to bob.test: key ${bob:0:8}.., 1 session"
type_line 'audit 12' && expect "connect to alice.test as ${alice:0:8}.." && expect "send to bob.test as ${bob:0:8}.. (18 bytes)"
grep -aq "$alice" "$WORK/out" && fail "the console showed a whole key"
stop
ok

case_ 'each peer sees the same identity again, and after a reboot'
KEEP=1 boot
greet y y
expect "$DONE"
[ "$(key alice.test)" = "$alice" ] || fail "alice.test saw $(key alice.test), not $alice, after a reboot"
[ "$(key bob.test)" = "$bob" ] || fail "bob.test saw $(key bob.test), not $bob, after a reboot"
greet y y
expect "$DONE" 2
[ "$(key alice.test)" = "$alice" ] && [ "$(key bob.test)" = "$bob" ] || fail 'a second run in the same boot saw other identities'
type_line identities && expect "to alice.test: key ${alice:0:8}.., 2 sessions"
stop
ok

case_ 'a peer the person declines is never contacted'
before=$(count bob.test)
boot
greet y n
expect "$DONE"
[ "$(count bob.test)" = "$before" ] || fail 'bob.test was contacted'
type_line identities && expect 'to alice.test' && sleep 0.5
grep -aq 'to bob.test: key' "$WORK/out" && fail 'identities lists bob.test'
stop
ok

case_ 'a forged answer is refused, and the app learns only that'
peers --forge-bob
boot
greet y y
expect "$FAILED"
[ "$(count bob.test)" = "$before" ] || fail 'bob.test saw an identity'
type_line identities && expect 'to alice.test' && sleep 0.5
grep -aq 'to bob.test: key' "$WORK/out" && fail 'a refused session was counted'
stop
peers
ok

case_ 'without network devices, the wallet refuses and nothing else changes'
before=$(wc -l <"$LOG")
boot no-net
greet y y
expect "$FAILED"
[ "$(wc -l <"$LOG")" = "$before" ] || fail 'a peer heard something'
type_line identities && expect '  none presented yet'
stop
ok

case_ 'a sealed root changed, or unrecognisable, is not used, nor overwritten'
boot
greet y y
expect "$DONE"
stop
python3 - "$DISK" "$WALLET_SECTOR" <<'PY' || fail 'no sealed root on the disk'
import sys
d = bytearray(open(sys.argv[1], 'rb').read())
at = int(sys.argv[2]) * 512
assert d[at:at + 8] == b'LWALLET1', d[at:at + 8]
d[at + 60] ^= 1  # inside the sealed root
open(sys.argv[1], 'wb').write(d)
PY
sealed=$(dd if="$DISK" bs=512 skip="$WALLET_SECTOR" count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
KEEP=1 boot
greet y y
expect "$FAILED"
stop
[ "$(dd if="$DISK" bs=512 skip="$WALLET_SECTOR" count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$sealed" ] ||
    fail 'the wallet overwrote a root it could not unseal'
# A sector it doesn't recognise at all, not just one that doesn't unseal: still not used, still not overwritten.
printf 'X' | dd of="$DISK" bs=1 seek=$((WALLET_SECTOR * 512)) conv=notrunc 2>/dev/null
sealed=$(dd if="$DISK" bs=512 skip="$WALLET_SECTOR" count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
KEEP=1 boot
greet y y
expect "$FAILED"
stop
[ "$(dd if="$DISK" bs=512 skip="$WALLET_SECTOR" count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$sealed" ] ||
    fail 'the wallet overwrote a sector it did not recognise'
ok

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
