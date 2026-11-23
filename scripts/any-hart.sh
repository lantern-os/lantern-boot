#!/usr/bin/env bash
# RFC-0039 §2's proof, under QEMU: LanternOS boots on whichever hart the firmware picks, and its interrupts then reach
# that hart. QEMU's OpenSBI chooses the boot hart at random among `-smp 4`'s harts, so each case boots lantern-boot-irq-demo
# until it has booted on a hart other than 0 (at most TRIES times), and then needs what irq-demo.sh needs of it: the
# driver's DONE for what was typed, and the echo. Two cases, one per interrupt controller:
#
#   PLIC   the boot hart's S-mode context is read from the device tree's `interrupts-extended`;
#   AIA    the boot hart's IMSIC file and APLIC hart index are.
#
# Exits nonzero on any mismatch, or if the firmware never picked another hart.
set -u
cd "$(dirname "$0")/.." || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET=target/riscv64gc-unknown-none-elf/release
INPUT='lantern'
WANT_SUM=$(printf '%s\n' "$INPUT" | od -An -tu1 -v | tr -s ' ' '\n' | awk 'NF { s += $1 } END { print s }')
WANT="count=$(( ${#INPUT} + 1 )) sum=$WANT_SUM"
TRIES=${TRIES:-24}

cargo build -q --release --bin lantern-boot-irq-demo || exit 2

failures=0
# boot <machine>: one boot; leaves the console in $WORK/out.
boot() {
    rm -f "$WORK/in" "$WORK/out"
    mkfifo "$WORK/in"
    qemu-system-riscv64 -machine "$1" -smp 4 -bios default -nographic -m 128M \
        -kernel "$TARGET/lantern-boot-irq-demo" <"$WORK/in" >"$WORK/out" 2>&1 &
    local qemu=$!
    exec 3>"$WORK/in"
    for _ in $(seq 1 30); do
        grep -aq "boot: hart" "$WORK/out" && break
        sleep 0.1
    done
    sleep 1
    printf '%s\n' "$INPUT" >&3
    for _ in $(seq 1 50); do
        grep -aq "Signal'd" "$WORK/out" && break
        sleep 0.1
    done
    exec 3>&-
    kill "$qemu" 2>/dev/null
    wait "$qemu" 2>/dev/null
}

# case <label> <machine>
case_() {
    local label=$1 machine=$2 hart=0 try
    for try in $(seq 1 "$TRIES"); do
        boot "$machine"
        hart=$(grep -a -o 'boot: hart [0-9]*' "$WORK/out" | head -1 | awk '{ print $3 }')
        [ -n "$hart" ] && [ "$hart" != 0 ] && break
    done
    local got
    got=$(grep -a "Signal'd" "$WORK/out" | head -1 | sed -nE "s/.*Signal'd (DONE|FAILURE) -- ok=[a-z]+ (count=[0-9]+ sum=[0-9]+).*/\1 \2/p")
    [ -n "$got" ] || got=NO-SIGNAL
    if [ -z "$hart" ] || [ "$hart" = 0 ]; then
        printf 'FAIL  %-36s the firmware never booted a hart but 0 in %s tries (last: %s)\n' "$label" "$TRIES" "${hart:-none}"
        failures=$((failures + 1))
    elif [ "$got" != "DONE $WANT" ]; then
        printf 'FAIL  %-36s on hart %s: want DONE %s, got %s\n' "$label" "$hart" "$WANT" "$got"
        failures=$((failures + 1))
    elif ! grep -aq "^$INPUT\$" "$WORK/out"; then
        printf 'FAIL  %-36s on hart %s: no echo of %s\n' "$label" "$hart" "$INPUT"
        failures=$((failures + 1))
    else
        printf 'ok    %-36s booted on hart %s (try %s); %s\n' "$label" "$hart" "$try" "$got"
    fi
}

case_ 'PLIC: interrupts reach the boot hart' virt
case_ 'AIA: interrupts reach the boot hart' virt,aia=aplic-imsic

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
