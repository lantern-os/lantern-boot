#!/usr/bin/env bash
# RFC-0027's proof, under QEMU: interrupts reach a confined driver, a program that never yields is preempted, and a
# hart with nothing to run idles. Builds lantern-boot-irq-demo twice:
#
#   spinner   the spinner runs first and never makes a system call; the driver must still read what's typed.
#   idle      the spinner parks too; QEMU must use (almost) no CPU while nothing is typed, and still wake on a key.
#
# Each case types "lantern\n" into the serial line after the system has settled, and needs the driver's DONE with the
# right count and byte sum, and the echo. Exits nonzero on any mismatch.
set -u
cd "$(dirname "$0")/.." || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET=target/riscv64gc-unknown-none-elf/release
INPUT='lantern'
WANT_SUM=$(printf '%s\n' "$INPUT" | od -An -tu1 -v | tr -s ' ' '\n' | awk 'NF { s += $1 } END { print s }')
WANT="count=$(( ${#INPUT} + 1 )) sum=$WANT_SUM"
# Idle: at most this many clock ticks of QEMU CPU over three seconds of silence. One core busy is ~3 * CLK_TCK.
IDLE_MAX_TICKS=$(( $(getconf CLK_TCK) * 3 / 10 ))

failures=0
# run <label> <features> <check-idle>
run() {
    local label=$1 features=$2 check_idle=$3
    cargo build -q --release --bin lantern-boot-irq-demo ${features:+--features "$features"} || exit 2
    mkfifo "$WORK/in"
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M \
        -kernel "$TARGET/lantern-boot-irq-demo" <"$WORK/in" >"$WORK/out" 2>&1 &
    local qemu=$!
    exec 3>"$WORK/in"
    sleep 1
    local before after ticks
    before=$(awk '{ print $14 + $15 }' "/proc/$qemu/stat")
    sleep 3
    after=$(awk '{ print $14 + $15 }' "/proc/$qemu/stat")
    ticks=$(( after - before ))
    printf '%s\n' "$INPUT" >&3
    for _ in $(seq 1 50); do
        grep -aq "Signal'd" "$WORK/out" && break
        sleep 0.1
    done
    exec 3>&-
    kill "$qemu" 2>/dev/null
    wait "$qemu" 2>/dev/null
    rm -f "$WORK/in"

    local got
    got=$(grep -a "Signal'd" "$WORK/out" | head -1 | sed -nE "s/.*Signal'd (DONE|FAILURE) -- ok=[a-z]+ (count=[0-9]+ sum=[0-9]+).*/\1 \2/p")
    [ -n "$got" ] || got=NO-SIGNAL
    local verdict="$got, cpu=$ticks ticks"
    if [ "$got" != "DONE $WANT" ]; then
        printf 'FAIL  %-34s want DONE %s, got %s\n' "$label" "$WANT" "$verdict"
        failures=$((failures + 1))
    elif ! grep -aq "^$INPUT\$" "$WORK/out"; then
        printf 'FAIL  %-34s no echo of %s\n' "$label" "$INPUT"
        failures=$((failures + 1))
    elif [ "$check_idle" = yes ] && [ "$ticks" -gt "$IDLE_MAX_TICKS" ]; then
        printf 'FAIL  %-34s idle used %s ticks, over %s\n' "$label" "$ticks" "$IDLE_MAX_TICKS"
        failures=$((failures + 1))
    else
        printf 'ok    %-34s %s\n' "$label" "$verdict"
    fi
}

run 'spinner: preempted, driver reads' '' no
run 'idle: no CPU, wakes on a key' irq-idle yes
cargo build -q --release --bin lantern-boot-irq-demo || exit 2

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
