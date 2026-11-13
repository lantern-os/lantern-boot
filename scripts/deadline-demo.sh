#!/usr/bin/env bash
# RFC-0028's proof, under QEMU: a confined program sleeps on deadlines and reads the time only through them. Builds
# lantern-boot-deadline-demo twice:
#
#   spinner   the spinner runs first and never yields; three 100 ms sleeps must still wake on time.
#   idle      the spinner parks; three 1 s sleeps, during which QEMU must use (almost) no CPU.
#
# Each needs the sleeper's DONE with all 4 checks (each wake from the right deadline alone, never early, and a deadline
# already past firing at once) and its worst lateness under a bound. Exits nonzero on any mismatch.
set -u
cd "$(dirname "$0")/.." || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET=target/riscv64gc-unknown-none-elf/release
# Late by at most this, in microseconds: one slice for the spinner, plus QEMU's own jitter.
LATE_MAX_US=30000
IDLE_MAX_TICKS=$(( $(getconf CLK_TCK) * 3 / 10 ))

failures=0
# run <label> <features> <check-idle>
run() {
    local label=$1 features=$2 check_idle=$3
    cargo build -q --release --bin lantern-boot-deadline-demo ${features:+--features "$features"} || exit 2
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M \
        -kernel "$TARGET/lantern-boot-deadline-demo" </dev/null >"$WORK/out" 2>&1 &
    local qemu=$!
    sleep 0.5
    local before after
    before=$(awk '{ print $14 + $15 }' "/proc/$qemu/stat")
    for _ in $(seq 1 100); do
        grep -aq "Signal'd" "$WORK/out" && break
        sleep 0.1
    done
    after=$(awk '{ print $14 + $15 }' "/proc/$qemu/stat")
    kill "$qemu" 2>/dev/null
    wait "$qemu" 2>/dev/null

    local line late checks
    line=$(grep -a "Signal'd" "$WORK/out" | head -1)
    late=$(printf '%s' "$line" | sed -nE "s/.*Signal'd DONE -- ok=true a=([0-9]+) b=([0-9]+).*/\1/p")
    checks=$(printf '%s' "$line" | sed -nE "s/.*Signal'd DONE -- ok=true a=([0-9]+) b=([0-9]+).*/\2/p")
    local verdict="worst lateness ${late:-?} us, checks ${checks:-?}, cpu $((after - before)) ticks"
    if [ -z "$late" ] || [ "$checks" != 4 ]; then
        printf 'FAIL  %-30s %s\n' "$label" "${line:-NO-SIGNAL}"
        failures=$((failures + 1))
    elif [ "$late" -gt "$LATE_MAX_US" ]; then
        printf 'FAIL  %-30s late by %s us, over %s\n' "$label" "$late" "$LATE_MAX_US"
        failures=$((failures + 1))
    elif [ "$check_idle" = yes ] && [ $((after - before)) -gt "$IDLE_MAX_TICKS" ]; then
        printf 'FAIL  %-30s idle used %s ticks, over %s\n' "$label" "$((after - before))" "$IDLE_MAX_TICKS"
        failures=$((failures + 1))
    else
        printf 'ok    %-30s %s\n' "$label" "$verdict"
    fi
}

run 'spinner: wakes on time' '' no
run 'idle: rests between wakes' deadline-idle yes
cargo build -q --release --bin lantern-boot-deadline-demo || exit 2

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
