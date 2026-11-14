#!/usr/bin/env bash
# RFC-0030's proof, under QEMU: a confined nursery builds a child process from user space 40 times, from one child
# Untyped, beside a spinner that never yields. Each child finishes or faults on purpose (four kinds of fault), and the
# nursery checks how it ended, Resets, and checks nothing it made survives. Every tenth round it resets its whole memory.
# Forty children need far more TCBs, VSpaces, Frames and page tables than the kernel has, so this passes only if
# reclamation returns them all, and only if no fault stops the system.
#
# Passes on the nursery's DONE, with the worst Reset (after the first) under a bound. Exits nonzero otherwise.
set -u
cd "$(dirname "$0")/.." || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET=target/riscv64gc-unknown-none-elf/release
# In microseconds, under QEMU: a slot holds one child's ~12 objects; the whole memory, the slot as well.
SLOT_MAX_US=500
WHOLE_MAX_US=1000
RUNS=${RUNS:-3}

cargo build -q --release --bin lantern-boot-lifecycle-demo || exit 2
failures=0
for run in $(seq 1 "$RUNS"); do
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M \
        -kernel "$TARGET/lantern-boot-lifecycle-demo" </dev/null >"$WORK/out" 2>&1 &
    qemu=$!
    for _ in $(seq 1 300); do
        grep -aq "Signal'd\|PANIC" "$WORK/out" && break
        sleep 0.1
    done
    kill "$qemu" 2>/dev/null
    wait "$qemu" 2>/dev/null
    grep -aq "OpenSBI" "$WORK/out" || { echo "run $run: QEMU didn't boot, so this run proves nothing"; exit 2; }

    line=$(grep -a "Signal'd\|PANIC" "$WORK/out" | head -1)
    slot=$(printf '%s' "$line" | sed -nE "s/.*Signal'd SUCCESS -- ok=true a=([0-9]+) b=([0-9]+).*/\1/p")
    whole=$(printf '%s' "$line" | sed -nE "s/.*Signal'd SUCCESS -- ok=true a=([0-9]+) b=([0-9]+).*/\2/p")
    if [ -z "$slot" ]; then
        printf 'FAIL  run %s  %s\n' "$run" "${line:-no signal: the system stopped}"
        failures=$((failures + 1))
    elif [ "$slot" -gt "$SLOT_MAX_US" ] || [ "$whole" -gt "$WHOLE_MAX_US" ]; then
        printf 'FAIL  run %s  Reset took %s us (slot), %s us (whole), over %s/%s\n' "$run" "$slot" "$whole" "$SLOT_MAX_US" "$WHOLE_MAX_US"
        failures=$((failures + 1))
    else
        printf 'ok    run %s  40 children built, ended and reclaimed; worst Reset %s us (slot), %s us (whole memory)\n' "$run" "$slot" "$whole"
    fi
done
[ "$failures" -eq 0 ] && echo 'all passed' || { echo "$failures failed"; exit 1; }
