#!/usr/bin/env bash
# Runs every demo with general memory full of a non-zero pattern, as real hardware's RAM may be at
# power-on: QEMU's own RAM starts zeroed, which hides any Frame the launcher fails to clear. Exits
# nonzero on any demo that doesn't reach its usual result.
set -u
cd "$(dirname "$0")/.."
TARGET=target/riscv64gc-unknown-none-elf/release
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# From `pmm::GENERAL_MEMORY_BASE`, covering every Frame the demos retype. It stops short of the top of
# RAM, where QEMU places the device tree: overwriting that stops OpenSBI before anything here runs.
head -c $((100 * 1024 * 1024)) /dev/zero | tr '\0' '\245' >"$WORK/dirty.bin"
head -c 33554432 /dev/zero | tr '\0' '\377' >"$WORK/flash.img"

failures=0
for demo in frame broker keystore store wasm-probe runtime runtime-fs; do
    cargo build -q --release --bin "lantern-boot-$demo-demo" || exit 2
    cp "$WORK/flash.img" "$WORK/run.img"
    out="$WORK/qemu.out"
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M \
        -device "loader,file=$WORK/dirty.bin,addr=0x80600000,force-raw=on" \
        -drive "if=pflash,format=raw,unit=1,file=$WORK/run.img" \
        -kernel "$TARGET/lantern-boot-$demo-demo" </dev/null >"$out" 2>&1 &
    pid=$!
    for _ in $(seq 1 600); do
        grep -aq "Signal'd" "$out" && break
        sleep 0.1
    done
    sleep 0.2
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    grep -aq "OpenSBI" "$out" || { echo "$demo: QEMU didn't boot, so this run proves nothing"; exit 2; }
    if grep -a "Signal'd" "$out" | head -1 | grep -aq "FAILURE" || ! grep -aq "Signal'd" "$out"; then
        printf 'FAIL  %-12s %s\n' "$demo" "$(grep -a "Signal'd\|PANIC" "$out" | head -1 | cut -c1-80)"
        failures=$((failures + 1))
    else
        printf 'ok    %-12s %s\n' "$demo" "$(grep -a "Signal'd" "$out" | head -1 | sed 's/.*Signal.d //' | cut -c1-40)"
    fi
done
[ "$failures" -eq 0 ] && echo 'all passed' || { echo "$failures failed"; exit 1; }
