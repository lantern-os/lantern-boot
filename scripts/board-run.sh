#!/usr/bin/env bash
# RFC-0039 §9's runner: RFC-0032's proof, driven over a serial console instead of QEMU's pipe, so the same cases run on a
# real board. A person installs the disk image (lantern-mkdisk's, written to the board's NVMe drive) and power-cycles
# the board when asked; the runner types at the console and checks what it shows.
#
#   SERIAL=/dev/ttyUSB0 scripts/board-run.sh     the board, through a 3.3 V USB serial adapter at 115,200 baud
#   QEMU=1 scripts/board-run.sh                  the same runner against QEMU: it boots a bootable disk through EDK2 on a
#                                                pseudo-terminal, and "power-cycles" by restarting QEMU
#
#   BOARD     a name for the record (default: qemu, or k3-pico-itx with SERIAL)
#   RECORD    1 to keep the console log and results under hardware/$BOARD/runs/ (default: 1 with SERIAL)
#
# Cases:
#   first boot   the console comes up; `run confined-fs-probe`, answered "always", finishes; a file is written
#   reboot       after a power cycle, the probe runs again without asking, and the file reads back
#
# Exits nonzero on any mismatch.
set -u
cd "$(dirname "$0")/.." || exit 2
WORK=$(mktemp -d)
QEMU_PID=
READER_PID=
cleanup() {
    [ -n "$READER_PID" ] && kill "$READER_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
HOST=$(rustc -vV | sed -n 's/^host: //p')
TARGET=target/riscv64gc-unknown-none-elf/release
BOARD=${BOARD:-$([ -n "${SERIAL:-}" ] && echo k3-pico-itx || echo qemu)}
RECORD=${RECORD:-$([ -n "${SERIAL:-}" ] && echo 1 || echo 0)}
[ -n "${SERIAL:-}" ] || [ -n "${QEMU:-}" ] || { echo "set SERIAL=/dev/ttyUSB0 (a board) or QEMU=1"; exit 2; }

if [ -n "${QEMU:-}" ]; then
    CODE="${EDK2_CODE:-/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd}"
    VARS="${EDK2_VARS:-/usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd}"
    (cd efi-loader && cargo build -q --release) || exit 2
    (cd tools/elf2efi && cargo run -q --target "$HOST" -- ../../efi-loader/$TARGET/lantern-efi-loader "$WORK/BOOTRISCV64.EFI") || exit 2
    cargo build -q --release --bin lantern-boot-system || exit 2
    (cd tools/mkdisk && cargo run -q --target "$HOST" -- --out "$WORK/disk.img" --bootable --loader "$WORK/BOOTRISCV64.EFI" \
        --boot-image "$OLDPWD/$TARGET/lantern-boot-system" --package "$OLDPWD/assets/probe.lpkg" \
        --package "$OLDPWD/assets/fs-probe.lpkg") >/dev/null || exit 2
    cp "$VARS" "$WORK/vars.fd"
fi

failures=0
CASE=
fail() {
    printf 'FAIL  %-40s %s\n' "$CASE" "$1"
    failures=$((failures + 1))
}

# power_on: a fresh boot, its console appended to $WORK/out from here on.
power_on() {
    : >"$WORK/out"
    if [ -n "${QEMU:-}" ]; then
        qemu-system-riscv64 -machine "${MACHINE:-virt}",acpi=off -m 256M -display none -serial pty -monitor none \
            -drive "if=pflash,unit=0,format=raw,readonly=on,file=$CODE" -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
            -global virtio-mmio.force-legacy=false -drive "if=none,format=raw,file=$WORK/disk.img,id=disk" \
            -device virtio-blk-device,drive=disk >"$WORK/qemu" 2>&1 &
        QEMU_PID=$!
        for _ in $(seq 1 50); do
            SERIAL=$(sed -n 's|.*redirected to \(/dev/pts/[0-9]*\).*|\1|p' "$WORK/qemu")
            [ -n "$SERIAL" ] && break
            sleep 0.1
        done
        [ -n "$SERIAL" ] || { echo "QEMU gave no pseudo-terminal"; exit 2; }
    else
        printf '\n>>> Power-cycle the board now (or power it on), then wait. <<<\n'
    fi
    stty -F "$SERIAL" 115200 raw -echo -echoe -echok -echoctl -echoke cs8 -cstopb -parenb || exit 2
    cat "$SERIAL" >>"$WORK/out" &
    READER_PID=$!
}

power_off() {
    kill "$READER_PID" 2>/dev/null
    wait "$READER_PID" 2>/dev/null
    READER_PID=
    if [ -n "${QEMU:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
        QEMU_PID=
    fi
}

type_line() {
    printf '%s\r' "$1" >"$SERIAL"
}

# expect <text> [seconds]: waits for it on the console (a real board's firmware takes its time).
expect() {
    local seconds=${2:-180}
    for _ in $(seq 1 $((seconds * 10))); do
        grep -aqF -- "$1" "$WORK/out" && return 0
        sleep 0.1
    done
    fail "no \"$1\" on the console"
    return 1
}

PROMPT='allow? [y]es once, [a]lways, [n]o, n[e]ver >'
DONE='lantern: "confined-fs-probe" finished.'
TEXT='kept across a power cycle'

CASE='first boot'
power_on
expect 'Type help for commands.' && {
    type_line 'run confined-fs-probe'
    expect "$PROMPT" 60 && type_line a && expect "$DONE" 60
    type_line "write 1 $TEXT" && expect 'written, as you.' 30
}
grep -aq PANIC "$WORK/out" && fail 'a panic'
cp "$WORK/out" "$WORK/first.log"
power_off
[ "$failures" = 0 ] && printf 'ok    %s\n' "$CASE"

CASE='reboot'
before=$failures
power_on
expect 'Type help for commands.' && {
    type_line 'run confined-fs-probe'
    expect "$DONE" 60
    type_line 'read 1' && expect "  $TEXT" 30
}
grep -aqF "$PROMPT" "$WORK/out" && fail 'asked again: the decision was lost'
grep -aq PANIC "$WORK/out" && fail 'a panic'
cp "$WORK/out" "$WORK/reboot.log"
power_off
[ "$failures" = "$before" ] && printf 'ok    %s\n' "$CASE"

if [ "$RECORD" = 1 ]; then
    RUN="hardware/$BOARD/runs/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$RUN"
    cp "$WORK/first.log" "$WORK/reboot.log" "$RUN/"
    { echo "board: $BOARD"; echo "commit: $(git rev-parse --short HEAD)"; echo "failures: $failures"; } >"$RUN/result"
    echo "recorded in $RUN"
fi
[ "$failures" -eq 0 ] && echo 'all passed' || { echo "$failures failed"; exit 1; }
