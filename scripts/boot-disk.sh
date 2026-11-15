#!/usr/bin/env bash
# RFC-0032's proof: LanternOS boots from its disk, through UEFI, with no `-kernel`. Builds the EFI loader, converts it to
# PE/COFF, writes a bootable disk with `lantern-mkdisk --bootable`, and boots QEMU `virt` with EDK2 and that disk alone.
#
#   first boot   the firmware runs \EFI\BOOT\BOOTRISCV64.EFI, which starts LanternOS; `run confined-fs-probe`, answered
#                "always", finishes.
#   second boot  the same disk: the app runs again without a prompt (the decision was kept on the disk), and the store's
#                second image follows its first (its file was kept on the disk).
#
#   EDK2_CODE / EDK2_VARS   the firmware (default: Debian/Ubuntu's qemu-efi-riscv64 package)
#
# QEMU's `virt` gives ACPI tables by default, and EDK2 then gives no device tree; LanternOS needs one, so `acpi=off`.
set -u
cd "$(dirname "$0")/.." || exit 2
CODE="${EDK2_CODE:-/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd}"
VARS_TEMPLATE="${EDK2_VARS:-/usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd}"
[ -f "$CODE" ] && [ -f "$VARS_TEMPLATE" ] || { echo "no EDK2 firmware at $CODE: set EDK2_CODE and EDK2_VARS"; exit 2; }
WORK=$(mktemp -d)
QEMU_PID=
trap '[ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null; rm -rf "$WORK"' EXIT
HOST=$(rustc -vV | sed -n 's/^host: //p')
TARGET=target/riscv64gc-unknown-none-elf/release

(cd efi-loader && cargo build -q --release) || exit 2
(cd tools/elf2efi && cargo run -q --target "$HOST" -- ../../efi-loader/$TARGET/lantern-efi-loader "$WORK/BOOTRISCV64.EFI") || exit 2
cargo build -q --release --bin lantern-boot-system || exit 2
(cd tools/mkdisk && cargo run -q --target "$HOST" -- --out "$WORK/disk.img" --bootable --loader "$WORK/BOOTRISCV64.EFI" \
    --boot-image "$OLDPWD/$TARGET/lantern-boot-system" --package "$OLDPWD/assets/probe.lpkg" \
    --package "$OLDPWD/assets/fs-probe.lpkg") >/dev/null || exit 2
cp "$VARS_TEMPLATE" "$WORK/vars.fd"
# The bootable layout, in sectors: the store partition after the EFI System Partition and the packages.
STORE_SECTOR=100352

failures=0
fail() {
    printf 'FAIL  %-44s %s\n' "$CASE" "$1"
    failures=$((failures + 1))
}

boot() {
    rm -f "$WORK/in"
    mkfifo "$WORK/in"
    qemu-system-riscv64 -machine virt,acpi=off -m 256M -nographic \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$CODE" -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
        -global virtio-mmio.force-legacy=false -drive "if=none,format=raw,file=$WORK/disk.img,id=disk" \
        -device virtio-blk-device,drive=disk <"$WORK/in" >"$WORK/out" 2>&1 &
    QEMU_PID=$!
    exec 3>"$WORK/in"
}

stop() {
    exec 3>&-
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=
}

# expect <text>: waits up to 90 s, since the firmware takes its time.
expect() {
    for _ in $(seq 1 900); do
        grep -aqF -- "$1" "$WORK/out" && return 0
        sleep 0.1
    done
    fail "no \"$1\" on the console"
    return 1
}

store_seq() {
    python3 - "$WORK/disk.img" "$STORE_SECTOR" <<'PY'
import struct, sys
disk, first = open(sys.argv[1], 'rb').read(), int(sys.argv[2])
seqs = []
for i in range(2):
    at = (first + i * 32) * 512
    if disk[at:at + 8] == b'LSTORE01':
        seqs.append(struct.unpack_from('<Q', disk, at + 8)[0])
print(max(seqs) if seqs else 0)
PY
}

PROMPT='allow? [y]es once, [a]lways, [n]o, n[e]ver >'
DONE='lantern: "confined-fs-probe" finished.'

CASE='the firmware boots LanternOS from its disk'
boot
expect 'Lantern EFI loader: starting LanternOS' && expect 'Type help for commands.'
printf 'run confined-fs-probe\r' >&3
expect "$PROMPT" && printf 'a\r' >&3 && expect "$DONE"
stop
grep -aq 'PANIC' "$WORK/out" && fail 'a panic'
[ "$(store_seq)" = 1 ] || fail "want the store's first image on the disk, got $(store_seq)"
[ "$failures" = 0 ] && printf 'ok    %s\n' "$CASE"

CASE='a reboot keeps the decision and the file'
before=$failures
boot
expect 'Type help for commands.'
printf 'run confined-fs-probe\r' >&3
expect "$DONE"
stop
grep -aqF "$PROMPT" "$WORK/out" && fail 'asked again: the decision was lost'
[ "$(store_seq)" = 2 ] || fail "want the store's second image, got $(store_seq)"
[ "$failures" = "$before" ] && printf 'ok    %s\n' "$CASE"

[ "$failures" -eq 0 ] && echo 'all passed' || { echo "$failures failed"; exit 1; }
