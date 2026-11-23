#!/usr/bin/env bash
# RFC-0032's proof: LanternOS boots from its disk, through UEFI, with no `-kernel`. Builds the EFI loader, converts it to
# PE/COFF, writes a bootable disk with `lantern-mkdisk --bootable`, and boots QEMU `virt` with EDK2 and that disk alone.
#
#   first boot   the firmware runs \EFI\BOOT\BOOTRISCV64.EFI, which starts LanternOS; `run confined-fs-probe`, answered
#                "always", finishes; so does the file assistant (RFC-0034), its model read from the disk's model partition.
#   second boot  the same disk: both run again without a prompt (the decisions were kept on the disk), and the store's
#                images follow the first boot's (its files were kept on the disk).
#
#   EDK2_CODE / EDK2_VARS   the firmware (default: Debian/Ubuntu's qemu-efi-riscv64 package)
#
# QEMU's `virt` gives ACPI tables by default, and EDK2 then gives no device tree; LanternOS needs one, so `acpi=off`.
set -u
# RFC-0039: DISK_BUS=nvme puts the disk on an NVMe controller on QEMU's PCIe bus instead of virtio-mmio.
disk_device() {
    if [ "${DISK_BUS:-virtio}" = nvme ]; then echo "-device nvme,serial=lantern,drive=disk"; else echo "-device virtio-blk-device,drive=disk"; fi
}
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
MODEL=$(scripts/get-model.sh) || exit 2
(cd tools/mkdisk && cargo run -q --target "$HOST" -- --out "$WORK/disk.img" --bootable --loader "$WORK/BOOTRISCV64.EFI" \
    --boot-image "$OLDPWD/$TARGET/lantern-boot-system" --package "$OLDPWD/assets/probe.lpkg" \
    --package "$OLDPWD/assets/fs-probe.lpkg" --package "$OLDPWD/assets/file-assistant.lpkg" --model "$MODEL") >/dev/null || exit 2
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
    qemu-system-riscv64 -machine "${MACHINE:-virt}",acpi=off ${SMP:+-smp "$SMP"} ${CPU:+-cpu "$CPU"} -m 256M -nographic \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$CODE" -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
        -global virtio-mmio.force-legacy=false -drive "if=none,format=raw,file=$WORK/disk.img,id=disk" \
        $(disk_device) <"$WORK/in" >"$WORK/out" 2>&1 &
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

# expect_nth <text> <n>: as `expect`, for the n-th time it appears.
expect_nth() {
    for _ in $(seq 1 900); do
        [ "$(grep -aoF -- "$1" "$WORK/out" | wc -l)" -ge "$2" ] && return 0
        sleep 0.1
    done
    fail "no \"$1\" on the console $2 times"
    return 1
}

store_seq() {
    python3 - "$WORK/disk.img" "$STORE_SECTOR" <<'PY'
import struct, sys
disk, first = open(sys.argv[1], 'rb').read(), int(sys.argv[2])
seqs = []
for i in range(2):
    at = (first + i * 32) * 512
    if disk[at:at + 8] in (b'LSTORE01', b'LSTORE02'):
        seqs.append(struct.unpack_from('<Q', disk, at + 8)[0])
print(max(seqs) if seqs else 0)
PY
}

PROMPT='allow? [y]es once, [a]lways, [n]o, n[e]ver >'
DONE='lantern: "confined-fs-probe" finished.'
AGENT_DONE='lantern: "file-assistant" finished.'
CONTINUED='Spot. Spot loved to play outside in the sun.'

CASE='the firmware boots LanternOS from its disk'
boot
expect 'Lantern EFI loader: starting LanternOS' && expect 'Type help for commands.'
printf 'run confined-fs-probe\r' >&3
expect "$PROMPT" && printf 'a\r' >&3 && expect "$DONE"
printf 'write 1 Once upon a time, there was a little dog named\r' >&3 && expect 'written, as you.'
printf 'run file-assistant\r' >&3
for n in 2 3 4; do
    expect_nth "$PROMPT" "$n" && printf 'a\r' >&3
done
expect "$AGENT_DONE" && printf 'read 2\r' >&3 && expect "  $CONTINUED"
stop
grep -aq 'PANIC' "$WORK/out" && fail 'a panic'
# RFC-0039: the loader handed over what EDK2 keeps after ExitBootServices, and boot reserved it.
kept=$(grep -a -o 'the firmware keeps [0-9]* ranges' "$WORK/out" | head -1 | awk '{ print $4 }')
[ "${kept:-0}" -gt 0 ] || fail "want the firmware's reserved ranges handed over, got ${kept:-none}"
# Three writes: the app's, the person's, the assistant's.
[ "$(store_seq)" = 3 ] || fail "want the store's third image on the disk, got $(store_seq)"
[ "$failures" = 0 ] && printf 'ok    %s\n' "$CASE"

CASE='a reboot keeps the decision and the file'
before=$failures
boot
expect 'Type help for commands.'
printf 'run confined-fs-probe\r' >&3
expect "$DONE"
printf 'run file-assistant\r' >&3
expect "$AGENT_DONE" && printf 'read 2\r' >&3 && expect "  $CONTINUED"
stop
grep -aqF "$PROMPT" "$WORK/out" && fail 'asked again: the decision was lost'
[ "$(store_seq)" = 5 ] || fail "want the store's fifth image, got $(store_seq)"
[ "$failures" = "$before" ] && printf 'ok    %s\n' "$CASE"

# RFC-0039: the same image, loaded away from its link address, relocates itself. A loader built `place-high` takes
# wherever EDK2's allocator puts it, high in RAM, instead of the lowest free range, which here is the link address.
CASE='a kernel loaded away from its link address relocates itself'
before=$failures
(cd efi-loader && cargo build -q --release --features place-high) || exit 2
(cd tools/elf2efi && cargo run -q --target "$HOST" -- ../../efi-loader/$TARGET/lantern-efi-loader "$WORK/BOOTRISCV64.EFI") || exit 2
(cd tools/mkdisk && cargo run -q --target "$HOST" -- --out "$WORK/disk.img" --bootable --loader "$WORK/BOOTRISCV64.EFI" \
    --boot-image "$OLDPWD/$TARGET/lantern-boot-system" --package "$OLDPWD/assets/probe.lpkg" \
    --package "$OLDPWD/assets/fs-probe.lpkg" --package "$OLDPWD/assets/file-assistant.lpkg" --model "$MODEL") >/dev/null || exit 2
cp "$VARS_TEMPLATE" "$WORK/vars.fd"
boot
expect 'Type help for commands.'
printf 'run confined-fs-probe\r' >&3
expect "$PROMPT" && printf 'a\r' >&3 && expect "$DONE"
stop
at=$(grep -a -o 'running at 0x[0-9a-f]*' "$WORK/out" | head -1 | awk '{ print $3 }')
[ -n "$at" ] && [ "$at" != 0x80200000 ] || fail "want the kernel away from its link address, got ${at:-nothing}"
grep -aq 'PANIC' "$WORK/out" && fail 'a panic'
(cd efi-loader && cargo build -q --release) || exit 2
[ "$failures" = "$before" ] && printf 'ok    %s (at %s)\n' "$CASE" "$at"

[ "$failures" -eq 0 ] && echo 'all passed' || { echo "$failures failed"; exit 1; }
