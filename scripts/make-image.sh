#!/usr/bin/env bash
# Builds an installable LanternOS disk ([RFC-0032](../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)): the EFI
# loader, converted to PE/COFF; the interactive system's boot image; and a bootable GPT disk holding both on its EFI System
# Partition, with the packages in assets/ on its packages partition, an empty store, and an erased policy log.
#
#   scripts/make-image.sh <out.img> [package.lpkg ...]   (default packages: assets/probe.lpkg assets/fs-probe.lpkg)
#
# Boot it as README.md shows. Rebuilding over an image erases what was on it.
set -eu
CALLER=$(pwd)
cd "$(dirname "$0")/.."
BOOT=$(pwd)
OUT=${1:?usage: scripts/make-image.sh <out.img> [package.lpkg ...]}
shift
case "$OUT" in /*) ;; *) OUT="$CALLER/$OUT" ;; esac
# Paths given are the caller's; the defaults are this repository's.
[ $# -gt 0 ] || { CALLER=$BOOT; set -- assets/probe.lpkg assets/fs-probe.lpkg; }
HOST=$(rustc -vV | sed -n 's/^host: //p')
TARGET=target/riscv64gc-unknown-none-elf/release
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

(cd efi-loader && cargo build -q --release)
(cd tools/elf2efi && cargo run -q --target "$HOST" -- "$BOOT/efi-loader/$TARGET/lantern-efi-loader" "$WORK/BOOTRISCV64.EFI")
cargo build -q --release --bin lantern-boot-system
packages=()
for p in "$@"; do
    case "$p" in /*) packages+=(--package "$p") ;; *) packages+=(--package "$CALLER/$p") ;; esac
done
(cd tools/mkdisk && cargo run -q --target "$HOST" -- --out "$OUT" --bootable --loader "$WORK/BOOTRISCV64.EFI" \
    --boot-image "$BOOT/$TARGET/lantern-boot-system" "${packages[@]}")
