#!/usr/bin/env bash
# RFC-0020's negative matrix: runs each runtime demo under QEMU with a package carrying a
# hostile manifest, and checks what the confined runtime signals. Exits nonzero on any
# mismatch, restoring the assets either way.
#
#   LANTERN_SDK   path to a lantern-sdk checkout (default: ../lantern-sdk)
#
# Expected values are `SUCCESS`, or `FAILURE:<stage>[:<detail>]`, with stages from
# lantern-runtime/confined-runtime/src/lib.rs. A declined grant has no stage of its own: the
# guest sees `none` and reports an error, which is stage 8 (Verdict).
#
# Every `SUCCESS` here also ran RFC-0021's revocation: the runtime's own badge refused the control
# ops, a request left open across the revocation, `grant-control`'s empty, out-of-range and repeated
# requests, and a second `probe` that had to report the refusal. See `grant-control/src/main.rs`.
#
# Each case gets a freshly erased flash image, unless it sets KEEP to continue from the last case's
# (RFC-0022). A second boot is simply a second run on the same image.
set -u
cd "$(dirname "$0")/.."
SDK="${LANTERN_SDK:-../lantern-sdk}"
TARGET=target/riscv64gc-unknown-none-elf/release
WORK=$(mktemp -d)
mkdir -p "$WORK/keep"
cp assets/probe.lpkg assets/fs-probe.lpkg "$WORK/keep/"
cleanup() { cp "$WORK/keep/"*.lpkg assets/; rm -rf "$WORK"; }
trap cleanup EXIT
# `virt.flash1` must be exactly 32 MiB. Erased flash reads as all ones.
ERASED="$WORK/erased.img"
IMAGE="$WORK/flash.img"
head -c 33554432 /dev/zero | tr '\0' '\377' >"$ERASED"

(cd "$SDK" && cargo build -q --example resign) || exit 2
RESIGN="$SDK/target/debug/examples/resign"
[ -x "$RESIGN" ] || { echo "no resign binary at $RESIGN" >&2; exit 2; }

# Prints the demo's `Signal'd` result: `SUCCESS`, `FAILURE:<stage>:<detail>`, or NO-SIGNAL.
# QEMU never exits by itself, since the demos park after signalling.
run_demo() {
    local out="$WORK/qemu.out"
    local drive=(-drive "if=pflash,format=raw,unit=1,file=$IMAGE")
    [ -n "${NO_FLASH:-}" ] && drive=()
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M "${drive[@]}" -kernel "$1" </dev/null >"$out" 2>&1 &
    local pid=$!
    for _ in $(seq 1 900); do
        grep -aq "Signal'd" "$out" && break
        sleep 0.1
    done
    sleep 0.2
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    grep -a "Signal'd" "$out" | head -1 | sed -nE \
        -e "s/.*Signal'd SUCCESS.*/SUCCESS/p" \
        -e "s/.*Signal'd FAILURE .*stage=([0-9]+) detail=([0-9]+).*/FAILURE:\1:\2/p" | grep . || echo NO-SIGNAL
}

failures=0
# check <label> <demo> <asset> <expected> <seed|keep|asis> [manifest text]
check() {
    local label=$1 demo=$2 asset=$3 want=$4 seed=$5 manifest=${6-}
    [ -n "${KEEP:-}" ] || cp "$ERASED" "$IMAGE"
    if [ "$seed" != asis ]; then
        printf '%s' "$manifest" >"$WORK/manifest.toml"
        "$RESIGN" "$WORK/keep/$asset" "$WORK/manifest.toml" "assets/$asset" "$seed" || exit 2
    fi
    cargo build -q --release --bin "lantern-boot-$demo-demo" || exit 2
    local got
    got=$(run_demo "$TARGET/lantern-boot-$demo-demo")
    cp "$WORK/keep/$asset" "assets/$asset"
    # A wanted `FAILURE:<stage>` matches any detail.
    case "$got" in
        "$want" | "$want":*) printf 'ok    %-44s %s\n' "$label" "$got" ;;
        *)
            printf 'FAIL  %-44s want %s, got %s\n' "$label" "$want" "$got"
            failures=$((failures + 1))
            ;;
    esac
}

app() { printf '[app]\nname = "%s"\nversion = "0.1.0"\n\n' "$1"; }
key() { printf '[[keystore.key]]\nrole = "%s"\nops = [%s]\njustification = "x"\n' "$1" "$2"; }
file() { printf '[[filesystem.file]]\nrole = "%s"\nops = [%s]\njustification = "x"\n' "$1" "$2"; }

P=runtime; K=probe.lpkg; F=runtime-fs; L=fs-probe.lpkg
check 'keystore: the real package'                 $P $K SUCCESS asis
check 'keystore: asks decrypt, approved sign'      $P $K FAILURE:8 4c "$(app confined-probe)
$(key probe-signing '"decrypt"')"
check 'keystore: asks sign+encrypt, not narrowed'  $P $K FAILURE:8 4c "$(app confined-probe)
$(key probe-signing '"sign", "encrypt"')"
check 'keystore: app not in policy'                $P $K FAILURE:8 4c "$(app other-app)
$(key probe-signing '"sign"')"
check 'keystore: role not in policy'               $P $K FAILURE:8 4c "$(app confined-probe)
$(key other-role '"sign"')"
check 'keystore: trusted publisher, not approved'  $P $K FAILURE:8 4d "$(app confined-probe)
$(key probe-signing '"sign"')"
check 'keystore: untrusted publisher'              $P $K FAILURE:9:4 11 "$(app confined-probe)
$(key probe-signing '"sign"')"
check 'keystore: garbage under original signature' $P $K FAILURE:9:4 keep 'this is not = = toml'
check 'keystore: signed, invalid manifest'         $P $K FAILURE:10:1 4c 'this is not = = toml'
check 'keystore: second role reads none'           $P $K SUCCESS 4c "$(app confined-probe)
$(key probe-signing '"sign"')
$(key other-role '"sign"')"

check 'filesystem: the real package'               $F $L SUCCESS asis
check 'filesystem: read-only role, guest writes'   $F $L FAILURE:8 4c "$(app confined-fs-probe)
$(file scratch '"read"')"
check 'filesystem: app not in policy'              $F $L FAILURE:8 4c "$(app other-app)
$(file scratch '"read", "write"')"
check 'filesystem: keystore manifest, no granter'  $F $L FAILURE:7 4c "$(app confined-probe)
$(key probe-signing '"sign"')"

# RFC-0022. The header is 32 bytes, so the first record's key starts at 32 and its check at 48.
patch_image() { printf "$2" | dd of="$IMAGE" bs=1 seek="$1" conv=notrunc status=none; }

check 'store: first boot revokes'                  $P $K SUCCESS asis
KEEP=1 check 'store: second boot is declined'      $P $K FAILURE:8 asis
KEEP=1 check 'store: another role is unaffected'   $F $L SUCCESS asis
KEEP=1 check 'store: and is declined next boot'    $F $L FAILURE:8 asis
KEEP=1 check 'store: the first stays declined'     $P $K FAILURE:8 asis

check 'store: first boot, to corrupt'              $P $K SUCCESS asis
patch_image 32 '\x5a\xa5\x5a\xa5'
KEEP=1 check 'store: corrupt record declines it'   $P $K FAILURE:8 asis
KEEP=1 check 'store: corrupt declines all roles'   $F $L FAILURE:8 asis

check 'store: first boot, to tear'                 $P $K SUCCESS asis
patch_image 48 '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
KEEP=1 check 'store: a torn record was never made' $P $K SUCCESS asis
KEEP=1 check 'store: the log recovered after it'   $P $K FAILURE:8 asis

NO_FLASH=1 check 'store: no flash declines everything' $P $K FAILURE:8 asis

# The known limit, tested so that it stays visible: nothing here resists writing the flash from outside.
check 'store: first boot, to erase'                $P $K SUCCESS asis
cp "$ERASED" "$IMAGE"
KEEP=1 check 'store: KNOWN LIMIT, erasing restores' $P $K SUCCESS asis

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
