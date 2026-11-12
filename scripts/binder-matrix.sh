#!/usr/bin/env bash
# RFC-0020's negative matrix: runs each runtime demo under QEMU with a package carrying a
# hostile manifest, and checks what the confined runtime signals. Exits nonzero on any
# mismatch, restoring the assets either way.
#
#   LANTERN_SDK     path to a lantern-sdk checkout (default: ../lantern-sdk)
#   LANTERN_SHELL   path to a lantern-shell checkout, for `audit-dump` (default: ../lantern-shell)
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
#
# RFC-0025: every runtime `SUCCESS` also had `grant-control` check each use the guest made of its grant, and the
# `use:` and `retain:` cases check exact sequences, the quota, and retention across a full ring, from outside.
set -u
cd "$(dirname "$0")/.."
SDK="${LANTERN_SDK:-../lantern-sdk}"
SHELL_REPO="${LANTERN_SHELL:-../lantern-shell}"
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
(cd "$SHELL_REPO/policy-store" && cargo build -q --example audit-dump --target x86_64-unknown-linux-gnu) || exit 2
DUMP="$SHELL_REPO/policy-store/target/x86_64-unknown-linux-gnu/debug/examples/audit-dump"

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
# check <label> <demo> <asset> <expected> <seed|keep|asis> [manifest text]. FEATURES builds the demo with those
# lantern-boot features.
check() {
    local label=$1 demo=$2 asset=$3 want=$4 seed=$5 manifest=${6-}
    [ -n "${KEEP:-}" ] || cp "$ERASED" "$IMAGE"
    if [ "$seed" != asis ]; then
        printf '%s' "$manifest" >"$WORK/manifest.toml"
        "$RESIGN" "$WORK/keep/$asset" "$WORK/manifest.toml" "assets/$asset" "$seed" || exit 2
    fi
    cargo build -q --release --bin "lantern-boot-$demo-demo" ${FEATURES:+--features "$FEATURES"} || exit 2
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
# One boot of each runtime demo, in full (RFC-0025). The keystore demo: the runtime's own ENCRYPT on its SIGN-only
# grant, refused; the guest's SIGN; both revocations; the request left open across them, refused; the second SIGN,
# refused. The filesystem demo: store-service's own grant on the keystore; then the guest's fresh READ, its WRITE and
# that WRITE's ENCRYPT, two READs each with its DECRYPT (the oversized write is refused by the runtime before any
# service sees it); both revocations; and the open request and second probe, refused.
K1='BOOT GRANTING GRANTED DECLINED:NOT_DECLARED USING USE_FAILED:ACCESS USING REVOKING REVOKING USING USE_FAILED:ACCESS USING USE_FAILED:ACCESS'
F1='BOOT SERVICE_GRANTED GRANTING GRANTED DECLINED:NOT_DECLARED USING USING USING USING USING USING USING REVOKING REVOKING USING USE_FAILED:ACCESS USING USE_FAILED:ACCESS'
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

# audit <label> <events>: the audit log's events, as EVENT or EVENT:REASON, must be exactly <events>,
# with a verifying chain. `CORRUPT` expects the dump to refuse the log.
audit() {
    local label=$1 want=$2 got
    got=$("$DUMP" "$IMAGE" | awk '/^record/ { printf "%s%s%s", sep, $3, ($4 == "-" ? "" : ":" $4); sep = " " } /^CORRUPT/ { printf "CORRUPT" }')
    if [ "$got" = "$want" ]; then
        printf 'ok    %-44s %s\n' "$label" "$got"
    else
        printf 'FAIL  %-44s want %s, got %s\n' "$label" "$want" "$got"
        failures=$((failures + 1))
    fi
}

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
audit 'audit: erasing left one boot'               "$K1"

# RFC-0024. `grant-control` verifies the chain and this boot's records inside every runtime `SUCCESS` above;
# these check the log across boots, from outside. The audit log's first header is at 0x80000 (sector 2, RFC-0026), then 64-byte records.
check 'audit: first boot'                          $P $K SUCCESS asis
audit 'audit: one boot is recorded'                "$K1"
KEEP=1 check 'audit: second boot'                  $P $K FAILURE:8 asis
audit 'audit: the log continues across boots'      "$K1 BOOT DECLINED:REVOKED"

check 'audit: app not in policy'                   $P $K FAILURE:8 4c "$(app other-app)
$(key probe-signing '"sign"')"
audit 'audit: records why'                         'BOOT DECLINED:NOT_IN_POLICY'
check 'audit: no granter for the interface'        $F $L FAILURE:7 4c "$(app confined-probe)
$(key probe-signing '"sign"')"
audit 'audit: a refused grant is recorded'         'BOOT SERVICE_GRANTED GRANTING GRANT_FAILED'

check 'audit: first boot, to edit'                 $P $K SUCCESS asis
patch_image $((0x80044)) '\x5a\xa5\x5a\xa5'
audit 'audit: an edited record reads as corrupt'   CORRUPT
KEEP=1 check 'audit: corrupt log declines grants'  $F $L FAILURE:8 asis

# Only the last record can be torn: the first boot writes 13, so the last is index 12.
check 'audit: first boot, to tear'                 $P $K SUCCESS asis
patch_image $((0x80040 + 12 * 64 + 60)) '\xff\xff\xff\xff'
KEEP=1 check 'audit: a torn record recovers'       $F $L SUCCESS asis
audit 'audit: and the chain continues'             "${K1% USE_FAILED:ACCESS} $F1"

# The known limit: without a key held in hardware, the whole chain can be rewritten consistently.
check 'audit: first boot, to rewrite'              $P $K SUCCESS asis
KEPT=$("$DUMP" "$IMAGE" | sed -n 's/^chain ok count=\([0-9]*\) head=\([0-9a-f]*\)$/\1 \2/p')
"$DUMP" "$IMAGE" --forge-drop 1 "$WORK/forged.img" >/dev/null
cp "$WORK/forged.img" "$IMAGE"
audit 'audit: KNOWN LIMIT, a rewrite verifies'     "BOOT ${K1#BOOT GRANTING }"
KEEP=1 check 'audit: and the store accepts it'     $F $L SUCCESS asis
# shellcheck disable=SC2086
if "$DUMP" "$IMAGE" --kept $KEPT >/dev/null; then
    printf 'FAIL  %-44s a kept head missed the rewrite\n' 'audit: a kept head reveals it'
    failures=$((failures + 1))
else
    printf 'ok    %-44s %s\n' 'audit: a kept head reveals it' MISMATCH
fi

# RFC-0025: every use of a grant, recorded by the service before it acts. `grant-control` checks each run's uses
# against its grant from inside; these check the exact sequences from outside, against each guest's code.
check 'use: filesystem, one boot'                  $F $L SUCCESS asis
audit 'use: every read, write, encrypt, decrypt'   "$F1"
# A quota of one: the fresh read is recorded, the write reaches it and never runs, and so there is no ENCRYPT.
FEATURES=audit-quota-test check 'use: quota of one'  $F $L FAILURE:8 asis
audit 'use: the write past the quota never ran'    'BOOT SERVICE_GRANTED GRANTING GRANTED DECLINED:NOT_DECLARED USING QUOTA_REACHED'
FEATURES=audit-quota-test check 'use: quota, keystore' $P $K FAILURE:8 asis
audit 'use: a refused USE_FAILED is still named'   'BOOT GRANTING GRANTED DECLINED:NOT_DECLARED USING QUOTA_REACHED:ACCESS'

# Retention. The ring holds 6 * 4095 records, in sectors 2 to 7. Fill to five short of it, so the next boot retires sector 2 mid-run.
# retention <label>: the dump must verify, hold from 4095, and show exactly one RETIRED, of sector 2.
retention() {
    local label=$1 got
    got=$("$DUMP" "$IMAGE" | awk '/^CORRUPT/ { print "CORRUPT"; exit } /^oldest/ { oldest = $2 }
        /^record/ && $3 == "RETIRED" { retired = retired " " $6 } END { if (oldest != "") print "oldest=" oldest " retired:" retired }')
    if [ "$got" = 'oldest=4095 retired: slot=2' ]; then
        printf 'ok    %-44s %s\n' "$label" "$got"
    else
        printf 'FAIL  %-44s want oldest=4095 retired: slot=2, got %s\n' "$label" "$got"
        failures=$((failures + 1))
    fi
}
CAPACITY=$((6 * 4095))
check 'retain: first boot, to keep its head'       $P $K SUCCESS asis
EARLY=$("$DUMP" "$IMAGE" | sed -n 's/^chain ok count=\([0-9]*\) head=\([0-9a-f]*\)$/\1 \2/p')
"$DUMP" "$IMAGE" --fill $((CAPACITY - 5 - ${EARLY%% *})) "$WORK/filled.img" >/dev/null
cp "$WORK/filled.img" "$IMAGE"
LATE=$("$DUMP" "$IMAGE" | sed -n 's/^chain ok count=\([0-9]*\) head=\([0-9a-f]*\)$/\1 \2/p')
KEEP=1 check 'retain: a boot across the full ring'  $F $L SUCCESS asis
retention 'retain: the oldest sector was retired'
# kept <label> <count head> <exit>: audit-dump --kept's exit: 0 matches, 3 mismatch, 4 retired.
kept() {
    local label=$1 code
    # shellcheck disable=SC2086
    "$DUMP" "$IMAGE" --kept $2 >/dev/null
    code=$?
    if [ "$code" = "$3" ]; then
        printf 'ok    %-44s exit %s\n' "$label" "$code"
    else
        printf 'FAIL  %-44s want exit %s, got %s\n' "$label" "$3" "$code"
        failures=$((failures + 1))
    fi
}
kept 'retain: a head kept after it still matches'   "$LATE" 0
kept 'retain: a head kept before it is RETIRED'      "$EARLY" 4

# A power cut mid-retirement: the ring is exactly full, and sector 2 is half erased, or erased with no header.
"$DUMP" "$ERASED" --fill "$CAPACITY" "$WORK/full.img" >/dev/null
for cut in 'half erased:131072' 'erased, no header:262144'; do
    cp "$WORK/full.img" "$IMAGE"
    head -c "${cut#*:}" "$ERASED" | dd of="$IMAGE" bs=1 seek=$((0x80000)) conv=notrunc status=none
    KEEP=1 check "retain: cut mid-erase, ${cut%:*}"  $P $K SUCCESS asis
    retention "retain: finished, ${cut%:*}"
done

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
