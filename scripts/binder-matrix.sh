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
set -u
cd "$(dirname "$0")/.."
SDK="${LANTERN_SDK:-../lantern-sdk}"
TARGET=target/riscv64gc-unknown-none-elf/release
WORK=$(mktemp -d)
mkdir -p "$WORK/keep"
cp assets/probe.lpkg assets/fs-probe.lpkg "$WORK/keep/"
cleanup() { cp "$WORK/keep/"*.lpkg assets/; rm -rf "$WORK"; }
trap cleanup EXIT

(cd "$SDK" && cargo build -q --example resign) || exit 2
RESIGN="$SDK/target/debug/examples/resign"
[ -x "$RESIGN" ] || { echo "no resign binary at $RESIGN" >&2; exit 2; }

# Prints the demo's `Signal'd` result: `SUCCESS`, `FAILURE:<stage>:<detail>`, or NO-SIGNAL.
# QEMU never exits by itself, since the demos park after signalling.
run_demo() {
    local out="$WORK/qemu.out"
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M -kernel "$1" </dev/null >"$out" 2>&1 &
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

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
