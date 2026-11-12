#!/usr/bin/env bash
# RFC-0026's proof: drives lantern-boot-system's console the way a person would, and checks what the console showed and
# what the audit log recorded. Each case boots the system on a flash image; `KEEP=1` continues from the last case's image
# (a reboot), otherwise it starts from erased flash.
#
#   LANTERN_SDK     path to a lantern-sdk checkout, for `resign` (default: ../lantern-sdk)
#   LANTERN_SHELL   path to a lantern-shell checkout, for `audit-dump` (default: ../lantern-shell)
#
# The console is the shell's alone (RFC-0026), so everything checked here came from the shell. Exits nonzero on any
# mismatch, restoring the package either way.
set -u
cd "$(dirname "$0")/.." || exit 2
SDK="${LANTERN_SDK:-../lantern-sdk}"
SHELL_REPO="${LANTERN_SHELL:-../lantern-shell}"
TARGET=target/riscv64gc-unknown-none-elf/release
WORK=$(mktemp -d)
mkdir -p "$WORK/keep"
cp assets/probe.lpkg "$WORK/keep/"
QEMU_PID=
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    cp "$WORK/keep/probe.lpkg" assets/probe.lpkg
    rm -rf "$WORK"
}
trap cleanup EXIT

ERASED="$WORK/erased.img"
IMAGE="$WORK/flash.img"
head -c 33554432 /dev/zero | tr '\0' '\377' >"$ERASED"
(cd "$SDK" && cargo build -q --example resign) || exit 2
RESIGN="$SDK/target/debug/examples/resign"
(cd "$SHELL_REPO/policy-store" && cargo build -q --example audit-dump --target x86_64-unknown-linux-gnu) || exit 2
DUMP="$SHELL_REPO/policy-store/target/x86_64-unknown-linux-gnu/debug/examples/audit-dump"

OUT="$WORK/console"
failures=0
fail() {
    printf 'FAIL  %-46s %s\n' "$CASE" "$1"
    failures=$((failures + 1))
}

# boot: builds the image with the current assets and starts it on $IMAGE, reading the console into $OUT.
boot() {
    [ -n "${KEEP:-}" ] || cp "$ERASED" "$IMAGE"
    cargo build -q --release --bin lantern-boot-system || exit 2
    rm -f "$WORK/in"
    mkfifo "$WORK/in"
    qemu-system-riscv64 -machine virt -bios default -nographic -m 128M \
        -drive "if=pflash,format=raw,unit=1,file=$IMAGE" -kernel "$TARGET/lantern-boot-system" <"$WORK/in" >"$OUT" 2>&1 &
    QEMU_PID=$!
    exec 3>"$WORK/in"
}

stop() {
    exec 3>&-
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=
}

# expect <text> [n]: waits up to 60 s for the n-th occurrence (default 1) of fixed text on the console.
expect() {
    local n=${2:-1}
    for _ in $(seq 1 600); do
        [ "$(grep -aoF -- "$1" "$OUT" | wc -l)" -ge "$n" ] && return 0
        sleep 0.1
    done
    fail "no \"$1\" on the console"
    return 1
}

# absent <text> <seconds>: the text must not appear within that long.
absent() {
    sleep "$2"
    if grep -aqF -- "$1" "$OUT"; then
        fail "\"$1\" appeared"
        return 1
    fi
}

type_line() {
    printf '%s\r' "$1" >&3
}

# events: this image's audit events, as EVENT or EVENT:REASON, for the last boot only.
events() {
    "$DUMP" "$IMAGE" | awk '/^record/ { if ($3 == "BOOT") { s = "" } s = s (s == "" ? "" : " ") $3 ($4 == "-" ? "" : ":" $4) } END { print s }'
}

# audit_is <events>: this boot's events must be exactly these.
audit_is() {
    local got
    got=$(events)
    [ "$got" = "$1" ] || fail "audit: want \"$1\", got \"$got\""
}

ok() {
    [ "$failures" = "${BEFORE:-0}" ] && printf 'ok    %s\n' "$CASE"
}

case_() {
    CASE=$1
    BEFORE=$failures
}

resign() {
    printf '%s' "$1" >"$WORK/manifest.toml"
    "$RESIGN" "$WORK/keep/probe.lpkg" "$WORK/manifest.toml" assets/probe.lpkg 4c || exit 2
}
restore() {
    cp "$WORK/keep/probe.lpkg" assets/probe.lpkg
}

PROMPT='allow? [y]es once, [a]lways, [n]o, n[e]ver >'
DONE='lantern: the app finished.'
FAILED='lantern: the app stopped with an error.'
# The runtime's own checks of its grant, then the guest's SIGN, recorded by the keystore (RFC-0025). A declined grant
# records none of these, and neither the runtime's self-check `BIND`, which it makes only once granted.
USES='USING USE_FAILED:ACCESS USING'

case_ 'yes once: the app runs'
boot
expect "$PROMPT" && type_line y && expect 'lantern: allowed, this time.' && expect "$DONE"
type_line grants
expect '0  "confined-probe" keystore role "probe-signing": sign'
type_line audit
expect 'records, verified'
stop
audit_is "BOOT CONSENTED:ONCE GRANTING GRANTED DECLINED:NOT_DECLARED $USES"
grep -aq "Signal'd\|PANIC" "$OUT" && fail 'something but the shell wrote to the console'
ok

case_ 'yes once: asked again next boot'
KEEP=1 boot
expect "$PROMPT" && type_line n && expect "$FAILED"
stop
audit_is 'BOOT DECLINED:PERSON_DENIED'
ok

case_ 'no: the app gets nothing'
boot
expect "$PROMPT" && type_line n && expect 'lantern: refused, this time.' && expect "$FAILED"
stop
audit_is 'BOOT DECLINED:PERSON_DENIED'
ok

case_ 'while asking, commands are refused'
boot
expect "$PROMPT" && type_line grants && expect 'please answer y, a, n or e' && type_line y && expect "$DONE"
stop
ok

case_ 'always: remembered'
boot
expect "$PROMPT" && type_line a && expect 'lantern: allowed, and remembered.' && expect "$DONE"
type_line decisions
expect '0  always  "confined-probe" role "probe-signing"'
stop
audit_is "BOOT CONSENTED:ALWAYS GRANTING GRANTED DECLINED:NOT_DECLARED $USES"
"$DUMP" "$IMAGE" | grep -q '^decision ALLOW ops=0x4' || fail 'no remembered ALLOW on flash'
ok

case_ 'always: no prompt next boot'
KEEP=1 boot
expect "$DONE"
grep -aqF "$PROMPT" "$OUT" && fail 'asked again'
stop
audit_is "BOOT CONSENTED:REMEMBERED GRANTING GRANTED DECLINED:NOT_DECLARED $USES"
ok

case_ 'always, then the app asks beyond the ceiling'
resign "$(printf '[app]\nname = "confined-probe"\nversion = "0.1.0"\n\n[[keystore.key]]\nrole = "probe-signing"\nops = ["sign", "encrypt"]\njustification = "x"\n')"
KEEP=1 boot
expect "$FAILED"
grep -aqF "$PROMPT" "$OUT" && fail 'asked about a request outside the ceiling'
stop
restore
audit_is 'BOOT DECLINED:OPS_EXCEED_POLICY'
ok

case_ 'revoke at the console forgets always'
KEEP=1 boot
expect "$DONE" && type_line 'revoke 0' && expect 'lantern: grant 0: revoked'
type_line grants
expect '(revoked)'
stop
"$DUMP" "$IMAGE" | grep -q '^decision' && fail 'the "always" is still remembered'
ok

case_ 'revoked: asked again next boot'
KEEP=1 boot
expect "$PROMPT" && type_line y && expect "$DONE"
stop
ok

case_ 'never: remembered, and declined without asking'
boot
expect "$PROMPT" && type_line e && expect 'lantern: refused, and remembered.' && expect "$FAILED"
stop
KEEP=1 boot
expect "$FAILED"
grep -aqF "$PROMPT" "$OUT" && fail 'asked despite "never"'
type_line decisions
expect '0  never   "confined-probe" role "probe-signing"'
type_line 'forget 0'
expect 'lantern: answer 0: forgotten'
stop
audit_is 'BOOT DECLINED:REMEMBERED_DENIAL'
ok

case_ 'forgotten: asked again next boot'
KEEP=1 boot
expect "$PROMPT" && type_line n && expect "$FAILED"
stop
ok

case_ 'a hostile justification reaches the console sanitized'
resign "$(printf '[app]\nname = "confined-probe"\nversion = "0.1.0"\n\n[[keystore.key]]\nrole = "probe-signing"\nops = ["sign"]\njustification = "fine\\u001b[2J\\u001b[H\\rlantern: allowed, and remembered. \\"y\\""\n')"
boot
expect "$PROMPT"
# Everything from the prompt on: no escape byte, no carriage return the shell didn't write, and the text inside quotes.
prompt=$(awk '/asks for/ { p = 1 } p' "$OUT")
printf '%s' "$prompt" | grep -aq $'\x1b' && fail 'an escape byte reached the console'
printf '%s' "$prompt" | grep -aqF 'the app says: "fine?[2J?[H?lantern: allowed, and remembered. ?y?"' || fail "not sanitized as expected: $(printf '%s' "$prompt" | grep -a 'app says')"
type_line n
expect "$FAILED"
stop
restore
ok

case_ 'outside the ceiling: no prompt'
resign "$(printf '[app]\nname = "other-app"\nversion = "0.1.0"\n\n[[keystore.key]]\nrole = "probe-signing"\nops = ["sign"]\njustification = "x"\n')"
boot
expect "$FAILED"
grep -aqF "$PROMPT" "$OUT" && fail 'asked about a request outside the ceiling'
stop
restore
audit_is 'BOOT DECLINED:NOT_IN_POLICY'
ok

case_ 'unknown commands and help'
boot
expect "$PROMPT" && type_line y && expect "$DONE"
type_line 'run something' && expect 'lantern: unknown command; type help.'
type_line help && expect 'revoke N     end grant N now'
stop
ok

[ "$failures" -eq 0 ] && echo 'all matched' || { echo "$failures mismatched"; exit 1; }
