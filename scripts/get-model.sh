#!/usr/bin/env bash
# The model the image ships (RFC-0034): downloads Andrej Karpathy's TinyStories `stories15M` checkpoint and llama2.c's
# tokenizer once, checks each against the SHA-256 pinned here, converts them with `lantern-mkmodel`, checks the converted
# model against the digest pinned here (the conversion is exact, so it's reproducible), and signs it as a model package
# (RFC-0038) under the **public** demo publisher seed the system trusts. Prints the package's path.
#
# Both are MIT-licensed. About 61 MB, downloaded once into $LANTERN_MODEL_CACHE (default ~/.cache/lantern).
set -eu
cd "$(dirname "$0")/.."
CACHE=${LANTERN_MODEL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/lantern}
mkdir -p "$CACHE"
HOST=$(rustc -vV | sed -n 's/^host: //p')

fetch() { # <file> <url> <sha256>
    if [ ! -f "$CACHE/$1" ] || ! echo "$3  $CACHE/$1" | sha256sum -c --status; then
        echo "get-model: downloading $1" >&2
        curl -fsSL -o "$CACHE/$1.part" "$2"
        echo "$3  $CACHE/$1.part" | sha256sum -c --status || { echo "get-model: $1 doesn't match its pinned SHA-256" >&2; exit 1; }
        mv "$CACHE/$1.part" "$CACHE/$1"
    fi
}
fetch stories15M.bin \
    https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories15M.bin \
    cd590644d963867a2b6e5a1107f51fad663c41d79c149fbecbbb1f95fa81f49a
fetch tokenizer.bin \
    https://raw.githubusercontent.com/karpathy/llama2.c/350e04fe35433e6d2941dce5a1f53308f87058eb/tokenizer.bin \
    50a52ef822ee9e83de5ce9d0be0a025a773d019437f58b5ff9dcafb063ece361

# The converted model's BLAKE3 digest: the conversion is exact, so a different one means a different input or converter.
WANT=7fad9779c58b107e51e8945aa8891d0bf5a2b66afbc2499adc4b45c161d275a9
DEMO_SEED=4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c
MODEL="$CACHE/stories15M.lmod"
if [ ! -f "$MODEL" ] || [ "$(cat "$MODEL.digest" 2>/dev/null)" != "$WANT" ]; then
    digest=$(cd tools/mkmodel && cargo run -q --release --target "$HOST" -- \
        "$CACHE/stories15M.bin" "$CACHE/tokenizer.bin" "$MODEL" --seed "$DEMO_SEED" --name stories15M)
    [ "$digest" = "$WANT" ] || { echo "get-model: the model converted to $digest, not $WANT" >&2; exit 1; }
    echo "$digest" > "$MODEL.digest"
fi
echo "$MODEL"
