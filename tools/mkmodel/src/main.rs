//! `lantern-mkmodel`: makes a signed model package ([RFC-0038](../../../../lantern-rfcs/rfcs/0038-signed-models-and-kept-audit-history.md)).
//!
//! ```text
//! lantern-mkmodel <checkpoint.bin> <tokenizer.bin> <out.lmod> --seed <64-hex> [--name <name>]
//! lantern-mkmodel --repackage <in.lmod> <out.lmod> --seed <64-hex> [--name <name>]
//! ```
//!
//! The first converts a llama2.c f32 checkpoint and its tokenizer to an `LMODEL01` model
//! ([RFC-0034](../../../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)). The second takes the model out
//! of an existing package. Either way it signs the model as its publisher, the key from `--seed`, and writes the package
//! (`lantern_sdk::model`). It prints the model's BLAKE3 digest. The name defaults to the output file's stem.
//!
//! The seed is the publisher's private key. `4c4c…4c` is the **public** demo seed the system trusts for apps and models
//! alike.

use std::process::ExitCode;

use lantern_crypto::signing::{SigningKey, SEED_LEN};

fn main() -> ExitCode {
    match run() {
        Ok(digest) => {
            println!("{digest}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("lantern-mkmodel: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage: lantern-mkmodel <checkpoint.bin> <tokenizer.bin> <out.lmod> --seed <64-hex> [--name <name>]\n       \
                     lantern-mkmodel --repackage <in.lmod> <out.lmod> --seed <64-hex> [--name <name>]";

fn run() -> Result<blake3::Hash, String> {
    let mut positional = Vec::new();
    let (mut seed, mut name, mut repackage) = (None, None, false);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => seed = Some(args.next().ok_or(USAGE)?),
            "--name" => name = Some(args.next().ok_or(USAGE)?),
            "--repackage" => repackage = true,
            _ => positional.push(arg),
        }
    }
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let (model, out) = match (repackage, positional.as_slice()) {
        (false, [checkpoint, tokenizer, out]) => {
            (lantern_ai_runtime::convert::convert(&read(checkpoint)?, &read(tokenizer)?)?, out.clone())
        }
        (true, [input, out]) => {
            let bytes = read(input)?;
            let package = lantern_sdk::model::decode_model(&bytes).map_err(|e| format!("{input}: {e}"))?;
            (package.model.to_vec(), out.clone())
        }
        _ => return Err(USAGE.into()),
    };
    let key = SigningKey::from_random_bytes(parse_seed(&seed.ok_or("--seed <64-hex> is required")?)?);
    let name = name.unwrap_or_else(|| {
        std::path::Path::new(&out).file_stem().map_or("model".into(), |s| s.to_string_lossy().into_owned())
    });
    let package = lantern_sdk::model::encode_model(&name, &model, &key)
        .ok_or("the name must be 1 to 64 bytes, with no newline, and the model under 4 GiB")?;
    std::fs::write(&out, &package).map_err(|e| format!("{out}: {e}"))?;
    Ok(blake3::hash(&model))
}

fn parse_seed(hex: &str) -> Result<[u8; SEED_LEN], String> {
    let hex = hex.trim();
    if hex.len() != SEED_LEN * 2 {
        return Err(format!("--seed must be {} hex digits", SEED_LEN * 2));
    }
    let mut seed = [0u8; SEED_LEN];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "--seed is not hex")?;
    }
    Ok(seed)
}
