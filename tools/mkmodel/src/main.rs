//! `lantern-mkmodel <checkpoint.bin> <tokenizer.bin> <out.lmodel>`: a llama2.c f32 checkpoint and its tokenizer, to an
//! `LMODEL01` model file ([RFC-0034](../../../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)). Prints
//! the file's BLAKE3 digest, which the inference service checks the model on its disk against.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [checkpoint, tokenizer, out] = args.as_slice() else {
        eprintln!("usage: lantern-mkmodel <checkpoint.bin> <tokenizer.bin> <out.lmodel>");
        return ExitCode::FAILURE;
    };
    let read = |p: &String| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let result = (|| -> Result<blake3::Hash, String> {
        let file = lantern_ai_runtime::convert::convert(&read(checkpoint)?, &read(tokenizer)?)?;
        std::fs::write(out, &file).map_err(|e| format!("{out}: {e}"))?;
        Ok(blake3::hash(&file))
    })();
    match result {
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
