//! `lantern-elf2efi <in.elf> <out.efi>`: see `lib.rs`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, output] = args.as_slice() else {
        eprintln!("usage: lantern-elf2efi <in.elf> <out.efi>");
        return ExitCode::FAILURE;
    };
    let result = std::fs::read(input)
        .map_err(|e| format!("{input}: {e}"))
        .and_then(|elf| lantern_elf2efi::read_elf(&elf).map_err(|e| format!("{input}: {e}")))
        .and_then(|image| std::fs::write(output, lantern_elf2efi::write_pe(&image)).map_err(|e| format!("{output}: {e}")));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lantern-elf2efi: {e}");
            ExitCode::FAILURE
        }
    }
}
