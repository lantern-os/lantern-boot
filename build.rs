//! Links this crate's boot images position-independent ([RFC-0039](../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)
//! §1), so one image runs wherever the firmware's RAM is: QEMU's starts at `0x8000_0000`, the K3's at `0x1_0200_0000`.
//!
//! RISC-V's default `medany` code model already reaches everything PC-relatively, so only data holding addresses needs
//! fixing up: the linker leaves those as `R_RISCV_RELATIVE` entries, written for the link address
//! (`--apply-dynamic-relocs`), and `src/entry.rs` adds the load offset to each before anything reads them. `-z notext`
//! lets those entries sit in read-only data such as vtables, which is fine: the image is fixed up with paging off.
//!
//! Only for `riscv64`, so host tests link normally, and only for this crate's binaries, not the programs in its
//! subdirectories, which `.cargo/config.toml` also reaches.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv64") {
        for arg in ["-pie", "--no-dynamic-linker", "-z", "notext", "--apply-dynamic-relocs"] {
            println!("cargo:rustc-link-arg-bins={arg}");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.ld");
}
