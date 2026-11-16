//! `lantern-mkdisk` — [RFC-0031](../../../../lantern-rfcs/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)'s
//! disk-image tool.
//!
//! ```text
//! lantern-mkdisk --out <disk.img> [--size-mib <n>] --package <a.lpkg> [--package <b.lpkg> ...]
//!                [--bootable --loader <BOOTRISCV64.EFI> --boot-image <lantern-boot-system>] [--model <m.lmodel>]
//! ```
//!
//! Writes a raw image: a GPT (`lantern_abi::gpt`) with partitions each aligned to 1 MiB:
//!
//! - with `--bootable` ([RFC-0032](../../../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)), first an **EFI
//!   System Partition**, 32 MiB, FAT16 (`fat`), holding `\EFI\BOOT\BOOTRISCV64.EFI` and `\LANTERN\BOOT.ELF`;
//! - **packages**, 16 MiB: an index sector (`lantern_abi::block::packages`), then each package from a sector boundary;
//! - **store**, 1 MiB, zeroed, so the store starts empty;
//! - the **policy store's** log, 2 MiB of `0xFF`, which is erased flash to it;
//! - the **wallet's** partition, 1 MiB, zeroed, so the wallet makes its root on first start
//!   ([RFC-0035](../../../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md));
//! - with `--model` ([RFC-0034](../../../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)), the
//!   **model**, 32 MiB: an `LMODEL01` file from `lantern-mkmodel`, which the inference service checks against the digest
//!   it was built with. A disk is 128 MiB unless `--size-mib` says otherwise.
//!
//! `--update` rewrites only the packages partition of the disk at `--out`, and leaves everything else on it, including the
//! store's files and the policy store's log: how a disk gets new packages without losing what's on it. With `--model`, it
//! rewrites the model partition too, on a disk that has one.
//!
//! A bootable image is what installing means for now: a VM uses it as its disk, and a machine has it written to its own.
//!
//! It doesn't sign or check packages: everything that reads them verifies them itself.

use std::process::ExitCode;

use lantern_abi::block::{packages, SECTOR};
use lantern_abi::gpt::{self, Extent};

mod fat;

const MIB: u64 = 1 << 20;
const ALIGN: u64 = MIB / SECTOR as u64;
const PACKAGES_SECTORS: u64 = 16 * ALIGN;
const STORE_SECTORS: u64 = ALIGN;
const ESP_SECTORS: u64 = 32 * ALIGN;
/// The policy store's 8 sectors of 256 KiB, as on flash.
const POLICY_SECTORS: u64 = 2 * ALIGN;
const MODELS_SECTORS: u64 = 32 * ALIGN;
const WALLET_SECTORS: u64 = ALIGN;
/// Each package must fit, with its length, in the 2 MiB a reader keeps it in (`lantern_abi::launcher::SET_STRIDE`).
const PACKAGE_MAX: usize = lantern_abi::launcher::SET_STRIDE - lantern_abi::launcher::SET_HEADER;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lantern-mkdisk: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let usage = "lantern-mkdisk --out <disk.img> [--size-mib <n>] --package <a.lpkg> [--package <b.lpkg> ...] \
                 [--bootable --loader <BOOTRISCV64.EFI> --boot-image <lantern-boot-system>] [--model <m.lmodel>] [--update]";
    let (mut out, mut size_mib, mut paths, mut bootable, mut loader, mut boot_image) = (None, None, Vec::new(), false, None, None);
    let mut model = None;
    let mut update = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--bootable" || flag == "--update" {
            bootable |= flag == "--bootable";
            update |= flag == "--update";
            continue;
        }
        let value = args.next().ok_or(usage)?;
        match flag.as_str() {
            "--out" => out = Some(value),
            "--size-mib" => size_mib = Some(value.parse::<u64>().map_err(|_| "--size-mib must be a number")?),
            "--model" => model = Some(value),
            "--package" => paths.push(value),
            "--loader" => loader = Some(value),
            "--boot-image" => boot_image = Some(value),
            _ => return Err(usage.into()),
        }
    }
    if bootable != (loader.is_some() && boot_image.is_some()) || (!bootable && (loader.is_some() || boot_image.is_some())) {
        return Err(usage.into());
    }
    let out = out.ok_or(usage)?;
    if paths.len() > packages::MAX {
        return Err(format!("at most {} packages", packages::MAX));
    }
    let model = model.map(|p| std::fs::read(&p).map_err(|e| format!("{p}: {e}"))).transpose()?;
    if model.as_ref().is_some_and(|m| m.len() as u64 > MODELS_SECTORS * SECTOR as u64) {
        return Err("the model doesn't fit its 32 MiB partition".into());
    }
    if update {
        return update_packages(&out, &paths, model.as_deref());
    }
    let size_mib = size_mib.unwrap_or(128);
    let sectors = size_mib * MIB / SECTOR as u64;
    let esp = Extent { first: ALIGN, sectors: ESP_SECTORS };
    let packages = Extent { first: if bootable { esp.first + esp.sectors } else { ALIGN }, sectors: PACKAGES_SECTORS };
    let store = Extent { first: packages.first + packages.sectors, sectors: STORE_SECTORS };
    let policy = Extent { first: store.first + store.sectors, sectors: POLICY_SECTORS };
    let mut partitions = vec![
        (gpt::PACKAGES_TYPE, packages, "lantern-packages"),
        (gpt::STORE_TYPE, store, "lantern-store"),
        (gpt::POLICY_TYPE, policy, "lantern-policy"),
    ];
    // After every partition there was before it, so the others stay where they were.
    let models = Extent { first: policy.first + policy.sectors, sectors: MODELS_SECTORS };
    let wallet = Extent { first: models.first + models.sectors, sectors: WALLET_SECTORS };
    partitions.push((gpt::WALLET_TYPE, wallet, "lantern-wallet"));
    if model.is_some() {
        partitions.push((gpt::MODELS_TYPE, models, "lantern-models"));
    }
    if bootable {
        partitions.insert(0, (gpt::ESP_TYPE, esp, "EFI system partition"));
    }
    let end = partitions.iter().map(|(_, e, _)| e.first + e.sectors).max().unwrap();
    // The backup table takes the last 33 sectors.
    if end + gpt::ENTRIES_SECTORS + 1 > sectors {
        return Err(format!("{size_mib} MiB is too small"));
    }
    let mut disk = vec![0u8; (sectors as usize) * SECTOR];
    let guid = disk_guid(&paths);
    gpt::write(&mut disk, &partitions, guid);
    let range = |e: Extent| e.first as usize * SECTOR..(e.first + e.sectors) as usize * SECTOR;
    if let (Some(loader), Some(boot_image)) = (&loader, &boot_image) {
        let mut volume = fat::Volume::default();
        volume.add("EFI/BOOT/BOOTRISCV64.EFI", std::fs::read(loader).map_err(|e| format!("{loader}: {e}"))?);
        volume.add("LANTERN/BOOT.ELF", std::fs::read(boot_image).map_err(|e| format!("{boot_image}: {e}"))?);
        volume.write(&mut disk[range(esp)], esp.first)?;
    }
    disk[range(policy)].fill(0xff);
    write_packages(&mut disk[range(packages)], &paths)?;
    if let Some(model) = &model {
        disk[range(models)][..model.len()].copy_from_slice(model);
    }
    std::fs::write(&out, &disk).map_err(|e| format!("{out}: {e}"))?;
    let boot = if bootable { ", bootable" } else { "" };
    let with_model = if model.is_some() { ", a model" } else { "" };
    println!("lantern-mkdisk: {out}: {size_mib} MiB, {} package(s), an empty store{with_model}{boot}", paths.len());
    Ok(())
}

/// `--update`: the disk's own packages partition, from its GPT, rewritten with `paths`.
fn update_packages(out: &str, paths: &[String], model: Option<&[u8]>) -> Result<(), String> {
    let mut disk = std::fs::read(out).map_err(|e| format!("{out}: {e}"))?;
    let at = |lba: u64| lba as usize * SECTOR;
    let header = disk.get(at(gpt::HEADER_LBA)..at(gpt::HEADER_LBA + 1)).ok_or("not a disk")?;
    let entries = disk.get(at(gpt::ENTRIES_LBA)..at(gpt::FIRST_USABLE_LBA)).ok_or("not a disk")?;
    let layout = gpt::parse(header, entries, (disk.len() / SECTOR) as u64).ok_or(format!("{out}: no LanternOS GPT"))?;
    let packages = layout.packages;
    write_packages(&mut disk[at(packages.first)..at(packages.first + packages.sectors)], paths)?;
    if let Some(model) = model {
        let models = layout.models.ok_or(format!("{out}: has no model partition; write a new disk with --model"))?;
        let partition = &mut disk[at(models.first)..at(models.first + models.sectors)];
        partition.fill(0);
        partition.get_mut(..model.len()).ok_or("the model doesn't fit the disk's model partition")?.copy_from_slice(model);
    }
    std::fs::write(out, &disk).map_err(|e| format!("{out}: {e}"))?;
    println!("lantern-mkdisk: {out}: {} package(s) written, everything else kept", paths.len());
    Ok(())
}

/// The packages partition `partition`, zeroed, then its index and each package from a sector boundary.
fn write_packages(partition: &mut [u8], paths: &[String]) -> Result<(), String> {
    partition.fill(0);
    let mut next = 1u64;
    let mut entries = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        if bytes.len() > PACKAGE_MAX {
            return Err(format!("{path}: {} bytes, over {PACKAGE_MAX}", bytes.len()));
        }
        let len_sectors = bytes.len().div_ceil(SECTOR) as u64;
        if (next + len_sectors) as usize * SECTOR > partition.len() {
            return Err("the packages don't fit their partition".into());
        }
        let at = next as usize * SECTOR;
        partition[at..at + bytes.len()].copy_from_slice(&bytes);
        entries.push((next, bytes.len()));
        next += len_sectors;
    }
    packages::encode(&entries, &mut partition[..SECTOR]);
    Ok(())
}

/// A disk GUID that's the same for the same inputs, so an image is reproducible.
fn disk_guid(paths: &[String]) -> gpt::Guid {
    let mut guid = [0u8; 16];
    for (i, b) in paths.join("\n").bytes().enumerate() {
        guid[i % 16] = guid[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    guid[6] = (guid[6] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}
