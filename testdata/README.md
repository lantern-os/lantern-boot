# Device-tree fixtures

Real device trees for `src/fdt.rs` and `src/platform.rs`'s host tests
([RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)).

| File | What it is | How it was made |
|---|---|---|
| `qemu-virt.dtb` | QEMU 10.2.1's `virt` machine, 256 MiB, PLIC | `qemu-system-riscv64 -machine virt,dumpdtb=qemu-virt.dtb -m 256M` |
| `qemu-virt-aia.dtb` | The same with AIA: machine- and supervisor-level APLICs and IMSICs | `-machine virt,aia=aplic-imsic,dumpdtb=qemu-virt-aia.dtb -m 256M` |
| `k3-pico-itx.dtb` | The Banana Pi K3 Pico-ITX, as SpacemiT's Linux describes it | `arch/riscv/boot/dts/spacemit/k3-pico-itx.dts` from `spacemit-com/linux-6.18`, branch `k3-br-v1.0.y` (SPDX `GPL-2.0 OR MIT`), through `cpp` with the tree's `include/` and `dtc -f` 1.7.2 |

QEMU's trees are the ones QEMU builds, before OpenSBI or EDK2 adjust them; firmware may add `reserved-memory` nodes and
remove machine-level controllers. The K3's is the vendor kernel's view, not necessarily what its firmware passes: RFC-0039's
pre-flight step replaces it with a copy of the tree the board's firmware actually hands over.
