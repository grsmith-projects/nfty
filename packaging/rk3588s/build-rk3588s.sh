#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BOARD="${1:-generic}"
CACHE_DIR="$ROOT_DIR/packaging/rk3588s/.cache"
OUT_DIR="$ROOT_DIR/dist/rk3588s"
STAGE_DIR="$ROOT_DIR/dist/unikernel-rootfs-arm64"
WORK_DIR="$ROOT_DIR/dist/rk3588s-build"

mkdir -p "$CACHE_DIR" "$OUT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"
export CC_aarch64_unknown_linux_musl="${CC_aarch64_unknown_linux_musl:-clang}"
export AR_aarch64_unknown_linux_musl="${AR_aarch64_unknown_linux_musl:-llvm-ar}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-rust-lld}"

echo "==> [1/6] Cross-compiling static ARM64 Rust Unikernel binary (aarch64-unknown-linux-musl)..."
rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release --target aarch64-unknown-linux-musl

STATIC_BIN="$ROOT_DIR/target/aarch64-unknown-linux-musl/release/nfty"
llvm-strip "$STATIC_BIN" 2>/dev/null || true

echo "==> [2/6] Fetching & caching ARM64 userland, Linux 6.18 LTS kernel, RK3588S DTBs, and bootloaders..."
ALPINE_V321="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/aarch64"
ALPINE_EDGE="https://dl-cdn.alpinelinux.org/alpine/edge/main/aarch64"

fetch_cached() {
    local name="$1"
    local url="$2"
    if [[ ! -s "$CACHE_DIR/$name" ]]; then
        echo "  -> Downloading $name..."
        curl -fSL "$url" -o "$CACHE_DIR/$name.tmp"
        mv "$CACHE_DIR/$name.tmp" "$CACHE_DIR/$name"
    fi
}

USERLAND_APKS=(
    "musl-1.2.5-r12.apk"
    "busybox-static-1.37.0-r14.apk"
    "nftables-1.1.1-r0.apk"
    "libmnl-1.0.5-r2.apk"
    "libnftnl-1.2.8-r0.apk"
    "gmp-6.3.0-r2.apk"
    "jansson-2.14-r4.apk"
    "readline-8.2.13-r0.apk"
    "ncurses-libs-6.5_p20241006-r3.apk"
    "iproute2-minimal-6.11.0-r0.apk"
    "libcap2-2.78-r0.apk"
    "libelf-0.191-r0.apk"
    "zlib-1.3.2-r1.apk"
    "zstd-libs-1.5.6-r2.apk"
    "wireguard-tools-wg-1.0.20210914-r4.apk"
    "dnsmasq-dnssec-nftset-2.90-r3.apk"
    "nettle-3.10.2-r0.apk"
    "libidn2-2.3.7-r0.apk"
    "libunistring-1.2-r0.apk"
    "libnfnetlink-1.0.2-r3.apk"
    "libnetfilter_conntrack-1.0.9-r3.apk"
)

for apk in "${USERLAND_APKS[@]}"; do
    fetch_cached "$apk" "$ALPINE_V321/$apk"
done

fetch_cached "linux-lts-6.18.58-r0.apk" "$ALPINE_EDGE/linux-lts-6.18.58-r0.apk"
fetch_cached "u-boot-rockchip-2026.10-r0.apk" "$ALPINE_EDGE/u-boot-rockchip-2026.10-r0.apk"
fetch_cached "systemd-boot-efi_262.1-1_arm64.deb" "https://deb.debian.org/debian/pool/main/s/systemd/systemd-boot-efi_262.1-1_arm64.deb"
fetch_cached "cloudflared-linux-arm64" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"

if [[ "$BOARD" != "generic" ]]; then
    EDK2_IMG="${BOARD}_UEFI_Release_v1.1.img"
    fetch_cached "$EDK2_IMG" "https://github.com/edk2-porting/edk2-rk3588/releases/download/v1.1/$EDK2_IMG" || true
fi

echo "==> [3/6] Assembling ARM64 Unikernel rootfs & kernel modules (PID-1 = /bin/nfty)..."
rm -rf "$STAGE_DIR" "$WORK_DIR"
mkdir -p "$STAGE_DIR"/{bin,sbin,usr/bin,usr/sbin,usr/lib,lib,etc/nfty,proc,sys,dev,data,run,root}
mkdir -p "$WORK_DIR/kern"

for apk in "${USERLAND_APKS[@]}"; do
    tar -xzf "$CACHE_DIR/$apk" -C "$STAGE_DIR" 2>/dev/null || true
done
rm -f "$STAGE_DIR"/.PKGINFO "$STAGE_DIR"/.SIGN.* "$STAGE_DIR"/.post-*

# Set up static busybox applets without overwriting full iproute2 (/sbin/ip), nft, or nfty shell
if [[ -f "$STAGE_DIR/bin/busybox.static" ]]; then
    mv "$STAGE_DIR/bin/busybox.static" "$STAGE_DIR/bin/busybox"
    chmod +x "$STAGE_DIR/bin/busybox"
    for applet in ping mount umount udhcpc ifconfig route arping modprobe insmod rmmod lsmod depmod vi ls cat rm mkdir sleep dmesg uname; do
        ln -sf /bin/busybox "$STAGE_DIR/bin/$applet"
        ln -sf /bin/busybox "$STAGE_DIR/sbin/$applet"
    done
fi

# Ensure ip, nft, wg, dnsmasq, and cloudflared are in standard PATH locations
ln -sf /sbin/ip "$STAGE_DIR/bin/ip"
ln -sf /sbin/ip "$STAGE_DIR/usr/bin/ip"
ln -sf /usr/sbin/nft "$STAGE_DIR/bin/nft"
ln -sf /usr/sbin/nft "$STAGE_DIR/sbin/nft"
ln -sf /usr/sbin/nft "$STAGE_DIR/usr/bin/nft"
ln -sf /usr/bin/wg "$STAGE_DIR/bin/wg"
ln -sf /usr/bin/wg "$STAGE_DIR/sbin/wg"
ln -sf /usr/sbin/dnsmasq "$STAGE_DIR/usr/bin/dnsmasq"
ln -sf /usr/sbin/dnsmasq "$STAGE_DIR/bin/dnsmasq"
ln -sf /usr/sbin/dnsmasq "$STAGE_DIR/sbin/dnsmasq"

cp "$CACHE_DIR/cloudflared-linux-arm64" "$STAGE_DIR/bin/cloudflared"
chmod +x "$STAGE_DIR/bin/cloudflared"
ln -sf /bin/cloudflared "$STAGE_DIR/usr/bin/cloudflared"

# Install ARM64 nfty as PID-1 (/init) and login shell
cp "$STATIC_BIN" "$STAGE_DIR/bin/nfty"
chmod +x "$STAGE_DIR/bin/nfty"
ln -sf /bin/nfty "$STAGE_DIR/init"
ln -sf /bin/nfty "$STAGE_DIR/sbin/init"
ln -sf /bin/nfty "$STAGE_DIR/usr/bin/nfty"
ln -sf /bin/nfty "$STAGE_DIR/bin/sh"
ln -sf /bin/nfty "$STAGE_DIR/bin/bash"
ln -sf /bin/nfty "$STAGE_DIR/bin/su"
ln -sf /bin/nfty "$STAGE_DIR/bin/udhcpc-hook"

if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    mkdir -p "$STAGE_DIR/etc/ssl/certs"
    cp -L /etc/ssl/certs/ca-certificates.crt "$STAGE_DIR/etc/ssl/certs/ca-certificates.crt"
fi

if [[ -d /usr/share/terminfo ]]; then
    mkdir -p "$STAGE_DIR/usr/share/terminfo"
    for d in x l v d s a; do
        if [[ -d "/usr/share/terminfo/$d" ]]; then
            cp -r "/usr/share/terminfo/$d" "$STAGE_DIR/usr/share/terminfo/"
        fi
    done
fi

echo -n "" > "$STAGE_DIR/etc/nfty/Nftyfile"
echo "root:x:0:0:root:/root:/bin/nfty" > "$STAGE_DIR/etc/passwd"
echo "root:x:0:" > "$STAGE_DIR/etc/group"

# Package ARM64 LXD container rootfs before adding bare-metal kernel modules
TIMESTAMP="$(date +%s)"
mkdir -p "$ROOT_DIR/dist/lxd-container-arm64" "$WORK_DIR/meta-ct"
cat > "$WORK_DIR/meta-ct/metadata.yaml" <<EOF
architecture: aarch64
creation_date: ${TIMESTAMP}
properties:
  architecture: aarch64
  description: nfty Static Rust Appliance Container (ARM64 / RK3588S)
  os: nfty-unikernel
  release: 0.1.0
EOF
tar -czf "$ROOT_DIR/dist/lxd-container-arm64/lxd.tar.gz" -C "$WORK_DIR/meta-ct" metadata.yaml
tar -czf "$ROOT_DIR/dist/lxd-container-arm64/rootfs.tar.gz" -C "$STAGE_DIR" .

# Extract kernel, DTBs, and modules for bare-metal RK3588S initramfs
tar -xzf "$CACHE_DIR/linux-lts-6.18.58-r0.apk" -C "$WORK_DIR/kern" 2>/dev/null || true
KVER="$(ls "$WORK_DIR/kern/lib/modules" | head -n 1)"
mkdir -p "$STAGE_DIR/lib/modules/$KVER"
cp -a "$WORK_DIR/kern/lib/modules/$KVER"/* "$STAGE_DIR/lib/modules/$KVER/"

# Prune desktop/multimedia/wireless modules not needed by a headless network appliance
rm -rf \
    "$STAGE_DIR/lib/modules/$KVER/kernel/sound" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/gpu" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/media" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/infiniband" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/net/wireless" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/bluetooth" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/staging" \
    "$STAGE_DIR/lib/modules/$KVER/vmlinuz"

# Decompress .ko.gz modules so busybox modprobe loads them directly via init_module
find "$STAGE_DIR/lib/modules/$KVER" -name "*.ko.gz" -exec gunzip -f {} +
depmod -b "$STAGE_DIR" "$KVER"

INITRD_IMG="$OUT_DIR/nfty-rk3588s-initramfs.cpio.gz"
(
    cd "$STAGE_DIR"
    find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$INITRD_IMG"
)

echo "==> [4/6] Building persistent ext4 storage partition (128 MiB, label: nfty-data)..."
mkdir -p "$WORK_DIR/data-seed"
echo -n "" > "$WORK_DIR/data-seed/Nftyfile"
echo "{}" > "$WORK_DIR/data-seed/hosts.json"

DATA_PART="$WORK_DIR/part2-data.ext4"
truncate -s 128M "$DATA_PART"
mkfs.ext4 -q -F -L "nfty-data" -d "$WORK_DIR/data-seed" "$DATA_PART"

echo "==> [5/6] Building Hybrid U-Boot (extlinux) + UEFI Boot Partition (192 MiB FAT32)..."
ESP_PART="$WORK_DIR/part1-boot.fat"
truncate -s 192M "$ESP_PART"
mformat -i "$ESP_PART" -F -v "NFTY_BOOT" ::

mmd -i "$ESP_PART" ::/EFI
mmd -i "$ESP_PART" ::/EFI/BOOT
mmd -i "$ESP_PART" ::/loader
mmd -i "$ESP_PART" ::/loader/entries
mmd -i "$ESP_PART" ::/extlinux
mmd -i "$ESP_PART" ::/dtbs
mmd -i "$ESP_PART" ::/dtbs/rockchip

# Extract uncompressed ARM64 Image from EFI zboot vmlinuz-lts for U-Boot booti compatibility
python3 - "$WORK_DIR/kern/boot/vmlinuz-lts" "$WORK_DIR/Image" <<'PY'
import sys, zlib
data = open(sys.argv[1], "rb").read()
idx = data.find(b"\x1f\x8b\x08\x00")
if idx < 0:
    raise RuntimeError("Could not find gzip stream inside vmlinuz-lts")
raw = zlib.decompress(data[idx:], 16 + zlib.MAX_WBITS)
open(sys.argv[2], "wb").write(raw)
PY

# Extract systemd-bootaa64.efi for UEFI boot
bsdtar -xOf "$CACHE_DIR/systemd-boot-efi_262.1-1_arm64.deb" data.tar.xz \
    | tar -xJf - -O ./usr/lib/systemd/boot/efi/systemd-bootaa64.efi > "$WORK_DIR/BOOTAA64.EFI"

DEFAULT_DTB="rk3588s-orangepi-5.dtb"
case "$BOARD" in
    orangepi-5)    DEFAULT_DTB="rk3588s-orangepi-5.dtb" ;;
    orangepi-5b)   DEFAULT_DTB="rk3588s-orangepi-5b.dtb" ;;
    rock-5a)       DEFAULT_DTB="rk3588s-rock-5a.dtb" ;;
    rock-5c)       DEFAULT_DTB="rk3588s-rock-5c.dtb" ;;
    nanopi-r6s)    DEFAULT_DTB="rk3588s-nanopi-r6s.dtb" ;;
    nanopi-r6c)    DEFAULT_DTB="rk3588s-nanopi-r6c.dtb" ;;
    edge2|khadas-edge2) DEFAULT_DTB="rk3588s-khadas-edge2.dtb" ;;
    odroid-m2)     DEFAULT_DTB="rk3588s-odroid-m2.dtb" ;;
    indiedroid-nova) DEFAULT_DTB="rk3588s-indiedroid-nova.dtb" ;;
    coolpi-4b)     DEFAULT_DTB="rk3588s-coolpi-4b.dtb" ;;
esac

BOOTARGS="console=ttyS2,1500000n8 console=ttyFIQ0,1500000n8 console=tty0 earlycon=uart8250,mmio32,0xfeb50000 rdinit=/init -- --unikernel --file /data/Nftyfile"

cat > "$WORK_DIR/extlinux.conf" <<EOF
timeout 10
default nfty-auto

label nfty-auto
    menu label nfty ARM64 Unikernel (Auto DTB via U-Boot fdtfile)
    kernel /Image
    initrd /initramfs.img
    fdtdir /dtbs
    append ${BOOTARGS}

label nfty-orangepi-5
    menu label nfty ARM64 Unikernel (Orange Pi 5 - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-orangepi-5.dtb
    append ${BOOTARGS}

label nfty-orangepi-5b
    menu label nfty ARM64 Unikernel (Orange Pi 5B - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-orangepi-5b.dtb
    append ${BOOTARGS}

label nfty-rock-5a
    menu label nfty ARM64 Unikernel (Radxa ROCK 5A - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-rock-5a.dtb
    append ${BOOTARGS}

label nfty-rock-5c
    menu label nfty ARM64 Unikernel (Radxa ROCK 5C - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-rock-5c.dtb
    append ${BOOTARGS}

label nfty-nanopi-r6s
    menu label nfty ARM64 Unikernel (FriendlyElec NanoPi R6S - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-nanopi-r6s.dtb
    append ${BOOTARGS}

label nfty-nanopi-r6c
    menu label nfty ARM64 Unikernel (FriendlyElec NanoPi R6C - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-nanopi-r6c.dtb
    append ${BOOTARGS}

label nfty-khadas-edge2
    menu label nfty ARM64 Unikernel (Khadas Edge2 - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-khadas-edge2.dtb
    append ${BOOTARGS}

label nfty-odroid-m2
    menu label nfty ARM64 Unikernel (Hardkernel ODROID-M2 - RK3588S)
    kernel /Image
    initrd /initramfs.img
    fdt /dtbs/rockchip/rk3588s-odroid-m2.dtb
    append ${BOOTARGS}
EOF

cat > "$WORK_DIR/loader.conf" <<'EOF'
default nfty.conf
timeout 1
console-mode max
EOF

cat > "$WORK_DIR/nfty.conf" <<EOF
title   nfty ARM64 Unikernel Appliance (RK3588S)
linux   /vmlinuz
initrd  /initramfs.img
devicetree /dtbs/rockchip/${DEFAULT_DTB}
options ${BOOTARGS}
EOF

mcopy -i "$ESP_PART" "$WORK_DIR/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -i "$ESP_PART" "$WORK_DIR/loader.conf" ::/loader/loader.conf
mcopy -i "$ESP_PART" "$WORK_DIR/nfty.conf" ::/loader/entries/nfty.conf
mcopy -i "$ESP_PART" "$WORK_DIR/extlinux.conf" ::/extlinux/extlinux.conf
mcopy -i "$ESP_PART" "$WORK_DIR/Image" ::/Image
mcopy -i "$ESP_PART" "$WORK_DIR/kern/boot/vmlinuz-lts" ::/vmlinuz
mcopy -i "$ESP_PART" "$INITRD_IMG" ::/initramfs.img

for dtb in "$WORK_DIR/kern/boot/dtbs-lts/rockchip"/rk3588*.dtb; do
    if [[ -f "$dtb" ]]; then
        mcopy -i "$ESP_PART" "$dtb" "::/dtbs/rockchip/$(basename "$dtb")"
    fi
done

echo "==> [6/6] Assembling Bare-Metal RK3588S GPT Disk Image..."
RAW_DISK="$OUT_DIR/nfty-rk3588s.img"
rm -f "$RAW_DISK" "$RAW_DISK.gz"
# Disk layout:
# - Sectors 64..32767 (32 KiB .. 16 MiB): Rockchip TPL/SPL + U-Boot/EDK2 FIT
# - Partition 1 (start=32768 = 16 MiB, size=192 MiB): FAT32 Boot / EFI System Partition
# - Partition 2 (start=425984 = 208 MiB, size=128 MiB): ext4 persistent /data (nfty-data)
truncate -s 340M "$RAW_DISK"

sfdisk "$RAW_DISK" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 64

part1 : start=32768, size=393216, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="boot", attrs="LegacyBIOSBootable"
part2 : start=425984, size=262144, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="nfty-data"
EOF

# Write bootloader to Rockchip BootROM offset (sector 64 = 32 KiB)
if [[ "$BOARD" != "generic" && -f "$CACHE_DIR/${BOARD}_UEFI_Release_v1.1.img" ]]; then
    echo "  -> Writing edk2-rk3588 UEFI bootloader for board '$BOARD'..."
    dd if="$CACHE_DIR/${BOARD}_UEFI_Release_v1.1.img" of="$RAW_DISK" bs=512 seek=64 skip=64 conv=notrunc status=none
else
    echo "  -> Writing mainline Rockchip RK3588 U-Boot (idbloader + u-boot.itb at sector 64)..."
    tar -xOf "$CACHE_DIR/u-boot-rockchip-2026.10-r0.apk" usr/share/u-boot/rock5b-rk3588/u-boot-rockchip.bin > "$WORK_DIR/u-boot-rockchip.bin" 2>/dev/null
    dd if="$WORK_DIR/u-boot-rockchip.bin" of="$RAW_DISK" bs=512 seek=64 conv=notrunc status=none
fi

# Write Partition 1 (16 MiB offset) and Partition 2 (208 MiB offset)
dd if="$ESP_PART" of="$RAW_DISK" bs=1M seek=16 conv=notrunc status=none
dd if="$DATA_PART" of="$RAW_DISK" bs=1M seek=208 conv=notrunc status=none

gzip -k -f -6 "$RAW_DISK"
rm -rf "$WORK_DIR"

echo ""
echo "================================================================================"
echo "✔ Bare-Metal RK3588S / ARM64 Unikernel Images Built!"
echo "================================================================================"
echo "1. Bare-Metal Flashable Disk Image (SD / eMMC / NVMe):"
echo "   - Raw Image:        $RAW_DISK"
echo "   - Compressed Image: $RAW_DISK.gz"
echo "   - Initramfs:        $INITRD_IMG"
echo ""
echo "   Flash to MicroSD / eMMC / NVMe:"
echo "     zcat $RAW_DISK.gz | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync"
echo ""
echo "   Or build with board-specific EDK2 UEFI firmware embedded:"
echo "     ./packaging/rk3588s/build-rk3588s.sh orangepi-5   # or rock-5a, nanopi-r6s, nanopi-r6c, edge2"
echo ""
echo "2. ARM64 LXD Container Image:"
echo "   - Metadata: $ROOT_DIR/dist/lxd-container-arm64/lxd.tar.gz"
echo "   - Rootfs:   $ROOT_DIR/dist/lxd-container-arm64/rootfs.tar.gz"
echo "================================================================================"
