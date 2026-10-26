#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

CACHE_DIR="$ROOT_DIR/packaging/unikernel/.cache"
OUT_DIR="$ROOT_DIR/dist"
STAGE_DIR="$ROOT_DIR/dist/unikernel-rootfs"
WORK_DIR="$ROOT_DIR/dist/x86_64-build"

mkdir -p "$CACHE_DIR" "$OUT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"

echo "==> [1/6] Compiling static musl Rust Unikernel binary (x86_64-unknown-linux-musl)..."
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release --target x86_64-unknown-linux-musl

STATIC_BIN="$ROOT_DIR/target/x86_64-unknown-linux-musl/release/nfty"
strip "$STATIC_BIN" 2>/dev/null || true

echo "==> [2/6] Fetching & caching x86_64 userland, Linux LTS kernel, and boot/ISO tools..."
ALPINE_V321="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64"

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
    "libncursesw-6.5_p20241006-r3.apk"
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

HOST_TOOL_APKS=(
    "musl-1.2.5-r12.apk"
    "zlib-1.3.2-r1.apk"
    "zstd-libs-1.5.6-r2.apk"
    "xz-libs-5.8.4-r0.apk"
    "libcrypto3-3.3.7-r2.apk"
    "acl-libs-2.3.2-r1.apk"
    "ncurses-libs-6.5_p20241006-r3.apk"
    "libncursesw-6.5_p20241006-r3.apk"
    "libedit-20240808.3.1-r0.apk"
    "libburn-1.5.6-r0.apk"
    "libisofs-1.5.6-r0.apk"
    "libisoburn-1.5.6-r0.apk"
    "xorriso-1.5.6-r0.apk"
    "mtools-4.0.46-r0.apk"
    "syslinux-6.04_pre1-r16.apk"
    "kmod-33-r2.apk"
)

for apk in "${USERLAND_APKS[@]}" "${HOST_TOOL_APKS[@]}"; do
    fetch_cached "$apk" "$ALPINE_V321/$apk"
done

fetch_cached "linux-lts-6.12.114-r0.apk" "$ALPINE_V321/linux-lts-6.12.114-r0.apk"
fetch_cached "systemd-boot-efi_262.1-1_amd64.deb" "https://deb.debian.org/debian/pool/main/s/systemd/systemd-boot-efi_262.1-1_amd64.deb"
fetch_cached "cloudflared-linux-amd64" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"

echo "==> [3/6] Assembling x86_64 Unikernel rootfs & kernel modules (PID-1 = /bin/nfty)..."
rm -rf "$STAGE_DIR" "$WORK_DIR"
mkdir -p "$STAGE_DIR"/{bin,sbin,usr/bin,usr/sbin,usr/lib,lib,etc/nfty,proc,sys,dev,data,run,root}
mkdir -p "$WORK_DIR/kern" "$WORK_DIR/tools"

for apk in "${HOST_TOOL_APKS[@]}"; do
    tar -xzf "$CACHE_DIR/$apk" -C "$WORK_DIR/tools" 2>/dev/null || true
done

run_tool() {
    "$WORK_DIR/tools/lib/ld-musl-x86_64.so.1" \
        --library-path "$WORK_DIR/tools/lib:$WORK_DIR/tools/usr/lib" \
        "$@"
}

for apk in "${USERLAND_APKS[@]}"; do
    tar -xzf "$CACHE_DIR/$apk" -C "$STAGE_DIR" 2>/dev/null || true
done
rm -f "$STAGE_DIR"/.PKGINFO "$STAGE_DIR"/.SIGN.* "$STAGE_DIR"/.post-*

if [[ -f "$STAGE_DIR/bin/busybox.static" ]]; then
    mv "$STAGE_DIR/bin/busybox.static" "$STAGE_DIR/bin/busybox"
    chmod +x "$STAGE_DIR/bin/busybox"
    for applet in ping mount umount udhcpc ifconfig route arping modprobe insmod rmmod lsmod depmod vi ls cat rm mkdir sleep dmesg uname; do
        ln -sf /bin/busybox "$STAGE_DIR/bin/$applet"
        ln -sf /bin/busybox "$STAGE_DIR/sbin/$applet"
    done
fi

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

cp "$CACHE_DIR/cloudflared-linux-amd64" "$STAGE_DIR/bin/cloudflared"
chmod +x "$STAGE_DIR/bin/cloudflared"
ln -sf /bin/cloudflared "$STAGE_DIR/usr/bin/cloudflared"

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

# Package x86_64 LXD container rootfs before adding VM/bare-metal kernel modules
TIMESTAMP="$(date +%s)"
mkdir -p "$ROOT_DIR/dist/lxd-container" "$WORK_DIR/meta-ct"
cat > "$WORK_DIR/meta-ct/metadata.yaml" <<EOF
architecture: x86_64
creation_date: ${TIMESTAMP}
properties:
  architecture: x86_64
  description: nfty Static Rust Appliance Container
  os: nfty-unikernel
  release: 0.3.0
EOF
tar -czf "$ROOT_DIR/dist/lxd-container/lxd.tar.gz" -C "$WORK_DIR/meta-ct" metadata.yaml
tar -czf "$ROOT_DIR/dist/lxd-container/rootfs.tar.gz" -C "$STAGE_DIR" .

# Extract kernel and modules for bootable x86_64 Unikernel ISO & Disk Image
tar -xzf "$CACHE_DIR/linux-lts-6.12.114-r0.apk" -C "$WORK_DIR/kern" 2>/dev/null || true
KVER="$(ls "$WORK_DIR/kern/lib/modules" | head -n 1)"
mkdir -p "$STAGE_DIR/lib/modules/$KVER"
cp -a "$WORK_DIR/kern/lib/modules/$KVER"/* "$STAGE_DIR/lib/modules/$KVER/"

# Prune desktop/multimedia/wireless modules not needed by a network appliance
rm -rf \
    "$STAGE_DIR/lib/modules/$KVER/kernel/sound" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/gpu" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/media" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/infiniband" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/net/wireless" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/bluetooth" \
    "$STAGE_DIR/lib/modules/$KVER/kernel/drivers/staging" \
    "$STAGE_DIR/lib/modules/$KVER/vmlinuz"

find "$STAGE_DIR/lib/modules/$KVER" -name "*.ko.gz" -exec gunzip -f {} +
run_tool "$WORK_DIR/tools/sbin/depmod" -b "$STAGE_DIR" "$KVER"

INITRD_IMG="$ROOT_DIR/dist/nfty-unikernel-initramfs.cpio.gz"
(
    cd "$STAGE_DIR"
    find . -print0 | "$STAGE_DIR/bin/busybox" cpio -0 -o -H newc 2>/dev/null | gzip -9 > "$INITRD_IMG"
)

echo "==> [4/6] Building UEFI ESP & Persistent ext4 Data Partitions..."
mkdir -p "$WORK_DIR/data-seed"
echo -n "" > "$WORK_DIR/data-seed/Nftyfile"
echo "{}" > "$WORK_DIR/data-seed/hosts.json"

DATA_PART="$WORK_DIR/part2-data.ext4"
truncate -s 128M "$DATA_PART"
mkfs.ext4 -q -F -L "nfty-data" -d "$WORK_DIR/data-seed" "$DATA_PART"

ESP_PART="$WORK_DIR/part1-esp.fat"
truncate -s 160M "$ESP_PART"
run_tool "$WORK_DIR/tools/usr/bin/mformat" -i "$ESP_PART" -F -v "NFTY_EFI" ::
run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ESP_PART" ::/EFI
run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ESP_PART" ::/EFI/BOOT
run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ESP_PART" ::/loader
run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ESP_PART" ::/loader/entries

# Extract systemd-bootx64.efi from Debian package using python3
python3 - "$CACHE_DIR/systemd-boot-efi_262.1-1_amd64.deb" "$WORK_DIR/BOOTX64.EFI" <<'PY'
import sys, tarfile, io
deb = open(sys.argv[1], "rb").read()
idx = deb.find(b"data.tar.xz")
if idx < 0:
    raise RuntimeError("data.tar.xz not found in deb")
hdr = deb[idx:idx+60].decode("ascii", errors="ignore")
size = int(hdr[48:58].strip())
payload = deb[idx+60:idx+60+size]
with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as tf:
    for m in tf.getmembers():
        if m.name.endswith("systemd-bootx64.efi"):
            open(sys.argv[2], "wb").write(tf.extractfile(m).read())
            break
PY

KERNEL_IMG="$WORK_DIR/kern/boot/vmlinuz-lts"
BOOTARGS="console=tty0 console=ttyS0,115200n8 quiet rdinit=/init -- --unikernel --file /data/Nftyfile --api-bind 0.0.0.0:9090"

cat > "$WORK_DIR/loader.conf" <<'EOF'
default nfty.conf
timeout 1
console-mode max
EOF

cat > "$WORK_DIR/nfty.conf" <<EOF
title   nfty x86_64 Unikernel Appliance
linux   /vmlinuz
initrd  /initramfs.img
options ${BOOTARGS}
EOF

run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/loader.conf" ::/loader/loader.conf
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/nfty.conf" ::/loader/entries/nfty.conf
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$KERNEL_IMG" ::/vmlinuz
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$INITRD_IMG" ::/initramfs.img

echo "==> [5/6] Building Hybrid BIOS + UEFI Bootable x86_64 Unikernel ISO (nfty-unikernel-x86_64.iso)..."
ISO_ROOT="$WORK_DIR/iso-root"
mkdir -p "$ISO_ROOT/boot/isolinux" "$ISO_ROOT/EFI/BOOT" "$ISO_ROOT/loader/entries"

cp "$KERNEL_IMG" "$ISO_ROOT/vmlinuz"
cp "$INITRD_IMG" "$ISO_ROOT/initramfs.img"
cp "$WORK_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI"
cp "$WORK_DIR/loader.conf" "$ISO_ROOT/loader/loader.conf"
cp "$WORK_DIR/nfty.conf" "$ISO_ROOT/loader/entries/nfty.conf"
cp "$ESP_PART" "$ISO_ROOT/boot/efiboot.img"

cp "$WORK_DIR/tools/usr/share/syslinux/isolinux.bin" "$ISO_ROOT/boot/isolinux/isolinux.bin"
cp "$WORK_DIR/tools/usr/share/syslinux/ldlinux.c32" "$ISO_ROOT/boot/isolinux/ldlinux.c32"

cat > "$ISO_ROOT/boot/isolinux/isolinux.cfg" <<EOF
DEFAULT nfty
PROMPT 0
TIMEOUT 10

LABEL nfty
    MENU LABEL nfty x86_64 Unikernel Appliance
    KERNEL /vmlinuz
    INITRD /initramfs.img
    APPEND ${BOOTARGS}
EOF

ISO_OUT="$ROOT_DIR/dist/nfty-unikernel-x86_64.iso"
rm -f "$ISO_OUT"

run_tool "$WORK_DIR/tools/usr/bin/xorriso" -as mkisofs \
    -V "NFTY_UNIKERNEL" \
    -o "$ISO_OUT" \
    -isohybrid-mbr "$WORK_DIR/tools/usr/share/syslinux/isohdpfx.bin" \
    -c boot/isolinux/boot.cat \
    -b boot/isolinux/isolinux.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e boot/efiboot.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    "$ISO_ROOT" >/dev/null 2>&1

echo "==> [6/6] Assembling GPT Bootable Disk Image (nfty-unikernel-x86_64.img.gz)..."
RAW_DISK="$ROOT_DIR/dist/nfty-unikernel-x86_64.img"
rm -f "$RAW_DISK" "$RAW_DISK.gz"
truncate -s 296M "$RAW_DISK"

sfdisk "$RAW_DISK" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

part1 : start=2048, size=327680, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System"
part2 : start=329728, size=262144, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="nfty-data"
EOF

dd if="$ESP_PART" of="$RAW_DISK" bs=1M seek=1 conv=notrunc status=none
dd if="$DATA_PART" of="$RAW_DISK" bs=1M seek=161 conv=notrunc status=none

if command -v qemu-img >/dev/null 2>&1; then
    mkdir -p "$ROOT_DIR/dist/lxd-vm" "$WORK_DIR/meta-vm"
    qemu-img convert -f raw -O qcow2 -c "$RAW_DISK" "$ROOT_DIR/dist/lxd-vm/disk.qcow2"
    cat > "$WORK_DIR/meta-vm/metadata.yaml" <<EOF
architecture: x86_64
creation_date: ${TIMESTAMP}
properties:
  architecture: x86_64
  description: nfty Rust Unikernel L4 Load Balancer (with 128MB persistent /data partition)
  os: nfty-unikernel
  release: 0.3.0
EOF
    tar -czf "$ROOT_DIR/dist/lxd-vm/lxd.tar.gz" -C "$WORK_DIR/meta-vm" metadata.yaml
fi

gzip -k -f -6 "$RAW_DISK"
rm -rf "$WORK_DIR"

echo ""
echo "================================================================================"
echo "x86_64 Unikernel ISO, Disk Image & LXD Container Built"
echo "================================================================================"
echo "1. Bootable Hybrid BIOS + UEFI ISO (Proxmox / VMware / QEMU / VirtualBox / Bare-Metal):"
echo "   - ISO:       $ISO_OUT"
echo ""
echo "2. Bootable UEFI GPT Disk Image (with 128 MiB ext4 persistent /data partition):"
echo "   - Raw Image: $RAW_DISK.gz"
echo "   - Initramfs: $INITRD_IMG"
echo ""
echo "3. LXD Container Image (Static musl PID-1 appliance):"
echo "   - Metadata:  $ROOT_DIR/dist/lxd-container/lxd.tar.gz"
echo "   - Rootfs:    $ROOT_DIR/dist/lxd-container/rootfs.tar.gz"
echo "================================================================================"
