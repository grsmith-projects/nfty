#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"

echo "==> [1/5] Compiling static musl Rust Unikernel binary (x86_64-unknown-linux-musl)..."
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release --target x86_64-unknown-linux-musl

STATIC_BIN="$ROOT_DIR/target/x86_64-unknown-linux-musl/release/nfty"
strip "$STATIC_BIN" || true

echo "==> [2/5] Building Unikernel initramfs (PID-1 = /bin/nfty)..."
STAGE_DIR="$ROOT_DIR/dist/unikernel-rootfs"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"/{bin,sbin,usr/bin,usr/sbin,usr/lib,lib64,etc/nfty,proc,sys,dev,data,run,root}

cp "$STATIC_BIN" "$STAGE_DIR/bin/nfty"
ln -sf /bin/nfty "$STAGE_DIR/init"
ln -sf /bin/nfty "$STAGE_DIR/sbin/init"
ln -sf /bin/nfty "$STAGE_DIR/usr/bin/nfty"
ln -sf /bin/nfty "$STAGE_DIR/bin/sh"
ln -sf /bin/nfty "$STAGE_DIR/bin/bash"
ln -sf /bin/nfty "$STAGE_DIR/bin/su"
ln -sf /bin/nfty "$STAGE_DIR/bin/udhcpc-hook"

if [[ -f "$ROOT_DIR/packaging/unikernel/busybox" ]]; then
    cp "$ROOT_DIR/packaging/unikernel/busybox" "$STAGE_DIR/bin/busybox"
    chmod +x "$STAGE_DIR/bin/busybox"
    for applet in ip ping mount udhcpc ifconfig route arping vi ls cat rm; do
        ln -sf /bin/busybox "$STAGE_DIR/bin/$applet"
        ln -sf /bin/busybox "$STAGE_DIR/sbin/$applet"
    done
fi

if [[ -f /usr/bin/nft ]]; then
    cp /usr/bin/nft "$STAGE_DIR/usr/bin/nft"
    ln -sf /usr/bin/nft "$STAGE_DIR/bin/nft"
    ln -sf /usr/bin/nft "$STAGE_DIR/sbin/nft"
    for lib in $(ldd /usr/bin/nft | awk '/=>/ {print $3}'); do
        if [[ -f "$lib" ]]; then
            cp -L "$lib" "$STAGE_DIR/usr/lib/"
        fi
    done
    cp -L /lib64/ld-linux-x86-64.so.2 "$STAGE_DIR/lib64/"
    ln -sf usr/lib "$STAGE_DIR/lib"
fi

if [[ -f /usr/bin/wg ]]; then
    cp /usr/bin/wg "$STAGE_DIR/usr/bin/wg"
    ln -sf /usr/bin/wg "$STAGE_DIR/bin/wg"
    ln -sf /usr/bin/wg "$STAGE_DIR/sbin/wg"
fi

if [[ -f /usr/bin/dnsmasq ]]; then
    cp /usr/bin/dnsmasq "$STAGE_DIR/usr/bin/dnsmasq"
    ln -sf /usr/bin/dnsmasq "$STAGE_DIR/bin/dnsmasq"
    ln -sf /usr/bin/dnsmasq "$STAGE_DIR/sbin/dnsmasq"
    for lib in $(ldd /usr/bin/dnsmasq | awk '/=>/ {print $3}'); do
        if [[ -f "$lib" ]]; then
            cp -L "$lib" "$STAGE_DIR/usr/lib/"
        fi
    done
fi

if [[ -f "$ROOT_DIR/packaging/unikernel/cloudflared" ]]; then
    cp "$ROOT_DIR/packaging/unikernel/cloudflared" "$STAGE_DIR/bin/cloudflared"
    chmod +x "$STAGE_DIR/bin/cloudflared"
    ln -sf /bin/cloudflared "$STAGE_DIR/usr/bin/cloudflared"
fi

if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    mkdir -p "$STAGE_DIR/etc/ssl/certs"
    cp -L /etc/ssl/certs/ca-certificates.crt "$STAGE_DIR/etc/ssl/certs/ca-certificates.crt"
fi

if [[ -f /usr/bin/nano ]]; then
    cp /usr/bin/nano "$STAGE_DIR/usr/bin/nano"
    ln -sf /usr/bin/nano "$STAGE_DIR/bin/nano"
    for lib in $(ldd /usr/bin/nano | awk '/=>/ {print $3}'); do
        if [[ -f "$lib" ]]; then
            cp -L "$lib" "$STAGE_DIR/usr/lib/"
        fi
    done
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

mkdir -p "$ROOT_DIR/dist"
INITRD_IMG="$ROOT_DIR/dist/nfty-unikernel-initramfs.cpio.gz"
(
    cd "$STAGE_DIR"
    find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$INITRD_IMG"
)

echo "==> [3/5] Building persistent ext4 storage partition (128 MiB, label: nfty-data)..."
WORK_DIR="$ROOT_DIR/dist/lxd-build"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/data-seed"
echo -n "" > "$WORK_DIR/data-seed/Nftyfile"
echo "{}" > "$WORK_DIR/data-seed/hosts.json"

DATA_PART="$WORK_DIR/part2-data.ext4"
truncate -s 128M "$DATA_PART"
mkfs.ext4 -q -F -L "nfty-data" -d "$WORK_DIR/data-seed" "$DATA_PART"

echo "==> [4/5] Building UEFI Boot Partition (64 MiB FAT32 ESP with kernel + nfty initramfs)..."
ESP_PART="$WORK_DIR/part1-esp.fat"
truncate -s 64M "$ESP_PART"
mformat -i "$ESP_PART" -F -v "NFTY_EFI" ::

mmd -i "$ESP_PART" ::/EFI
mmd -i "$ESP_PART" ::/EFI/BOOT
mmd -i "$ESP_PART" ::/loader
mmd -i "$ESP_PART" ::/loader/entries

EFI_BOOTLOADER="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
KERNEL_IMG="/usr/lib/modules/6.18.55-2-cachyos-lts/vmlinuz"
if [[ ! -f "$KERNEL_IMG" ]]; then
    KERNEL_IMG="$(ls /usr/lib/modules/*/vmlinuz | head -n 1)"
fi

cat > "$WORK_DIR/loader.conf" <<'EOF'
default nfty.conf
timeout 0
console-mode max
EOF

cat > "$WORK_DIR/nfty.conf" <<'EOF'
title   nfty Rust Unikernel L4 Load Balancer
linux   /vmlinuz
initrd  /initramfs.img
options console=ttyS0 console=tty0 quiet rdinit=/init -- --unikernel --file /data/Nftyfile --api-bind 0.0.0.0:9090
EOF

mcopy -i "$ESP_PART" "$EFI_BOOTLOADER" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESP_PART" "$WORK_DIR/loader.conf" ::/loader/loader.conf
mcopy -i "$ESP_PART" "$WORK_DIR/nfty.conf" ::/loader/entries/nfty.conf
mcopy -i "$ESP_PART" "$KERNEL_IMG" ::/vmlinuz
mcopy -i "$ESP_PART" "$INITRD_IMG" ::/initramfs.img

echo "==> [5/5] Assembling GPT Bootable Disk Image (disk.qcow2) + LXD Metadata..."
RAW_DISK="$WORK_DIR/disk.raw"
# Total disk size: 196 MiB (1 MiB header + 64 MiB ESP + 128 MiB ext4 data + 3 MiB backup GPT)
truncate -s 196M "$RAW_DISK"

sfdisk "$RAW_DISK" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

part1 : start=2048, size=131072, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System"
part2 : start=133120, size=262144, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="nfty-data"
EOF

# Write Partition 1 (ESP at sector 2048 = 1 MiB) and Partition 2 (ext4 at sector 133120 = 65 MiB)
dd if="$ESP_PART" of="$RAW_DISK" bs=1M seek=1 conv=notrunc status=none
dd if="$DATA_PART" of="$RAW_DISK" bs=1M seek=65 conv=notrunc status=none

mkdir -p "$ROOT_DIR/dist/lxd-vm" "$ROOT_DIR/dist/lxd-container"
QCOW2_DISK="$ROOT_DIR/dist/lxd-vm/disk.qcow2"
qemu-img convert -f raw -O qcow2 -c "$RAW_DISK" "$QCOW2_DISK"

TIMESTAMP="$(date +%s)"
mkdir -p "$WORK_DIR/meta-vm" "$WORK_DIR/meta-ct"

cat > "$WORK_DIR/meta-vm/metadata.yaml" <<EOF
architecture: x86_64
creation_date: ${TIMESTAMP}
properties:
  architecture: x86_64
  description: nfty Rust Unikernel L4 Load Balancer (with 128MB persistent /data partition)
  os: nfty-unikernel
  release: 0.1.0
EOF
tar -czf "$ROOT_DIR/dist/lxd-vm/lxd.tar.gz" -C "$WORK_DIR/meta-vm" metadata.yaml

cat > "$WORK_DIR/meta-ct/metadata.yaml" <<EOF
architecture: x86_64
creation_date: ${TIMESTAMP}
properties:
  architecture: x86_64
  description: nfty Static Rust Appliance Container
  os: nfty-unikernel
  release: 0.1.0
EOF
tar -czf "$ROOT_DIR/dist/lxd-container/lxd.tar.gz" -C "$WORK_DIR/meta-ct" metadata.yaml
tar -czf "$ROOT_DIR/dist/lxd-container/rootfs.tar.gz" -C "$STAGE_DIR" .

rm -rf "$WORK_DIR"

echo ""
echo "================================================================================"
echo "✔ LXD Bootable Unikernel VM & Container Images Built!"
echo "================================================================================"
echo "1. Bootable LXD VM Unikernel (UEFI GPT + 128MB ext4 persistent /data storage):"
echo "   - Metadata: $ROOT_DIR/dist/lxd-vm/lxd.tar.gz"
echo "   - Disk:     $ROOT_DIR/dist/lxd-vm/disk.qcow2"
echo ""
echo "   Run on your LXD server:"
echo "     lxc image import lxd.tar.gz disk.qcow2 --alias nfty-unikernel"
echo "     lxc launch nfty-unikernel nfty-lb --vm -c security.secureboot=false"
echo "     lxc console nfty-lb"
echo ""
echo "2. LXD Container Unikernel (Static musl PID-1 appliance):"
echo "   - Metadata: $ROOT_DIR/dist/lxd-container/lxd.tar.gz"
echo "   - Rootfs:   $ROOT_DIR/dist/lxd-container/rootfs.tar.gz"
echo ""
echo "   Run on your LXD server:"
echo "     lxc image import lxd.tar.gz rootfs.tar.gz --alias nfty-ct"
echo "     lxc launch nfty-ct nfty-lb"
echo "================================================================================"
