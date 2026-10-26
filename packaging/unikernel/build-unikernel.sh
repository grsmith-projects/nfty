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

echo "==> [2/6] Fetching & caching x86_64 userland, Secure Boot signed kernel + shim/grub, and ISO tools..."
ALPINE_V321="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64"
DEBIAN_POOL="https://deb.debian.org/debian/pool/main"

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

# Microsoft UEFI CA + Debian Secure Boot signed shim, grub, and Linux 6.12 LTS cloud kernel
SHIM_DEB="shim-signed_1.51~1+deb13u1+16.1-2~deb13u1_amd64.deb"
SHIM_HELPERS_DEB="shim-helpers-amd64-signed_1+16.1+2~deb13u1_amd64.deb"
GRUB_SIGNED_DEB="grub-efi-amd64-signed_1+2.12+9+deb13u2_amd64.deb"
SIGNED_KERNEL_DEB="linux-image-6.12.107+deb13-cloud-amd64_6.12.107-1_amd64.deb"

fetch_cached "$SHIM_DEB" "$DEBIAN_POOL/s/shim-signed/$SHIM_DEB"
fetch_cached "$SHIM_HELPERS_DEB" "$DEBIAN_POOL/s/shim-helpers-amd64-signed/$SHIM_HELPERS_DEB"
fetch_cached "$GRUB_SIGNED_DEB" "$DEBIAN_POOL/g/grub-efi-amd64-signed/$GRUB_SIGNED_DEB"
fetch_cached "$SIGNED_KERNEL_DEB" "$DEBIAN_POOL/l/linux-signed-amd64/$SIGNED_KERNEL_DEB"
fetch_cached "cloudflared-linux-amd64" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"

echo "==> [3/6] Assembling x86_64 Unikernel rootfs & signed kernel modules (PID-1 = /bin/nfty)..."
rm -rf "$STAGE_DIR" "$WORK_DIR"
mkdir -p "$STAGE_DIR"/{bin,sbin,usr/bin,usr/sbin,usr/lib,lib,etc/nfty,proc,sys,dev,data,run,root}
mkdir -p "$WORK_DIR/kern" "$WORK_DIR/tools" "$WORK_DIR/efi"

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
  release: 0.4.0
EOF
tar -czf "$ROOT_DIR/dist/lxd-container/lxd.tar.gz" -C "$WORK_DIR/meta-ct" metadata.yaml
tar -czf "$ROOT_DIR/dist/lxd-container/rootfs.tar.gz" -C "$STAGE_DIR" .

# Extract Secure Boot signed shim, grub, and signed Linux 6.12 LTS kernel + modules using python3
python3 - "$CACHE_DIR/$SHIM_DEB" "$CACHE_DIR/$SHIM_HELPERS_DEB" "$CACHE_DIR/$GRUB_SIGNED_DEB" "$CACHE_DIR/$SIGNED_KERNEL_DEB" "$WORK_DIR/efi" "$WORK_DIR/kern" "$STAGE_DIR" <<'PY'
import sys, os, io, tarfile, lzma

shim_deb, helpers_deb, grub_deb, kern_deb, efi_dir, kern_dir, stage_dir = sys.argv[1:8]

def open_deb_data(path):
    raw = open(path, "rb").read()
    idx = raw.find(b"data.tar.xz")
    if idx < 0:
        raise RuntimeError(f"data.tar.xz not found in {path}")
    hdr = raw[idx:idx+60].decode("ascii", errors="ignore")
    size = int(hdr[48:58].strip())
    return tarfile.open(fileobj=io.BytesIO(raw[idx+60:idx+60+size]), mode="r:xz")

with open_deb_data(shim_deb) as tf:
    for m in tf.getmembers():
        if m.name.endswith("shimx64.efi.signed"):
            open(os.path.join(efi_dir, "BOOTX64.EFI"), "wb").write(tf.extractfile(m).read())

with open_deb_data(helpers_deb) as tf:
    for m in tf.getmembers():
        if m.name.endswith("mmx64.efi.signed"):
            open(os.path.join(efi_dir, "mmx64.efi"), "wb").write(tf.extractfile(m).read())
        elif m.name.endswith("fbx64.efi.signed"):
            open(os.path.join(efi_dir, "fbx64.efi"), "wb").write(tf.extractfile(m).read())

with open_deb_data(grub_deb) as tf:
    for m in tf.getmembers():
        if m.name.endswith("gcdx64.efi.signed"):
            # gcdx64.efi.signed is Debian's signed GRUB EFI image that searches for /boot/grub/grub.cfg on ISO/ESP
            open(os.path.join(efi_dir, "grubx64.efi"), "wb").write(tf.extractfile(m).read())

with open_deb_data(kern_deb) as tf:
    for m in tf.getmembers():
        if not m.isfile():
            continue
        if "/boot/vmlinuz-" in m.name:
            open(os.path.join(kern_dir, "vmlinuz"), "wb").write(tf.extractfile(m).read())
        elif "/lib/modules/" in m.name:
            rel = m.name.lstrip("./")
            if rel.startswith("usr/lib/modules/"):
                rel = rel[4:]  # normalize usr/lib/modules -> lib/modules
            out_path = os.path.join(stage_dir, rel)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            data = tf.extractfile(m).read()
            if out_path.endswith(".ko.xz"):
                out_path = out_path[:-3]
                data = lzma.decompress(data)
            open(out_path, "wb").write(data)
PY

KVER="$(ls "$STAGE_DIR/lib/modules" | head -n 1)"
run_tool "$WORK_DIR/tools/sbin/depmod" -b "$STAGE_DIR" "$KVER"

INITRD_IMG="$ROOT_DIR/dist/nfty-unikernel-initramfs.cpio.gz"
(
    cd "$STAGE_DIR"
    find . -print0 | "$STAGE_DIR/bin/busybox" cpio -0 -o -H newc 2>/dev/null | gzip -9 > "$INITRD_IMG"
)

echo "==> [4/6] Building Secure Boot UEFI ESP & Persistent ext4 Data Partitions..."
mkdir -p "$WORK_DIR/data-seed"
echo -n "" > "$WORK_DIR/data-seed/Nftyfile"
echo "{}" > "$WORK_DIR/data-seed/hosts.json"

DATA_PART="$WORK_DIR/part2-data.ext4"
truncate -s 128M "$DATA_PART"
mkfs.ext4 -q -F -L "nfty-data" -d "$WORK_DIR/data-seed" "$DATA_PART"

KERNEL_IMG="$WORK_DIR/kern/vmlinuz"
# Put console=tty0 last so Hyper-V VMConnect / VGA console is /dev/console (while serial ttyS0 also receives kernel logs)
BOOTARGS="console=ttyS0,115200n8 console=tty0 quiet rdinit=/init -- --unikernel --file /data/Nftyfile --api-bind 0.0.0.0:9090"

cat > "$WORK_DIR/grub.cfg" <<EOF
set default=0
set timeout=1

menuentry "nfty x86_64 Unikernel Appliance (UEFI Secure Boot)" {
    linux /vmlinuz ${BOOTARGS}
    initrd /initramfs.img
}
EOF

# 1. Tiny 8 MiB El Torito UEFI Boot Image for the ISO (loads /vmlinuz and /initramfs.img from ISO9660 root without duplication!)
ISO_EFIBOOT="$WORK_DIR/efiboot-iso.img"
truncate -s 8M "$ISO_EFIBOOT"
run_tool "$WORK_DIR/tools/usr/bin/mformat" -i "$ISO_EFIBOOT" -F -v "NFTY_EFI" ::
for dir in ::/EFI ::/EFI/BOOT ::/EFI/debian ::/boot ::/boot/grub; do
    run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ISO_EFIBOOT" "$dir"
done
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/efi/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/efi/grubx64.efi" ::/EFI/BOOT/grubx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/efi/mmx64.efi" ::/EFI/BOOT/mmx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/efi/fbx64.efi" ::/EFI/BOOT/fbx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/efi/grubx64.efi" ::/EFI/debian/grubx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/grub.cfg" ::/EFI/debian/grub.cfg
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/grub.cfg" ::/EFI/BOOT/grub.cfg
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ISO_EFIBOOT" "$WORK_DIR/grub.cfg" ::/boot/grub/grub.cfg

# 2. Standalone 96 MiB ESP Partition for the Raw GPT Disk Image
ESP_PART="$WORK_DIR/part1-esp.fat"
truncate -s 96M "$ESP_PART"
run_tool "$WORK_DIR/tools/usr/bin/mformat" -i "$ESP_PART" -F -v "NFTY_EFI" ::
for dir in ::/EFI ::/EFI/BOOT ::/EFI/debian ::/boot ::/boot/grub; do
    run_tool "$WORK_DIR/tools/usr/bin/mmd" -i "$ESP_PART" "$dir"
done
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/efi/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/efi/grubx64.efi" ::/EFI/BOOT/grubx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/efi/mmx64.efi" ::/EFI/BOOT/mmx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/efi/fbx64.efi" ::/EFI/BOOT/fbx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/efi/grubx64.efi" ::/EFI/debian/grubx64.efi
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/grub.cfg" ::/EFI/debian/grub.cfg
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/grub.cfg" ::/EFI/BOOT/grub.cfg
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$WORK_DIR/grub.cfg" ::/boot/grub/grub.cfg
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$KERNEL_IMG" ::/vmlinuz
run_tool "$WORK_DIR/tools/usr/bin/mcopy" -i "$ESP_PART" "$INITRD_IMG" ::/initramfs.img

echo "==> [5/6] Building Hybrid BIOS + UEFI Secure Boot ISO (nfty-unikernel-x86_64.iso)..."
ISO_ROOT="$WORK_DIR/iso-root"
mkdir -p "$ISO_ROOT/boot/isolinux" "$ISO_ROOT/boot/grub" "$ISO_ROOT/EFI/BOOT" "$ISO_ROOT/EFI/debian"

cp "$KERNEL_IMG" "$ISO_ROOT/vmlinuz"
cp "$INITRD_IMG" "$ISO_ROOT/initramfs.img"
cp "$WORK_DIR/efi/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI"
cp "$WORK_DIR/efi/grubx64.efi" "$ISO_ROOT/EFI/BOOT/grubx64.efi"
cp "$WORK_DIR/efi/mmx64.efi" "$ISO_ROOT/EFI/BOOT/mmx64.efi"
cp "$WORK_DIR/efi/fbx64.efi" "$ISO_ROOT/EFI/BOOT/fbx64.efi"
cp "$WORK_DIR/efi/grubx64.efi" "$ISO_ROOT/EFI/debian/grubx64.efi"
cp "$WORK_DIR/grub.cfg" "$ISO_ROOT/EFI/debian/grub.cfg"
cp "$WORK_DIR/grub.cfg" "$ISO_ROOT/EFI/BOOT/grub.cfg"
cp "$WORK_DIR/grub.cfg" "$ISO_ROOT/boot/grub/grub.cfg"
cp "$ISO_EFIBOOT" "$ISO_ROOT/boot/efiboot.img"

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
truncate -s 232M "$RAW_DISK"

sfdisk "$RAW_DISK" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

part1 : start=2048, size=196608, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System"
part2 : start=198656, size=262144, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="nfty-data"
EOF

dd if="$ESP_PART" of="$RAW_DISK" bs=1M seek=1 conv=notrunc status=none
dd if="$DATA_PART" of="$RAW_DISK" bs=1M seek=97 conv=notrunc status=none

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
  release: 0.4.0
EOF
    tar -czf "$ROOT_DIR/dist/lxd-vm/lxd.tar.gz" -C "$WORK_DIR/meta-vm" metadata.yaml
fi

gzip -k -f -6 "$RAW_DISK"
rm -rf "$WORK_DIR"

echo ""
echo "================================================================================"
echo "x86_64 Secure Boot Unikernel ISO, Disk Image & LXD Container Built"
echo "================================================================================"
echo "1. Bootable Hybrid BIOS + UEFI Secure Boot ISO (Hyper-V Gen1/Gen2 / Proxmox / VMware / QEMU):"
echo "   - ISO:       $ISO_OUT"
echo ""
echo "2. Bootable UEFI Secure Boot GPT Disk Image (with 128 MiB ext4 persistent /data partition):"
echo "   - Raw Image: $RAW_DISK.gz"
echo "   - Initramfs: $INITRD_IMG"
echo ""
echo "3. LXD Container Image (Static musl PID-1 appliance):"
echo "   - Metadata:  $ROOT_DIR/dist/lxd-container/lxd.tar.gz"
echo "   - Rootfs:    $ROOT_DIR/dist/lxd-container/rootfs.tar.gz"
echo "================================================================================"
