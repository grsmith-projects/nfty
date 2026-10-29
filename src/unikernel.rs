use crate::state::{AppState, SharedState};
use anyhow::{Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

fn sys_mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong) -> bool {
    let Ok(src_c) = CString::new(source) else {
        return false;
    };
    let Ok(tgt_c) = CString::new(target) else {
        return false;
    };
    let Ok(fs_c) = CString::new(fstype) else {
        return false;
    };
    unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            fs_c.as_ptr(),
            flags,
            ptr::null(),
        ) == 0
    }
}

/// Pure-Rust DHCP lease hook invoked by `udhcpc -s /bin/udhcpc-hook`
pub fn handle_udhcpc_hook(action: &str) {
    std::env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    let iface = std::env::var("interface").unwrap_or_else(|_| "eth0".to_string());
    let is_primary = iface == "eth0";
    match action {
        "deconfig" => {
            let _ = Command::new("ip")
                .args(["link", "set", "dev", &iface, "up"])
                .status();
        }
        "bound" | "renew" => {
            if is_primary {
                if let Ok(ip) = std::env::var("ip") {
                    let mask = std::env::var("mask").unwrap_or_else(|_| "24".to_string());
                    let cidr = format!("{}/{}", ip, mask);
                    let _ = Command::new("ip")
                        .args(["addr", "replace", &cidr, "dev", &iface])
                        .status();
                    let _ = fs::create_dir_all("/run");
                    let _ = fs::write(format!("/run/nfty-dhcp-{}.ip", iface), format!("{}\n", ip));
                }
                if let Ok(routers) = std::env::var("router") {
                    if let Some(gw) = routers.split_whitespace().next() {
                        let _ = Command::new("ip")
                            .args(["route", "replace", "default", "via", gw, "dev", &iface])
                            .status();
                    }
                }
                if let Ok(dns_list) = std::env::var("dns") {
                    let mut resolv = String::new();
                    for d in dns_list.split_whitespace() {
                        resolv.push_str(&format!("nameserver {}\n", d));
                    }
                    if !resolv.is_empty() {
                        let _ = fs::write("/etc/resolv.conf", resolv);
                    }
                }
            } else if let Ok(ip) = std::env::var("ip") {
                // Secondary macvlan / VLAN DHCP VIP interface:
                // 1. Prevent ARP flux and ICMP redirects across macvlan interfaces on the same L2 bridge/VLAN
                for scope in ["all", "default", "eth0", iface.as_str()] {
                    let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_ignore", scope), "1\n");
                    let _ = fs::write(
                        format!("/proc/sys/net/ipv4/conf/{}/arp_announce", scope),
                        "2\n",
                    );
                    let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_filter", scope), "1\n");
                    let _ = fs::write(
                        format!("/proc/sys/net/ipv4/conf/{}/send_redirects", scope),
                        "0\n",
                    );
                    let _ = fs::write(
                        format!("/proc/sys/net/ipv4/conf/{}/accept_redirects", scope),
                        "0\n",
                    );
                    let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", scope), "0\n");
                }

                // 2. Bind /32 so it does not override eth0's metric-0 connected subnet route
                let cidr32 = format!("{}/32", ip);
                let _ = Command::new("ip")
                    .args(["addr", "replace", &cidr32, "dev", &iface])
                    .status();

                // 3. Persist the leased IP to /run/nfty-dhcp-<iface>.ip for nfty to read
                let _ = fs::create_dir_all("/run");
                let _ = fs::write(format!("/run/nfty-dhcp-{}.ip", iface), format!("{}\n", ip));

                // 4. Announce Gratuitous ARP so UDM / switch learns the VIP immediately
                let _ = Command::new("/bin/busybox")
                    .args(["arping", "-U", "-c", "2", "-w", "1", "-I", &iface, &ip])
                    .output();
            }
        }
        _ => {}
    }
}

/// Initializes kernel pseudo-filesystems, networking, and mounts the persistent `/data` partition
/// when `nfty` boots as PID 1 in an LXD / QEMU / KVM Unikernel VM.
/// Returns the resolved persistent Nftyfile path if `/data` is mounted.
extern "C" fn pid1_shutdown_signal(_sig: libc::c_int) {
    std::process::exit(0);
}

fn collect_modalias_recursive(dir: &Path, out: &mut std::collections::BTreeSet<String>, depth: usize) {
    if depth > 7 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if ft.is_dir() {
            collect_modalias_recursive(&path, out, depth + 1);
        } else if ft.is_file() && entry.file_name() == "modalias" {
            if let Ok(content) = fs::read_to_string(&path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    out.insert(trimmed.to_string());
                }
            }
        }
    }
}

fn load_sysfs_modalias_modules() {
    for pass in 0..2 {
        let mut aliases = std::collections::BTreeSet::new();
        collect_modalias_recursive(Path::new("/sys/devices"), &mut aliases, 0);
        for chunk in aliases.into_iter().collect::<Vec<_>>().chunks(32) {
            let mut cmd = Command::new("modprobe");
            cmd.arg("-a").arg("-q");
            for a in chunk {
                cmd.arg(a);
            }
            let _ = cmd.status();
        }
        if pass == 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
}

pub fn ensure_primary_eth0_up() -> String {
    let mut candidate_ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo"
                || name.starts_with("wg")
                || name.starts_with("mv-")
                || name.starts_with("sit")
                || name.starts_with("ip6tnl")
                || name.starts_with("tunl")
                || name.starts_with("gre")
                || name.contains('.')
            {
                continue;
            }
            candidate_ifaces.push(name);
        }
    }
    candidate_ifaces.sort();

    if !candidate_ifaces.iter().any(|n| n == "eth0") {
        if let Some(first) = candidate_ifaces.first() {
            let _ = Command::new("/sbin/ip")
                .args(["link", "set", first, "down"])
                .status();
            let _ = Command::new("/sbin/ip")
                .args(["link", "set", first, "name", "eth0"])
                .status();
        }
    }

    for iface in ["eth0", "eth1", "enp5s0", "enp0s3", "ens33", "ens18", "eth2"] {
        if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            let _ = Command::new("/sbin/ip")
                .args(["link", "set", iface, "up"])
                .status();
        }
    }

    if Path::new("/sys/class/net/eth0").exists() {
        return "eth0".to_string();
    }
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo"
                && !name.starts_with("wg")
                && !name.starts_with("mv-")
                && !name.starts_with("sit")
                && !name.starts_with("ip6tnl")
            {
                let _ = Command::new("/sbin/ip")
                    .args(["link", "set", &name, "up"])
                    .status();
                return name;
            }
        }
    }
    "eth0".to_string()
}

fn is_nfty_data_device(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut superblock = [0u8; 136];
    if file.seek(SeekFrom::Start(1024)).is_err()
        || file.read_exact(&mut superblock).is_err()
    {
        return false;
    }
    let label = &superblock[120..136];
    let label_len = label.iter().position(|&b| b == 0).unwrap_or(label.len());
    superblock[56..58] == [0x53, 0xef] && &label[..label_len] == b"nfty-data"
}

fn nfty_data_devices() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut devices: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| Path::new("/dev").join(entry.file_name()))
        .filter(|path| is_nfty_data_device(path))
        .collect();
    devices.sort();
    devices
}

/// Checks if a block device (`/dev/vda`, `/dev/sda`, `/dev/nvme0n1`, etc.) is a writable,
/// unpartitioned, completely blank virtual disk (first 1 MiB all zeros) safe to initialize
/// with an `ext4` filesystem labeled `nfty-data` on first boot.
fn is_blank_unpartitioned_disk(dev_name: &str) -> bool {
    let sys_dir = PathBuf::from(format!("/sys/class/block/{}", dev_name));
    if !sys_dir.exists() {
        return false;
    }
    if fs::read_to_string(sys_dir.join("ro"))
        .map(|s| s.trim() != "0")
        .unwrap_or(true)
    {
        return false;
    }
    let sectors: u64 = fs::read_to_string(sys_dir.join("size"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if sectors < 32768 {
        return false;
    }
    if let Ok(entries) = fs::read_dir(&sys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(dev_name) && name != dev_name {
                return false;
            }
        }
    }
    let dev_path = PathBuf::from(format!("/dev/{}", dev_name));
    let Ok(mut f) = fs::File::open(&dev_path) else {
        return false;
    };
    let mut buf = vec![0u8; 1024 * 1024];
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    n >= 65536 && buf[..n].iter().all(|&b| b == 0)
}

pub fn init_unikernel_appliance() -> Option<PathBuf> {
    if std::env::var("PATH")
        .map(|p| !p.contains("/sbin") || !p.contains("/usr/sbin"))
        .unwrap_or(true)
    {
        std::env::set_var(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
    }
    let is_pid1 = std::process::id() == 1;
    if is_pid1 {
        unsafe {
            let handler = pid1_shutdown_signal as *const () as libc::sighandler_t;
            libc::signal(libc::SIGPWR, handler);
            libc::signal(libc::SIGTERM, handler);
            libc::signal(libc::SIGINT, handler);
        }
        eprintln!("[nfty-unikernel] Booting as PID 1 Rust Unikernel appliance...");
        let _ = fs::create_dir_all("/proc");
        let _ = fs::create_dir_all("/sys");
        let _ = fs::create_dir_all("/dev");
        let _ = fs::create_dir_all("/dev/pts");
        let _ = fs::create_dir_all("/data");
        let _ = fs::create_dir_all("/run");

        // Check if we are in a bare VM initramfs (/proc/self/mounts not mounted yet)
        // vs an LXD container (where LXD already mounted /proc, /dev, and persistent ZFS /)
        let is_bare_vm_initrd = !Path::new("/proc/self/mounts").exists();

        if is_bare_vm_initrd {
            let _ = sys_mount("proc", "/proc", "proc", 0);
            let _ = sys_mount("sysfs", "/sys", "sysfs", 0);
            let _ = sys_mount("devtmpfs", "/dev", "devtmpfs", 0);
            let _ = fs::create_dir_all("/dev/pts");
            let _ = sys_mount("devpts", "/dev/pts", "devpts", 0);

            if Path::new("/lib/modules").exists() {
                let core_mods = [
                    "ext4",
                    "virtio_pci",
                    "virtio_blk",
                    "virtio_net",
                    "virtio_scsi",
                    "e1000",
                    "e1000e",
                    "igb",
                    "8139cp",
                    "8139too",
                    "pcnet32",
                    "vmxnet3",
                    "ahci",
                    "ata_piix",
                    "sd_mod",
                    "sr_mod",
                    "nvme",
                    "mmc_block",
                    "dw_mmc-rockchip",
                    "sdhci-of-dwcmshc",
                    "phy-rockchip-naneng-combphy",
                    "phy-rockchip-snps-pcie3",
                    "dwmac-rk",
                    "stmmac-platform",
                    "stmmac",
                    "motorcomm",
                    "realtek",
                    "r8169",
                    "r8152",
                    "nf_tables",
                    "nf_conntrack",
                    "nf_nat",
                    "nft_ct",
                    "nft_nat",
                    "nft_masq",
                    "nft_redir",
                    "nft_chain_nat",
                    "nft_counter",
                    "nft_limit",
                    "nft_numgen",
                    "nft_hash",
                    "nft_reject",
                    "nft_reject_inet",
                    "wireguard",
                    "8021q",
                    "macvlan",
                ];
                for m in core_mods {
                    let _ = Command::new("/sbin/modprobe").args(["-q", m]).status();
                }
                load_sysfs_modalias_modules();
                for _ in 0..8 {
                    let has_nic = fs::read_dir("/sys/class/net")
                        .ok()
                        .map(|entries| {
                            entries.flatten().any(|e| {
                                let n = e.file_name().to_string_lossy().to_string();
                                n != "lo" && !n.starts_with("sit") && !n.starts_with("ip6tnl")
                            })
                        })
                        .unwrap_or(false);
                    if has_nic {
                        break;
                    }
                    load_sysfs_modalias_modules();
                    std::thread::sleep(Duration::from_millis(250));
                }
            }

            let mut mounted = false;
            for pass in 0..4 {
                let devices = nfty_data_devices();
                if devices.len() > 1 {
                    eprintln!(
                        "[nfty-unikernel] Multiple nfty-data filesystems found; refusing to choose: {:?}",
                        devices
                    );
                    break;
                }
                if let Some(device) = devices.first() {
                    if let Some(dev) = device.to_str() {
                        mounted = sys_mount(dev, "/data", "ext4", 0);
                        eprintln!(
                            "[nfty-unikernel] {} persistent storage {} at /data",
                            if mounted { "Mounted" } else { "Failed to mount" },
                            device.display()
                        );
                    }
                    break;
                }
                if pass >= 1 && Path::new("/sbin/mke2fs").exists() {
                    for disk in ["vda", "sda", "nvme0n1", "vdb", "sdb"] {
                        if is_blank_unpartitioned_disk(disk) {
                            let dev = format!("/dev/{}", disk);
                            eprintln!(
                                "[nfty-unikernel] Formatting blank virtual disk {} as ext4 (label: nfty-data)...",
                                dev
                            );
                            let ok = Command::new("/sbin/mke2fs")
                                .args(["-t", "ext4", "-F", "-q", "-L", "nfty-data", &dev])
                                .status()
                                .map(|s| s.success())
                                .unwrap_or(false);
                            if ok && sys_mount(&dev, "/data", "ext4", 0) {
                                mounted = true;
                                eprintln!(
                                    "[nfty-unikernel] Auto-formatted and mounted persistent storage {} at /data",
                                    dev
                                );
                                break;
                            }
                        }
                    }
                    if mounted {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }

            if !mounted {
                let _ = fs::write("/run/nfty-ephemeral-storage", "1\n");
                eprintln!(
                    "[nfty-unikernel] WARNING: No persistent disk mounted at /data — running in ephemeral RAM! Attach a virtual disk to persist configuration across reboots."
                );
            }
        }

        let _ = Command::new("/sbin/ip").args(["link", "set", "lo", "up"]).status();
        let _ = Command::new("/sbin/ip")
            .args(["addr", "replace", "127.0.0.1/8", "dev", "lo"])
            .status();

        // Bring physical link(s) up without acquiring an unconfigured base OS IP;
        // all IPv4 addresses (static or DHCP) are bound strictly from Nftyfile.
        let _ = ensure_primary_eth0_up();
    }

    // Enable kernel IPv4 packet forwarding, secondary IP promotion, and disable ICMP redirects / ARP flux
    let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1\n");
    for scope in ["all", "default", "eth0"] {
        let _ = fs::write(
            format!("/proc/sys/net/ipv4/conf/{}/promote_secondaries", scope),
            "1\n",
        );
        let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_ignore", scope), "1\n");
        let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_announce", scope), "2\n");
        let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_filter", scope), "1\n");
        let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/send_redirects", scope), "0\n");
        let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/accept_redirects", scope), "0\n");
    }

    let default_seed = "gateway default {\n    dhcp eth0\n    ssh:22\n}\n";
    let data_dir = Path::new("/data");
    if data_dir.exists() && data_dir.is_dir() {
        let _ = fs::create_dir_all(data_dir.join("wg"));
        let _ = fs::create_dir_all(data_dir.join("ssh"));
        let persistent_cfg = data_dir.join("Nftyfile");
        let is_empty = fs::read_to_string(&persistent_cfg)
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if !persistent_cfg.exists() || is_empty {
            let seed = fs::read_to_string("/etc/nfty/Nftyfile")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| default_seed.to_string());
            if let Err(e) = fs::write(&persistent_cfg, seed) {
                eprintln!("[nfty-unikernel] Failed to seed {}: {}", persistent_cfg.display(), e);
            }
        }
        if persistent_cfg.exists() {
            return Some(persistent_cfg);
        }
    }
    None
}

pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    write_atomic_with_mode(path, contents, 0o600)
}

pub(crate) fn write_atomic_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    static NEXT_TEMP_FILE: AtomicUsize = AtomicUsize::new(0);
    let mut created = None;
    for _ in 0..128 {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".tmp.{}.{}", std::process::id(), sequence));
        let candidate = PathBuf::from(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("Failed to open {}", candidate.display())),
        }
    }
    let (tmp, mut file) = created.context("Could not allocate a unique temporary file")?;
    let result = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("Failed to set permissions on {}", tmp.display()))?;
        file.write_all(contents)
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("Failed to replace {}", path.display()))?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("Failed to sync directory {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() && tmp.exists() {
        if let Err(e) = fs::remove_file(&tmp) {
            eprintln!("nfty: failed to remove {}: {}", tmp.display(), e);
        }
    }
    result
}

pub(crate) fn persist_state(st: &mut AppState) -> Result<()> {
    if Path::new("/run/nfty-ephemeral-storage").exists() {
        eprintln!(
            "nfty: warning: /data is running in ephemeral RAM (no persistent virtual disk attached to VM); changes will not survive a reboot."
        );
    }
    let config = st.pending_confirm.as_ref().map(|pending| &pending.revert_to).unwrap_or(&st.running);
    let cfg_txt = config.format_nftyfile();
    #[cfg(test)]
    if st.config_path == Path::new("Nftyfile") && !st.config_path.exists() {
        st.last_disk_nftyfile = cfg_txt;
        return Ok(());
    }
    write_atomic(&st.config_path, cfg_txt.as_bytes())?;
    st.last_disk_nftyfile = cfg_txt;
    Ok(())
}

pub(crate) fn read_persisted_hosts(path: &Path) -> Result<std::collections::BTreeMap<String, Vec<Ipv4Addr>>> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).context("Failed to parse persisted host mappings"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

pub(crate) fn persist_host_mapping(host: &str, ips: &[Ipv4Addr]) -> Result<()> {
    let data = Path::new("/data");
    if !data.is_dir() {
        if unsafe { libc::geteuid() != 0 } {
            return Ok(());
        }
        anyhow::bail!("Cannot persist host mapping: /data is unavailable");
    }
    persist_host_mapping_at(&data.join("hosts.json"), host, ips)
}

fn persist_host_mapping_at(path: &Path, host: &str, ips: &[Ipv4Addr]) -> Result<()> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| format!("Cannot open {}", lock_path.display()))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Cannot lock {}", lock_path.display()));
    }
    let mut hosts = read_persisted_hosts(path)?;
    if ips.is_empty() {
        hosts.remove(host);
    } else {
        hosts.insert(host.to_string(), ips.to_vec());
    }
    write_atomic(path, serde_json::to_string_pretty(&hosts)?.as_bytes())
}

#[cfg(test)]
mod host_persistence_tests {
    use super::*;

    #[test]
    fn deleting_a_host_preserves_other_mappings_and_can_empty_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "nfty-hosts-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("hosts.json");
        let first = Ipv4Addr::new(192, 0, 2, 1);
        let second = Ipv4Addr::new(192, 0, 2, 2);
        persist_host_mapping_at(&path, "first.example", &[first]).unwrap();
        persist_host_mapping_at(&path, "second.example", &[second]).unwrap();
        persist_host_mapping_at(&path, "first.example", &[]).unwrap();
        let hosts = read_persisted_hosts(&path).unwrap();
        assert!(!hosts.contains_key("first.example"));
        assert_eq!(hosts["second.example"], vec![second]);
        persist_host_mapping_at(&path, "second.example", &[]).unwrap();
        assert!(read_persisted_hosts(&path).unwrap().is_empty());
        fs::remove_file(dir.join("hosts.json.lock")).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}

pub fn persist_to_storage(shared: &SharedState) -> Result<()> {
    let mut st = shared.write().unwrap();
    persist_state(&mut st)
}

pub(crate) fn pid1_is_nfty() -> bool {
    std::process::id() == 1
        || fs::read_link("/proc/1/exe")
            .map(|p| p.file_name().and_then(|n| n.to_str()) == Some("nfty"))
            .unwrap_or(false)
}


/// Root-only Unix socket the authoritative controller listens on for CLI/SSH-session updates.
pub fn controller_socket_path() -> PathBuf {
    if unsafe { libc::geteuid() } != 0 {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            return PathBuf::from(xdg).join("nfty-ctl.sock");
        }
    }
    PathBuf::from("/run/nfty/ctl.sock")
}

fn is_controller_unavailable(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io_err| {
            matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            )
        })
    })
}

fn send_controller_request(socket: &Path, method: &str, path: &str, body: &str) -> Result<()> {
    use std::io::BufRead;

    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("Failed to connect to controller {}", socket.display()))?;
    let timeout = Some(Duration::from_secs(10));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let mut req = serde_json::json!({"method": method, "path": path, "body": body}).to_string();
    req.push('\n');
    stream.write_all(req.as_bytes())?;
    let mut line = String::new();
    std::io::BufReader::new(stream).read_line(&mut line)?;
    let resp: serde_json::Value =
        serde_json::from_str(line.trim()).context("Malformed controller response")?;
    if resp.get("status").and_then(|s| s.as_u64()) != Some(200) {
        let error = resp
            .pointer("/body/error")
            .and_then(|e| e.as_str())
            .unwrap_or("request failed");
        anyhow::bail!("Controller rejected request: {}", error);
    }
    Ok(())
}

fn notify_controller(shared: &SharedState) -> Result<()> {
    let (socket, body, authoritative) = {
        let st = shared.read().unwrap();
        (st.controller_socket.clone(), st.running.format_nftyfile(), st.controller_is_authoritative)
    };
    if authoritative {
        return Ok(());
    }
    if socket.exists() {
        if let Err(e) = send_controller_request(&socket, "PUT", "/api/v1/config", &body) {
            if !pid1_is_nfty() && is_controller_unavailable(&e) {
                return Ok(());
            }
            return Err(e);
        }
    } else if pid1_is_nfty() && std::process::id() != 1 {
        unsafe {
            libc::kill(1, libc::SIGHUP);
        }
    }
    Ok(())
}

pub(crate) fn notify_controller_host_mapping(
    shared: &SharedState,
    host: &str,
    ips: &[Ipv4Addr],
) -> Result<()> {
    let (socket, authoritative) = {
        let st = shared.read().unwrap();
        (st.controller_socket.clone(), st.controller_is_authoritative)
    };
    if !authoritative && socket.exists() {
        let body = serde_json::json!({"host": host, "ips": ips}).to_string();
        if let Err(e) = send_controller_request(&socket, "PUT", "/api/v1/allow/hosts", &body) {
            if !pid1_is_nfty() && is_controller_unavailable(&e) {
                return Ok(());
            }
            return Err(e);
        }
    }
    Ok(())
}

pub(crate) fn dispatch_backend_drain_state(
    shared: &SharedState,
    endpoints: &[String],
    drained: bool,
) -> Result<()> {
    let socket = {
        let mut st = shared.write().unwrap();
        if st.controller_is_authoritative || (!st.controller_socket.exists() && !pid1_is_nfty()) {
            return crate::compiler::set_backend_drain_state(&mut st, endpoints, drained);
        }
        st.controller_socket.clone()
    };

    let path = if drained {
        "/api/v1/drain"
    } else {
        "/api/v1/enable"
    };
    for endpoint in endpoints {
        let body = serde_json::json!({"backend": endpoint}).to_string();
        send_controller_request(&socket, "POST", path, &body).with_context(|| {
            format!(
                "Controller failed to update backend {}; earlier updates, if any, may already be active",
                endpoint
            )
        })?;
        if let Some(runtime) = shared.write().unwrap().runtime.get_mut(endpoint) {
            runtime.drained = drained;
        }
    }
    Ok(())
}
#[cfg(test)]
mod controller_dispatch_tests {
    use super::*;
    use std::io::BufRead;
    use std::sync::RwLock;

    #[test]
    fn secondary_drain_uses_controller_and_keeps_state_on_rejection() {
        let dir = std::env::temp_dir().join(format!("nfty-ctl-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for (path, status) in [("/api/v1/drain", 200), ("/api/v1/enable", 500)] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&mut stream).read_line(&mut line).unwrap();
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(req["method"], "POST");
                assert_eq!(req["path"], path);
                let body: serde_json::Value =
                    serde_json::from_str(req["body"].as_str().unwrap()).unwrap();
                assert_eq!(body["backend"].as_str(), Some("192.0.2.21:80"));
                writeln!(stream, "{}", serde_json::json!({"status": status, "body": {}})).unwrap();
            }
        });
        let mut state = AppState::new(crate::ast::Config::new(), PathBuf::from("Nftyfile"));
        state.controller_socket = socket;
        state
            .runtime
            .insert("192.0.2.21:80".to_string(), Default::default());
        let shared = Arc::new(RwLock::new(state));
        let endpoints = vec!["192.0.2.21:80".to_string()];
        dispatch_backend_drain_state(&shared, &endpoints, true).unwrap();
        assert!(shared.read().unwrap().runtime[&endpoints[0]].drained);
        assert!(dispatch_backend_drain_state(&shared, &endpoints, false).is_err());
        let state = shared.read().unwrap();
        assert!(state.runtime[&endpoints[0]].drained);
        assert!(!state.kernel_applied);
        drop(state);
        server.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}

pub fn persist_and_notify_controller(shared: &SharedState) -> Result<()> {
    persist_to_storage(shared)
        .context("Configuration was applied locally but could not be persisted")?;
    notify_controller(shared)
        .context("Configuration was applied and saved, but controller synchronization failed")
}
