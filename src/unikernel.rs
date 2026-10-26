use crate::ast::{Backend, BalanceStrategy, Proto};
use crate::state::SharedState;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

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
                // 1. Prevent ARP flux across macvlan interfaces on the same L2 bridge/VLAN
                let _ = fs::write("/proc/sys/net/ipv4/conf/all/arp_ignore", "1\n");
                let _ = fs::write("/proc/sys/net/ipv4/conf/all/arp_announce", "2\n");
                let _ = fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n");
                let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_ignore", iface), "1\n");
                let _ = fs::write(
                    format!("/proc/sys/net/ipv4/conf/{}/arp_announce", iface),
                    "2\n",
                );
                let _ = fs::write(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", iface), "0\n");

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

fn ensure_primary_eth0_up() {
    let mut candidate_ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" || name.starts_with("wg") || name.starts_with("sit") || name.starts_with("ip6tnl") {
                continue;
            }
            candidate_ifaces.push(name);
        }
    }
    candidate_ifaces.sort();

    if !candidate_ifaces.iter().any(|n| n == "eth0") {
        if let Some(first) = candidate_ifaces.first() {
            let _ = Command::new("ip")
                .args(["link", "set", first, "down"])
                .status();
            let _ = Command::new("ip")
                .args(["link", "set", first, "name", "eth0"])
                .status();
        }
    }

    for iface in ["eth0", "eth1", "enp5s0"] {
        if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            let _ = Command::new("ip")
                .args(["link", "set", iface, "up"])
                .status();
        }
    }
}

pub fn init_unikernel_appliance() -> Option<PathBuf> {
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
                    "mmc_block",
                    "dw_mmc-rockchip",
                    "sdhci-of-dwcmshc",
                    "phy-rockchip-naneng-combphy",
                    "phy-rockchip-snps-pcie3",
                    "nvme",
                    "dwmac-rk",
                    "stmmac-platform",
                    "stmmac",
                    "motorcomm",
                    "realtek",
                    "r8169",
                    "r8152",
                    "nf_tables",
                    "nf_conntrack",
                    "nft_ct",
                    "nft_nat",
                    "nft_masq",
                    "nft_chain_nat",
                    "nft_counter",
                    "nft_limit",
                    "nft_numgen",
                    "nft_hash",
                    "wireguard",
                    "8021q",
                    "macvlan",
                ];
                for m in core_mods {
                    let _ = Command::new("modprobe").args(["-q", m]).status();
                }
                load_sysfs_modalias_modules();
            }

            let data_devs = [
                "/dev/vda2",
                "/dev/sda2",
                "/dev/nvme0n1p2",
                "/dev/mmcblk0p2",
                "/dev/mmcblk1p2",
                "/dev/mmcblk2p2",
                "/dev/sdb2",
            ];
            let mut mounted = false;
            for _ in 0..8 {
                for dev in data_devs {
                    if Path::new(dev).exists() && sys_mount(dev, "/data", "ext4", 0) {
                        eprintln!(
                            "[nfty-unikernel] Mounted persistent storage {} at /data (ext4)",
                            dev
                        );
                        mounted = true;
                        break;
                    }
                }
                if mounted {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        let _ = Command::new("ip").args(["link", "set", "lo", "up"]).status();
        let _ = Command::new("ip")
            .args(["addr", "replace", "127.0.0.1/8", "dev", "lo"])
            .status();

        ensure_primary_eth0_up();

        // Automatically acquire IPv4 address via DHCP on eth0
        if Path::new("/bin/udhcpc").exists() {
            let _ = Command::new("/bin/udhcpc")
                .args(["-i", "eth0", "-s", "/bin/udhcpc-hook", "-b", "-q"])
                .status();
        }
    }

    // Enable kernel IPv4 packet forwarding if writable
    let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1\n");

    let data_dir = Path::new("/data");
    if data_dir.exists() && data_dir.is_dir() {
        let persistent_cfg = data_dir.join("Nftyfile");
        if !persistent_cfg.exists() {
            if let Ok(seed) = fs::read_to_string("/etc/nfty/Nftyfile") {
                let _ = fs::write(&persistent_cfg, seed);
            }
        }
        if persistent_cfg.exists() {
            return Some(persistent_cfg);
        }
    }
    None
}

/// Automatically persists the running configuration & resolved hosts to `/data` (if writable)
/// and syncs with PID 1's local API (`127.0.0.1:9090`) if invoked from a secondary `lxc exec` shell.
pub fn persist_to_storage(shared: &SharedState) {
    let (cfg_txt, is_empty_cfg, config_path, resolved_hosts) = {
        let mut st = shared.write().unwrap();
        let is_empty = st.running.is_empty();
        let txt = st.running.format_nftyfile();
        st.last_disk_nftyfile = txt.clone();
        (txt, is_empty, st.config_path.clone(), st.resolved_hosts.clone())
    };

    let pid = std::process::id();

    if config_path.starts_with("/data") || Path::new("/data").exists() {
        let target = if config_path.starts_with("/data") {
            config_path
        } else {
            PathBuf::from("/data/Nftyfile")
        };

        // Never overwrite an existing non-empty Nftyfile with an empty default state
        let existing_non_empty = fs::read_to_string(&target)
            .map(|s| {
                let t = s.trim();
                !t.is_empty() && t != "# Empty Nftyfile"
            })
            .unwrap_or(false);

        if !(is_empty_cfg && existing_non_empty) {
            let tmp_path = target.with_extension(format!("tmp.{}", pid));
            if fs::write(&tmp_path, &cfg_txt).is_ok() {
                let _ = fs::rename(&tmp_path, &target);
            }
        }

        // Merge resolved_hosts with existing /data/hosts.json and write atomically
        let mut merged_hosts = fs::read_to_string("/data/hosts.json")
            .ok()
            .and_then(|s| {
                serde_json::from_str::<std::collections::BTreeMap<String, Vec<Ipv4Addr>>>(&s).ok()
            })
            .unwrap_or_default();
        for (k, v) in resolved_hosts {
            if !v.is_empty() {
                merged_hosts.insert(k, v);
            }
        }
        if !merged_hosts.is_empty() {
            if let Ok(hj) = serde_json::to_string_pretty(&merged_hosts) {
                let tmp_hosts = PathBuf::from(format!("/data/hosts.json.tmp.{}", pid));
                if fs::write(&tmp_hosts, &hj).is_ok() {
                    let _ = fs::rename(&tmp_hosts, "/data/hosts.json");
                }
            }
        }
    }

    // If this is a secondary `lxc exec` or `--ssh-session` shell (PID != 1), push config to PID 1's local control API
    if pid != 1 && !is_empty_cfg {
        let body = cfg_txt;
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                &"127.0.0.1:9090".parse().unwrap(),
                Duration::from_millis(500),
            ) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let req = format!(
                    "PUT /api/v1/config HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nX-Nfty-Internal-IPC: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(req.as_bytes());
                let _ = stream.flush();
                let mut resp = [0u8; 256];
                let _ = stream.read(&mut resp);
            }
        });
    }
}

/// Spawns the native Rust L4 Load-Balancer Dataplane for Unikernel / Standalone Userspace mode.
pub fn spawn_unikernel_dataplane(shared: SharedState) {
    tokio::spawn(async move {
        let mut active_listeners: HashMap<(String, Option<Ipv4Addr>, u16, Proto), tokio::task::JoinHandle<()>> = HashMap::new();

        loop {
            let services_snapshot = {
                let st = shared.read().unwrap();
                st.active_config().services.clone()
            };

            active_listeners.retain(|(k, lip, port, proto), handle| {
                let keep = services_snapshot.get(k).map(|svc| {
                    let is_local_loopback =
                        svc.backends.is_empty() || svc.backends.iter().all(|b| b.ip.is_loopback());
                    let is_unleased_dhcp =
                        svc.listen_ip.is_none() && svc.vip.as_ref().map(|v| v.dhcp).unwrap_or(false);
                    matches!(svc.proto, Proto::Tcp | Proto::Both)
                        && !is_local_loopback
                        && !is_unleased_dhcp
                        && svc.port != 22
                        && svc.listen_ip == *lip
                        && svc.port == *port
                        && svc.proto == *proto
                }).unwrap_or(false);
                if !keep {
                    handle.abort();
                }
                keep
            });

            for (key, svc) in services_snapshot {
                let is_local_loopback =
                    svc.backends.is_empty() || svc.backends.iter().all(|b| b.ip.is_loopback());
                let is_unleased_dhcp =
                    svc.listen_ip.is_none() && svc.vip.as_ref().map(|v| v.dhcp).unwrap_or(false);
                let listener_key = (key.clone(), svc.listen_ip, svc.port, svc.proto);
                if matches!(svc.proto, Proto::Tcp | Proto::Both)
                    && !is_local_loopback
                    && !is_unleased_dhcp
                    && svc.port != 22
                    && !active_listeners.contains_key(&listener_key)
                {
                    let st_clone = shared.clone();
                    let svc_key = key.clone();
                    let bind_ip = svc.listen_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let bind_addr = SocketAddr::new(IpAddr::V4(bind_ip), svc.port);

                    let handle = tokio::spawn(async move {
                        let Ok(listener) = TcpListener::bind(bind_addr).await else {
                            return;
                        };
                        let rr_counter = Arc::new(AtomicUsize::new(0));
                        let rate_buckets: Arc<Mutex<HashMap<Ipv4Addr, (Instant, u32)>>> =
                            Arc::new(Mutex::new(HashMap::new()));

                        while let Ok((mut client_stream, peer_addr)) = listener.accept().await {
                            let client_ip = match peer_addr.ip() {
                                IpAddr::V4(ip4) => ip4,
                                IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
                            };

                            let selection = {
                                let st = st_clone.read().unwrap();
                                let cfg = st.active_config();
                                let Some(cur_svc) = cfg.services.get(&svc_key) else {
                                    continue;
                                };

                                if !st.is_ip_allowed(
                                    client_ip,
                                    &cur_svc.allow,
                                    &cfg.global_allow,
                                ) {
                                    None
                                } else {
                                    let active = st.active_backends_for_service(&cur_svc.backends);
                                    let chosen = select_weighted_backend(
                                        &active,
                                        cur_svc.balance,
                                        client_ip,
                                        &rr_counter,
                                    );
                                    chosen.map(|b| (b.clone(), cur_svc.limit.clone(), cur_svc.auth.clone(), cur_svc.display_name()))
                                }
                            };

                            let Some((target_backend, rate_limit, auth_rules, svc_label)) = selection else {
                                continue;
                            };

                            if let Some(lim) = rate_limit {
                                let mut buckets = rate_buckets.lock().await;
                                let window = match lim.unit {
                                    crate::ast::RateUnit::Second => Duration::from_secs(1),
                                    crate::ast::RateUnit::Minute => Duration::from_secs(60),
                                };
                                if buckets.len() > 4096 {
                                    buckets.retain(|_, (ts, _)| ts.elapsed() < window);
                                }
                                let max_allowed = lim.rate + lim.burst.unwrap_or(0);
                                let bucket_key = if lim.per_ip {
                                    client_ip
                                } else {
                                    Ipv4Addr::UNSPECIFIED
                                };
                                let entry = buckets
                                    .entry(bucket_key)
                                    .or_insert_with(|| (Instant::now(), 0));
                                if entry.0.elapsed() >= window {
                                    *entry = (Instant::now(), 1);
                                } else {
                                    entry.1 += 1;
                                    if entry.1 > max_allowed {
                                        continue;
                                    }
                                }
                            }

                            let st_for_conn = st_clone.clone();
                            tokio::spawn(async move {
                                let mut initial_buf = Vec::new();
                                if !auth_rules.is_empty() {
                                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                    let mut peek_buf = [0u8; 4096];
                                    let Ok(Ok(n)) = tokio::time::timeout(
                                        Duration::from_secs(5),
                                        client_stream.read(&mut peek_buf),
                                    )
                                    .await
                                    else {
                                        return;
                                    };
                                    if n == 0 {
                                        return;
                                    }
                                    if !crate::features::check_http_basic_auth(&peek_buf[..n], &auth_rules) {
                                        let resp = format!(
                                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nfty ({})\"\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\n401 Authentication Needed\n",
                                            svc_label
                                        );
                                        let _ = client_stream.write_all(resp.as_bytes()).await;
                                        return;
                                    }
                                    initial_buf = crate::features::sanitize_authenticated_http_request(&peek_buf[..n]);
                                }

                                let target_addr = SocketAddr::new(
                                    IpAddr::V4(target_backend.ip),
                                    target_backend.port,
                                );
                                if let Ok(mut upstream) = TcpStream::connect(target_addr).await {
                                    if !initial_buf.is_empty() {
                                        use tokio::io::AsyncWriteExt;
                                        if upstream.write_all(&initial_buf).await.is_err() {
                                            return;
                                        }
                                    }
                                    if let Ok((from_client, from_server)) =
                                        copy_bidirectional(&mut client_stream, &mut upstream).await
                                    {
                                        let mut st = st_for_conn.write().unwrap();
                                        let rt = st
                                            .runtime
                                            .entry(target_backend.endpoint())
                                            .or_default();
                                        rt.packets += 2;
                                        rt.bytes += (initial_buf.len() as u64) + from_client + from_server;
                                    }
                                }
                            });
                        }
                    });
                    active_listeners.insert(listener_key, handle);
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

fn select_weighted_backend<'a>(
    active: &[&'a Backend],
    strategy: BalanceStrategy,
    client_ip: Ipv4Addr,
    rr_counter: &AtomicUsize,
) -> Option<&'a Backend> {
    if active.is_empty() {
        return None;
    }
    let mut slots: Vec<&'a Backend> = Vec::new();
    for b in active {
        for _ in 0..b.weight.max(1) {
            slots.push(*b);
        }
    }
    let idx = match strategy {
        BalanceStrategy::RoundRobin => rr_counter.fetch_add(1, Ordering::Relaxed) % slots.len(),
        BalanceStrategy::Sticky => {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            client_ip.hash(&mut hasher);
            (hasher.finish() as usize) % slots.len()
        }
    };
    slots.get(idx).copied()
}
