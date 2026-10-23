use crate::ast::{Config, GatewayServiceKind, WgTunnel};
use crate::state::{HealthState, SharedState};
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedWgConf {
    pub address: String,
    pub private_key: String,
    pub peer_pubkey: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub keepalive: u16,
}

/// Parses a standard WireGuard / Mullvad `.conf` file
pub fn parse_wg_conf_str(raw: &str) -> Result<ParsedWgConf> {
    let mut address = None;
    let mut private_key = None;
    let mut peer_pubkey = None;
    let mut preshared_key = None;
    let mut endpoint = None;
    let mut keepalive = 25u16;

    for raw_line in raw.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "address" => {
                    // Take first IPv4 address if comma-separated (Mullvad includes IPv4,IPv6)
                    for part in val.split(',') {
                        let p = part.trim();
                        if !p.contains(':') {
                            address = Some(if p.contains('/') {
                                p.to_string()
                            } else {
                                format!("{}/32", p)
                            });
                            break;
                        }
                    }
                }
                "privatekey" => private_key = Some(val.to_string()),
                "publickey" => peer_pubkey = Some(val.to_string()),
                "presharedkey" => preshared_key = Some(val.to_string()),
                "endpoint" => endpoint = Some(val.to_string()),
                "persistentkeepalive" => {
                    if let Ok(ka) = val.parse::<u16>() {
                        keepalive = ka;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(ParsedWgConf {
        address: address.context("Missing IPv4 'Address =' in WireGuard config")?,
        private_key: private_key.context("Missing 'PrivateKey =' in WireGuard config")?,
        peer_pubkey: peer_pubkey.context("Missing 'PublicKey =' in WireGuard config")?,
        preshared_key,
        endpoint: endpoint.context("Missing 'Endpoint =' in WireGuard config")?,
        keepalive,
    })
}

pub fn resolve_tunnel_config(t: &WgTunnel) -> Result<ParsedWgConf> {
    if let (Some(addr), Some(pk), Some(peer), Some(ep)) = (
        &t.address,
        &t.private_key,
        &t.peer_pubkey,
        &t.endpoint,
    ) {
        return Ok(ParsedWgConf {
            address: if addr.contains('/') {
                addr.clone()
            } else {
                format!("{}/32", addr)
            },
            private_key: pk.clone(),
            peer_pubkey: peer.clone(),
            preshared_key: None,
            endpoint: ep.clone(),
            keepalive: 25,
        });
    }

    let candidates = [
        PathBuf::from(format!("/data/wg/{}", t.name)),
        PathBuf::from(format!("/data/wg/{}.conf", t.name)),
        PathBuf::from(format!("/etc/wireguard/{}", t.name)),
        PathBuf::from(&t.name),
    ];

    for path in &candidates {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("Failed to read WireGuard config {}", path.display()))?;
            return parse_wg_conf_str(&raw)
                .with_context(|| format!("Invalid WireGuard config in {}", path.display()));
        }
    }

    bail!(
        "WireGuard config '{}' not found in /data/wg/ (upload via 'wg import {}' or POST /api/v1/wg)",
        t.name,
        t.name
    )
}

/// Applies all configured WireGuard Virtual Gateways:
/// - Creates kernel `wgN` interfaces
/// - Configures private keys, endpoints, and `FwMark = 0x51820`
/// - Installs policy routing rules (`fwmark 0x101+i lookup 101+i`)
pub fn apply_wireguard_gateways(cfg: &Config) -> Vec<String> {
    let mut logs = Vec::new();
    let _ = fs::create_dir_all("/data/wg");
    let _ = fs::create_dir_all("/run");

    // Enable loose rp_filter so policy-routed asymmetric WireGuard return packets aren't dropped
    let _ = fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "2\n");
    let _ = fs::write("/proc/sys/net/ipv4/conf/default/rp_filter", "2\n");

    let mut global_idx = 0usize;
    for gw in cfg.gateways.values() {
        for t in &gw.tunnels {
            let iface = if t.iface.is_empty() {
                format!("wg{}", global_idx)
            } else {
                t.iface.clone()
            };
            let table_id = 101 + global_idx;
            let fwmark = 0x101 + global_idx;
            global_idx += 1;

            let parsed = match resolve_tunnel_config(t) {
                Ok(p) => p,
                Err(e) => {
                    logs.push(format!("WARN: {}", e));
                    continue;
                }
            };

            // Write stripped wg-setconf file to /run/nfty-<iface>.conf
            let mut wg_conf = format!(
                "[Interface]\nPrivateKey = {}\nFwMark = 0x51820\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {}\n",
                parsed.private_key, parsed.peer_pubkey, parsed.endpoint, parsed.keepalive
            );
            if let Some(psk) = &parsed.preshared_key {
                wg_conf.push_str(&format!("PresharedKey = {}\n", psk));
            }
            let run_conf_path = format!("/run/nfty-{}.conf", iface);
            let _ = fs::write(&run_conf_path, wg_conf);

            // Create and configure kernel WireGuard interface
            let _ = Command::new("ip")
                .args(["link", "add", "dev", &iface, "type", "wireguard"])
                .output();
            let _ = Command::new("ip")
                .args(["addr", "flush", "dev", &iface])
                .output();
            let _ = Command::new("ip")
                .args(["addr", "replace", &parsed.address, "dev", &iface])
                .output();
            let _ = Command::new("ip")
                .args(["link", "set", "mtu", "1420", " up", "dev", &iface])
                .output();
            let _ = Command::new("ip")
                .args(["link", "set", "dev", &iface, "up"])
                .output();

            let wg_res = Command::new("wg")
                .args(["setconf", &iface, &run_conf_path])
                .output();

            // Policy routing table for this tunnel (both fwmark and source IP from tunnel)
            let table_str = table_id.to_string();
            let mark_hex = format!("0x{:x}", fwmark);
            let prio_str = (1000 + global_idx).to_string();
            let src_ip = parsed
                .address
                .split('/')
                .next()
                .unwrap_or(&parsed.address)
                .trim()
                .to_string();

            let _ = Command::new("ip")
                .args(["route", "replace", "default", "dev", &iface, "table", &table_str])
                .output();
            // Ensure rules aren't duplicated
            let _ = Command::new("ip")
                .args(["rule", "del", "fwmark", &mark_hex, "table", &table_str])
                .output();
            let _ = Command::new("ip")
                .args([
                    "rule",
                    "add",
                    "fwmark",
                    &mark_hex,
                    "table",
                    &table_str,
                    "priority",
                    &prio_str,
                ])
                .output();
            if !src_ip.is_empty() {
                let _ = Command::new("ip")
                    .args(["rule", "del", "from", &src_ip, "table", &table_str])
                    .output();
                let _ = Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "from",
                        &src_ip,
                        "table",
                        &table_str,
                        "priority",
                        &prio_str,
                    ])
                    .output();
            }

            match wg_res {
                Ok(o) if o.status.success() => {
                    logs.push(format!(
                        "WireGuard tunnel {} ({}) -> {} [addr {}, table {}, mark {}] ACTIVE",
                        t.name, iface, parsed.endpoint, parsed.address, table_id, mark_hex
                    ));
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    logs.push(format!(
                        "WARN: wg setconf {} failed: {}",
                        iface,
                        err.trim()
                    ));
                }
                Err(e) => {
                    logs.push(format!("WARN: failed to invoke 'wg' for {}: {}", iface, e));
                }
            }
        }
    }

    logs
}

/// Lists all `.conf` files saved in `/data/wg`
pub fn list_saved_wg_configs() -> BTreeMap<String, Result<ParsedWgConf, String>> {
    let mut out = BTreeMap::new();
    let dir = Path::new("/data/wg");
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if let Ok(raw) = fs::read_to_string(&path) {
                        let parsed = parse_wg_conf_str(&raw).map_err(|e| e.to_string());
                        out.insert(name.to_string(), parsed);
                    }
                }
            }
        }
    }
    out
}

pub fn normalize_wg_filename(name: &str) -> Result<String> {
    let clean_name = Path::new(name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid config filename")?;
    if clean_name.is_empty() {
        bail!("Filename cannot be empty");
    }
    Ok(if clean_name.ends_with(".conf") {
        clean_name.to_string()
    } else {
        format!("{}.conf", clean_name)
    })
}

/// Saves a Mullvad / WireGuard `.conf` file to `/data/wg/<name>`
pub fn save_wg_config_file(name: &str, content: &str) -> Result<(String, ParsedWgConf)> {
    let parsed = parse_wg_conf_str(content)?;
    let _ = fs::create_dir_all("/data/wg");
    let filename = normalize_wg_filename(name)?;
    let full_path = Path::new("/data/wg").join(&filename);
    fs::write(&full_path, content)
        .with_context(|| format!("Failed to write {}", full_path.display()))?;
    Ok((filename, parsed))
}

/// Opens `nano` (or `vi`) on `/data/wg/<name>.conf` so the user can paste/edit any WireGuard config
pub fn edit_wg_config_interactive(name: &str, preferred_editor: Option<&str>) -> Result<Option<String>> {
    let _ = fs::create_dir_all("/data/wg");
    let filename = normalize_wg_filename(name)?;
    let full_path = Path::new("/data/wg").join(&filename);
    let existed_before = full_path.exists();

    let template = format!(
        "# WireGuard configuration: {}\n# Paste your [Interface] and [Peer] blocks below, then save (Ctrl+O, Enter, Ctrl+X in nano).\n\n",
        filename
    );
    if !existed_before {
        let _ = fs::write(&full_path, &template);
    }

    let editor = match preferred_editor {
        Some("vi") | Some("vim") => "vi",
        Some("nano") => "nano",
        _ => {
            if Path::new("/bin/nano").exists() || Path::new("/usr/bin/nano").exists() {
                "nano"
            } else {
                "vi"
            }
        }
    };

    let status = Command::new(editor)
        .arg(&full_path)
        .env("TERM", std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()))
        .env("TERMINFO", "/usr/share/terminfo")
        .status()
        .with_context(|| format!("Failed to launch editor '{}'", editor))?;

    if !status.success() {
        bail!("Editor '{}' exited with non-zero status", editor);
    }

    let raw = fs::read_to_string(&full_path).unwrap_or_default();
    let non_comment_lines: usize = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .count();

    if non_comment_lines == 0 {
        if !existed_before {
            let _ = fs::remove_file(&full_path);
        }
        println!("  {} Aborted (empty WireGuard config).", "⚠".yellow());
        return Ok(None);
    }

    match parse_wg_conf_str(&raw) {
        Ok(parsed) => {
            println!(
                "  {} Saved & validated {} -> endpoint {} (addr {})",
                "✔".green().bold(),
                filename.bold().cyan(),
                parsed.endpoint.yellow(),
                parsed.address.green()
            );
            Ok(Some(filename))
        }
        Err(e) => {
            println!(
                "  {} Saved /data/wg/{}, but validation warning: {}",
                "⚠".yellow().bold(),
                filename.bold(),
                e
            );
            Ok(Some(filename))
        }
    }
}

/// Interactive line-by-line paste mode for a WireGuard config (`wg paste <name>`)
pub fn paste_wg_config_interactive(name: &str) -> Result<Option<String>> {
    use std::io::{self, BufRead};
    let filename = normalize_wg_filename(name)?;
    println!(
        "  Paste WireGuard configuration for {} below.",
        filename.bold().cyan()
    );
    println!(
        "  Type {} (or {}) on a new line when finished, or {} to cancel:\n",
        "EOF".yellow().bold(),
        ".".yellow().bold(),
        "ABORT".red()
    );

    let stdin = io::stdin();
    let mut content = String::new();
    for line in stdin.lock().lines() {
        let l = line?;
        let trimmed = l.trim();
        if trimmed.eq_ignore_ascii_case("abort") || trimmed.eq_ignore_ascii_case("cancel") {
            println!("  {} Aborted.", "⚠".yellow());
            return Ok(None);
        }
        if trimmed.eq_ignore_ascii_case("eof") || trimmed == "." {
            break;
        }
        content.push_str(&l);
        content.push('\n');
    }

    if content.trim().is_empty() {
        println!("  {} Aborted (nothing pasted).", "⚠".yellow());
        return Ok(None);
    }

    let (saved_name, parsed) = save_wg_config_file(&filename, &content)?;
    println!(
        "  {} Saved & validated /data/wg/{} -> endpoint {} (addr {})",
        "✔".green().bold(),
        saved_name.bold().cyan(),
        parsed.endpoint.yellow(),
        parsed.address.green()
    );
    Ok(Some(saved_name))
}

/// Handles `wg ...` CLI subcommands (`wg`, `wg add <name>`, `wg edit <name>`, `wg vi <name>`, `wg paste <name>`, `wg show <name>`, `wg rm <name>`)
pub fn handle_wg_cli_command(args: &[&str]) -> Result<Option<String>> {
    if args.is_empty() || args[0].eq_ignore_ascii_case("list") || args[0].eq_ignore_ascii_case("ls") {
        let saved = list_saved_wg_configs();
        println!("{}", "Saved WireGuard Configs (/data/wg/):".bold().cyan());
        if saved.is_empty() {
            println!(
                "  {}",
                "(none — run 'wg add <name>' to open nano and paste a config, or 'wg paste <name>')"
                    .dimmed()
            );
        } else {
            for (name, res) in saved {
                match res {
                    Ok(p) => println!(
                        "  {} {:<28} -> endpoint {:<22} (addr {})",
                        "✔".green().bold(),
                        name.bold(),
                        p.endpoint.yellow(),
                        p.address.cyan()
                    ),
                    Err(e) => println!("  {} {:<28} -> {}", "✖".red(), name, e),
                }
            }
        }
        println!(
            "\n  {}",
            "Tip: 'wg add <name>' (opens nano), 'wg vi <name>', 'wg paste <name>', 'wg show <name>', 'wg rm <name>'"
                .dimmed()
        );
        return Ok(None);
    }

    let sub = args[0].to_ascii_lowercase();
    match sub.as_str() {
        "add" | "edit" | "nano" | "new" => {
            if args.len() < 2 {
                bail!("Usage: wg {} <name> (e.g. 'wg {} mullvad-us-sea-001')", sub, sub);
            }
            edit_wg_config_interactive(args[1], Some("nano"))
        }
        "vi" | "vim" => {
            if args.len() < 2 {
                bail!("Usage: wg vi <name> (e.g. 'wg vi mullvad-us-sea-001')");
            }
            edit_wg_config_interactive(args[1], Some("vi"))
        }
        "paste" | "import" => {
            if args.len() < 2 {
                bail!("Usage: wg paste <name> (e.g. 'wg paste mullvad-us-sea-001')");
            }
            paste_wg_config_interactive(args[1])
        }
        "show" | "cat" | "view" => {
            if args.len() < 2 {
                bail!("Usage: wg show <name>");
            }
            let filename = normalize_wg_filename(args[1])?;
            let full_path = Path::new("/data/wg").join(&filename);
            let raw = fs::read_to_string(&full_path)
                .with_context(|| format!("/data/wg/{} not found", filename))?;
            println!("{}", format!("--- /data/wg/{} ---", filename).bold().cyan());
            print!("{}", raw);
            if !raw.ends_with('\n') {
                println!();
            }
            Ok(None)
        }
        "rm" | "del" | "delete" | "remove" => {
            if args.len() < 2 {
                bail!("Usage: wg rm <name>");
            }
            let filename = normalize_wg_filename(args[1])?;
            let full_path = Path::new("/data/wg").join(&filename);
            fs::remove_file(&full_path)
                .with_context(|| format!("Failed to remove /data/wg/{}", filename))?;
            println!(
                "  {} Deleted /data/wg/{}",
                "✔".green().bold(),
                filename.bold()
            );
            Ok(None)
        }
        _ => {
            // If user typed `wg mullvad-us-sea-001`, treat it as `wg add mullvad-us-sea-001`!
            edit_wg_config_interactive(args[0], Some("nano"))
        }
    }
}

/// Probes a WireGuard tunnel interface (`wg0`, `wg1`, ...) via `ping -I <iface> 1.1.1.1`
pub async fn probe_wg_tunnel(iface: &str) -> (HealthState, Option<f64>, Option<String>) {
    let iface_owned = iface.to_string();
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let out = Command::new("ping")
            .args(["-c", "1", "-W", "1", "-I", &iface_owned, "1.1.1.1"])
            .output();
        match out {
            Ok(o) if o.status.success() => (
                HealthState::Up,
                Some(start.elapsed().as_secs_f64() * 1000.0),
                None,
            ),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                let msg = if stderr.is_empty() {
                    format!("ping via {} timed out", iface_owned)
                } else {
                    stderr
                };
                (HealthState::Down, None, Some(msg))
            }
            Err(e) => (HealthState::Down, None, Some(e.to_string())),
        }
    })
    .await
    .unwrap_or((
        HealthState::Down,
        None,
        Some("probe task failed".to_string()),
    ))
}

// ============================================================================
// Feature 2: Embedded mDNS (*.local) Responder + L7 Host / TLS SNI Router
// ============================================================================

pub fn spawn_mdns_and_sni_router(shared: SharedState) {
    let shared_mdns = shared.clone();
    tokio::task::spawn_blocking(move || {
        run_mdns_responder_loop(shared_mdns);
    });

    let shared_http = shared.clone();
    tokio::spawn(async move {
        run_l7_virtual_host_listener(shared_http, 80).await;
    });

    let shared_tls = shared.clone();
    tokio::spawn(async move {
        run_l7_virtual_host_listener(shared_tls, 443).await;
    });

    let shared_cf_auth = shared.clone();
    tokio::spawn(async move {
        run_cf_auth_proxy_listener(shared_cf_auth).await;
    });

    let shared_gw_proxies = shared;
    tokio::spawn(async move {
        run_gateway_proxy_supervisor(shared_gw_proxies).await;
    });
}

fn find_hostname_ip(shared: &SharedState, qname: &str) -> Option<Ipv4Addr> {
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    let st = shared.read().ok()?;
    let cfg = if !st.running.services.is_empty() || !st.running.gateways.is_empty() {
        &st.running
    } else {
        &st.candidate
    };

    for (vip_key, vip_cfg) in &cfg.vips {
        if let Some(ip) = vip_cfg.leased_ip.or_else(|| vip_key.parse::<Ipv4Addr>().ok()) {
            let k_clean = vip_key.trim_end_matches('.').to_ascii_lowercase();
            let k_local = if k_clean.ends_with(".local") {
                k_clean.clone()
            } else {
                format!("{}.local", k_clean)
            };
            if q == k_clean || q == k_local {
                return Some(ip);
            }
        }
    }

    for svc in cfg.services.values() {
        if let Some(h) = &svc.hostname {
            let h_clean = h.trim_end_matches('.').to_ascii_lowercase();
            let h_local = if h_clean.ends_with(".local") {
                h_clean.clone()
            } else {
                format!("{}.local", h_clean)
            };
            if q == h_clean || q == h_local {
                if let Some(ip) = svc.listen_ip {
                    return Some(ip);
                }
            }
        }
    }

    for gw in cfg.gateways.values() {
        if let Some(h) = &gw.hostname {
            let h_clean = h.trim_end_matches('.').to_ascii_lowercase();
            let h_local = if h_clean.ends_with(".local") {
                h_clean.clone()
            } else {
                format!("{}.local", h_clean)
            };
            if q == h_clean || q == h_local {
                return Some(gw.listen_ip);
            }
        }
    }

    None
}

fn parse_dns_qname(pkt: &[u8], mut offset: usize) -> Option<(String, usize, u16, u16)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;
    let mut steps = 0;

    loop {
        if offset >= pkt.len() || steps > 64 {
            return None;
        }
        steps += 1;
        let len = pkt[offset] as usize;
        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            let ptr = (((len & 0x3F) << 8) | (pkt[offset + 1] as usize)) as usize;
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        offset += 1;
        if offset + len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    if end_offset + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[end_offset], pkt[end_offset + 1]]);
    let qclass = u16::from_be_bytes([pkt[end_offset + 2], pkt[end_offset + 3]]);
    Some((labels.join("."), end_offset + 4, qtype, qclass))
}

fn build_mdns_a_response(tx_id: u16, qname: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);
    // Header: ID, Flags (0x8400 = QR + AA), QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&0x8400u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    for label in qname.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if !b.is_empty() && b.len() < 64 {
            resp.push(b.len() as u8);
            resp.extend_from_slice(b);
        }
    }
    resp.push(0);

    // Type A (1), Class IN + cache-flush (0x8001), TTL 60s, RDLENGTH 4, IPv4
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0x8001u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

fn list_vlan_iface_ips() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    let Ok(out) = Command::new("ip").args(["-4", "-o", "addr", "show"]).output() else {
        return ips;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let dev = parts[1];
            if dev == "eth0" || dev.starts_with("eth0.") || dev.starts_with("mv-") {
                if let Some(ip_str) = parts[3].split('/').next() {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    ips
}

fn run_mdns_responder_loop(shared: SharedState) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:5353") else {
        return;
    };
    let mcast_group = Ipv4Addr::new(224, 0, 0, 251);
    let _ = sock.join_multicast_v4(&mcast_group, &Ipv4Addr::UNSPECIFIED);
    let _ = sock.set_multicast_loop_v4(false);
    let mcast_dest: SocketAddr = "224.0.0.251:5353".parse().unwrap();
    let mut buf = [0u8; 1500];
    let mut joined_ips: Vec<Ipv4Addr> = Vec::new();
    let mut last_join_check = std::time::Instant::now() - Duration::from_secs(30);

    loop {
        if last_join_check.elapsed() >= Duration::from_secs(15) {
            last_join_check = std::time::Instant::now();
            for ip in list_vlan_iface_ips() {
                if !joined_ips.contains(&ip) {
                    let _ = sock.join_multicast_v4(&mcast_group, &ip);
                    joined_ips.push(ip);
                }
            }
        }

        let Ok((n, peer)) = sock.recv_from(&mut buf) else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        if n < 12 {
            continue;
        }
        // Ignore packets originating from our own local interface IPs to prevent mDNS repeater loops
        if let SocketAddr::V4(v4) = peer {
            if joined_ips.contains(v4.ip()) {
                continue;
            }
        }

        // Cross-VLAN mDNS Repeater: if multiple VLAN interfaces exist, relay multicast mDNS packets across VLANs
        if joined_ips.len() > 1 {
            for &iface_ip in &joined_ips {
                if let SocketAddr::V4(v4) = peer {
                    // Relay to other subnets/interfaces
                    if v4.ip().octets()[0..3] != iface_ip.octets()[0..3] {
                        if let Ok(tx_sock) = UdpSocket::bind(SocketAddr::new(std::net::IpAddr::V4(iface_ip), 0)) {
                            let _ = tx_sock.set_multicast_loop_v4(false);
                            let _ = tx_sock.send_to(&buf[..n], mcast_dest);
                        }
                    }
                }
            }
        }

        let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        if (flags & 0x8000) != 0 {
            // Ignore responses for local responder
            continue;
        }
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let mut offset = 12usize;
        for _ in 0..qdcount {
            let Some((qname, next_off, qtype, _qclass)) = parse_dns_qname(&buf[..n], offset) else {
                break;
            };
            offset = next_off;
            // Type 1 = A, Type 255 = ANY
            if qtype == 1 || qtype == 255 {
                if let Some(ip) = find_hostname_ip(&shared, &qname) {
                    let pkt = build_mdns_a_response(tx_id, &qname, ip);
                    let _ = sock.send_to(&pkt, peer);
                    let _ = sock.send_to(&pkt, mcast_dest);
                }
            }
        }
    }
}

/// Extracts either the HTTP `Host:` header or TLS ClientHello `SNI` hostname from the first packet
pub fn extract_host_or_sni(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    // 1. Check TLS ClientHello (0x16 = Handshake, 0x03 = SSL/TLS)
    if buf.len() > 43 && buf[0] == 0x16 && buf[1] == 0x03 {
        if let Some(sni) = parse_tls_sni(buf) {
            return Some(sni.to_ascii_lowercase());
        }
    }
    // 2. Check HTTP Host header
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines().take(32) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let host_port = v.trim();
                let host = host_port.split(':').next().unwrap_or(host_port).trim();
                if !host.is_empty() {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS record header (5 bytes) + Handshake header (4 bytes) + Version (2) + Random (32) = 43
    let mut pos = 43;
    if pos >= buf.len() {
        return None;
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos + 1 > buf.len() {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            // Server Name Indication
            let name_type = buf[pos + 2];
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            if name_type == 0 && pos + 5 + name_len <= pos + ext_len {
                if let Ok(s) = std::str::from_utf8(&buf[pos + 5..pos + 5 + name_len]) {
                    return Some(s.to_string());
                }
            }
        }
        pos += ext_len;
    }
    None
}

static L7_VHOST_RR_COUNTER: AtomicUsize = AtomicUsize::new(0);

async fn run_l7_virtual_host_listener(shared: SharedState, listen_port: u16) {
    let bind_addr = format!("0.0.0.0:{}", listen_port);
    let listener = loop {
        match TcpListener::bind(&bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    loop {
        let Ok((mut client, peer)) = listener.accept().await else {
            continue;
        };
        let local_dst_ip = client.local_addr().ok().and_then(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        });
        let shared_conn = shared.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 2048];
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), client.read(&mut peek_buf)).await
            else {
                return;
            };
            if n == 0 {
                return;
            }
            let Some(host) = extract_host_or_sni(&peek_buf[..n]) else {
                return;
            };

            let target_info: Option<(String, String, Vec<String>)> = {
                let st = shared_conn.read().unwrap();
                let cfg = if !st.running.services.is_empty() {
                    &st.running
                } else {
                    &st.candidate
                };
                // Prefer a service whose listen_ip matches the destination VIP IP, falling back to any service with that hostname
                let mut candidates: Vec<&crate::ast::Service> = cfg
                    .services
                    .values()
                    .filter(|svc| {
                        if let Some(svc_host) = &svc.hostname {
                            let sh = svc_host.trim_end_matches('.').to_ascii_lowercase();
                            let sh_short = sh.strip_suffix(".local").unwrap_or(&sh);
                            let req_short = host.strip_suffix(".local").unwrap_or(&host);
                            host == sh || req_short == sh_short
                        } else {
                            false
                        }
                    })
                    .collect();

                candidates.sort_by_key(|svc| {
                    let ip_match = match (local_dst_ip, svc.listen_ip) {
                        (Some(dst), Some(lip)) if dst == lip => 0,
                        _ => 1,
                    };
                    let port_match = if svc.port == listen_port { 0 } else { 1 };
                    (ip_match, port_match)
                });

                let mut found = None;
                if let Some(svc) = candidates.first() {
                    let active = st.active_backends_for_service(&svc.backends);
                    if !active.is_empty() {
                        let mut weighted_slots = Vec::new();
                        for b in &active {
                            for _ in 0..b.weight.max(1) {
                                weighted_slots.push(*b);
                            }
                        }
                        let idx = match svc.balance {
                            crate::ast::BalanceStrategy::RoundRobin => {
                                L7_VHOST_RR_COUNTER.fetch_add(1, Ordering::Relaxed)
                                    % weighted_slots.len()
                            }
                            crate::ast::BalanceStrategy::Sticky => {
                                let hash = match peer.ip() {
                                    std::net::IpAddr::V4(v4) => u32::from(v4) as usize,
                                    std::net::IpAddr::V6(_) => 0usize,
                                };
                                hash % weighted_slots.len()
                            }
                        };
                        let chosen = weighted_slots[idx];
                        let addr = format!("{}:{}", chosen.ip, chosen.port);
                        found = Some((addr, chosen.endpoint(), svc.auth.clone()));
                    }
                }
                found
            };

            if let Some((addr, ep_key, auth_rules)) = target_info {
                let first_line_http = std::str::from_utf8(&peek_buf[..n])
                    .map(|s| {
                        let u = s.trim_start();
                        u.starts_with("GET ")
                            || u.starts_with("POST ")
                            || u.starts_with("HEAD ")
                            || u.starts_with("PUT ")
                            || u.starts_with("DELETE ")
                            || u.starts_with("OPTIONS ")
                            || u.starts_with("PATCH ")
                    })
                    .unwrap_or(false);
                if !auth_rules.is_empty() && first_line_http && !check_http_basic_auth(&peek_buf[..n], &auth_rules) {
                    let resp = format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nfty ({})\"\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\n401 Authentication Needed\n",
                        host
                    );
                    let _ = client.write_all(resp.as_bytes()).await;
                    return;
                }
                let forward_buf = if !auth_rules.is_empty() && first_line_http {
                    sanitize_authenticated_http_request(&peek_buf[..n])
                } else {
                    peek_buf[..n].to_vec()
                };
                if let Ok(Ok(mut upstream)) =
                    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await
                {
                    if upstream.write_all(&forward_buf).await.is_ok() {
                        if let Ok((up_b, down_b)) =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                        {
                            if let Ok(mut st) = shared_conn.write() {
                                let rt = st.runtime.entry(ep_key).or_default();
                                rt.packets += 2;
                                rt.bytes += (forward_buf.len() as u64) + up_b + down_b;
                            }
                        }
                    }
                }
            }
        });
    }
}

// ============================================================================
// Feature 3: Live Kernel Conntrack Flow Inspector
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackFlow {
    pub proto: String,
    pub state: String,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub nat_target: Option<String>,
    pub mark: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Reads active connections from `/proc/net/nf_conntrack` (or falls back to `ss` / `conntrack`)
pub fn read_active_flows(shared: &SharedState) -> Vec<ConntrackFlow> {
    let mut flows = Vec::new();
    let raw = fs::read_to_string("/proc/net/nf_conntrack")
        .or_else(|_| fs::read_to_string("/proc/net/ip_conntrack"))
        .unwrap_or_default();

    let (vip_ips, backend_ips) = {
        let st = shared.read().unwrap();
        let cfg = if !st.running.services.is_empty() || !st.running.gateways.is_empty() {
            &st.running
        } else {
            &st.candidate
        };
        let mut vips = Vec::new();
        let mut bips = Vec::new();
        for svc in cfg.services.values() {
            if let Some(ip) = svc.listen_ip {
                vips.push(ip.to_string());
            }
            for b in &svc.backends {
                bips.push(b.ip.to_string());
            }
        }
        for gw in cfg.gateways.values() {
            vips.push(gw.listen_ip.to_string());
        }
        (vips, bips)
    };

    for line in raw.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 6 {
            continue;
        }
        let proto = tokens[2].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let state = if proto == "TCP" && !tokens[5].contains('=') {
            tokens[5].to_string()
        } else {
            "ACTIVE".to_string()
        };

        let mut orig_src = None;
        let mut orig_dst = None;
        let mut orig_sport = None;
        let mut orig_dport = None;
        let mut reply_src = None;
        let mut reply_sport = None;
        let mut packets = 0u64;
        let mut bytes = 0u64;
        let mut mark = "0".to_string();

        for tok in &tokens {
            if let Some((k, v)) = tok.split_once('=') {
                match k {
                    "src" => {
                        if orig_src.is_none() {
                            orig_src = Some(v.to_string());
                        } else if reply_src.is_none() {
                            reply_src = Some(v.to_string());
                        }
                    }
                    "dst" => {
                        if orig_dst.is_none() {
                            orig_dst = Some(v.to_string());
                        }
                    }
                    "sport" => {
                        if orig_sport.is_none() {
                            orig_sport = v.parse::<u16>().ok();
                        } else if reply_sport.is_none() {
                            reply_sport = v.parse::<u16>().ok();
                        }
                    }
                    "dport" => {
                        if orig_dport.is_none() {
                            orig_dport = v.parse::<u16>().ok();
                        }
                    }
                    "packets" => {
                        packets += v.parse::<u64>().unwrap_or(0);
                    }
                    "bytes" => {
                        bytes += v.parse::<u64>().unwrap_or(0);
                    }
                    "mark" => {
                        mark = v.to_string();
                    }
                    _ => {}
                }
            }
        }

        let (Some(src), Some(dst), Some(sport), Some(dport)) =
            (orig_src, orig_dst, orig_sport, orig_dport)
        else {
            continue;
        };

        // Skip API polling noise on :9090
        if dport == 9090 || sport == 9090 {
            continue;
        }

        let is_relevant = mark != "0"
            || vip_ips.iter().any(|ip| ip == &dst || ip == &src)
            || reply_src
                .as_ref()
                .map(|rs| backend_ips.iter().any(|ip| ip == rs))
                .unwrap_or(false);

        if !is_relevant && !vip_ips.is_empty() {
            continue;
        }

        let nat_target = match (&reply_src, reply_sport) {
            (Some(rs), Some(rsp)) if rs != &dst || rsp != dport => Some(format!("{}:{}", rs, rsp)),
            _ => None,
        };

        flows.push(ConntrackFlow {
            proto,
            state,
            src,
            dst,
            sport,
            dport,
            nat_target,
            mark,
            packets,
            bytes,
        });
    }

    // Fallback/supplement with `/proc/net/tcp` if `/proc/net/nf_conntrack` is not exposed in container procfs
    if flows.is_empty() {
        if let Ok(tcp_raw) = fs::read_to_string("/proc/net/tcp") {
            for line in tcp_raw.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let Some((local_ip, local_port)) = parse_proc_net_addr(parts[1]) else {
                    continue;
                };
                let Some((rem_ip, rem_port)) = parse_proc_net_addr(parts[2]) else {
                    continue;
                };
                if rem_ip == Ipv4Addr::UNSPECIFIED || local_port == 9090 || rem_port == 9090 {
                    continue;
                }
                let state_str = match parts[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "06" => "TIME_WAIT",
                    _ => continue,
                };
                flows.push(ConntrackFlow {
                    proto: "TCP".to_string(),
                    state: state_str.to_string(),
                    src: rem_ip.to_string(),
                    dst: local_ip.to_string(),
                    sport: rem_port,
                    dport: local_port,
                    nat_target: None,
                    mark: "0".to_string(),
                    packets: 1,
                    bytes: 0,
                });
            }
        }
    }

    flows.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    flows.truncate(100);
    flows
}

fn parse_proc_net_addr(hex_pair: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_hex, port_hex) = hex_pair.split_once(':')?;
    let ip_u32 = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv4Addr::from(ip_u32.swap_bytes()), port))
}

pub fn print_flows_table(shared: &SharedState) {
    let flows = read_active_flows(shared);
    println!(
        "{:<6} {:<13} {:<22} {:<22} {:<24} {:<8} {:<14}",
        "PROTO".bold().underline(),
        "STATE".bold().underline(),
        "CLIENT (SRC)".bold().underline(),
        "VIP / DEST".bold().underline(),
        "NAT BACKEND / WG".bold().underline(),
        "MARK".bold().underline(),
        "TRAFFIC".bold().underline()
    );
    if flows.is_empty() {
        println!(
            "  {}",
            "(No active conntrack flows found matching configured VIPs/gateways)".dimmed()
        );
        return;
    }

    for f in flows {
        let src_col = format!("{}:{}", f.src, f.sport);
        let dst_col = format!("{}:{}", f.dst, f.dport);
        let nat_col = f.nat_target.unwrap_or_else(|| "direct".to_string());
        let mark_col = if f.mark == "0" {
            "-".to_string()
        } else {
            format!("0x{}", f.mark)
        };
        let state_colored = match f.state.as_str() {
            "ESTABLISHED" => f.state.green().bold().to_string(),
            "TIME_WAIT" | "CLOSE" => f.state.dimmed().to_string(),
            _ => f.state.yellow().to_string(),
        };
        println!(
            "{:<6} {:<22} {:<22} {:<22} {:<24} {:<8} {} pkts / {} B",
            f.proto.cyan(),
            state_colored,
            src_col,
            dst_col.bold(),
            nat_col.green(),
            mark_col,
            f.packets,
            f.bytes
        );
    }
}

// ============================================================================
// Feature 4: Gateway-Attached Privoxy (HTTP/CONNECT Proxy) & SOCKS5 Proxy
// ============================================================================

static GW_PROXY_RR_COUNTER: AtomicUsize = AtomicUsize::new(0);

async fn run_gateway_proxy_supervisor(shared: SharedState) {
    let _ = fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1\n");
    let mut active_tasks: HashMap<(Ipv4Addr, u16, GatewayServiceKind), tokio::task::JoinHandle<()>> =
        HashMap::new();

    loop {
        let mut desired: Vec<(String, Ipv4Addr, u16, GatewayServiceKind)> = Vec::new();
        {
            if let Ok(mut st) = shared.write() {
                st.sync_from_disk_if_changed();
                let cfg = if !st.running.gateways.is_empty() || !st.running.services.is_empty() {
                    &st.running
                } else {
                    &st.candidate
                };
                for gw in cfg.gateways.values() {
                    for gs in &gw.services {
                        if matches!(
                            gs.kind,
                            GatewayServiceKind::Privoxy | GatewayServiceKind::Socks5
                        ) {
                            desired.push((gw.key.clone(), gw.listen_ip, gs.port, gs.kind));
                        }
                    }
                }
            }
        }

        // Stop listeners that were removed
        active_tasks.retain(|k, handle| {
            let keep = desired
                .iter()
                .any(|(_, ip, port, kind)| *ip == k.0 && *port == k.1 && *kind == k.2);
            if !keep {
                handle.abort();
            }
            keep
        });

        // Start new listeners
        for (gw_key, ip, port, kind) in desired {
            let key = (ip, port, kind);
            if !active_tasks.contains_key(&key) {
                let shared_cl = shared.clone();
                let handle = tokio::spawn(async move {
                    run_single_gateway_proxy(shared_cl, gw_key, ip, port, kind).await;
                });
                active_tasks.insert(key, handle);
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[derive(Debug, Clone)]
enum GatewayRouteDecision {
    /// Gateway has no tunnels configured (or all tunnels are down and killswitch is off): route directly via host eth0
    DirectHost,
    /// Route through an active WireGuard tunnel `(iface, fwmark, ep_key, local_wg_ip)`
    ViaTunnel {
        iface: String,
        fwmark: u32,
        ep_key: String,
        local_ip: Option<Ipv4Addr>,
    },
    /// Gateway has tunnels configured with `killswitch on`, and all tunnels are currently DOWN
    KillswitchBlocked(String),
}

/// Selects the routing decision for a gateway: if a tunnel exists and is UP, routes via that tunnel.
fn select_gateway_tunnel(shared: &SharedState, gw_key: &str) -> GatewayRouteDecision {
    if let Ok(mut st) = shared.write() {
        st.sync_from_disk_if_changed();
    }
    let Ok(st) = shared.read() else {
        return GatewayRouteDecision::DirectHost;
    };
    let cfg = if !st.running.gateways.is_empty() {
        &st.running
    } else {
        &st.candidate
    };

    let mut base_idx = 0usize;
    for (k, gw) in &cfg.gateways {
        if k == gw_key {
            if gw.tunnels.is_empty() {
                return GatewayRouteDecision::DirectHost;
            }
            let mut active = Vec::new();
            for (local_i, t) in gw.tunnels.iter().enumerate() {
                let global_i = base_idx + local_i;
                let fwmark = (0x101 + global_i) as u32;
                let iface = if t.iface.is_empty() {
                    format!("wg{}", global_i)
                } else {
                    t.iface.clone()
                };
                let iface_exists = Path::new(&format!("/sys/class/net/{}", iface)).exists();
                let healthy = iface_exists
                    && st
                        .runtime
                        .get(&t.endpoint_key())
                        .map(|rt| !rt.drained && rt.health != HealthState::Down)
                        .unwrap_or(true);
                if healthy {
                    let local_ip = resolve_tunnel_config(t)
                        .ok()
                        .and_then(|p| p.address.split('/').next()?.trim().parse::<Ipv4Addr>().ok());
                    for _ in 0..t.weight.max(1) {
                        active.push((iface.clone(), fwmark, t.endpoint_key(), local_ip));
                    }
                }
            }
            // If runtime hasn't probed yet, check if any configured tunnel interface is present in kernel
            if active.is_empty() {
                for (local_i, t) in gw.tunnels.iter().enumerate() {
                    let global_i = base_idx + local_i;
                    let fwmark = (0x101 + global_i) as u32;
                    let iface = if t.iface.is_empty() {
                        format!("wg{}", global_i)
                    } else {
                        t.iface.clone()
                    };
                    if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
                        let not_down = st
                            .runtime
                            .get(&t.endpoint_key())
                            .map(|rt| !rt.drained && rt.health != HealthState::Down)
                            .unwrap_or(true);
                        if not_down {
                            let local_ip = resolve_tunnel_config(t).ok().and_then(|p| {
                                p.address.split('/').next()?.trim().parse::<Ipv4Addr>().ok()
                            });
                            active.push((iface, fwmark, t.endpoint_key(), local_ip));
                        }
                    }
                }
            }
            if active.is_empty() {
                if gw.killswitch {
                    return GatewayRouteDecision::KillswitchBlocked(format!(
                        "Gateway {} killswitch is ON and no WireGuard tunnels are UP",
                        gw_key
                    ));
                } else {
                    return GatewayRouteDecision::DirectHost;
                }
            }
            let idx = GW_PROXY_RR_COUNTER.fetch_add(1, Ordering::Relaxed) % active.len();
            let (iface, fwmark, ep_key, local_ip) = active.swap_remove(idx);
            return GatewayRouteDecision::ViaTunnel {
                iface,
                fwmark,
                ep_key,
                local_ip,
            };
        }
        base_idx += gw.tunnels.len();
    }
    GatewayRouteDecision::DirectHost
}

async fn connect_via_gateway_tunnel(
    shared: &SharedState,
    gw_key: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, Option<String>)> {
    let resolved_ip = crate::parser::resolve_hostname_sync(target_host)
        .ok_or_else(|| anyhow::anyhow!("Could not resolve '{}'", target_host))?;
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(resolved_ip), target_port);

    let sock = TcpSocket::new_v4()?;
    let mut ep_key_opt = None;

    match select_gateway_tunnel(shared, gw_key) {
        GatewayRouteDecision::KillswitchBlocked(reason) => {
            bail!("{}", reason);
        }
        GatewayRouteDecision::ViaTunnel {
            iface,
            fwmark,
            ep_key,
            local_ip,
        } => {
            ep_key_opt = Some(ep_key);
            let fd = sock.as_raw_fd();
            unsafe {
                let mark_val: libc::c_uint = fwmark;
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
                let mut iface_cstr = iface.into_bytes();
                iface_cstr.push(0);
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_cstr.as_ptr() as *const libc::c_void,
                    iface_cstr.len() as libc::socklen_t,
                );
            }
            if let Some(ip) = local_ip {
                let _ = sock.bind(SocketAddr::new(std::net::IpAddr::V4(ip), 0));
            }
        }
        GatewayRouteDecision::DirectHost => {}
    }

    let stream = tokio::time::timeout(Duration::from_secs(6), sock.connect(target_addr)).await??;
    Ok((stream, ep_key_opt))
}

async fn run_single_gateway_proxy(
    shared: SharedState,
    gw_key: String,
    listen_ip: Ipv4Addr,
    port: u16,
    kind: GatewayServiceKind,
) {
    let bind_addr = SocketAddr::new(std::net::IpAddr::V4(listen_ip), port);
    let listener = loop {
        match TcpListener::bind(bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    loop {
        let Ok((client, _peer)) = listener.accept().await else {
            continue;
        };
        let shared_c = shared.clone();
        let gw_k = gw_key.clone();
        tokio::spawn(async move {
            match kind {
                GatewayServiceKind::Privoxy => {
                    let _ = handle_privoxy_client(client, shared_c, gw_k).await;
                }
                GatewayServiceKind::Socks5 => {
                    let _ = handle_socks5_client(client, shared_c, gw_k).await;
                }
                GatewayServiceKind::Ssh => {}
            }
        });
    }
}

async fn handle_privoxy_client(
    mut client: TcpStream,
    shared: SharedState,
    gw_key: String,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n == 0 {
        return Ok(());
    }
    let req_str = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let raw_target = parts[1];
    let http_ver = parts.get(2).copied().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS CONNECT tunnel (e.g. `CONNECT example.com:443 HTTP/1.1`)
        let (host, port) = if let Some((h, p)) = raw_target.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(443))
        } else {
            (raw_target, 443)
        };
        let (mut upstream, ep_opt) =
            connect_via_gateway_tunnel(&shared, &gw_key, host, port).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: nfty-privoxy\r\n\r\n")
            .await?;
        if let Ok((up_bytes, down_bytes)) =
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        {
            if let Some(ep) = ep_opt {
                if let Ok(mut st) = shared.write() {
                    let rt = st.runtime.entry(ep).or_default();
                    rt.packets += 2;
                    rt.bytes += up_bytes + down_bytes;
                }
            }
        }
        return Ok(());
    }

    // Standard HTTP proxy request (e.g. `GET http://ifconfig.me/ip HTTP/1.1`)
    let without_scheme = raw_target.strip_prefix("http://").unwrap_or(raw_target);
    let (host_port, rel_path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h, p.parse::<u16>().unwrap_or(80))
    } else {
        (host_port, 80)
    };

    let (mut upstream, ep_opt) = connect_via_gateway_tunnel(&shared, &gw_key, host, port).await?;

    // Rebuild privacy-sanitized HTTP request (strip Proxy-Connection, Via, X-Forwarded-For)
    let mut sanitized = format!("{} {} {}\r\n", method, rel_path, http_ver);
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, _)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "proxy-connection" | "proxy-authorization" | "x-forwarded-for" | "via"
            ) {
                continue;
            }
        }
        sanitized.push_str(line);
        sanitized.push_str("\r\n");
    }
    sanitized.push_str("Connection: close\r\n\r\n");

    upstream.write_all(sanitized.as_bytes()).await?;
    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes + down_bytes + (sanitized.len() as u64);
            }
        }
    }
    Ok(())
}

async fn handle_socks5_client(
    mut client: TcpStream,
    shared: SharedState,
    gw_key: String,
) -> Result<()> {
    let mut greet = [0u8; 258];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut greet)).await??;
    if n < 2 || greet[0] != 0x05 {
        return Ok(());
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut req)).await??;
    if n < 7 || req[0] != 0x05 || req[1] != 0x01 {
        return Ok(());
    }

    let (host, port) = match req[3] {
        0x01 if n >= 10 => {
            let ip = Ipv4Addr::new(req[4], req[5], req[6], req[7]);
            let port = u16::from_be_bytes([req[8], req[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            let dlen = req[4] as usize;
            if n < 5 + dlen + 2 {
                return Ok(());
            }
            let domain = std::str::from_utf8(&req[5..5 + dlen])?.to_string();
            let port = u16::from_be_bytes([req[5 + dlen], req[5 + dlen + 1]]);
            (domain, port)
        }
        _ => return Ok(()),
    };

    let (mut upstream, ep_opt) = connect_via_gateway_tunnel(&shared, &gw_key, &host, port).await?;
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes + down_bytes;
            }
        }
    }
    Ok(())
}

// ============================================================================
// Feature 5: Homelab & LXD Container Service Discovery (`scan` + `adopt`)
// ============================================================================

pub const SCAN_PORTS: &[(u16, &str)] = &[
    (22, "ssh"),
    (80, "http"),
    (443, "https"),
    (3000, "grafana/web"),
    (5000, "web-app"),
    (5055, "overseerr"),
    (6767, "bazarr"),
    (6789, "nzbget"),
    (7878, "radarr"),
    (8000, "http-alt"),
    (8006, "proxmox"),
    (8080, "qbittorrent/web"),
    (8081, "sabnzbd"),
    (8096, "jellyfin"),
    (8112, "deluge"),
    (8123, "homeassistant"),
    (8181, "tautulli"),
    (8384, "syncthing"),
    (8443, "https-alt"),
    (8686, "lidarr"),
    (8787, "readarr"),
    (8989, "sonarr"),
    (9000, "portainer"),
    (9090, "gamble/prometheus"),
    (9091, "transmission"),
    (9117, "jackett"),
    (9696, "prowlarr"),
    (32400, "plex"),
];

pub const COMMON_CONTAINER_HOSTNAMES: &[&str] = &[
    "gamble",
    "media-util",
    "media",
    "sonarr",
    "radarr",
    "plex",
    "jellyfin",
    "prowlarr",
    "bazarr",
    "overseerr",
    "jellyseerr",
    "qbittorrent",
    "sabnzbd",
    "transmission",
    "deluge",
    "nzbget",
    "tautulli",
    "lidarr",
    "readarr",
    "grafana",
    "prometheus",
    "homeassistant",
    "hass",
    "pihole",
    "adguard",
    "portainer",
    "nextcloud",
    "immich",
    "vaultwarden",
    "syncthing",
    "gitea",
];

fn reverse_lookup_ip(ip: Ipv4Addr) -> Option<String> {
    if let Ok(raw) = fs::read_to_string("/etc/hosts") {
        for line in raw.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            let mut parts = clean.split_whitespace();
            if let (Some(ip_str), Some(host)) = (parts.next(), parts.next()) {
                if ip_str.parse::<Ipv4Addr>().ok() == Some(ip) {
                    let h = host.trim_end_matches(".local").to_string();
                    if !h.eq_ignore_ascii_case("localhost") {
                        return Some(h);
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("getent").args(["hosts", &ip.to_string()]).output() {
        if out.status.success() {
            let line = String::from_utf8_lossy(&out.stdout);
            let mut parts = line.split_whitespace();
            let _ = parts.next();
            if let Some(host) = parts.next() {
                let h = host
                    .trim_end_matches('.')
                    .trim_end_matches(".local")
                    .trim_end_matches(".lan")
                    .trim_end_matches(".localdomain")
                    .to_string();
                if !h.is_empty() && h.parse::<Ipv4Addr>().is_err() {
                    return Some(h);
                }
            }
        }
    }
    None
}

fn identify_http_banner(default_name: &str, host: Option<&str>, port: u16, raw: &str) -> (String, Option<String>) {
    let lower = raw.to_ascii_lowercase();
    let mut title = None;
    if let Some(start) = lower.find("<title>") {
        if let Some(end) = lower[start + 7..].find("</title>") {
            let t = raw[start + 7..start + 7 + end].trim();
            if !t.is_empty() {
                title = Some(t.chars().take(40).collect::<String>());
            }
        }
    }
    let detected = if lower.contains("sonarr") || port == 8989 {
        "sonarr"
    } else if lower.contains("radarr") || port == 7878 {
        "radarr"
    } else if lower.contains("prowlarr") || port == 9696 {
        "prowlarr"
    } else if lower.contains("bazarr") || port == 6767 {
        "bazarr"
    } else if lower.contains("lidarr") || port == 8686 {
        "lidarr"
    } else if lower.contains("readarr") || port == 8787 {
        "readarr"
    } else if lower.contains("plex") || port == 32400 {
        "plex"
    } else if lower.contains("jellyfin") || port == 8096 {
        "jellyfin"
    } else if lower.contains("overseerr") || lower.contains("jellyseerr") || port == 5055 {
        "overseerr"
    } else if lower.contains("qbittorrent") {
        "qbittorrent"
    } else if lower.contains("sabnzbd") || port == 8081 {
        "sabnzbd"
    } else if lower.contains("transmission") || port == 9091 {
        "transmission"
    } else if lower.contains("deluge") || port == 8112 {
        "deluge"
    } else if lower.contains("tautulli") || port == 8181 {
        "tautulli"
    } else if lower.contains("home assistant") || port == 8123 {
        "homeassistant"
    } else if lower.contains("grafana") {
        "grafana"
    } else if lower.contains("prometheus") {
        "prometheus"
    } else if lower.contains("gamble") || (port == 9090 && host.map(|h| h.contains("gamble")).unwrap_or(false)) {
        "gamble"
    } else if let Some(h) = host {
        if default_name.contains('/') {
            h
        } else {
            default_name
        }
    } else {
        default_name
    };
    (detected.to_string(), title)
}

async fn probe_single_port(
    ip: Ipv4Addr,
    host: Option<String>,
    port: u16,
    default_name: &'static str,
) -> Option<crate::state::DiscoveredService> {
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    let t0 = std::time::Instant::now();
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_millis(350), TcpStream::connect(addr)).await
    else {
        return None;
    };
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut service_name = default_name.to_string();
    let mut banner = None;

    if port == 22 {
        let mut buf = [0u8; 128];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await
        {
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").trim().to_string();
                if !s.is_empty() {
                    banner = Some(s.chars().take(36).collect());
                }
            }
        }
    } else {
        let host_hdr = host.clone().unwrap_or_else(|| ip.to_string());
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: nfty-scanner/1.0\r\nConnection: close\r\n\r\n",
            host_hdr
        );
        if stream.write_all(req.as_bytes()).await.is_ok() {
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buf)).await
            {
                if n > 0 {
                    let raw = String::from_utf8_lossy(&buf[..n]);
                    let (det, title) =
                        identify_http_banner(default_name, host.as_deref(), port, &raw);
                    service_name = det;
                    banner = title.or_else(|| {
                        raw.lines()
                            .next()
                            .map(|l| l.trim().chars().take(36).collect())
                    });
                }
            }
        }
        if service_name.contains('/') {
            if let Some(h) = &host {
                if h.contains("gamble") && port == 9090 {
                    service_name = "gamble".to_string();
                } else {
                    service_name = service_name.split('/').next().unwrap_or(&service_name).to_string();
                }
            } else {
                service_name = service_name.split('/').next().unwrap_or(&service_name).to_string();
            }
        }
    }

    Some(crate::state::DiscoveredService {
        index: 0,
        host,
        ip,
        port,
        service_name,
        banner: banner.unwrap_or_default(),
        latency_ms,
    })
}

pub fn scan_network_services(
    target_filter: Option<&str>,
    shared: &SharedState,
) -> Vec<crate::state::DiscoveredService> {
    let local_ips: BTreeSet<Ipv4Addr> = list_vlan_iface_ips().into_iter().collect();
    let mut host_map: BTreeMap<Ipv4Addr, Option<String>> = BTreeMap::new();

    if let Some(filter) = target_filter.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        // Check if filter is a CIDR like `192.168.1.0/24`, an IP, or a hostname
        if let Some((base_str, prefix_str)) = filter.split_once('/') {
            if let (Ok(base_ip), Ok(prefix)) = (base_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>()) {
                let base_u32 = u32::from(base_ip);
                let host_bits = 32u8.saturating_sub(prefix.clamp(22, 32));
                let count = (1u32 << host_bits).min(256);
                let net_u32 = base_u32 & (!0u32 << host_bits);
                for offset in 1..count.saturating_sub(1).max(2) {
                    let ip = Ipv4Addr::from(net_u32 + offset);
                    if !local_ips.contains(&ip) {
                        host_map.insert(ip, None);
                    }
                }
            }
        } else if let Ok(ip) = filter.parse::<Ipv4Addr>() {
            host_map.insert(ip, reverse_lookup_ip(ip));
        } else if let Some(ip) = crate::parser::resolve_hostname_sync(filter) {
            host_map.insert(ip, Some(filter.to_string()));
        }
    } else {
        // 1. Collect from existing state (resolved_hosts + configured backends)
        if let Ok(st) = shared.read() {
            for (h, ips) in &st.resolved_hosts {
                for &ip in ips {
                    if !ip.is_loopback() && !local_ips.contains(&ip) {
                        host_map.insert(ip, Some(h.clone()));
                    }
                }
            }
            for svc in st.candidate.services.values().chain(st.running.services.values()) {
                for b in &svc.backends {
                    if !b.ip.is_loopback() && !local_ips.contains(&b.ip) {
                        let entry = host_map.entry(b.ip).or_insert(None);
                        if entry.is_none() && b.host.is_some() {
                            *entry = b.host.clone();
                        }
                    }
                }
            }
        }

        // 2. Collect from `/etc/hosts`
        if let Ok(raw) = fs::read_to_string("/etc/hosts") {
            for line in raw.lines() {
                let clean = line.split('#').next().unwrap_or("").trim();
                let mut parts = clean.split_whitespace();
                if let (Some(ip_str), Some(host)) = (parts.next(), parts.next()) {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !local_ips.contains(&ip) {
                            host_map.insert(ip, Some(host.trim_end_matches(".local").to_string()));
                        }
                    }
                }
            }
        }

        // 3. Collect from `/proc/net/arp`
        if let Ok(raw) = fs::read_to_string("/proc/net/arp") {
            for line in raw.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[2] != "0x0" {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !local_ips.contains(&ip) {
                            host_map.entry(ip).or_insert(None);
                        }
                    }
                }
            }
        }

        // 4. Probe common homelab container names via DNS
        for &name in COMMON_CONTAINER_HOSTNAMES {
            if let Some(ip) = crate::parser::resolve_hostname_sync(name) {
                if !ip.is_loopback() && !local_ips.contains(&ip) {
                    host_map.entry(ip).or_insert_with(|| Some(name.to_string()));
                }
            }
        }
    }

    // Populate any missing hostnames via reverse lookup
    for (ip, host_opt) in host_map.iter_mut() {
        if host_opt.is_none() {
            *host_opt = reverse_lookup_ip(*ip);
        }
    }

    let targets: Vec<(Ipv4Addr, Option<String>)> = host_map.into_iter().collect();
    let run_scan = async move {
        let mut handles = Vec::new();
        for (ip, host_opt) in targets {
            for &(port, default_name) in SCAN_PORTS {
                let h_cl = host_opt.clone();
                handles.push(tokio::spawn(async move {
                    probe_single_port(ip, h_cl, port, default_name).await
                }));
            }
        }
        let mut results = Vec::new();
        for h in handles {
            if let Ok(Some(item)) = h.await {
                results.push(item);
            }
        }
        results
    };

    let mut discovered = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        std::thread::scope(|s| {
            s.spawn(move || handle.block_on(run_scan))
                .join()
                .unwrap_or_default()
        })
    } else if let Ok(rt) = tokio::runtime::Runtime::new() {
        rt.block_on(run_scan)
    } else {
        Vec::new()
    };

    discovered.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then_with(|| a.port.cmp(&b.port))
    });
    for (idx, item) in discovered.iter_mut().enumerate() {
        item.index = idx + 1;
    }

    if let Ok(mut st) = shared.write() {
        for item in &discovered {
            if let Some(h) = &item.host {
                let entry = st.resolved_hosts.entry(h.clone()).or_default();
                if !entry.contains(&item.ip) {
                    entry.push(item.ip);
                }
            }
        }
        st.discovered_services = discovered.clone();
    }
    crate::unikernel::persist_to_storage(shared);

    discovered
}

pub fn print_scan_table(discovered: &[crate::state::DiscoveredService], shared: &SharedState) {
    let existing_backends: BTreeSet<(Ipv4Addr, u16)> = {
        let st = shared.read().unwrap();
        st.candidate
            .services
            .values()
            .chain(st.running.services.values())
            .flat_map(|s| s.backends.iter().map(|b| (b.ip, b.port)))
            .collect()
    };

    println!(
        "{:<4} {:<16} {:<16} {:<7} {:<16} {:<10} {:<24}",
        "#".bold().underline(),
        "HOST".bold().underline(),
        "IP".bold().underline(),
        "PORT".bold().underline(),
        "SERVICE".bold().underline(),
        "LATENCY".bold().underline(),
        "STATUS / ADOPT".bold().underline()
    );

    if discovered.is_empty() {
        println!(
            "  {}",
            "(No open container/LAN services discovered; try 'scan <hostname>' or 'scan 192.168.1.0/24')"
                .dimmed()
        );
        return;
    }

    for d in discovered {
        let host_col = d.host.as_deref().unwrap_or("-");
        let adopted = existing_backends.contains(&(d.ip, d.port));
        let status_col = if adopted {
            "[ADOPTED]".green().bold().to_string()
        } else {
            format!("adopt {}", d.index).cyan().to_string()
        };
        let banner_suffix = if d.banner.is_empty() {
            String::new()
        } else {
            format!(" ({})", d.banner.dimmed())
        };
        println!(
            "{:<4} {:<16} {:<16} {:<7} {:<16} {:<10} {}{}",
            format!("#{}", d.index).yellow().bold(),
            host_col.bold(),
            d.ip,
            d.port,
            d.service_name.green().bold(),
            format!("{:.1}ms", d.latency_ms),
            status_col,
            banner_suffix
        );
    }
    println!(
        "\n  {} Run {} to create a dedicated DHCP VIP on port 80, or {} to attach to an existing VIP.",
        "Tip:".cyan().bold(),
        "adopt <# | host:port>".bold(),
        "adopt <#> vip 192.168.1.4".bold()
    );
}

// ============================================================================
// Feature 6: Automated Cloudflare Tunnel (`cloudflare-dns`) & Edge Connector
// ============================================================================

const CF_CONFIG_PATH: &str = "/data/cloudflare.json";
const CF_PID_FILE: &str = "/run/cloudflared.pid";
const CF_LOG_FILE: &str = "/run/cloudflared.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub tunnel_id: Option<String>,
    #[serde(default = "default_cf_tunnel_name")]
    pub tunnel_name: String,
    #[serde(default)]
    pub tunnel_token: Option<String>,
    /// hostname -> (zone_id, record_id)
    #[serde(default)]
    pub managed_dns_records: BTreeMap<String, (String, String)>,
    /// hostname -> access_app_id
    #[serde(default)]
    pub managed_access_apps: BTreeMap<String, String>,
    #[serde(default)]
    pub access_api_enabled: Option<bool>,
    #[serde(default)]
    pub last_status: Option<String>,
}

fn default_cf_tunnel_name() -> String {
    "nfty-appliance".to_string()
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            api_token: None,
            account_id: None,
            tunnel_id: None,
            tunnel_name: default_cf_tunnel_name(),
            tunnel_token: None,
            managed_dns_records: BTreeMap::new(),
            managed_access_apps: BTreeMap::new(),
            access_api_enabled: None,
            last_status: None,
        }
    }
}

pub fn load_cloudflare_config() -> CloudflareConfig {
    fs::read_to_string(CF_CONFIG_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_cloudflare_config(cfg: &CloudflareConfig) -> Result<()> {
    let _ = fs::create_dir_all("/data");
    let json_str = serde_json::to_string_pretty(cfg)?;
    fs::write(CF_CONFIG_PATH, json_str)?;
    Ok(())
}

fn cf_api_request(
    method: &str,
    path: &str,
    api_token: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/{}",
        path.trim_start_matches('/')
    );
    let ipv4_resolver = |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = netloc
            .to_socket_addrs()?
            .filter(|a| a.is_ipv4())
            .collect();
        if addrs.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No IPv4 address found for api.cloudflare.com",
            ))
        } else {
            Ok(addrs)
        }
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .resolver(ipv4_resolver)
        .build();
    let req = agent
        .request(method, &url)
        .set("Authorization", &format!("Bearer {}", api_token.trim()))
        .set("Content-Type", "application/json");

    let resp = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };

    let val: serde_json::Value = match resp {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, r)) => {
            let err_json: serde_json::Value = r
                .into_json()
                .unwrap_or_else(|_| serde_json::json!({"http_status": code}));
            bail!(
                "Cloudflare API {} {} returned HTTP {}: {}",
                method,
                path,
                code,
                err_json
            );
        }
        Err(e) => bail!("Cloudflare API request failed ({} {}): {}", method, path, e),
    };

    if val.get("success").and_then(|v| v.as_bool()) == Some(false) {
        let errs = val
            .get("errors")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        bail!("Cloudflare API error on {} {}: {}", method, path, errs);
    }
    Ok(val)
}

/// Discovers Cloudflare Account ID and Zone list (`zone_name -> (zone_id, account_id)`) using the API token
fn discover_cf_account_and_zones(
    api_token: &str,
) -> Result<(Option<String>, BTreeMap<String, String>)> {
    let mut zones = BTreeMap::new();
    let mut account_id = None;

    if let Ok(z_resp) = cf_api_request("GET", "zones?per_page=50", api_token, None) {
        if let Some(arr) = z_resp.get("result").and_then(|v| v.as_array()) {
            for item in arr {
                if let (Some(name), Some(zid)) = (
                    item.get("name").and_then(|v| v.as_str()),
                    item.get("id").and_then(|v| v.as_str()),
                ) {
                    zones.insert(name.to_ascii_lowercase(), zid.to_string());
                }
                if account_id.is_none() {
                    account_id = item
                        .get("account")
                        .and_then(|a| a.get("id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    if account_id.is_none() {
        if let Ok(a_resp) = cf_api_request("GET", "accounts?per_page=10", api_token, None) {
            if let Some(arr) = a_resp.get("result").and_then(|v| v.as_array()) {
                if let Some(first) = arr.first() {
                    account_id = first
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    Ok((account_id, zones))
}

pub const CF_LOCAL_AUTH_PORT: u16 = 18443;

fn base64_decode_simple(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for &b in input.trim().as_bytes() {
        if b == b'=' {
            break;
        }
        let val = TABLE.iter().position(|&c| c == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

pub fn check_http_basic_auth(req_buf: &[u8], auth_rules: &[String]) -> bool {
    if auth_rules.is_empty() {
        return true;
    }
    let Ok(text) = std::str::from_utf8(req_buf) else {
        return false;
    };
    let mut provided_user_pass: Option<(String, String)> = None;
    for line in text.lines().take(48) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("authorization") {
                let v_trim = v.trim();
                if let Some(b64) = v_trim.strip_prefix("Basic ").or_else(|| v_trim.strip_prefix("basic ")) {
                    if let Some(decoded_bytes) = base64_decode_simple(b64) {
                        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                            if let Some((u, p)) = decoded_str.split_once(':') {
                                provided_user_pass = Some((u.to_string(), p.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    let Some((user, pass)) = provided_user_pass else {
        return false;
    };

    for rule in auth_rules {
        if rule.eq_ignore_ascii_case("nfty") {
            if crate::ssh::verify_login(&user, &pass) {
                return true;
            }
        } else if let Some((ru, rp)) = rule.split_once(':') {
            if user == ru && pass == rp {
                return true;
            }
        } else if rule.contains('@') {
            // Fallback when Cloudflare Access API is not enabled on the Cloudflare account:
            // accept either the email username / 'nfty' with the nfty appliance password
            let email_prefix = rule.split('@').next().unwrap_or("");
            let auth_cfg = crate::ssh::load_auth_config();
            let pw_ok = auth_cfg.password_sha256 == crate::ssh::hash_password(&pass);
            if pw_ok
                && (user.eq_ignore_ascii_case(&auth_cfg.username)
                    || user.eq_ignore_ascii_case(rule)
                    || (!email_prefix.is_empty() && email_prefix != "*" && user.eq_ignore_ascii_case(email_prefix)))
            {
                return true;
            }
        }
    }
    false
}

/// Strips the nfty `Authorization: Basic ...` header before forwarding to the backend app,
/// and sets `Connection: close` on non-WebSocket HTTP requests so `cloudflared` does not pool
/// an authenticated TCP connection across different visitors.
pub fn sanitize_authenticated_http_request(req_buf: &[u8]) -> Vec<u8> {
    let Some(hdr_end) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return req_buf.to_vec();
    };
    let Ok(hdr_str) = std::str::from_utf8(&req_buf[..hdr_end]) else {
        return req_buf.to_vec();
    };
    let body = &req_buf[hdr_end + 4..];
    let is_websocket = hdr_str
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("websocket"));

    let mut out = String::with_capacity(hdr_str.len() + 32);
    for (idx, line) in hdr_str.lines().enumerate() {
        if idx == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if kl == "authorization" && v.trim().to_ascii_lowercase().starts_with("basic ") {
                continue;
            }
            if kl == "connection" && !is_websocket {
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !is_websocket {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn run_cf_auth_proxy_listener(shared: SharedState) {
    let bind_addr = format!("127.0.0.1:{}", CF_LOCAL_AUTH_PORT);
    let listener = loop {
        match TcpListener::bind(&bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    loop {
        let Ok((mut client, _peer)) = listener.accept().await else {
            continue;
        };
        let shared_conn = shared.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 4096];
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(5), client.read(&mut peek_buf)).await
            else {
                return;
            };
            if n == 0 {
                return;
            }
            let Some(host) = extract_host_or_sni(&peek_buf[..n]) else {
                return;
            };

            let route_match: Option<(String, Vec<String>, String)> = {
                let st = shared_conn.read().unwrap();
                let cfg = if !st.running.services.is_empty() {
                    &st.running
                } else {
                    &st.candidate
                };
                cfg.services.values().find_map(|svc| {
                    let cf_host = svc.cloudflare.as_ref()?;
                    if cf_host.eq_ignore_ascii_case(&host) {
                        let b = svc.backends.first()?;
                        let addr = format!("{}:{}", b.ip, b.port);
                        let mut rules = svc.auth.clone();
                        for r in &svc.cloudflare_auth {
                            if !rules.contains(r) {
                                rules.push(r.clone());
                            }
                        }
                        Some((addr, rules, b.endpoint()))
                    } else {
                        None
                    }
                })
            };

            let Some((upstream_addr, auth_rules, ep_key)) = route_match else {
                let _ = client
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n")
                    .await;
                return;
            };

            if !check_http_basic_auth(&peek_buf[..n], &auth_rules) {
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nfty ({})\"\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\n401 Authentication Needed\n",
                    host
                );
                let _ = client.write_all(resp.as_bytes()).await;
                return;
            }

            let sanitized_req = sanitize_authenticated_http_request(&peek_buf[..n]);
            if let Ok(Ok(mut upstream)) =
                tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&upstream_addr))
                    .await
            {
                if upstream.write_all(&sanitized_req).await.is_ok() {
                    if let Ok((up_b, down_b)) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        if let Ok(mut st) = shared_conn.write() {
                            let rt = st.runtime.entry(ep_key).or_default();
                            rt.packets += 2;
                            rt.bytes += (sanitized_req.len() as u64) + up_b + down_b;
                        }
                    }
                }
            }
        });
    }
}

pub fn service_uses_local_cf_auth_proxy(svc: &crate::ast::Service, access_api_enabled: Option<bool>) -> bool {
    if !svc.auth.is_empty() {
        return true;
    }
    if svc.cloudflare_auth.is_empty() {
        return false;
    }
    let has_local_rule = svc
        .cloudflare_auth
        .iter()
        .any(|r| r.eq_ignore_ascii_case("nfty") || r.contains(':'));
    has_local_rule || access_api_enabled == Some(false)
}

pub fn collect_cloudflare_routes(config: &Config) -> Vec<(String, String, String)> {
    let cf_cfg = load_cloudflare_config();
    let mut routes = Vec::new();
    for svc in config.services.values() {
        let Some(cf_host) = &svc.cloudflare else {
            continue;
        };
        let upstream = if service_uses_local_cf_auth_proxy(svc, cf_cfg.access_api_enabled) {
            format!("http://127.0.0.1:{}", CF_LOCAL_AUTH_PORT)
        } else if let Some(b) = svc.backends.first() {
            let scheme = if b.port == 443 || b.port == 8443 {
                "https"
            } else if b.port == 22 {
                "ssh"
            } else {
                "http"
            };
            format!("{}://{}:{}", scheme, b.ip, b.port)
        } else if let Some(lip) = svc.listen_ip {
            format!("http://{}:{}", lip, svc.port)
        } else {
            format!("http://127.0.0.1:{}", svc.port)
        };
        routes.push((svc.key.clone(), cf_host.clone(), upstream));
    }
    routes
}

pub fn cloudflared_running_pid() -> Option<u32> {
    let pid = fs::read_to_string(CF_PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())?;
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
        if cmdline.contains("cloudflared") {
            return Some(pid);
        }
    }
    None
}

pub fn stop_cloudflared_daemon() {
    if let Some(pid) = cloudflared_running_pid() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    let _ = fs::remove_file(CF_PID_FILE);
}

pub fn start_or_ensure_cloudflared_daemon(tunnel_token: &str) -> Result<u32> {
    if let Some(pid) = cloudflared_running_pid() {
        return Ok(pid);
    }
    let bin = if Path::new("/bin/cloudflared").exists() {
        "/bin/cloudflared"
    } else if Path::new("/usr/bin/cloudflared").exists() {
        "/usr/bin/cloudflared"
    } else {
        bail!("cloudflared binary not found in /bin/cloudflared");
    };

    // Ensure /etc/resolv.conf and /etc/hosts exist for Go's DNS resolver inside the unikernel/container
    if !Path::new("/etc/resolv.conf").exists() {
        let _ = fs::write("/etc/resolv.conf", "nameserver 192.168.1.1\nnameserver 1.1.1.1\n");
    }
    if !fs::read_to_string("/etc/hosts")
        .unwrap_or_default()
        .contains("localhost")
    {
        let mut h = fs::read_to_string("/etc/hosts").unwrap_or_default();
        if !h.is_empty() && !h.ends_with('\n') {
            h.push('\n');
        }
        h.push_str("127.0.0.1 localhost\n");
        let _ = fs::write("/etc/hosts", h);
    }

    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CF_LOG_FILE)?;
    let log_err = log_file.try_clone()?;

    let child = Command::new(bin)
        .args([
            "tunnel",
            "--metrics",
            "127.0.0.1:0",
            "--edge-ip-version",
            "4",
            "--no-autoupdate",
            "--protocol",
            "http2",
            "run",
            "--token",
            tunnel_token.trim(),
        ])
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_err))
        .spawn()
        .with_context(|| "Failed to spawn cloudflared daemon")?;

    let pid = child.id();
    let _ = fs::write(CF_PID_FILE, format!("{}\n", pid));
    Ok(pid)
}

/// Reconciles Cloudflare Tunnel, ingress rules, DNS CNAME records, and the local `cloudflared` daemon
pub fn reconcile_cloudflare_tunnel(config: &Config) -> Vec<String> {
    let mut logs = Vec::new();
    let routes = collect_cloudflare_routes(config);
    let mut cf_cfg = load_cloudflare_config();

    if routes.is_empty() && cf_cfg.managed_dns_records.is_empty() {
        if cloudflared_running_pid().is_some() {
            stop_cloudflared_daemon();
            logs.push("Cloudflare: stopped cloudflared daemon (no cloudflare-dns services active)".to_string());
        }
        return logs;
    }

    if let Some(api_token) = cf_cfg.api_token.clone() {
        match reconcile_with_cf_api(config, &api_token, &routes, &mut cf_cfg) {
            Ok(mut api_logs) => {
                cf_cfg.last_status = Some("OK (synced with Cloudflare API)".to_string());
                let _ = save_cloudflare_config(&cf_cfg);
                logs.append(&mut api_logs);
            }
            Err(e) => {
                let err_msg = format!("ERROR: {}", e);
                cf_cfg.last_status = Some(err_msg.clone());
                let _ = save_cloudflare_config(&cf_cfg);
                logs.push(format!("Cloudflare API sync failed: {}", e));
            }
        }
    } else if !routes.is_empty() && cf_cfg.tunnel_token.is_none() {
        logs.push(
            "Cloudflare: services have 'cloudflare-dns' configured, but no API token is set yet (run 'cf token <API_TOKEN>')".to_string(),
        );
        return logs;
    }

    if routes.is_empty() {
        stop_cloudflared_daemon();
    } else if let Some(tok) = &cf_cfg.tunnel_token {
        match start_or_ensure_cloudflared_daemon(tok) {
            Ok(pid) => {
                logs.push(format!(
                    "Cloudflare: cloudflared edge connector active (PID {}, {} route(s))",
                    pid,
                    routes.len()
                ));
            }
            Err(e) => {
                logs.push(format!("Cloudflare: failed to start cloudflared: {}", e));
            }
        }
    }

    logs
}

fn reconcile_with_cf_api(
    config: &Config,
    api_token: &str,
    _routes: &[(String, String, String)],
    cf_cfg: &mut CloudflareConfig,
) -> Result<Vec<String>> {
    let mut logs = Vec::new();
    let (discovered_acct, zones) = discover_cf_account_and_zones(api_token)?;
    if cf_cfg.account_id.is_none() {
        cf_cfg.account_id = discovered_acct;
    }
    let account_id = cf_cfg.account_id.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "Could not auto-discover Cloudflare Account ID from token; run 'cf token <TOKEN> <ACCOUNT_ID>'"
        )
    })?;

    // 0. Reconcile Cloudflare Zero-Trust Access Apps & Policies for services with email-based `cloudflare-auth`
    let mut active_access_hosts = BTreeSet::new();
    for svc in config.services.values() {
        let Some(hostname) = &svc.cloudflare else {
            continue;
        };
        let email_rules: Vec<&String> = svc
            .cloudflare_auth
            .iter()
            .filter(|r| r.contains('@'))
            .collect();
        if email_rules.is_empty() {
            continue;
        }
        active_access_hosts.insert(hostname.clone());

        let mut include_objs = Vec::new();
        for rule in &email_rules {
            if let Some(dom) = rule.strip_prefix("*@").or_else(|| rule.strip_prefix('@')) {
                include_objs.push(serde_json::json!({
                    "email_domain": { "domain": dom }
                }));
            } else {
                include_objs.push(serde_json::json!({
                    "email": { "email": *rule }
                }));
            }
        }

        let apps_path = format!("accounts/{}/access/apps", account_id);
        match cf_api_request("GET", &apps_path, api_token, None) {
            Ok(apps_resp) => {
                cf_cfg.access_api_enabled = Some(true);
                let existing_app_id = apps_resp
                    .get("result")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter().find(|a| {
                            a.get("domain")
                                .and_then(|d| d.as_str())
                                .map(|d| d.eq_ignore_ascii_case(hostname))
                                .unwrap_or(false)
                        })
                    })
                    .and_then(|a| a.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Discover or create a non-Cloudflare-account IdP (e.g. `onetimepin` or `google`) so visitors aren't asked for a Cloudflare account
                let idps_path = format!("accounts/{}/access/identity_providers", account_id);
                let mut allowed_idps: Vec<String> = cf_api_request("GET", &idps_path, api_token, None)
                    .ok()
                    .and_then(|resp| {
                        resp.get("result")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter(|item| {
                                        item.get("type").and_then(|t| t.as_str()) != Some("cloudflare")
                                    })
                                    .filter_map(|item| {
                                        item.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    })
                                    .collect::<Vec<String>>()
                            })
                    })
                    .unwrap_or_default();
                if allowed_idps.is_empty() {
                    let otp_body = serde_json::json!({
                        "name": "One-time PIN",
                        "type": "onetimepin",
                        "config": {}
                    });
                    if let Ok(created_idp) = cf_api_request("POST", &idps_path, api_token, Some(otp_body)) {
                        if let Some(idp_id) = created_idp
                            .get("result")
                            .and_then(|r| r.get("id"))
                            .and_then(|v| v.as_str())
                        {
                            allowed_idps.push(idp_id.to_string());
                        }
                    }
                }

                let app_body = if allowed_idps.is_empty() {
                    serde_json::json!({
                        "name": format!("nfty: {}", hostname),
                        "domain": hostname,
                        "type": "self_hosted",
                        "session_duration": "24h"
                    })
                } else {
                    serde_json::json!({
                        "name": format!("nfty: {}", hostname),
                        "domain": hostname,
                        "type": "self_hosted",
                        "session_duration": "24h",
                        "allowed_idps": allowed_idps,
                        "auto_redirect_to_identity": allowed_idps.len() == 1
                    })
                };

                let app_id = if let Some(aid) = existing_app_id {
                    let put_app = format!("accounts/{}/access/apps/{}", account_id, aid);
                    let _ = cf_api_request("PUT", &put_app, api_token, Some(app_body));
                    aid
                } else {
                    let created_app = cf_api_request("POST", &apps_path, api_token, Some(app_body))?;
                    created_app
                        .get("result")
                        .and_then(|r| r.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };

                if !app_id.is_empty() {
                    cf_cfg
                        .managed_access_apps
                        .insert(hostname.clone(), app_id.clone());
                    let pols_path =
                        format!("accounts/{}/access/apps/{}/policies", account_id, app_id);
                    let existing_pol_id = cf_api_request("GET", &pols_path, api_token, None)
                        .ok()
                        .and_then(|p| {
                            p.get("result")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|item| item.get("id"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                        });
                    let pol_body = serde_json::json!({
                        "name": "nfty allow policy",
                        "decision": "allow",
                        "include": include_objs,
                        "precedence": 1
                    });
                    if let Some(pid) = existing_pol_id {
                        let put_pol = format!("{}/{}", pols_path, pid);
                        let _ = cf_api_request("PUT", &put_pol, api_token, Some(pol_body));
                    } else {
                        let _ = cf_api_request("POST", &pols_path, api_token, Some(pol_body));
                    }
                    logs.push(format!(
                        "Cloudflare Access: synced Zero-Trust policy for {} ({:?})",
                        hostname, email_rules
                    ));
                }
            }
            Err(e) => {
                cf_cfg.access_api_enabled = Some(false);
                let err_s = e.to_string();
                if err_s.contains("not_enabled") {
                    logs.push(format!(
                        "Cloudflare Auth: Access Zero-Trust is not enabled in Cloudflare dashboard yet — enabled local nfty Basic-Auth gate on '{}' (login with your 'nfty' password)",
                        hostname
                    ));
                } else {
                    logs.push(format!(
                        "Cloudflare Auth: Access API unavailable ({}) — enabled local nfty Basic-Auth gate on '{}'",
                        err_s, hostname
                    ));
                }
            }
        }
    }

    // Clean up removed Cloudflare Access Apps
    if cf_cfg.access_api_enabled == Some(true) {
        let stale_apps: Vec<String> = cf_cfg
            .managed_access_apps
            .keys()
            .filter(|h| !active_access_hosts.contains(*h))
            .cloned()
            .collect();
        for stale in stale_apps {
            if let Some(app_id) = cf_cfg.managed_access_apps.remove(&stale) {
                let del_path = format!("accounts/{}/access/apps/{}", account_id, app_id);
                let _ = cf_api_request("DELETE", &del_path, api_token, None);
                logs.push(format!(
                    "Cloudflare Access: removed Access Application for '{}'",
                    stale
                ));
            }
        }
    }

    // Recompute routes in case `access_api_enabled` changed to `Some(false)` (switching to local Basic-Auth proxy)
    let effective_routes: Vec<(String, String, String)> = config
        .services
        .values()
        .filter_map(|svc| {
            let cf_host = svc.cloudflare.as_ref()?;
            let upstream = if service_uses_local_cf_auth_proxy(svc, cf_cfg.access_api_enabled) {
                format!("http://127.0.0.1:{}", CF_LOCAL_AUTH_PORT)
            } else if let Some(b) = svc.backends.first() {
                let scheme = if b.port == 443 || b.port == 8443 {
                    "https"
                } else if b.port == 22 {
                    "ssh"
                } else {
                    "http"
                };
                format!("{}://{}:{}", scheme, b.ip, b.port)
            } else if let Some(lip) = svc.listen_ip {
                format!("http://{}:{}", lip, svc.port)
            } else {
                format!("http://127.0.0.1:{}", svc.port)
            };
            Some((svc.key.clone(), cf_host.clone(), upstream))
        })
        .collect();
    let routes = &effective_routes[..];

    // 1. Ensure Tunnel exists if we have routes
    if !routes.is_empty() {
        if cf_cfg.tunnel_id.is_none() {
            let list_path = format!(
                "accounts/{}/cfd_tunnel?name={}&is_deleted=false",
                account_id, cf_cfg.tunnel_name
            );
            let list_resp = cf_api_request("GET", &list_path, api_token, None)?;
            if let Some(existing) = list_resp
                .get("result")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
            {
                if let Some(tid) = existing.get("id").and_then(|v| v.as_str()) {
                    cf_cfg.tunnel_id = Some(tid.to_string());
                }
            }
        }

        if cf_cfg.tunnel_id.is_none() {
            let create_path = format!("accounts/{}/cfd_tunnel", account_id);
            let body = serde_json::json!({
                "name": cf_cfg.tunnel_name,
                "config_src": "cloudflare"
            });
            let create_resp = cf_api_request("POST", &create_path, api_token, Some(body))?;
            let tid = create_resp
                .get("result")
                .and_then(|r| r.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Cloudflare tunnel creation returned no id"))?
                .to_string();
            if let Some(tok) = create_resp
                .get("result")
                .and_then(|r| r.get("token"))
                .and_then(|v| v.as_str())
            {
                cf_cfg.tunnel_token = Some(tok.to_string());
            }
            logs.push(format!(
                "Cloudflare: created tunnel '{}' ({})",
                cf_cfg.tunnel_name, tid
            ));
            cf_cfg.tunnel_id = Some(tid);
        }

        let tunnel_id = cf_cfg.tunnel_id.clone().unwrap();

        // Fetch tunnel connector token if not cached yet
        if cf_cfg.tunnel_token.is_none() {
            let tok_path = format!("accounts/{}/cfd_tunnel/{}/token", account_id, tunnel_id);
            let tok_resp = cf_api_request("GET", &tok_path, api_token, None)?;
            if let Some(tok) = tok_resp.get("result").and_then(|v| v.as_str()) {
                cf_cfg.tunnel_token = Some(tok.to_string());
            }
        }

        // 2. Push remotely-managed ingress rules
        let mut ingress = Vec::new();
        for (_svc_key, hostname, upstream) in routes {
            ingress.push(serde_json::json!({
                "hostname": hostname,
                "service": upstream,
                "originRequest": {
                    "noTLSVerify": true
                }
            }));
        }
        ingress.push(serde_json::json!({
            "service": "http_status:404"
        }));

        let cfg_path = format!(
            "accounts/{}/cfd_tunnel/{}/configurations",
            account_id, tunnel_id
        );
        let cfg_body = serde_json::json!({
            "config": {
                "ingress": ingress
            }
        });
        cf_api_request("PUT", &cfg_path, api_token, Some(cfg_body))?;
        logs.push(format!(
            "Cloudflare: synced {} ingress route(s) to tunnel {}",
            routes.len(),
            tunnel_id
        ));

        // 3. Upsert proxied DNS CNAME records for each route
        let cname_target = format!("{}.cfargotunnel.com", tunnel_id);
        for (_svc_key, hostname, upstream) in routes {
            // Find matching zone (longest suffix match)
            let matched_zone = zones
                .iter()
                .filter(|(zname, _)| {
                    hostname == *zname || hostname.ends_with(&format!(".{}", zname))
                })
                .max_by_key(|(zname, _)| zname.len());

            let Some((_zname, zone_id)) = matched_zone else {
                logs.push(format!(
                    "Cloudflare Warning: no matching zone found in account for '{}' (available zones: {:?})",
                    hostname,
                    zones.keys().collect::<Vec<_>>()
                ));
                continue;
            };

            let list_dns_path = format!("zones/{}/dns_records?name={}", zone_id, hostname);
            let dns_list = cf_api_request("GET", &list_dns_path, api_token, None)?;
            let existing_rec = dns_list
                .get("result")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first());

            let rec_body = serde_json::json!({
                "type": "CNAME",
                "name": hostname,
                "content": cname_target,
                "proxied": true,
                "ttl": 1,
                "comment": "Managed by nfty appliance"
            });

            if let Some(rec) = existing_rec {
                let rec_id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let cur_content = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let cur_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if cur_type != "CNAME" || !cur_content.eq_ignore_ascii_case(&cname_target) {
                    let put_path = format!("zones/{}/dns_records/{}", zone_id, rec_id);
                    cf_api_request("PUT", &put_path, api_token, Some(rec_body))?;
                    logs.push(format!(
                        "Cloudflare DNS: updated CNAME {} -> {} ({})",
                        hostname, cname_target, upstream
                    ));
                } else {
                    logs.push(format!(
                        "Cloudflare DNS: verified CNAME {} -> {} ({})",
                        hostname, cname_target, upstream
                    ));
                }
                cf_cfg
                    .managed_dns_records
                    .insert(hostname.clone(), (zone_id.clone(), rec_id.to_string()));
            } else {
                let post_path = format!("zones/{}/dns_records", zone_id);
                let created = cf_api_request("POST", &post_path, api_token, Some(rec_body))?;
                if let Some(rec_id) = created
                    .get("result")
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                {
                    cf_cfg
                        .managed_dns_records
                        .insert(hostname.clone(), (zone_id.clone(), rec_id.to_string()));
                }
                logs.push(format!(
                    "Cloudflare DNS: created proxied CNAME {} -> {} ({})",
                    hostname, cname_target, upstream
                ));
            }
        }
    }

    // 4. Clean up any managed DNS records that were removed from Nftyfile
    let active_hosts: BTreeSet<String> = routes.iter().map(|(_, h, _)| h.clone()).collect();
    let stale_hosts: Vec<String> = cf_cfg
        .managed_dns_records
        .keys()
        .filter(|h| !active_hosts.contains(*h))
        .cloned()
        .collect();
    for stale in stale_hosts {
        if let Some((zone_id, rec_id)) = cf_cfg.managed_dns_records.remove(&stale) {
            let del_path = format!("zones/{}/dns_records/{}", zone_id, rec_id);
            let _ = cf_api_request("DELETE", &del_path, api_token, None);
            logs.push(format!(
                "Cloudflare DNS: removed stale CNAME record '{}'",
                stale
            ));
        }
    }

    Ok(logs)
}

pub fn handle_cf_cli_command(args: &[&str], shared: &SharedState) -> Result<()> {
    let sub = args.first().map(|s| s.to_ascii_lowercase());
    match sub.as_deref() {
        None | Some("status") | Some("list") | Some("show") => {
            let cf_cfg = load_cloudflare_config();
            let st = shared.read().unwrap();
            let cfg = if !st.running.services.is_empty() {
                &st.running
            } else {
                &st.candidate
            };
            let routes = collect_cloudflare_routes(cfg);
            let pid_opt = cloudflared_running_pid();

            println!("{}", "Cloudflare Tunnel & Automated DNS Status:".bold().cyan());
            let tok_display = match &cf_cfg.api_token {
                Some(t) if t.len() > 8 => format!(
                    "{}...{} {}",
                    &t[..4],
                    &t[t.len() - 4..],
                    "(configured)".green()
                ),
                Some(_) => "(configured)".green().to_string(),
                None => "(not set — run 'cf token <API_TOKEN>')".yellow().to_string(),
            };
            println!("  API Token:      {}", tok_display);
            println!(
                "  Account ID:     {}",
                cf_cfg.account_id.as_deref().unwrap_or("-")
            );
            println!(
                "  Tunnel:         {} ({})",
                cf_cfg.tunnel_name.bold(),
                cf_cfg.tunnel_id.as_deref().unwrap_or("not created yet")
            );
            let daemon_str = match pid_opt {
                Some(pid) => format!("RUNNING (PID {})", pid).green().bold().to_string(),
                None => "STOPPED".dimmed().to_string(),
            };
            println!("  Connector:      {}", daemon_str);
            if let Some(status) = &cf_cfg.last_status {
                println!("  Last Sync:      {}", status);
            }

            println!(
                "\n  {:<22} {:<30} {:<26} {}",
                "SERVICE".bold().underline(),
                "PUBLIC CLOUDFLARE HOSTNAME".bold().underline(),
                "UPSTREAM TARGET".bold().underline(),
                "AUTH POLICY".bold().underline()
            );
            if routes.is_empty() {
                println!(
                    "  {}",
                    "(No services have 'cloudflare-dns <fqdn>' configured yet)".dimmed()
                );
            } else {
                for (svc_key, fqdn, upstream) in routes {
                    let auth_str = cfg
                        .services
                        .get(&svc_key)
                        .map(|s| {
                            let mut policies = Vec::new();
                            for r in &s.auth {
                                let masked = r.split(':').next().unwrap_or(r);
                                policies.push(format!("basic:{}", masked));
                            }
                            for r in &s.cloudflare_auth {
                                policies.push(r.clone());
                            }
                            if policies.is_empty() {
                                "open (none)".dimmed().to_string()
                            } else {
                                format!("🔒 {}", policies.join(", "))
                                    .yellow()
                                    .bold()
                                    .to_string()
                            }
                        })
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "  {:<22} {:<30} {:<26} {}",
                        svc_key.yellow().bold(),
                        format!("https://{}", fqdn).green().bold(),
                        upstream,
                        auth_str
                    );
                }
            }
            Ok(())
        }
        Some("token") | Some("key") | Some("login") => {
            if args.len() < 2 {
                bail!("Usage: cf token <CLOUDFLARE_API_TOKEN> [ACCOUNT_ID]");
            }
            let api_token = args[1].trim().to_string();
            let explicit_acct = args.get(2).map(|s| s.trim().to_string());
            println!("Verifying Cloudflare API token...");
            let (disc_acct, zones) = discover_cf_account_and_zones(&api_token)?;
            let mut cf_cfg = load_cloudflare_config();
            cf_cfg.api_token = Some(api_token);
            if let Some(a) = explicit_acct.or(disc_acct) {
                cf_cfg.account_id = Some(a);
            }
            save_cloudflare_config(&cf_cfg)?;
            println!(
                "  {} Saved Cloudflare API token in {} (Account: {}, Zones discovered: {:?})",
                "✔".green().bold(),
                CF_CONFIG_PATH.bold(),
                cf_cfg.account_id.as_deref().unwrap_or("pending"),
                zones.keys().collect::<Vec<_>>()
            );
            let cfg_clone = {
                let st = shared.read().unwrap();
                if !st.running.services.is_empty() {
                    st.running.clone()
                } else {
                    st.candidate.clone()
                }
            };
            for log in reconcile_cloudflare_tunnel(&cfg_clone) {
                println!("  {} {}", "→".cyan(), log);
            }
            Ok(())
        }
        Some("tunnel-token") => {
            if args.len() < 2 {
                bail!("Usage: cf tunnel-token <EYJH...>");
            }
            let mut cf_cfg = load_cloudflare_config();
            cf_cfg.tunnel_token = Some(args[1].trim().to_string());
            save_cloudflare_config(&cf_cfg)?;
            let pid = start_or_ensure_cloudflared_daemon(args[1].trim())?;
            println!(
                "  {} Saved Cloudflare tunnel connector token & started cloudflared (PID {})",
                "✔".green().bold(),
                pid
            );
            Ok(())
        }
        Some("sync") | Some("apply") => {
            let cfg_clone = {
                let st = shared.read().unwrap();
                if !st.running.services.is_empty() {
                    st.running.clone()
                } else {
                    st.candidate.clone()
                }
            };
            let logs = reconcile_cloudflare_tunnel(&cfg_clone);
            if logs.is_empty() {
                println!("  (No Cloudflare Tunnel routes configured)");
            } else {
                for l in logs {
                    println!("  {} {}", "→".cyan(), l);
                }
            }
            Ok(())
        }
        Some("logs") | Some("log") => {
            let raw = fs::read_to_string(CF_LOG_FILE).unwrap_or_default();
            if raw.is_empty() {
                println!("  (No cloudflared logs in {} yet)", CF_LOG_FILE);
            } else {
                let lines: Vec<&str> = raw.lines().collect();
                let start = lines.len().saturating_sub(25);
                for l in &lines[start..] {
                    println!("  {}", l);
                }
            }
            Ok(())
        }
        Some("stop") | Some("clear") | Some("logout") => {
            stop_cloudflared_daemon();
            if sub.as_deref() != Some("stop") {
                let _ = fs::remove_file(CF_CONFIG_PATH);
                println!("  {} Stopped cloudflared and cleared {}", "✔".green().bold(), CF_CONFIG_PATH);
            } else {
                println!("  {} Stopped cloudflared daemon", "✔".green().bold());
            }
            Ok(())
        }
        Some(other) => bail!(
            "Unknown cf subcommand '{}'. Valid commands: 'cf status', 'cf token <API_TOKEN>', 'cf sync', 'cf logs', 'cf stop'",
            other
        ),
    }
}


