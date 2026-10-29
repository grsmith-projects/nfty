use crate::ast::{Config, Gateway, GatewayServiceKind, WgIngressPeer, WgTunnel};
use crate::state::HealthState;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use colored::Colorize;
use qrcode::{Color as QrColor, EcLevel, QrCode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) fn wireguard_iface_index(iface: &str) -> Option<usize> {
    let suffix = iface.strip_prefix("wg")?;
    if suffix.is_empty() || iface.len() > 15 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<usize>().ok().filter(|n| *n <= 1_999_999)
}

pub(crate) fn wg_ingress_iface_index(iface: &str) -> Option<usize> {
    let suffix = iface.strip_prefix("ig")?;
    if suffix.is_empty() || iface.len() > 15 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<usize>().ok().filter(|n| *n <= 1_999_999)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWgServerKeys {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWgClientPeer {
    pub name: String,
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub private_key: Option<String>,
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
}

/// Generates a fresh Curve25519 WireGuard `(private_key_base64, public_key_base64)` pair.
pub fn generate_wg_keypair() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let pubkey = PublicKey::from(&secret);
    (
        BASE64.encode(secret.to_bytes()),
        BASE64.encode(pubkey.as_bytes()),
    )
}

/// Generates a fresh 256-bit WireGuard PresharedKey in standard Base64.
pub fn generate_wg_psk() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

/// Validates a Base64-encoded 32-byte WireGuard key.
pub fn validate_wg_key_base64(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let decoded = BASE64
        .decode(trimmed)
        .with_context(|| format!("Invalid Base64 WireGuard key '{}'", trimmed))?;
    if decoded.len() != 32 {
        bail!(
            "Invalid WireGuard key length: expected 32 bytes (44 base64 chars), got {} bytes",
            decoded.len()
        );
    }
    Ok(trimmed.to_string())
}

fn wg_storage_base_dir() -> PathBuf {
    let data_dir = Path::new("/data");
    if unsafe { libc::geteuid() == 0 } || (data_dir.exists() && ! cfg!(test)) {
        data_dir.to_path_buf()
    } else {
        std::env::temp_dir().join(format!("nfty-wg-{}", unsafe { libc::getuid() }))
    }
}

fn sanitize_storage_id(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Loads or generates the persistent WireGuard server keypair for a gateway (`wg-in:<port>`).
pub fn ensure_gateway_server_keys(gw_key: &str) -> Result<StoredWgServerKeys> {
    let dir = wg_storage_base_dir().join("wg-server");
    fs::create_dir_all(&dir).with_context(|| format!("Cannot create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", sanitize_storage_id(gw_key)));
    if path.exists() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(keys) = serde_json::from_str::<StoredWgServerKeys>(&raw) {
                if validate_wg_key_base64(&keys.private_key).is_ok()
                    && validate_wg_key_base64(&keys.public_key).is_ok()
                {
                    return Ok(keys);
                }
            }
        }
    }
    let (private_key, public_key) = generate_wg_keypair();
    let keys = StoredWgServerKeys {
        private_key,
        public_key,
    };
    let json = serde_json::to_string_pretty(&keys)?;
    write_runtime_wg_config(&path.to_string_lossy(), &json)?;
    Ok(keys)
}

/// Saves client peer metadata (including optional generated client private key) to `/data/wg-peers/<gw>/<peer>.json`.
pub fn save_stored_client_peer(gw_key: &str, peer: &StoredWgClientPeer) -> Result<()> {
    let dir = wg_storage_base_dir()
        .join("wg-peers")
        .join(sanitize_storage_id(gw_key));
    fs::create_dir_all(&dir).with_context(|| format!("Cannot create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", sanitize_storage_id(&peer.name)));
    let json = serde_json::to_string_pretty(peer)?;
    write_runtime_wg_config(&path.to_string_lossy(), &json)?;
    Ok(())
}

/// Loads stored client peer metadata if present.
pub fn load_stored_client_peer(gw_key: &str, peer_name: &str) -> Option<StoredWgClientPeer> {
    let path = wg_storage_base_dir()
        .join("wg-peers")
        .join(sanitize_storage_id(gw_key))
        .join(format!("{}.json", sanitize_storage_id(peer_name)));
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Removes stored client peer metadata when a peer is deleted.
pub fn delete_stored_client_peer(gw_key: &str, peer_name: &str) {
    let path = wg_storage_base_dir()
        .join("wg-peers")
        .join(sanitize_storage_id(gw_key))
        .join(format!("{}.json", sanitize_storage_id(peer_name)));
    let _ = fs::remove_file(path);
}

/// Builds the ready-to-import WireGuard client `.conf` for a peer on `gw`.
pub fn build_client_wg_conf(cfg: &Config, gw: &Gateway, peer_name: &str) -> Result<String> {
    let wg_in = gw
        .wg_ingress
        .as_ref()
        .with_context(|| format!("Gateway '{}' does not have a wg-in endpoint configured", gw.key))?;
    let peer: &WgIngressPeer = wg_in
        .peers
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(peer_name))
        .with_context(|| format!("Peer '{}' not found on gateway '{}'", peer_name, gw.key))?;

    let server_keys = ensure_gateway_server_keys(&gw.key)?;
    let stored = load_stored_client_peer(&gw.key, &peer.name);
    let priv_key = stored
        .as_ref()
        .and_then(|s| s.private_key.as_deref())
        .unwrap_or("<INSERT_CLIENT_PRIVATE_KEY>");

    let endpoint = if let Some(ep) = &wg_in.endpoint {
        if ep.contains(':') {
            ep.clone()
        } else {
            format!("{}:{}", ep, wg_in.port)
        }
    } else if !gw.listen_ip.is_unspecified() {
        format!("{}:{}", gw.listen_ip, wg_in.port)
    } else if let Some(h) = &gw.hostname {
        format!("{}:{}", h, wg_in.port)
    } else {
        format!("{}:{}", gw.key, wg_in.port)
    };

    let dns_ip = if let Some(d) = wg_in.dns {
        d
    } else if gw.services.iter().any(|s| s.kind == GatewayServiceKind::Dns) {
        wg_in.address
    } else if cfg.has_any_dns_enabled() && !gw.listen_ip.is_unspecified() {
        gw.listen_ip
    } else {
        Ipv4Addr::new(1, 1, 1, 1)
    };

    let allowed_ips = wg_in
        .split_tunnel
        .allowed_ips_for_client(wg_in.address, wg_in.prefix_len);

    let mut conf = String::new();
    conf.push_str(&format!(
        "# nfty WireGuard Client — {} (gateway {})\n",
        peer.name, gw.key
    ));
    conf.push_str("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", priv_key));
    conf.push_str(&format!("Address = {}/{}\n", peer.ip, wg_in.prefix_len));
    conf.push_str(&format!("DNS = {}\n\n", dns_ip));
    conf.push_str("[Peer]\n");
    conf.push_str(&format!("PublicKey = {}\n", server_keys.public_key));
    if let Some(psk) = &peer.preshared_key {
        conf.push_str(&format!("PresharedKey = {}\n", psk));
    }
    conf.push_str(&format!("Endpoint = {}\n", endpoint));
    conf.push_str(&format!("AllowedIPs = {}\n", allowed_ips));
    conf.push_str("PersistentKeepalive = 25\n");
    Ok(conf)
}

/// Renders a string (such as a WireGuard client `.conf`) into a compact UTF-8 half-block QR code for terminal scanning.
pub fn render_qr_unicode(content: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(content.as_bytes(), EcLevel::L)
        .context("Failed to encode QR code")?;
    let width = code.width();
    let quiet = 2isize;
    let total = (width as isize) + quiet * 2;

    let is_dark = |x: isize, y: isize| -> bool {
        if x < quiet || y < quiet || x >= (width as isize) + quiet || y >= (width as isize) + quiet
        {
            false
        } else {
            code[((y - quiet) as usize, (x - quiet) as usize)] == QrColor::Dark
        }
    };

    let mut out = String::new();
    let mut y = 0isize;
    while y < total {
        out.push_str("  ");
        for x in 0..total {
            let top = is_dark(x, y);
            let bottom = if y + 1 < total {
                is_dark(x, y + 1)
            } else {
                false
            };
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

pub(crate) fn wireguard_table_id(index: usize) -> usize {
    if index <= 150 { 101 + index } else { 1_000_000 + index }
}

pub(crate) fn wireguard_mark(index: usize) -> usize {
    if index <= 150 { 0x101 + index } else { 0x0100_0000 + index }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedWgConf {
    pub address: String,
    pub private_key: String,
    pub peer_pubkey: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub keepalive: u16,
}

/// Parses a standard WireGuard / Mullvad `.conf` file.
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

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").env("LC_ALL", "C").args(args).output().context("Failed to invoke ip")?;
    if !output.status.success() {
        bail!("ip {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

fn remove_ip_rule_or_route(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").env("LC_ALL", "C").args(args).output().context("Failed to invoke ip")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && !stderr.contains("No such file or directory")
        && !stderr.contains("FIB table does not exist")
        && !stderr.contains("No such process")
    {
        bail!("ip {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

fn read_route_source(path: &str) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let source = raw.trim();
            source.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("Invalid WireGuard route source in {}", path))?;
            Ok(Some(source.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Cannot read {}", path)),
    }
}

fn write_runtime_wg_config(path: &str, config: &str) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| format!("Cannot write {}", path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(config.as_bytes())?;
    Ok(())
}

/// Applies configured tunnels and only cleans up interfaces marked as managed by nfty.
pub fn apply_wireguard_gateways(cfg: &Config) -> Result<Vec<String>> {
    if unsafe { libc::geteuid() != 0 } {
        return Ok(Vec::new());
    }
    let mut logs = Vec::new();
    fs::create_dir_all("/run").context("Cannot prepare WireGuard runtime directory")?;
    if cfg
        .gateways
        .values()
        .any(|g| !g.tunnels.is_empty() || g.wg_ingress.is_some())
    {
        fs::create_dir_all("/data/wg").context("Cannot prepare WireGuard config directory")?;
        let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1\n");
        fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "2\n")
            .context("Cannot configure WireGuard reverse-path filtering")?;
        fs::write("/proc/sys/net/ipv4/conf/default/rp_filter", "2\n")
            .context("Cannot configure default reverse-path filtering")?;
    }

    let mut active_wg_ifaces = std::collections::BTreeSet::new();
    let mut active_ig_ifaces = std::collections::BTreeSet::new();
    let mut global_idx = 0usize;
    let mut ig_idx = 0usize;
    for gw in cfg.gateways.values() {
        if let Some(wg_in) = &gw.wg_ingress {
            let iface = format!("ig{}", ig_idx);
            ig_idx += 1;
            active_ig_ifaces.insert(iface.clone());
            let server_keys = ensure_gateway_server_keys(&gw.key)?;
            let run_conf_path = format!("/run/nfty-{}.conf", iface);
            let iface_exists = Path::new(&format!("/sys/class/net/{}", iface)).exists();
            if iface_exists && !Path::new(&run_conf_path).is_file() {
                bail!("Refusing to modify unmanaged WireGuard interface '{}'", iface);
            }
            if !iface_exists {
                run_ip(&["link", "add", "dev", &iface, "type", "wireguard"])?;
            }
            let mut wg_conf = format!(
                "[Interface]\nPrivateKey = {}\nListenPort = {}\n",
                server_keys.private_key, wg_in.port
            );
            for peer in &wg_in.peers {
                wg_conf.push_str(&format!(
                    "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
                    peer.public_key, peer.ip
                ));
                if let Some(psk) = &peer.preshared_key {
                    wg_conf.push_str(&format!("PresharedKey = {}\n", psk));
                }
            }
            if let Err(e) = write_runtime_wg_config(&run_conf_path, &wg_conf) {
                if !iface_exists {
                    let _ = run_ip(&["link", "del", "dev", &iface]);
                }
                return Err(e);
            }
            let cidr_addr = format!("{}/{}", wg_in.address, wg_in.prefix_len);
            run_ip(&["addr", "flush", "dev", &iface])?;
            run_ip(&["addr", "replace", &cidr_addr, "dev", &iface])?;
            run_ip(&["link", "set", "mtu", "1420", "up", "dev", &iface])?;
            let wg_output = Command::new("wg")
                .args(["setconf", &iface, &run_conf_path])
                .output()
                .context("Failed to invoke wg")?;
            if !wg_output.status.success() {
                bail!(
                    "wg setconf {} failed: {}",
                    iface,
                    String::from_utf8_lossy(&wg_output.stderr).trim()
                );
            }
            logs.push(format!(
                "WireGuard ingress endpoint {}:{} ({}) [subnet {}, peers={}] ACTIVE",
                gw.key,
                wg_in.port,
                iface,
                cidr_addr,
                wg_in.peers.len()
            ));
        }

        for t in &gw.tunnels {
            let iface = if t.iface.is_empty() {
                format!("wg{}", global_idx)
            } else {
                t.iface.clone()
            };
            global_idx += 1;
            let index = wireguard_iface_index(&iface)
                .with_context(|| format!("Invalid WireGuard interface '{}'", iface))?;
            if !active_wg_ifaces.insert(iface.clone()) {
                bail!("WireGuard interface '{}' is configured more than once", iface);
            }
            let table_str = wireguard_table_id(index).to_string();
            let mark_hex = format!("0x{:x}", wireguard_mark(index));
            let prio_str = "1000";
            let parsed = resolve_tunnel_config(t)?;
            let src_ip = parsed.address.split('/').next().unwrap_or("").trim();
            src_ip.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("Invalid WireGuard address '{}'", parsed.address))?;

            let run_conf_path = format!("/run/nfty-{}.conf", iface);
            let route_path = format!("/run/nfty-{}.route", iface);
            let iface_exists = Path::new(&format!("/sys/class/net/{}", iface)).exists();
            if iface_exists && !Path::new(&run_conf_path).is_file() {
                bail!("Refusing to modify unmanaged WireGuard interface '{}'", iface);
            }
            if !iface_exists {
                run_ip(&["link", "add", "dev", &iface, "type", "wireguard"])?;
            }
            let mut wg_conf = format!(
                "[Interface]\nPrivateKey = {}\nFwMark = 0x51820\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {}\n",
                parsed.private_key, parsed.peer_pubkey, parsed.endpoint, parsed.keepalive
            );
            if let Some(psk) = &parsed.preshared_key {
                wg_conf.push_str(&format!("PresharedKey = {}\n", psk));
            }
            if let Err(e) = write_runtime_wg_config(&run_conf_path, &wg_conf) {
                if !iface_exists {
                    if let Err(cleanup) = run_ip(&["link", "del", "dev", &iface]) {
                        bail!("{}; failed to remove new interface '{}': {}", e, iface, cleanup);
                    }
                }
                return Err(e);
            }

            run_ip(&["addr", "flush", "dev", &iface])?;
            run_ip(&["addr", "replace", &parsed.address, "dev", &iface])?;
            run_ip(&["link", "set", "mtu", "1420", "up", "dev", &iface])?;
            let wg_output = Command::new("wg")
                .args(["setconf", &iface, &run_conf_path])
                .output()
                .context("Failed to invoke wg")?;
            if !wg_output.status.success() {
                bail!("wg setconf {} failed: {}", iface, String::from_utf8_lossy(&wg_output.stderr).trim());
            }

            run_ip(&["route", "replace", "default", "dev", &iface, "table", &table_str])?;
            remove_ip_rule_or_route(&["rule", "del", "fwmark", &mark_hex, "table", &table_str])?;
            run_ip(&["rule", "add", "fwmark", &mark_hex, "table", &table_str, "priority", prio_str])?;
            if let Some(old_src) = read_route_source(&route_path)? {
                remove_ip_rule_or_route(&["rule", "del", "from", &old_src, "table", &table_str])?;
            }
            remove_ip_rule_or_route(&["rule", "del", "from", src_ip, "table", &table_str])?;
            run_ip(&["rule", "add", "from", src_ip, "table", &table_str, "priority", prio_str])?;
            fs::write(&route_path, src_ip).with_context(|| format!("Cannot write {}", route_path))?;
            logs.push(format!(
                "WireGuard tunnel {} ({}) -> {} [addr {}, table {}, mark {}] ACTIVE",
                t.name, iface, parsed.endpoint, parsed.address, table_str, mark_hex
            ));
        }
    }

    for entry in fs::read_dir("/run").context("Cannot inspect managed WireGuard interfaces")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(iface) = name.strip_prefix("nfty-").and_then(|n| n.strip_suffix(".conf")) else { continue };
        if wg_ingress_iface_index(iface).is_some() {
            if active_ig_ifaces.contains(iface) {
                continue;
            }
            if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
                run_ip(&["link", "del", "dev", iface])?;
            }
            fs::remove_file(entry.path()).with_context(|| format!("Cannot remove {}", name))?;
            logs.push(format!("Removed managed WireGuard ingress interface {}", iface));
            continue;
        }
        let Some(index) = wireguard_iface_index(iface) else { continue };
        if active_wg_ifaces.contains(iface) {
            continue;
        }
        let table_str = wireguard_table_id(index).to_string();
        let mark_hex = format!("0x{:x}", wireguard_mark(index));
        let route_path = format!("/run/nfty-{}.route", iface);
        remove_ip_rule_or_route(&["rule", "del", "fwmark", &mark_hex, "table", &table_str])?;
        if let Some(src) = read_route_source(&route_path)? {
            remove_ip_rule_or_route(&["rule", "del", "from", &src, "table", &table_str])?;
        }
        remove_ip_rule_or_route(&["route", "flush", "table", &table_str])?;
        if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            run_ip(&["link", "del", "dev", iface])?;
        }
        if Path::new(&route_path).exists() {
            fs::remove_file(&route_path).with_context(|| format!("Cannot remove {}", route_path))?;
        }
        fs::remove_file(entry.path()).with_context(|| format!("Cannot remove {}", name))?;
        logs.push(format!("Removed managed WireGuard interface {}", iface));
    }
    Ok(logs)
}

/// Lists all `.conf` files saved in `/data/wg`.
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

/// Saves a Mullvad / WireGuard `.conf` file to `/data/wg/<name>`.
pub fn save_wg_config_file(name: &str, content: &str) -> Result<(String, ParsedWgConf)> {
    let parsed = parse_wg_conf_str(content)?;
    fs::create_dir_all("/data/wg").context("Failed to prepare WireGuard config directory")?;
    let filename = normalize_wg_filename(name)?;
    let full_path = Path::new("/data/wg").join(&filename);
    crate::unikernel::write_atomic(&full_path, content.as_bytes())
        .with_context(|| format!("Failed to write {}", full_path.display()))?;
    Ok((filename, parsed))
}

/// Interactive line-by-line paste mode for a WireGuard config (`wg add <name>`).
pub fn paste_wg_config_interactive(name: &str) -> Result<Option<String>> {
    use std::io::{self, BufRead};
    crate::repl::require_interactive_terminal(
        "Pasting a WireGuard config (upload it via POST /api/v1/wg instead)",
    )?;
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

/// Handles `wg` config-file subcommands: `wg [list]`, `wg add <name>` (paste, terminal only), `wg show <name>`, `wg rm <name>`.
pub fn handle_wg_cli_command(args: &[&str]) -> Result<Option<String>> {
    if args.is_empty() || args[0].eq_ignore_ascii_case("list") {
        let saved = list_saved_wg_configs();
        println!("{}", "Saved WireGuard Configs (/data/wg/):".bold().cyan());
        if saved.is_empty() {
            println!(
                "  {}",
                "(none — run 'wg add <name>' to paste a config, or POST /api/v1/wg)".dimmed()
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
            "Tip: 'wg add <name>', 'wg show <name>', 'wg rm <name>'".dimmed()
        );
        return Ok(None);
    }

    match args[0].to_ascii_lowercase().as_str() {
        "add" => {
            if args.len() < 2 {
                bail!("Usage: wg add <name> (e.g. 'wg add mullvad-us-sea-001')");
            }
            paste_wg_config_interactive(args[1])
        }
        "show" => {
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
        "rm" => {
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
        other => bail!(
            "Unknown wg subcommand '{}' (expected: list, add <name>, show <name>, rm <name>, peer ...)",
            other
        ),
    }
}
/// Probes a WireGuard tunnel interface (`wg0`, `wg1`, ...) via `ping -I <iface> 1.1.1.1`.
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
