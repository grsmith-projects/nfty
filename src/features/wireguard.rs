use crate::ast::{Config, WgTunnel};
use crate::state::HealthState;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

pub(crate) fn wireguard_iface_index(iface: &str) -> Option<usize> {
    let suffix = iface.strip_prefix("wg")?;
    if suffix.is_empty() || iface.len() > 15 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<usize>().ok().filter(|n| *n <= 1_999_999)
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
    if cfg.gateways.values().any(|g| !g.tunnels.is_empty()) {
        fs::create_dir_all("/data/wg").context("Cannot prepare WireGuard config directory")?;
        fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "2\n")
            .context("Cannot configure WireGuard reverse-path filtering")?;
        fs::write("/proc/sys/net/ipv4/conf/default/rp_filter", "2\n")
            .context("Cannot configure default reverse-path filtering")?;
    }

    let mut active_wg_ifaces = std::collections::BTreeSet::new();
    let mut global_idx = 0usize;
    for gw in cfg.gateways.values() {
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

/// Opens `nano` (or `vi`) on `/data/wg/<name>.conf` so the user can paste/edit any WireGuard config.
pub fn edit_wg_config_interactive(
    name: &str,
    preferred_editor: Option<&str>,
) -> Result<Option<String>> {
    fs::create_dir_all("/data/wg").context("Failed to prepare WireGuard config directory")?;
    let filename = normalize_wg_filename(name)?;
    let full_path = Path::new("/data/wg").join(&filename);
    let existed_before = full_path.exists();

    let template = format!(
        "# WireGuard configuration: {}\n# Paste your [Interface] and [Peer] blocks below, then save (Ctrl+O, Enter, Ctrl+X in nano).\n\n",
        filename
    );
    if !existed_before {
        crate::unikernel::write_atomic(&full_path, template.as_bytes())?;
    } else {
        let metadata = fs::symlink_metadata(&full_path)
            .with_context(|| format!("Cannot inspect {}", full_path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("WireGuard config '{}' is not a regular file", full_path.display());
        }
        fs::set_permissions(&full_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Cannot secure {}", full_path.display()))?;
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
        .env(
            "TERM",
            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        )
        .env("TERMINFO", "/usr/share/terminfo")
        .status()
        .with_context(|| format!("Failed to launch editor '{}'", editor))?;

    fs::set_permissions(&full_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Cannot secure {}", full_path.display()))?;
    if !status.success() {
        bail!("Editor '{}' exited with non-zero status", editor);
    }

    let raw = fs::read_to_string(&full_path)
        .with_context(|| format!("Cannot read {}", full_path.display()))?;
    let non_comment_lines: usize = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .count();

    if non_comment_lines == 0 {
        if !existed_before {
            fs::remove_file(&full_path)
                .with_context(|| format!("Cannot remove {}", full_path.display()))?;
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

/// Interactive line-by-line paste mode for a WireGuard config (`wg paste <name>`).
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

/// Handles `wg ...` CLI subcommands (`wg`, `wg add <name>`, `wg edit <name>`, `wg vi <name>`, `wg paste <name>`, `wg show <name>`, `wg rm <name>`).
pub fn handle_wg_cli_command(args: &[&str]) -> Result<Option<String>> {
    if args.is_empty()
        || args[0].eq_ignore_ascii_case("list")
        || args[0].eq_ignore_ascii_case("ls")
    {
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
                bail!(
                    "Usage: wg {} <name> (e.g. 'wg {} mullvad-us-sea-001')",
                    sub,
                    sub
                );
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
            // Treat `wg mullvad-us-sea-001` as `wg add mullvad-us-sea-001`
            edit_wg_config_interactive(args[0], Some("nano"))
        }
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
