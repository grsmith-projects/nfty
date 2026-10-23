use crate::ast::{Config, Gateway, Service};
use crate::compiler::{
    apply_vip_commands, compile_nft_ruleset, generate_vip_commands, reconcile_dhcp_and_vlan_vips,
    reload_kernel_from_state, validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once};
use crate::parser::{
    apply_gateway_directive, apply_service_directive, create_or_find_vip_service_by_key,
    parse_backend, parse_gateway_service, parse_ip_and_optional_cidr, parse_nftyfile,
    parse_service_spec, parse_vip, parse_vip_header, parse_vlan_id, parse_wg_tunnel,
    remove_backend_from_service, validate_allow_entry,
};
use crate::state::{HealthState, PendingConfirm, SharedState};
use crate::tui::run_watch_dashboard;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context as RlContext, Editor, Helper};
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellLevel {
    Operational,
    ConfigRoot,
    GlobalAllow,
    Vip(String),
    VipService(String),
    Service(String),
    ServiceTo(String),
    ServiceAllow(String),
    Gateway(String),
    GatewayTunnels(String),
    GatewayService(String),
}

impl ShellLevel {
    pub fn prompt(&self) -> String {
        match self {
            ShellLevel::Operational => "nfty> ".to_string(),
            ShellLevel::ConfigRoot => "nfty(config)# ".to_string(),
            ShellLevel::GlobalAllow => "nfty(config-allow)# ".to_string(),
            ShellLevel::Vip(k) => format!("nfty(config-vip:{})# ", k),
            ShellLevel::VipService(k) => format!("nfty(config-vip:{}-service)# ", k),
            ShellLevel::Service(k) => format!("nfty(config-service:{})# ", k),
            ShellLevel::ServiceTo(k) => format!("nfty(config-service:{}-to)# ", k),
            ShellLevel::ServiceAllow(k) => format!("nfty(config-service:{}-allow)# ", k),
            ShellLevel::Gateway(k) => format!("nfty(config-gateway:{})# ", k),
            ShellLevel::GatewayTunnels(k) => format!("nfty(config-gateway:{}-tunnels)# ", k),
            ShellLevel::GatewayService(k) => format!("nfty(config-gateway:{}-service)# ", k),
        }
    }
}

struct NftyHelper {
    level: Arc<Mutex<ShellLevel>>,
    state: SharedState,
}

impl NftyHelper {
    fn known_hosts(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        if let Ok(st) = self.state.read() {
            for h in st.resolved_hosts.keys() {
                set.insert(h.clone());
            }
            for d in &st.discovered_services {
                if let Some(h) = &d.host {
                    set.insert(h.clone());
                }
            }
            for svc in st.candidate.services.values() {
                for b in &svc.backends {
                    if let Some(h) = &b.host {
                        set.insert(h.clone());
                    }
                }
            }
        }
        if let Ok(raw) = fs::read_to_string("/etc/hosts") {
            for line in raw.lines() {
                let clean = line.split('#').next().unwrap_or("").trim();
                let mut parts = clean.split_whitespace();
                let _ = parts.next();
                for host in parts {
                    if !host.eq_ignore_ascii_case("localhost")
                        && !host.contains("ip6-")
                        && !host.is_empty()
                    {
                        set.insert(host.to_string());
                    }
                }
            }
        }
        set.into_iter().collect()
    }

    fn known_host_ports(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        if let Ok(st) = self.state.read() {
            for d in &st.discovered_services {
                set.insert(d.target_spec());
            }
            for svc in st.candidate.services.values() {
                for b in &svc.backends {
                    if !b.ip.is_loopback() {
                        set.insert(b.to_string());
                    }
                }
            }
        }
        for h in self.known_hosts() {
            set.insert(format!("{}:80", h));
        }
        set.into_iter().collect()
    }

    fn wg_conf_files(&self) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(entries) = fs::read_dir("/data/wg") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".conf") {
                    list.push(name);
                }
            }
        }
        list.sort();
        list
    }
}

impl Completer for NftyHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &RlContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let slice = &line[..pos];
        let words: Vec<&str> = slice.split_whitespace().collect();
        let trailing_space = slice.ends_with(' ');
        let prefix = if trailing_space {
            ""
        } else {
            words.last().copied().unwrap_or("")
        };
        let start_pos = pos - prefix.len();
        let word_idx = if trailing_space {
            words.len()
        } else {
            words.len().saturating_sub(1)
        };
        let cmd0 = words.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
        let cmd1 = words.get(1).map(|s| s.to_ascii_lowercase()).unwrap_or_default();

        // Global argument completions that apply at any shell level
        if word_idx == 1 {
            match cmd0.as_str() {
                "show" => {
                    let list = vec![
                        "running", "candidate", "all", "nft", "allow", "hosts", "vips",
                    ];
                    let matches = list
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.to_string(),
                            replacement: c.to_string(),
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "wg" | "wireguard" => {
                    let list = vec!["list", "add", "edit", "paste", "show", "rm", " status"];
                    let matches = list
                        .into_iter()
                        .map(|s| s.trim())
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.to_string(),
                            replacement: c.to_string(),
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "cf" | "cloudflare" => {
                    let list = vec![
                        "status",
                        "token",
                        "tunnel-token",
                        "sync",
                        "logs",
                        "stop",
                    ];
                    let matches = list
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.to_string(),
                            replacement: c.to_string(),
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "drain" | "enable" => {
                    let st = self.state.read().unwrap();
                    let mut eps = std::collections::BTreeSet::new();
                    for svc in st.running.services.values().chain(st.candidate.services.values()) {
                        for b in &svc.backends {
                            if !b.ip.is_loopback() {
                                eps.insert(b.endpoint());
                            }
                        }
                    }
                    let matches = eps
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.clone(),
                            replacement: c,
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "scan" => {
                    let mut list = self.known_hosts();
                    list.push("192.168.1.0/24".to_string());
                    let matches = list
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.clone(),
                            replacement: c,
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "adopt" => {
                    let st = self.state.read().unwrap();
                    let mut list = Vec::new();
                    for d in &st.discovered_services {
                        list.push(d.index.to_string());
                        list.push(d.suggested_vip_name());
                        list.push(d.target_spec());
                    }
                    let matches = list
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.clone(),
                            replacement: c,
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                "apply" | "commit" => {
                    let list = vec!["confirm 60".to_string(), "confirm 30".to_string()];
                    let matches = list
                        .into_iter()
                        .filter(|c| c.starts_with(prefix))
                        .map(|c| Pair {
                            display: c.clone(),
                            replacement: c,
                        })
                        .collect();
                    return Ok((start_pos, matches));
                }
                _ => {}
            }
        } else if word_idx == 2 && (cmd0 == "wg" || cmd0 == "wireguard") {
            let files = self.wg_conf_files();
            let matches = files
                .into_iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| Pair {
                    display: c.clone(),
                    replacement: c,
                })
                .collect();
            return Ok((start_pos, matches));
        } else if word_idx >= 2 && cmd0 == "adopt" {
            if words.get(word_idx.saturating_sub(1)).copied() == Some("vip") {
                let st = self.state.read().unwrap();
                let list: Vec<String> = st.candidate.vips.keys().cloned().collect();
                let matches = list
                    .into_iter()
                    .filter(|c| c.starts_with(prefix))
                    .map(|c| Pair {
                        display: c.clone(),
                        replacement: c,
                    })
                    .collect();
                return Ok((start_pos, matches));
            } else {
                let list = vec!["vip".to_string(), "port".to_string(), "vlan".to_string()];
                let matches = list
                    .into_iter()
                    .filter(|c| c.starts_with(prefix))
                    .map(|c| Pair {
                        display: c.clone(),
                        replacement: c,
                    })
                    .collect();
                return Ok((start_pos, matches));
            }
        }

        let lvl = self.level.lock().unwrap().clone();
        let candidates: Vec<String> = match (&lvl, word_idx) {
            (ShellLevel::Operational, 0) => vec![
                "scan",
                "adopt",
                "bootstrap",
                "configure",
                "status",
                "flows",
                "wg",
                "cf",
                "watch",
                "probe",
                "show",
                "drain",
                "enable",
                "password",
                "help",
                "exit",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            (ShellLevel::ConfigRoot, 0) => vec![
                "vip",
                "gateway",
                "service",
                "scan",
                "adopt",
                "bootstrap",
                "allow",
                "host",
                "no",
                "show",
                "flows",
                "wg",
                "cf",
                "diff",
                "test",
                "apply",
                "confirm",
                "rollback",
                "save",
                "load",
                "status",
                "watch",
                "probe",
                "password",
                "exit",
                "help",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            (ShellLevel::ConfigRoot, 1) if cmd0 == "vip" => {
                let st = self.state.read().unwrap();
                let mut list: Vec<String> = st.candidate.vips.keys().cloned().collect();
                for d in &st.discovered_services {
                    let s = d.suggested_vip_name();
                    if !list.contains(&s) {
                        list.push(s);
                    }
                }
                list
            }
            (ShellLevel::ConfigRoot, 1) if cmd0 == "gateway" => {
                let st = self.state.read().unwrap();
                st.candidate.gateways.keys().cloned().collect()
            }
            (ShellLevel::ConfigRoot, 1) if cmd0 == "service" => {
                let st = self.state.read().unwrap();
                st.candidate.services.keys().cloned().collect()
            }
            (ShellLevel::ConfigRoot, 1) if cmd0 == "no" => {
                vec![
                    "vip".to_string(),
                    "gateway".to_string(),
                    "service".to_string(),
                    "allow".to_string(),
                ]
            }
            (ShellLevel::ConfigRoot, 2) if cmd0 == "no" => {
                let st = self.state.read().unwrap();
                match cmd1.as_str() {
                    "vip" => st.candidate.vips.keys().cloned().collect(),
                    "gateway" => st.candidate.gateways.keys().cloned().collect(),
                    "service" => st.candidate.services.keys().cloned().collect(),
                    "allow" => st.candidate.global_allow.clone(),
                    _ => Vec::new(),
                }
            }
            (ShellLevel::Vip(vip_str), 0) | (ShellLevel::VipService(vip_str), 0) => {
                let st = self.state.read().unwrap();
                let mut list: Vec<String> = st
                    .candidate
                    .services
                    .values()
                    .filter(|s| s.belongs_to_vip(vip_str))
                    .map(|s| s.display_name())
                    .collect();
                for hp in self.known_host_ports() {
                    if !list.contains(&hp) {
                        list.push(hp);
                    }
                }
                for cmd in [
                    "80",
                    "443",
                    "ssh:22",
                    "dhcp",
                    "vlan",
                    "interface",
                    "cloudflare-dns",
                    "cloudflare-auth",
                    "auth",
                    "scan",
                    "adopt",
                    "no",
                    "show",
                    "diff",
                    "test",
                    "apply",
                    "top",
                    "..",
                    "up",
                    "exit",
                    "help",
                ] {
                    list.push(cmd.to_string());
                }
                list
            }
            (ShellLevel::Vip(_), 1) | (ShellLevel::VipService(_), 1)
                if cmd0.parse::<u16>().is_ok() || cmd0.contains('/') =>
            {
                vec!["to".to_string()]
            }
            (ShellLevel::Vip(_), 2) | (ShellLevel::VipService(_), 2) if cmd1 == "to" => {
                self.known_host_ports()
            }
            (ShellLevel::Vip(vip_str), 1) | (ShellLevel::VipService(vip_str), 1)
                if cmd0 == "no" =>
            {
                let st = self.state.read().unwrap();
                let mut list: Vec<String> = st
                    .candidate
                    .services
                    .values()
                    .filter(|s| s.belongs_to_vip(vip_str))
                    .map(|s| s.display_name())
                    .collect();
                list.push("vlan".to_string());
                list.push("dhcp".to_string());
                list.push("cloudflare-dns".to_string());
                list.push("cloudflare-auth".to_string());
                list.push("auth".to_string());
                list.push("ssh:22".to_string());
                list
            }
            (ShellLevel::Service(_), 0) => vec![
                "port",
                "proto",
                "to",
                "hostname",
                "cloudflare-dns",
                "cloudflare-auth",
                "auth",
                "balance",
                "mode",
                "interface",
                "vlan",
                "check",
                "limit",
                "allow",
                "no",
                "show",
                "diff",
                "test",
                "apply",
                "top",
                "..",
                "up",
                "exit",
                "help",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            (ShellLevel::Service(_), 1) if cmd0 == "to" => self.known_host_ports(),
            (ShellLevel::Service(_), 1) if cmd0 == "hostname" => self
                .known_hosts()
                .into_iter()
                .map(|h| {
                    if h.ends_with(".local") {
                        h
                    } else {
                        format!("{}.local", h)
                    }
                })
                .collect(),
            (ShellLevel::Service(_), 1) if cmd0 == "proto" => {
                vec!["tcp".to_string(), "udp".to_string(), "both".to_string()]
            }
            (ShellLevel::Service(_), 1) if cmd0 == "balance" => {
                vec!["round-robin".to_string(), "sticky".to_string()]
            }
            (ShellLevel::Service(_), 1) if cmd0 == "mode" => {
                vec!["nat".to_string(), "transparent".to_string()]
            }
            (ShellLevel::Service(_), 1) if cmd0 == "check" => vec![
                "tcp 5s".to_string(),
                "http /healthz 5s".to_string(),
                "ping 5s".to_string(),
            ],
            (ShellLevel::Service(_), 1) if cmd0 == "limit" => vec![
                "100/sec per-ip".to_string(),
                "50/sec burst 100 per-ip".to_string(),
                "600/min per-ip".to_string(),
            ],
            (ShellLevel::Service(_), 1) if cmd0 == "cloudflare-auth" || cmd0 == "cf-auth" => vec![
                "*@smith.gr".to_string(),
                "you@email.com".to_string(),
            ],
            (ShellLevel::Service(_), 1) if cmd0 == "auth" => vec![
                "admin:password".to_string(),
                "nfty".to_string(),
            ],
            (ShellLevel::Service(k), 1) if cmd0 == "no" => {
                let mut list = vec![
                    "hostname".to_string(),
                    "cloudflare-dns".to_string(),
                    "cloudflare-auth".to_string(),
                    "auth".to_string(),
                    "check".to_string(),
                    "limit".to_string(),
                    "allow".to_string(),
                    "vlan".to_string(),
                    "to".to_string(),
                ];
                let st = self.state.read().unwrap();
                if let Some(svc) = st.candidate.services.get(k) {
                    for b in &svc.backends {
                        list.push(b.to_string());
                    }
                }
                list
            }
            (ShellLevel::Gateway(_), 0) => vec![
                "privoxy:8118",
                "socks5:1080",
                "ssh:22",
                "service",
                "tunnels",
                "tunnel",
                "dhcp",
                "vlan",
                "interface",
                "hostname",
                "balance",
                "killswitch",
                "check",
                "allow",
                "no",
                "show",
                "diff",
                "test",
                "apply",
                "top",
                "..",
                "up",
                "exit",
                "help",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            (ShellLevel::Gateway(_), 1) if cmd0 == "tunnel" || cmd0 == "tunnels" => {
                self.wg_conf_files()
            }
            (ShellLevel::Gateway(_), 1) if cmd0 == "balance" => {
                vec!["round-robin".to_string(), "sticky".to_string()]
            }
            (ShellLevel::Gateway(_), 1) if cmd0 == "killswitch" => {
                vec!["on".to_string(), "off".to_string()]
            }
            (ShellLevel::Gateway(gw_k), 1) if cmd0 == "no" => {
                let mut list = vec![
                    "privoxy".to_string(),
                    "socks5".to_string(),
                    "ssh".to_string(),
                    "killswitch".to_string(),
                    "hostname".to_string(),
                    "vlan".to_string(),
                ];
                let st = self.state.read().unwrap();
                if let Some(gw) = st.candidate.gateways.get(gw_k) {
                    for t in &gw.tunnels {
                        list.push(t.name.clone());
                    }
                }
                list
            }
            (ShellLevel::GatewayTunnels(_), 0) => {
                let mut list = self.wg_conf_files();
                for cmd in [
                    "add", "paste", "nano", "vi", "no", "show", "apply", "top", "..", "up", "exit",
                    "help",
                ] {
                    list.push(cmd.to_string());
                }
                list
            }
            (ShellLevel::GatewayService(_), 0) => vec![
                "privoxy:8118",
                "socks5:1080",
                "ssh:22",
                "no",
                "show",
                "top",
                "..",
                "up",
                "exit",
                "help",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            (ShellLevel::ServiceTo(k), 0) => {
                let st = self.state.read().unwrap();
                let mut list = self.known_host_ports();
                for cmd in ["..", "up", "top", "no", "show", "apply"] {
                    list.push(cmd.to_string());
                }
                if let Some(svc) = st.candidate.services.get(k) {
                    for b in &svc.backends {
                        list.push(b.endpoint());
                    }
                }
                list
            }
            (ShellLevel::ServiceAllow(_), 0) | (ShellLevel::GlobalAllow, 0) => {
                let mut list = self.known_hosts();
                for pat in [
                    "*.office.lan",
                    "192.168.1.*",
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "..",
                    "up",
                    "top",
                    "no",
                    "show",
                ] {
                    list.push(pat.to_string());
                }
                list
            }
            _ => Vec::new(),
        };

        let matches: Vec<Pair> = candidates
            .into_iter()
            .filter(|c| c.starts_with(prefix))
            .map(|c| Pair {
                display: c.clone(),
                replacement: c,
            })
            .collect();

        Ok((start_pos, matches))
    }
}

impl Hinter for NftyHelper {
    type Hint = String;
}
impl Highlighter for NftyHelper {}
impl Validator for NftyHelper {}
impl Helper for NftyHelper {}

pub async fn run_repl(shared: SharedState) -> Result<()> {
    let level = Arc::new(Mutex::new(ShellLevel::Operational));
    let helper = NftyHelper {
        level: level.clone(),
        state: shared.clone(),
    };

    let mut rl = Editor::new()?;
    rl.set_helper(Some(helper));

    let api_bind = shared.read().unwrap().api_bind.clone();
    println!(
        "{}",
        "Welcome to nfty — Caddy-style L4 Service Load Balancer & Port Router for nftables"
            .bold()
            .cyan()
    );
    println!(
        "1:1 Control API listening on {} (endpoints: /api/v1/allow, /api/v1/cli, /api/v1/status)",
        format!("http://{}", api_bind).green().bold()
    );
    println!(
        "Type {} to enter config mode, {} for live status, {} for live TUI, or {} for help.\n",
        "configure".yellow(),
        "status".green(),
        "watch".cyan(),
        "?".magenta()
    );

    loop {
        let current_level = level.lock().unwrap().clone();
        let prompt = current_level.prompt();

        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);

                let should_quit = handle_line(trimmed, &level, &shared).await;
                if should_quit {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                let mut lvl = level.lock().unwrap();
                match *lvl {
                    ShellLevel::Vip(_)
                    | ShellLevel::VipService(_)
                    | ShellLevel::ServiceTo(_)
                    | ShellLevel::ServiceAllow(_)
                    | ShellLevel::Service(_)
                    | ShellLevel::Gateway(_)
                    | ShellLevel::GatewayTunnels(_)
                    | ShellLevel::GatewayService(_)
                    | ShellLevel::GlobalAllow => {
                        *lvl = ShellLevel::ConfigRoot;
                        println!("^C (returned to config root)");
                    }
                    ShellLevel::ConfigRoot => {
                        *lvl = ShellLevel::Operational;
                        println!("^C (returned to operational mode)");
                    }
                    ShellLevel::Operational => {
                        println!("(Type 'exit' or Ctrl-D to quit)");
                    }
                }
            }
            Err(ReadlineError::Eof) => {
                println!("Exiting nfty.");
                break;
            }
            Err(err) => {
                eprintln!("Input error: {}", err);
                break;
            }
        }
    }

    Ok(())
}

pub async fn handle_line(
    line: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    {
        if let Ok(mut st) = shared.write() {
            st.sync_from_disk_if_changed();
        }
    }

    let cur_level = level.lock().unwrap().clone();
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let cmd = tokens[0].to_ascii_lowercase();

    match cmd.as_str() {
        "?" | "help" => {
            print_context_help(&cur_level);
            return false;
        }
        "quit" => return true,
        "bootstrap" => {
            if let Err(e) = handle_bootstrap(&tokens[1..], shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
            return false;
        }
        "password" | "passwd" => {
            if let Err(e) = crate::ssh::interactive_change_password(false) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
            return false;
        }
        ".." | "up" => {
            let mut lvl = level.lock().unwrap();
            *lvl = match &*lvl {
                ShellLevel::ServiceTo(k) | ShellLevel::ServiceAllow(k) => {
                    ShellLevel::Service(k.clone())
                }
                ShellLevel::Service(k) => {
                    if let Some((vip_part, _)) = k.split_once(':') {
                        ShellLevel::Vip(vip_part.to_string())
                    } else {
                        ShellLevel::ConfigRoot
                    }
                }
                ShellLevel::VipService(k) => ShellLevel::Vip(k.clone()),
                ShellLevel::GatewayTunnels(k) | ShellLevel::GatewayService(k) => {
                    ShellLevel::Gateway(k.clone())
                }
                ShellLevel::Vip(_) | ShellLevel::Gateway(_) | ShellLevel::GlobalAllow => {
                    ShellLevel::ConfigRoot
                }
                ShellLevel::ConfigRoot => ShellLevel::Operational,
                ShellLevel::Operational => ShellLevel::Operational,
            };
            return false;
        }
        "top" => {
            let mut lvl = level.lock().unwrap();
            if *lvl != ShellLevel::Operational {
                *lvl = ShellLevel::ConfigRoot;
            }
            return false;
        }
        "exit" | "end" => {
            let mut lvl = level.lock().unwrap();
            match &*lvl {
                ShellLevel::ServiceTo(k) | ShellLevel::ServiceAllow(k) => {
                    *lvl = ShellLevel::Service(k.clone());
                }
                ShellLevel::Service(k) => {
                    if let Some((vip_part, _)) = k.split_once(':') {
                        *lvl = ShellLevel::Vip(vip_part.to_string());
                    } else {
                        *lvl = ShellLevel::ConfigRoot;
                    }
                }
                ShellLevel::VipService(k) => {
                    *lvl = ShellLevel::Vip(k.clone());
                }
                ShellLevel::GatewayTunnels(k) | ShellLevel::GatewayService(k) => {
                    *lvl = ShellLevel::Gateway(k.clone());
                }
                ShellLevel::Vip(_) | ShellLevel::Gateway(_) | ShellLevel::GlobalAllow => {
                    *lvl = ShellLevel::ConfigRoot;
                }
                ShellLevel::ConfigRoot => {
                    *lvl = ShellLevel::Operational;
                }
                ShellLevel::Operational => return true,
            }
            return false;
        }
        "scan" | "discover" => {
            let filter = tokens.get(1).copied();
            println!(
                "{}",
                "Scanning LXD / LAN neighbors for active services...".cyan()
            );
            let discovered = crate::features::scan_network_services(filter, shared);
            crate::features::print_scan_table(&discovered, shared);
            return false;
        }
        "adopt" => {
            if let Err(e) = handle_adopt(&tokens[1..], level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
            return false;
        }
        "status" => {
            print_status_table(shared);
            return false;
        }
        "flows" | "conntrack" => {
            crate::features::print_flows_table(shared);
            return false;
        }
        "wg" | "wireguard" => {
            match crate::features::handle_wg_cli_command(&tokens[1..]) {
                Ok(Some(saved_filename)) => {
                    // If currently inside a gateway context, auto-add the newly created tunnel!
                    if let ShellLevel::Gateway(gw_key) | ShellLevel::GatewayTunnels(gw_key) = &cur_level {
                        let mut st = shared.write().unwrap();
                        if let Some(gw) = st.candidate.gateways.get_mut(gw_key) {
                            let next_idx = gw.tunnels.len();
                            if let Ok(t) = parse_wg_tunnel(&[saved_filename.as_str()], next_idx) {
                                if !gw.tunnels.iter().any(|x| x.name == t.name) {
                                    gw.tunnels.push(t);
                                    println!(
                                        "  {} Added tunnel {} to gateway {}",
                                        "✔".green().bold(),
                                        saved_filename.bold(),
                                        gw_key.cyan()
                                    );
                                }
                            }
                        }
                        st.sync_runtime_entries();
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
            }
            return false;
        }
        "cf" | "cloudflare"
            if tokens.len() == 1
                || matches!(
                    tokens[1].to_ascii_lowercase().as_str(),
                    "status"
                        | "token"
                        | "api-token"
                        | "key"
                        | "tunnel-token"
                        | "connector-token"
                        | "sync"
                        | "reconcile"
                        | "logs"
                        | "log"
                        | "stop"
                        | "clear"
                        | "off"
                )
                || matches!(cur_level, ShellLevel::Operational | ShellLevel::ConfigRoot) =>
        {
            if let Err(e) = crate::features::handle_cf_cli_command(&tokens[1..], shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
            return false;
        }
        "watch" => {
            if let Err(e) = run_watch_dashboard(shared.clone()).await {
                eprintln!("{} {}", "Error in watch TUI:".red().bold(), e);
            }
            return false;
        }
        "probe" => {
            println!("Running active health checks across all backends...");
            let outcomes = run_all_probes_once(shared).await;
            if outcomes.is_empty() {
                println!("  (No backends configured yet)");
            } else {
                for o in outcomes {
                    match o.state {
                        HealthState::Up => {
                            let ms = o.latency_ms.unwrap_or(0.0);
                            println!(
                                "  {} {} -> {} ({:.2}ms)",
                                "✔".green().bold(),
                                o.endpoint.bold(),
                                "UP".green().bold(),
                                ms
                            );
                        }
                        _ => {
                            println!(
                                "  {} {} -> {} ({})",
                                "✖".red().bold(),
                                o.endpoint.bold(),
                                "DOWN".red().bold(),
                                o.error.unwrap_or_else(|| "unreachable".to_string())
                            );
                        }
                    }
                }
            }
            return false;
        }
        "host" => {
            if let Err(e) = handle_host_mapping(&tokens[1..], shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
            return false;
        }
        "drain" => {
            if tokens.len() < 2 {
                eprintln!("Usage: drain <ip:port>");
            } else {
                set_drain_state(shared, tokens[1], true);
            }
            return false;
        }
        "enable" => {
            if tokens.len() < 2 {
                eprintln!("Usage: enable <ip:port>");
            } else {
                set_drain_state(shared, tokens[1], false);
            }
            return false;
        }
        "show" => {
            handle_show(&tokens[1..], &cur_level, shared);
            return false;
        }
        "diff" | "compare" => {
            print_config_diff(shared);
            return false;
        }
        "test" | "validate" | "check-config" => {
            handle_validate(shared);
            return false;
        }
        "apply" | "commit" => {
            handle_apply(&tokens[1..], shared).await;
            return false;
        }
        "confirm" | "keep" => {
            handle_confirm(shared);
            return false;
        }
        "rollback" => {
            handle_rollback(&tokens[1..], shared);
            return false;
        }
        "save" => {
            handle_save(&tokens[1..], shared);
            return false;
        }
        "load" => {
            handle_load(&tokens[1..], shared);
            return false;
        }
        _ => {}
    }

    match cur_level {
        ShellLevel::Operational => match cmd.as_str() {
            "configure" | "conf" | "config" | "edit" => {
                *level.lock().unwrap() = ShellLevel::ConfigRoot;
            }
            "vip" | "service" | "gateway" | "allow" => {
                *level.lock().unwrap() = ShellLevel::ConfigRoot;
                if let Err(e) = handle_config_root_command(trimmed, level, shared) {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                }
            }
            _ => {
                eprintln!(
                    "{} Unknown command '{}'. Type {} to enter configuration mode or {} for help.",
                    "Error:".red().bold(),
                    cmd,
                    "configure".yellow(),
                    "?".magenta()
                );
            }
        },
        ShellLevel::ConfigRoot => {
            if let Err(e) = handle_config_root_command(trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::GlobalAllow => {
            if let Err(e) = handle_global_allow_command(trimmed, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::Vip(vip_key) => {
            if let Err(e) = handle_vip_level_command(&vip_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::VipService(vip_key) => {
            if let Err(e) = handle_vip_service_command(&vip_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::Service(svc_key) => {
            if let Err(e) = handle_service_level_command(&svc_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::ServiceTo(svc_key) => {
            if let Err(e) = handle_service_to_command(&svc_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::ServiceAllow(svc_key) => {
            if let Err(e) = handle_service_allow_command(&svc_key, trimmed, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::Gateway(gw_key) => {
            if let Err(e) = handle_gateway_level_command(&gw_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::GatewayTunnels(gw_key) => {
            if let Err(e) = handle_gateway_tunnels_command(&gw_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
        ShellLevel::GatewayService(gw_key) => {
            if let Err(e) = handle_gateway_service_command(&gw_key, trimmed, level, shared) {
                eprintln!("{} {}", "Error:".red().bold(), e);
            }
        }
    }

    false
}

fn handle_host_mapping(args: &[&str], shared: &SharedState) -> Result<()> {
    if args.len() < 2 {
        bail!("Usage: host <hostname> <ipv4> [ipv4...] (e.g. 'host laptop.office.lan 192.168.1.77')");
    }
    let host = args[0].trim().to_ascii_lowercase();
    let mut ips = Vec::new();
    for a in &args[1..] {
        let ip: Ipv4Addr = a
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}'", a))?;
        ips.push(ip);
    }
    let mut st = shared.write().unwrap();
    st.resolved_hosts.insert(host.clone(), ips.clone());
    if let Some(&first_ip) = ips.first() {
        let st_ref = &mut *st;
        for svc in st_ref
            .running
            .services
            .values_mut()
            .chain(st_ref.candidate.services.values_mut())
        {
            for b in &mut svc.backends {
                if b.host.as_deref() == Some(host.as_str()) {
                    b.ip = first_ip;
                }
            }
        }
    }
    st.sync_runtime_entries();
    if !st.running.services.is_empty() {
        let _ = reload_kernel_from_state(&mut st);
    }
    println!(
        "  {} Mapped host {} -> {:?} (and updated wildcard allow-lists)",
        "✔".green().bold(),
        host.bold(),
        ips
    );
    Ok(())
}

/// Bootstraps one or more Virtual IPs (`bootstrap <ip[/prefix]> [ip2...] [dev <iface>]`):
/// - Configures `<ip>` as a VIP on `eth0/24` (or specified prefix/interface)
/// - Creates a base SSH service block (`service <ip>:22`) allowing SSH to that IP
/// - Applies the VIP and ruleset so you can bootstrap as many IPs as you want
pub fn handle_bootstrap(args: &[&str], shared: &SharedState) -> Result<()> {
    if args.is_empty() {
        bail!("Usage: bootstrap <ip[/prefix]> [ip2...] (e.g. 'bootstrap 192.168.4.250')");
    }

    let mut iface = "eth0".to_string();
    let mut ip_specs = Vec::new();
    let mut idx = 0;
    while idx < args.len() {
        if matches!(args[idx].to_ascii_lowercase().as_str(), "dev" | "interface") {
            idx += 1;
            if idx >= args.len() {
                bail!("Expected interface name after 'dev'");
            }
            iface = args[idx].to_string();
        } else if args[idx].chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
            iface = args[idx].to_string();
        } else {
            ip_specs.push(args[idx]);
        }
        idx += 1;
    }

    if ip_specs.is_empty() {
        bail!("Expected at least one IPv4 address to bootstrap (e.g. 'bootstrap 192.168.4.250')");
    }

    let mut parsed_targets = Vec::new();
    for spec in ip_specs {
        let (ip_str, prefix_len) = if let Some((l, r)) = spec.split_once('/') {
            let p: u8 = r
                .parse()
                .with_context(|| format!("Invalid prefix length '{}'", r))?;
            if p == 0 || p > 32 {
                bail!("Prefix length must be between 1 and 32");
            }
            (l, p)
        } else {
            (spec, 24u8)
        };
        let ip: Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}'", ip_str))?;
        parsed_targets.push((ip, prefix_len));
    }

    let vip_logs;
    {
        let mut st = shared.write().unwrap();
        let prev_running = st.running.clone();

        for (ip, prefix_len) in &parsed_targets {
            let vip_cfg = crate::ast::VipConfig::new(&iface, *prefix_len);
            st.candidate.vips.insert(ip.to_string(), vip_cfg.clone());
            let key = format!("{}:22", ip);
            let mut svc = Service::new(key.clone(), Some(*ip), 22, crate::ast::Proto::Tcp);
            svc.name = Some("ssh:22".to_string());
            svc.vip = Some(vip_cfg);
            svc.check = Some(crate::ast::HealthCheckConfig {
                kind: crate::ast::HealthCheckKind::Tcp,
                interval_secs: 5,
            });
            svc.limit = Some(crate::ast::RateLimit {
                rate: 30,
                unit: crate::ast::RateUnit::Minute,
                burst: Some(10),
                per_ip: true,
            });
            svc.backends.push(crate::ast::Backend {
                host: None,
                ip: Ipv4Addr::new(127, 0, 0, 1),
                port: 22,
                weight: 1,
                backup: false,
            });

            st.candidate.services.insert(key, svc);
        }

        let vip_cmds = generate_vip_commands(&prev_running, &st.candidate);
        vip_logs = apply_vip_commands(&vip_cmds);

        st.history.push(prev_running);
        st.running = st.candidate.clone();
        st.sync_runtime_entries();
        let _ = reload_kernel_from_state(&mut st);
    }

    crate::unikernel::persist_to_storage(shared);

    for (ip, prefix_len) in parsed_targets {
        println!(
            "  {} Bootstrapped VIP {}/{} on {} (created base config 'service {}:22' with SSH enabled)",
            "✔".green().bold(),
            ip.to_string().bold().cyan(),
            prefix_len,
            iface.yellow(),
            ip
        );
    }
    for log in vip_logs {
        println!("  {} {}", "→".cyan(), log);
    }

    Ok(())
}

fn handle_config_root_command(
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    if trimmed.contains('{') && trimmed.ends_with('}') {
        let parsed = parse_nftyfile(trimmed)?;
        let mut st = shared.write().unwrap();
        for g in parsed.global_allow {
            if !st.candidate.global_allow.contains(&g) {
                st.candidate.global_allow.push(g);
            }
        }
        for (k, v) in parsed.vips {
            println!("  {} Updated vip {}", "✔".green().bold(), k.bold());
            st.candidate.vips.insert(k, v);
        }
        for (k, svc) in parsed.services {
            println!("  {} Updated service {}", "✔".green().bold(), k.bold());
            st.candidate.services.insert(k, svc);
        }
        for (k, gw) in parsed.gateways {
            println!("  {} Updated gateway {}", "✔".green().bold(), k.bold());
            st.candidate.gateways.insert(k, gw);
        }
        st.sync_runtime_entries();
        return Ok(());
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    match tokens[0].to_ascii_lowercase().as_str() {
        "allow" => {
            if tokens.len() == 1 {
                *level.lock().unwrap() = ShellLevel::GlobalAllow;
            } else {
                handle_global_allow_command(&tokens[1..].join(" "), shared)?;
            }
            Ok(())
        }
        "vip" => {
            if tokens.len() < 2 {
                bail!("Usage: vip <ipv4[/cidr] | hostname> [dhcp [iface]] [vlan <id>] (e.g. 'vip 192.168.1.4' or 'vip sonarr')");
            }
            let (key, _ip_opt, parsed_vip) = parse_vip_header(&tokens[1..])?;
            {
                let mut st = shared.write().unwrap();
                let entry = st
                    .candidate
                    .vips
                    .entry(key.clone())
                    .or_insert_with(|| parsed_vip.clone());
                if parsed_vip.dhcp {
                    entry.dhcp = true;
                }
                if parsed_vip.vlan.is_some() {
                    entry.vlan = parsed_vip.vlan;
                }
                if tokens[1].contains('/') {
                    entry.prefix_len = parsed_vip.prefix_len;
                }
                if parsed_vip.interface != "eth0" {
                    entry.interface = parsed_vip.interface.clone();
                }
                let vip_cfg = entry.clone();
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(&key))
                {
                    s.vip = Some(vip_cfg.clone());
                }
            }
            // Check if there are trailing service/ssh commands after header options
            let mut idx = 2;
            while idx < tokens.len() {
                match tokens[idx].to_ascii_lowercase().as_str() {
                    "dhcp" => {
                        idx += 1;
                        if idx < tokens.len()
                            && !matches!(
                                tokens[idx].to_ascii_lowercase().as_str(),
                                "vlan" | "service" | "services" | "ssh"
                            )
                            && !tokens[idx].starts_with("ssh:")
                        {
                            idx += 1;
                        }
                    }
                    "vlan" | "dev" | "interface" | "vip" => {
                        idx += 2;
                    }
                    _ => break,
                }
            }
            if idx >= tokens.len() {
                *level.lock().unwrap() = ShellLevel::Vip(key);
            } else {
                let rest = tokens[idx..].join(" ");
                handle_vip_level_command(&key, &rest, level, shared)?;
            }
            Ok(())
        }
        "gateway" => {
            if tokens.len() < 2 {
                bail!("Usage: gateway <ipv4[/cidr] | hostname> [dhcp [iface]] [vlan <id>] (e.g. 'gateway 192.168.1.10' or 'gateway mullvad')");
            }
            let (key, ip_opt, parsed_vip) = parse_vip_header(&tokens[1..])?;
            {
                let mut st = shared.write().unwrap();
                let gw = st.candidate.gateways.entry(key.clone()).or_insert_with(|| {
                    if let Some(ip) = ip_opt {
                        Gateway::new(ip)
                    } else {
                        Gateway::new_named(
                            key.clone(),
                            Ipv4Addr::UNSPECIFIED,
                            parsed_vip.clone(),
                        )
                    }
                });
                let entry = gw.vip.get_or_insert_with(|| parsed_vip.clone());
                if parsed_vip.dhcp {
                    entry.dhcp = true;
                }
                if parsed_vip.vlan.is_some() {
                    entry.vlan = parsed_vip.vlan;
                }
                if tokens[1].contains('/') {
                    entry.prefix_len = parsed_vip.prefix_len;
                }
                if parsed_vip.interface != "eth0" {
                    entry.interface = parsed_vip.interface.clone();
                }
            }
            let mut idx = 2;
            while idx < tokens.len() {
                match tokens[idx].to_ascii_lowercase().as_str() {
                    "dhcp" => {
                        idx += 1;
                        if idx < tokens.len()
                            && !matches!(
                                tokens[idx].to_ascii_lowercase().as_str(),
                                "vlan" | "service" | "services" | "tunnel" | "tunnels"
                            )
                        {
                            idx += 1;
                        }
                    }
                    "vlan" | "dev" | "interface" | "vip" => {
                        idx += 2;
                    }
                    _ => break,
                }
            }
            if idx >= tokens.len() {
                *level.lock().unwrap() = ShellLevel::Gateway(key);
            } else {
                let rest = tokens[idx..].join(" ");
                let mut st = shared.write().unwrap();
                if let Some(gw) = st.candidate.gateways.get_mut(&key) {
                    apply_gateway_directive(gw, &rest)?;
                    println!(
                        "  {} Updated gateway {}: {}",
                        "✔".green().bold(),
                        key.bold(),
                        rest
                    );
                }
                st.sync_runtime_entries();
            }
            Ok(())
        }
        "service" => {
            if tokens.len() < 2 {
                bail!("Usage: service <port | ip:port[/proto]> (e.g. 'service 9000' or 'service 192.168.1.240:443')");
            }
            let (key, listen_ip, port, proto) = parse_service_spec(tokens[1])?;
            {
                let mut st = shared.write().unwrap();
                st.candidate
                    .services
                    .entry(key.clone())
                    .or_insert_with(|| Service::new(key.clone(), listen_ip, port, proto));
            }
            if tokens.len() == 2 {
                *level.lock().unwrap() = ShellLevel::Service(key);
            } else {
                let rest = tokens[2..].join(" ");
                let mut st = shared.write().unwrap();
                if let Some(svc) = st.candidate.services.get_mut(&key) {
                    apply_service_directive(svc, &rest)?;
                    println!(
                        "  {} Updated service {}: {}",
                        "✔".green().bold(),
                        key.bold(),
                        rest
                    );
                }
                st.sync_runtime_entries();
            }
            Ok(())
        }
        "no" | "delete" | "remove" => {
            if tokens.len() < 2 {
                bail!("Usage: no <vip|gateway|service|allow> <target>");
            }
            if tokens[1].eq_ignore_ascii_case("allow") {
                let mut st = shared.write().unwrap();
                if tokens.len() == 2 {
                    st.candidate.global_allow.clear();
                    println!("  {} Cleared global allow-list", "✔".green().bold());
                } else {
                    let target =
                        validate_allow_entry(tokens[2]).unwrap_or_else(|_| tokens[2].to_string());
                    st.candidate.global_allow.retain(|x| x != &target);
                    println!(
                        "  {} Removed {} from global allow-list",
                        "✔".green().bold(),
                        target.bold()
                    );
                }
                return Ok(());
            }
            if tokens[1].eq_ignore_ascii_case("vip") {
                if tokens.len() < 3 {
                    bail!("Usage: no vip <ipv4_or_name>");
                }
                let (key, _, _) = parse_vip_header(&tokens[2..])?;
                let mut st = shared.write().unwrap();
                let removed_vip = st.candidate.vips.remove(&key).is_some();
                let before_svcs = st.candidate.services.len();
                st.candidate
                    .services
                    .retain(|_, s| !s.belongs_to_vip(&key));
                if removed_vip || st.candidate.services.len() < before_svcs {
                    println!(
                        "  {} Removed VIP {} and its attached services",
                        "✔".green().bold(),
                        key.bold()
                    );
                } else {
                    bail!("VIP '{}' not found in candidate config", key);
                }
                return Ok(());
            }
            if tokens[1].eq_ignore_ascii_case("gateway") {
                if tokens.len() < 3 {
                    bail!("Usage: no gateway <ipv4_or_name>");
                }
                let (key, _, _) = parse_vip_header(&tokens[2..])?;
                let mut st = shared.write().unwrap();
                if st.candidate.gateways.remove(&key).is_some() {
                    println!("  {} Removed gateway {}", "✔".green().bold(), key.bold());
                } else {
                    bail!("Gateway '{}' not found in candidate config", key);
                }
                return Ok(());
            }
            let target_raw = if tokens[1].eq_ignore_ascii_case("service") {
                if tokens.len() < 3 {
                    bail!("Usage: no service <port | ip:port>");
                }
                tokens[2]
            } else {
                tokens[1]
            };
            let (key, _, _, _) = parse_service_spec(target_raw)?;
            let mut st = shared.write().unwrap();
            if st.candidate.services.remove(&key).is_some() {
                println!("  {} Removed service {}", "✔".green().bold(), key.bold());
            } else {
                bail!("Service '{}' not found in candidate config", key);
            }
            Ok(())
        }
        _ => {
            if tokens[0].starts_with(':')
                || tokens[0]
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                let (key, listen_ip, port, proto) = parse_service_spec(tokens[0])?;
                {
                    let mut st = shared.write().unwrap();
                    st.candidate
                        .services
                        .entry(key.clone())
                        .or_insert_with(|| Service::new(key.clone(), listen_ip, port, proto));
                }
                *level.lock().unwrap() = ShellLevel::Service(key);
                Ok(())
            } else {
                bail!(
                    "Unknown config command '{}'. Type 'service <port>' (e.g. 'service 9000'), 'allow', or '?' for help.",
                    tokens[0]
                )
            }
        }
    }
}

fn handle_global_allow_command(trimmed: &str, shared: &SharedState) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    let first_lower = tokens[0].to_ascii_lowercase();
    let mut st = shared.write().unwrap();
    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <host|wildcard|cidr>");
        }
        let target = validate_allow_entry(tokens[1]).unwrap_or_else(|_| tokens[1].to_string());
        let before = st.candidate.global_allow.len();
        st.candidate.global_allow.retain(|x| x != &target);
        if st.candidate.global_allow.len() < before {
            println!(
                "  {} Removed {} from global allow-list",
                "✔".green().bold(),
                target.bold()
            );
        } else {
            bail!("'{}' not found in global allow-list", target);
        }
        return Ok(());
    }

    for tok in tokens {
        let entry = validate_allow_entry(tok)?;
        if !st.candidate.global_allow.contains(&entry) {
            st.candidate.global_allow.push(entry.clone());
            println!(
                "  {} Added {} to global allow-list",
                "✔".green().bold(),
                entry.bold()
            );
        }
    }
    Ok(())
}

fn handle_vip_level_command(
    vip_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    let first_lower = tokens[0].to_ascii_lowercase();

    match first_lower.as_str() {
        "service" | "services" => {
            if tokens.len() == 1 {
                *level.lock().unwrap() = ShellLevel::VipService(vip_key.to_string());
                return Ok(());
            } else {
                return handle_vip_service_command(
                    vip_key,
                    &tokens[1..].join(" "),
                    level,
                    shared,
                );
            }
        }
        "dhcp" => {
            let mut st = shared.write().unwrap();
            let entry = st
                .candidate
                .vips
                .entry(vip_key.to_string())
                .or_insert_with(|| crate::ast::VipConfig::new("eth0", 32));
            if tokens.len() >= 2
                && matches!(
                    tokens[1].to_ascii_lowercase().as_str(),
                    "off" | "false" | "no"
                )
            {
                entry.dhcp = false;
            } else {
                entry.dhcp = true;
                if tokens.len() >= 2
                    && !matches!(
                        tokens[1].to_ascii_lowercase().as_str(),
                        "on" | "true" | "yes"
                    )
                {
                    let parsed = parse_vip(tokens[1])?;
                    entry.interface = parsed.interface;
                    if parsed.vlan.is_some() {
                        entry.vlan = parsed.vlan;
                    }
                }
            }
            let updated = entry.clone();
            for s in st
                .candidate
                .services
                .values_mut()
                .filter(|s| s.belongs_to_vip(vip_key))
            {
                s.vip = Some(updated.clone());
            }
            println!(
                "  {} [vip {}] {}",
                "✔".green().bold(),
                vip_key.cyan(),
                updated
            );
            return Ok(());
        }
        "vlan" => {
            if tokens.len() < 2 {
                bail!("Expected VLAN ID (1-4094) after 'vlan' (e.g. 'vlan 20')");
            }
            let vid = parse_vlan_id(tokens[1])?;
            let mut st = shared.write().unwrap();
            let entry = st
                .candidate
                .vips
                .entry(vip_key.to_string())
                .or_insert_with(|| crate::ast::VipConfig::new("eth0", 24));
            entry.vlan = Some(vid);
            let updated = entry.clone();
            for s in st
                .candidate
                .services
                .values_mut()
                .filter(|s| s.belongs_to_vip(vip_key))
            {
                s.vip = Some(updated.clone());
            }
            println!(
                "  {} [vip {}] vlan {} ({})",
                "✔".green().bold(),
                vip_key.cyan(),
                vid,
                updated
            );
            return Ok(());
        }
        "vip" | "interface" | "dev" => {
            if tokens.len() < 2 {
                bail!("Expected interface[/prefix] (e.g. 'vip eth0/21')");
            }
            if let Ok((other_ip, _)) = parse_ip_and_optional_cidr(tokens[1]) {
                let _ = other_ip;
                return handle_config_root_command(trimmed, level, shared);
            }
            let mut v = parse_vip(tokens[1])?;
            let mut st = shared.write().unwrap();
            if let Some(existing) = st.candidate.vips.get(vip_key) {
                v.dhcp = existing.dhcp;
                v.leased_ip = existing.leased_ip;
                if v.vlan.is_none() {
                    v.vlan = existing.vlan;
                }
            }
            st.candidate.vips.insert(vip_key.to_string(), v.clone());
            for s in st
                .candidate
                .services
                .values_mut()
                .filter(|s| s.belongs_to_vip(vip_key))
            {
                s.vip = Some(v.clone());
            }
            println!(
                "  {} [vip {}] interface {}",
                "✔".green().bold(),
                vip_key.cyan(),
                v
            );
            return Ok(());
        }
        "ssh" | "local" => {
            let spec = if first_lower == "local" {
                tokens.get(1).copied().unwrap_or("ssh:22")
            } else if tokens.len() >= 2 && tokens[1].parse::<u16>().is_ok() {
                &format!("ssh:{}", tokens[1])
            } else {
                "ssh:22"
            };
            let mut st = shared.write().unwrap();
            let _ = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, spec)?;
            st.sync_runtime_entries();
            println!(
                "  {} [vip {}] + {}",
                "✔".green().bold(),
                vip_key.cyan(),
                spec.bold()
            );
            return Ok(());
        }
        _ if first_lower.starts_with("ssh:") => {
            let mut st = shared.write().unwrap();
            let _ = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, tokens[0])?;
            st.sync_runtime_entries();
            println!(
                "  {} [vip {}] + {}",
                "✔".green().bold(),
                vip_key.cyan(),
                tokens[0].bold()
            );
            return Ok(());
        }
        "gateway" => {
            return handle_config_root_command(trimmed, level, shared);
        }
        "cloudflare-dns"
        | "cloudflare"
        | "cf"
        | "tunnel-dns"
        | "cloudflare-auth"
        | "cf-auth"
        | "tunnel-auth"
        | "auth" => {
            if tokens.len() < 2 {
                bail!(
                    "Expected argument after '{}' (e.g. 'cloudflare-dns sonarr.domain.com' or 'cloudflare-auth nfty')",
                    tokens[0]
                );
            }
            let target_svc_key = {
                let st = shared.read().unwrap();
                let mut candidates: Vec<&Service> = st
                    .candidate
                    .services
                    .values()
                    .filter(|s| s.belongs_to_vip(vip_key) && s.name.as_deref() != Some("ssh"))
                    .collect();
                candidates.sort_by_key(|s| {
                    if s.cloudflare.is_some() {
                        0
                    } else if s.port == 80 || s.port == 443 {
                        1
                    } else {
                        2
                    }
                });
                candidates.first().map(|s| s.key.clone())
            };
            if let Some(svc_k) = target_svc_key {
                return handle_service_level_command(&svc_k, trimmed, level, shared);
            } else {
                bail!(
                    "Add a service to vip {} first (e.g. '80 to sonarr:8989') before setting {}.",
                    vip_key,
                    tokens[0]
                );
            }
        }
        "no" | "delete" | "remove" => {
            if tokens.len() < 2 {
                bail!("Usage: no <vlan | dhcp | cloudflare-dns | cloudflare-auth | ssh:22 | service <target>>");
            }
            if matches!(
                tokens[1].to_ascii_lowercase().as_str(),
                "cloudflare-dns" | "cloudflare" | "cf" | "tunnel-dns"
            ) {
                let mut st = shared.write().unwrap();
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(vip_key))
                {
                    s.cloudflare = None;
                }
                println!(
                    "  {} [vip {}] Removed cloudflare-dns",
                    "✔".green().bold(),
                    vip_key.cyan()
                );
                return Ok(());
            }
            if matches!(
                tokens[1].to_ascii_lowercase().as_str(),
                "cloudflare-auth" | "cf-auth" | "tunnel-auth"
            ) {
                let mut st = shared.write().unwrap();
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(vip_key))
                {
                    s.cloudflare_auth.clear();
                }
                println!(
                    "  {} [vip {}] Removed cloudflare-auth",
                    "✔".green().bold(),
                    vip_key.cyan()
                );
                return Ok(());
            }
            if matches!(
                tokens[1].to_ascii_lowercase().as_str(),
                "auth" | "basic-auth"
            ) {
                let mut st = shared.write().unwrap();
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(vip_key))
                {
                    s.auth.clear();
                }
                println!(
                    "  {} [vip {}] Removed auth",
                    "✔".green().bold(),
                    vip_key.cyan()
                );
                return Ok(());
            }
            if tokens[1].eq_ignore_ascii_case("vlan") {
                let mut st = shared.write().unwrap();
                if let Some(v) = st.candidate.vips.get_mut(vip_key) {
                    v.vlan = None;
                }
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(vip_key))
                {
                    if let Some(sv) = &mut s.vip {
                        sv.vlan = None;
                    }
                }
                println!("  {} [vip {}] Removed VLAN tag", "✔".green().bold(), vip_key.cyan());
                return Ok(());
            }
            if tokens[1].eq_ignore_ascii_case("dhcp") {
                let mut st = shared.write().unwrap();
                if let Some(v) = st.candidate.vips.get_mut(vip_key) {
                    v.dhcp = false;
                }
                for s in st
                    .candidate
                    .services
                    .values_mut()
                    .filter(|s| s.belongs_to_vip(vip_key))
                {
                    if let Some(sv) = &mut s.vip {
                        sv.dhcp = false;
                    }
                }
                println!("  {} [vip {}] Disabled DHCP", "✔".green().bold(), vip_key.cyan());
                return Ok(());
            }
            let target = if tokens[1].eq_ignore_ascii_case("service") {
                if tokens.len() < 3 {
                    bail!("Usage: no service <target>");
                }
                tokens[2]
            } else {
                tokens[1]
            };
            return handle_vip_service_command(
                vip_key,
                &format!("no {}", target),
                level,
                shared,
            );
        }
        _ => {
            // Allow typing a service target directly inside `vip <ip>` as a shortcut
            return handle_vip_service_command(vip_key, trimmed, level, shared);
        }
    }
}

fn handle_vip_service_command(
    vip_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    let first_lower = tokens[0].to_ascii_lowercase();

    if matches!(
        first_lower.as_str(),
        "vip" | "interface" | "dev" | "dhcp" | "vlan" | "gateway"
    ) {
        *level.lock().unwrap() = ShellLevel::Vip(vip_key.to_string());
        return handle_vip_level_command(vip_key, trimmed, level, shared);
    }

    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <target> (e.g. 'no plex:32400' or 'no 80')");
        }
        let target = if tokens[1].eq_ignore_ascii_case("service") && tokens.len() >= 3 {
            tokens[2]
        } else {
            tokens[1]
        };
        let clean = target.trim_start_matches(':');
        let mut st = shared.write().unwrap();
        let before = st.candidate.services.len();
        st.candidate.services.retain(|k, s| {
            if !s.belongs_to_vip(vip_key) {
                return true;
            }
            let matches = s.display_name().eq_ignore_ascii_case(target)
                || s.name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false)
                || k.eq_ignore_ascii_case(&format!("{}:{}", vip_key, clean))
                || s.port.to_string() == clean;
            !matches
        });
        if st.candidate.services.len() < before {
            println!(
                "  {} [vip {} -> service] Removed {}",
                "✔".green().bold(),
                vip_key.cyan(),
                target.bold()
            );
            return Ok(());
        } else {
            bail!("Service '{}' not found in vip {}", target, vip_key);
        }
    }

    let eff_tokens = if first_lower == "service" && tokens.len() >= 2 {
        &tokens[1..]
    } else {
        &tokens[..]
    };

    let (spec_string, rest_tokens, is_to_shorthand) =
        if eff_tokens.len() >= 3 && eff_tokens[1].eq_ignore_ascii_case("to") {
            (
                format!("{} to {}", eff_tokens[0], eff_tokens[2]),
                &eff_tokens[3..],
                true,
            )
        } else {
            (eff_tokens[0].to_string(), &eff_tokens[1..], false)
        };

    let svc_key = {
        let mut st = shared.write().unwrap();
        let k = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, &spec_string)?;
        st.sync_runtime_entries();
        k
    };

    if is_to_shorthand {
        println!(
            "  {} [vip {}] {} ({})",
            "✔".green().bold(),
            vip_key.cyan(),
            spec_string.bold(),
            svc_key
        );
    }

    if rest_tokens.is_empty() {
        *level.lock().unwrap() = ShellLevel::Service(svc_key);
    } else {
        let rest_cmd = rest_tokens.join(" ");
        handle_service_level_command(&svc_key, &rest_cmd, level, shared)?;
    }
    Ok(())
}

pub fn handle_adopt(
    args: &[&str],
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    if args.is_empty() {
        bail!(
            "Usage: adopt <# | service_name | host:port> [vip <vip_name_or_ip>] [port <listen_port>] [vlan <id>]"
        );
    }

    let raw_target = args[0].trim().trim_start_matches('#');
    let mut explicit_vip: Option<String> = None;
    let mut explicit_port: Option<u16> = None;
    let mut explicit_vlan: Option<u16> = None;

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].to_ascii_lowercase().as_str() {
            "vip" | "on" => {
                idx += 1;
                if idx >= args.len() {
                    bail!("Expected VIP name or IPv4 address after 'vip'");
                }
                explicit_vip = Some(args[idx].to_string());
            }
            "port" | "as" => {
                idx += 1;
                if idx >= args.len() {
                    bail!("Expected port number (1-65535) after 'port'");
                }
                explicit_port = Some(args[idx].parse()?);
            }
            "vlan" => {
                idx += 1;
                if idx >= args.len() {
                    bail!("Expected VLAN ID (1-4094) after 'vlan'");
                }
                explicit_vlan = Some(parse_vlan_id(args[idx])?);
            }
            other => {
                if explicit_vip.is_none() {
                    explicit_vip = Some(other.to_string());
                }
            }
        }
        idx += 1;
    }

    // If no scan has been run yet, run a quick scan automatically when adopting by # or service name
    let need_auto_scan = {
        let st = shared.read().unwrap();
        st.discovered_services.is_empty() && !raw_target.contains(':')
    };
    if need_auto_scan {
        let _ = crate::features::scan_network_services(None, shared);
    }

    let resolved = {
        let st = shared.read().unwrap();
        if let Ok(num) = raw_target.parse::<usize>() {
            st.discovered_services
                .iter()
                .find(|d| d.index == num)
                .cloned()
        } else {
            st.discovered_services
                .iter()
                .find(|d| {
                    d.service_name.eq_ignore_ascii_case(raw_target)
                        || d.suggested_vip_name().eq_ignore_ascii_case(raw_target)
                        || d.target_spec().eq_ignore_ascii_case(raw_target)
                        || format!("{}:{}", d.ip, d.port).eq_ignore_ascii_case(raw_target)
                })
                .cloned()
        }
    };

    let (target_spec, service_name, backend_port) = if let Some(d) = resolved {
        (d.target_spec(), d.suggested_vip_name(), d.port)
    } else if raw_target.contains(':') {
        let b = parse_backend(&[raw_target], 80)?;
        let name = b
            .host
            .clone()
            .unwrap_or_else(|| format!("svc-{}", b.port));
        (b.to_string(), name, b.port)
    } else {
        bail!(
            "Could not find '{}' in discovered services. Run 'scan' first or specify '<host>:<port>' (e.g. 'adopt media-util:8989').",
            args[0]
        );
    };

    let cur_lvl = level.lock().unwrap().clone();
    let vip_key = if let Some(v) = explicit_vip {
        v
    } else if let ShellLevel::Vip(cur_v) | ShellLevel::VipService(cur_v) = &cur_lvl {
        cur_v.clone()
    } else {
        service_name.clone()
    };

    let (vip_key, _ip_opt, mut parsed_vip) = parse_vip_header(&[vip_key.as_str()])?;
    if let Some(vid) = explicit_vlan {
        parsed_vip.vlan = Some(vid);
    }

    // Determine external listen port:
    // - If explicit `port <N>` was given, use N
    // - If adopting onto a dedicated DHCP VIP (`parsed_vip.dhcp`), default HTTP/app services to port 80 (`80 to sonarr:8989`)
    // - If adopting onto a shared static VIP (e.g. `192.168.1.4`), keep backend_port + set `hostname <service_name>.local`
    let listen_port = if let Some(p) = explicit_port {
        p
    } else if parsed_vip.dhcp && backend_port != 22 && backend_port != 443 {
        80
    } else {
        backend_port
    };

    let svc_spec = if listen_port != backend_port {
        format!("{} to {}", listen_port, target_spec)
    } else {
        target_spec.clone()
    };

    let svc_key = {
        let mut st = shared.write().unwrap();
        let entry = st
            .candidate
            .vips
            .entry(vip_key.clone())
            .or_insert_with(|| parsed_vip.clone());
        if parsed_vip.dhcp {
            entry.dhcp = true;
        }
        if let Some(vid) = explicit_vlan {
            entry.vlan = Some(vid);
        }
        let k = create_or_find_vip_service_by_key(&mut st.candidate, &vip_key, &svc_spec)?;
        if let Some(svc) = st.candidate.services.get_mut(&k) {
            if svc.check.is_none() {
                svc.check = Some(crate::ast::HealthCheckConfig {
                    kind: crate::ast::HealthCheckKind::Tcp,
                    interval_secs: 5,
                });
            }
            if !parsed_vip.dhcp && svc.hostname.is_none() && !service_name.is_empty() {
                let h = if service_name.ends_with(".local") {
                    service_name.clone()
                } else {
                    format!("{}.local", service_name)
                };
                svc.hostname = Some(h);
            }
        }
        st.sync_runtime_entries();
        k
    };

    *level.lock().unwrap() = ShellLevel::Vip(vip_key.clone());
    println!(
        "  {} Adopted {} into vip {} -> {} ({}) — run {} to activate!",
        "✔".green().bold(),
        target_spec.bold(),
        vip_key.cyan().bold(),
        svc_spec.green().bold(),
        svc_key,
        "apply".yellow().bold()
    );
    Ok(())
}

fn handle_service_level_command(
    svc_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    match tokens[0].to_ascii_lowercase().as_str() {
        "to" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::ServiceTo(svc_key.to_string());
            return Ok(());
        }
        "allow" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::ServiceAllow(svc_key.to_string());
            return Ok(());
        }
        "service" => {
            if let Some((vip_part, _)) = svc_key.split_once(':') {
                return handle_vip_service_command(vip_part, trimmed, level, shared);
            }
            return handle_config_root_command(trimmed, level, shared);
        }
        "vip" if tokens.len() >= 2 && parse_ip_and_optional_cidr(tokens[1]).is_ok() => {
            return handle_config_root_command(trimmed, level, shared);
        }
        _ => {}
    }

    let new_key = {
        let mut st = shared.write().unwrap();
        let mut svc = st
            .candidate
            .services
            .remove(svc_key)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' no longer exists", svc_key))?;
        if let Err(e) = apply_service_directive(&mut svc, trimmed) {
            st.candidate.services.insert(svc_key.to_string(), svc);
            return Err(e);
        }
        let updated_key = svc.key.clone();
        let label = svc.display_name();
        st.candidate.services.insert(updated_key.clone(), svc);
        st.sync_runtime_entries();
        println!(
            "  {} [service {} ({})] {}",
            "✔".green().bold(),
            label.cyan(),
            updated_key,
            trimmed
        );
        updated_key
    };
    if new_key != svc_key {
        *level.lock().unwrap() = ShellLevel::Service(new_key);
    }
    Ok(())
}

fn handle_service_to_command(
    svc_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    let first_lower = tokens[0].to_ascii_lowercase();
    if matches!(
        first_lower.as_str(),
        "balance" | "check" | "vip" | "mode" | "limit" | "allow" | "service"
    ) {
        *level.lock().unwrap() = ShellLevel::Service(svc_key.to_string());
        return handle_service_level_command(svc_key, trimmed, level, shared);
    }

    let mut st = shared.write().unwrap();
    let svc = st
        .candidate
        .services
        .get_mut(svc_key)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' no longer exists", svc_key))?;

    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <ip[:port]> (e.g. 'no 192.168.1.60:9000')");
        }
        if remove_backend_from_service(svc, tokens[1])? {
            println!(
                "  {} Removed backend {} from service {}",
                "✔".green().bold(),
                tokens[1].bold(),
                svc_key.cyan()
            );
        } else {
            bail!("Backend '{}' not found in service {}", tokens[1], svc_key);
        }
        return Ok(());
    }

    let backend_tokens = if first_lower == "to" && tokens.len() > 1 {
        &tokens[1..]
    } else {
        &tokens[..]
    };

    let mut b = parse_backend(backend_tokens, svc.port)?;
    let _ = svc;
    if let Some(h) = &b.host {
        if b.ip.is_unspecified() {
            if let Some(ips) = st.resolved_hosts.get(h) {
                if let Some(&first_ip) = ips.first() {
                    b.ip = first_ip;
                }
            }
        }
    }
    let svc = st.candidate.services.get_mut(svc_key).unwrap();
    let display_str = b.to_string();
    if let Some(existing) = svc.backends.iter_mut().find(|x| {
        x.port == b.port
            && ((b.host.is_some() && x.host == b.host) || (b.host.is_none() && x.ip == b.ip))
    }) {
        *existing = b;
        println!(
            "  {} Updated backend {} in service {}",
            "✔".green().bold(),
            display_str.bold(),
            svc_key.cyan()
        );
    } else {
        svc.backends.push(b);
        println!(
            "  {} Added backend {} to service {}",
            "✔".green().bold(),
            display_str.bold(),
            svc_key.cyan()
        );
    }
    st.sync_runtime_entries();
    Ok(())
}

fn handle_service_allow_command(
    svc_key: &str,
    trimmed: &str,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    let mut st = shared.write().unwrap();
    let svc = st
        .candidate
        .services
        .get_mut(svc_key)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' no longer exists", svc_key))?;

    let first_lower = tokens[0].to_ascii_lowercase();
    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <host|wildcard|cidr>");
        }
        let target = validate_allow_entry(tokens[1]).unwrap_or_else(|_| tokens[1].to_string());
        let before = svc.allow.len();
        svc.allow.retain(|x| x != &target);
        if svc.allow.len() < before {
            println!(
                "  {} Removed {} from allowlist",
                "✔".green().bold(),
                target.bold()
            );
        } else {
            bail!("'{}' not found in allowlist", target);
        }
        return Ok(());
    }

    for tok in tokens {
        let entry = validate_allow_entry(tok)?;
        if !svc.allow.contains(&entry) {
            svc.allow.push(entry.clone());
            println!(
                "  {} Allowed source '{}' on service {}",
                "✔".green().bold(),
                entry.bold(),
                svc_key.cyan()
            );
        }
    }
    Ok(())
}

fn handle_gateway_level_command(
    gw_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    match tokens[0].to_ascii_lowercase().as_str() {
        "tunnels" | "to" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::GatewayTunnels(gw_key.to_string());
            return Ok(());
        }
        "service" | "services" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::GatewayService(gw_key.to_string());
            return Ok(());
        }
        "gateway" => {
            return handle_config_root_command(trimmed, level, shared);
        }
        _ => {}
    }

    let mut st = shared.write().unwrap();
    let gw = st
        .candidate
        .gateways
        .get_mut(gw_key)
        .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;
    apply_gateway_directive(gw, trimmed)?;
    st.sync_runtime_entries();
    println!(
        "  {} [gateway {}] {}",
        "✔".green().bold(),
        gw_key.cyan(),
        trimmed
    );
    Ok(())
}

fn handle_gateway_service_command(
    gw_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    let first_lower = tokens[0].to_ascii_lowercase();
    if matches!(
        first_lower.as_str(),
        "tunnels" | "tunnel" | "vip" | "hostname" | "balance" | "killswitch" | "check" | "allow" | "gateway"
    ) {
        *level.lock().unwrap() = ShellLevel::Gateway(gw_key.to_string());
        return handle_gateway_level_command(gw_key, trimmed, level, shared);
    }

    let mut st = shared.write().unwrap();
    let gw = st
        .candidate
        .gateways
        .get_mut(gw_key)
        .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;

    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <privoxy|socks5|ssh>");
        }
        let gs = parse_gateway_service(tokens[1])?;
        let before = gw.services.len();
        gw.services.retain(|s| s.kind != gs.kind);
        if gw.services.len() < before {
            println!(
                "  {} Removed service {} from gateway {}",
                "✔".green().bold(),
                gs.kind.to_string().bold(),
                gw_key.cyan()
            );
        } else {
            bail!("Service '{}' not found in gateway {}", gs.kind, gw_key);
        }
        return Ok(());
    }

    for tok in tokens {
        let gs = parse_gateway_service(tok)?;
        let label = gs.to_string();
        if let Some(existing) = gw.services.iter_mut().find(|x| x.kind == gs.kind) {
            *existing = gs;
        } else {
            gw.services.push(gs);
        }
        println!(
            "  {} [gateway {} -> service] + {}",
            "✔".green().bold(),
            gw_key.cyan(),
            label.bold()
        );
    }
    Ok(())
}

fn handle_gateway_tunnels_command(
    gw_key: &str,
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }

    let first_lower = tokens[0].to_ascii_lowercase();
    if matches!(
        first_lower.as_str(),
        "vip" | "hostname" | "balance" | "killswitch" | "check" | "allow" | "gateway" | "service"
    ) {
        *level.lock().unwrap() = ShellLevel::Gateway(gw_key.to_string());
        return handle_gateway_level_command(gw_key, trimmed, level, shared);
    }

    if matches!(
        first_lower.as_str(),
        "add" | "edit" | "nano" | "vi" | "vim" | "paste"
    ) {
        if tokens.len() < 2 {
            bail!("Usage: {} <tunnel-name> (e.g. '{} mullvad-us-sea-001')", first_lower, first_lower);
        }
        let saved_opt = if first_lower == "paste" {
            crate::features::paste_wg_config_interactive(tokens[1])?
        } else if first_lower == "vi" || first_lower == "vim" {
            crate::features::edit_wg_config_interactive(tokens[1], Some("vi"))?
        } else {
            crate::features::edit_wg_config_interactive(tokens[1], Some("nano"))?
        };
        let Some(saved_filename) = saved_opt else {
            return Ok(());
        };
        let mut st = shared.write().unwrap();
        let gw = st
            .candidate
            .gateways
            .get_mut(gw_key)
            .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;
        let next_idx = gw.tunnels.len();
        let t = parse_wg_tunnel(&[saved_filename.as_str()], next_idx)?;
        let display_str = t.to_string();
        if let Some(existing) = gw.tunnels.iter_mut().find(|x| x.name == t.name) {
            *existing = t;
        } else {
            gw.tunnels.push(t);
        }
        st.sync_runtime_entries();
        println!(
            "  {} [gateway {} -> tunnels] + {}",
            "✔".green().bold(),
            gw_key.cyan(),
            display_str.bold()
        );
        return Ok(());
    }

    // If the user typed a single tunnel name (e.g. `mullvad-us-sea-001` or `mullvad-us-sea-001.conf`)
    // and that file does not exist yet in `/data/wg/`, automatically open nano so they can paste it!
    let mut effective_tokens: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
    if tokens.len() == 1 || (tokens.len() == 3 && tokens[1].eq_ignore_ascii_case("weight")) {
        let filename = crate::features::normalize_wg_filename(tokens[0])?;
        let full_path = std::path::Path::new("/data/wg").join(&filename);
        if !full_path.exists() {
            if let Some(saved_name) = crate::features::edit_wg_config_interactive(&filename, Some("nano"))? {
                effective_tokens[0] = saved_name;
            } else {
                return Ok(());
            }
        } else {
            effective_tokens[0] = filename;
        }
    }

    let mut st = shared.write().unwrap();
    let gw = st
        .candidate
        .gateways
        .get_mut(gw_key)
        .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;

    if matches!(first_lower.as_str(), "no" | "delete" | "remove") {
        if tokens.len() < 2 {
            bail!("Usage: no <tunnel-name>");
        }
        let target = tokens[1];
        let before = gw.tunnels.len();
        gw.tunnels.retain(|t| t.name != target && t.iface != target);
        if gw.tunnels.len() < before {
            println!(
                "  {} Removed tunnel {} from gateway {}",
                "✔".green().bold(),
                target.bold(),
                gw_key.cyan()
            );
        } else {
            bail!("Tunnel '{}' not found in gateway {}", target, gw_key);
        }
        return Ok(());
    }

    let next_idx = gw.tunnels.len();
    let ref_tokens: Vec<&str> = effective_tokens.iter().map(|s| s.as_str()).collect();
    let t = parse_wg_tunnel(&ref_tokens, next_idx)?;
    let display_str = t.to_string();
    if let Some(existing) = gw.tunnels.iter_mut().find(|x| x.name == t.name) {
        *existing = t;
    } else {
        gw.tunnels.push(t);
    }
    st.sync_runtime_entries();
    println!(
        "  {} [gateway {} -> tunnels] + {}",
        "✔".green().bold(),
        gw_key.cyan(),
        display_str.bold()
    );
    Ok(())
}

fn handle_show(args: &[&str], level: &ShellLevel, shared: &SharedState) {
    let st = shared.read().unwrap();
    if let Some(first) = args.first() {
        match first.to_ascii_lowercase().as_str() {
            "nft" | "nftables" | "rules" => {
                let cfg = if *level == ShellLevel::Operational && !st.running.services.is_empty() {
                    &st.running
                } else {
                    &st.candidate
                };
                print!("{}", compile_nft_ruleset(cfg, Some(&st)));
                return;
            }
            "allow" | "hosts" => {
                println!("{}", "Global Allow-List Patterns:".bold().cyan());
                if st.candidate.global_allow.is_empty() {
                    println!("  (none)");
                } else {
                    for g in &st.candidate.global_allow {
                        println!("  - {}", g.yellow());
                    }
                }
                println!("\n{}", "Resolved Host -> IPv4 Cache:".bold().cyan());
                if st.resolved_hosts.is_empty() {
                    println!("  (none)");
                } else {
                    for (h, ips) in &st.resolved_hosts {
                        println!("  {:<28} -> {:?}", h.green(), ips);
                    }
                }
                return;
            }
            "running" => {
                print!("{}", st.running.format_nftyfile());
                return;
            }
            "candidate" | "all" => {
                print!("{}", st.candidate.format_nftyfile());
                return;
            }
            "vip" | "vips" => {
                let cmds = generate_vip_commands(&Config::new(), &st.candidate);
                if cmds.is_empty() {
                    println!("(No VIPs configured)");
                } else {
                    for c in cmds {
                        println!("{}", c);
                    }
                }
                return;
            }
            _ => {}
        }
    }

    match level {
        ShellLevel::Operational => {
            if !st.running.services.is_empty()
                || !st.running.gateways.is_empty()
                || !st.running.global_allow.is_empty()
            {
                print!("{}", st.running.format_nftyfile());
            } else {
                print!("{}", st.candidate.format_nftyfile());
            }
        }
        ShellLevel::ConfigRoot | ShellLevel::GlobalAllow => {
            print!("{}", st.candidate.format_nftyfile());
        }
        ShellLevel::Vip(k) | ShellLevel::VipService(k) => {
            print!("{}", st.candidate.format_vip_block_by_key(k));
            if st.candidate.vips.len() + st.candidate.gateways.len() > 1 {
                println!(
                    "{}",
                    format!(
                        "# (Showing scoped vip {} — run 'show all' or 'top; show' to view full config)",
                        k
                    )
                    .dimmed()
                );
            }
        }
        ShellLevel::Service(k) | ShellLevel::ServiceTo(k) | ShellLevel::ServiceAllow(k) => {
            if let Some(svc) = st.candidate.services.get(k) {
                print!("{}", svc.format_block());
                if st.candidate.services.len() + st.candidate.gateways.len() > 1 {
                    println!(
                        "{}",
                        format!(
                            "# (Showing scoped service {} — run 'show all' or 'top; show' to view full config)",
                            k
                        )
                        .dimmed()
                    );
                }
            } else {
                println!("(Service {} not found)", k);
            }
        }
        ShellLevel::Gateway(k) | ShellLevel::GatewayTunnels(k) | ShellLevel::GatewayService(k) => {
            if let Some(gw) = st.candidate.gateways.get(k) {
                print!("{}", gw.format_block());
                if st.candidate.services.len() + st.candidate.gateways.len() > 1 {
                    println!(
                        "{}",
                        format!(
                            "# (Showing scoped gateway {} — run 'show all' or 'top; show' to view full config)",
                            k
                        )
                        .dimmed()
                    );
                }
            } else {
                println!("(Gateway {} not found)", k);
            }
        }
    }
}

fn print_config_diff(shared: &SharedState) {
    let st = shared.read().unwrap();
    let old_txt = st.running.format_nftyfile();
    let new_txt = st.candidate.format_nftyfile();

    if old_txt == new_txt {
        println!(
            "{}",
            "No uncommitted changes (candidate matches running).".green()
        );
        return;
    }

    let diff = TextDiff::from_lines(&old_txt, &new_txt);
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => print!("{}{}", "- ".red().bold(), change.to_string().red()),
            ChangeTag::Insert => print!("{}{}", "+ ".green().bold(), change.to_string().green()),
            ChangeTag::Equal => print!("  {}", change),
        }
    }
}

fn handle_validate(shared: &SharedState) -> bool {
    let st = shared.read().unwrap();
    let report = validate_config(&st.candidate, Some(&st));

    for w in &report.warnings {
        println!("  {} {}", "⚠ Warning:".yellow().bold(), w);
    }
    for e in &report.errors {
        println!("  {} {}", "✖ Error:".red().bold(), e);
    }

    if report.valid {
        println!(
            "  {} Configuration is valid! ({})",
            "✔".green().bold(),
            report.nft_message
        );
    }
    report.valid
}

async fn handle_apply(args: &[&str], shared: &SharedState) {
    // Refresh DNS/wildcard host resolutions before compiling
    refresh_allowlist_hosts(shared).await;

    if !handle_validate(shared) {
        eprintln!(
            "{}",
            "Apply aborted due to validation errors.".red().bold()
        );
        return;
    }

    let mut confirm_secs: Option<u64> = None;
    if !args.is_empty() {
        if args[0].eq_ignore_ascii_case("confirm") {
            let secs = args
                .get(1)
                .and_then(|s| s.trim_end_matches('s').parse::<u64>().ok())
                .unwrap_or(60);
            confirm_secs = Some(secs.max(5));
        } else if let Ok(secs) = args[0].trim_end_matches('s').parse::<u64>() {
            confirm_secs = Some(secs.max(5));
        }
    }

    let vip_logs;
    let dhcp_logs;
    let apply_res;
    {
        let mut st = shared.write().unwrap();
        let prev_running = st.running.clone();
        let mut next_running = st.candidate.clone();

        dhcp_logs = reconcile_dhcp_and_vlan_vips(&mut next_running);
        let vip_cmds = generate_vip_commands(&prev_running, &next_running);
        vip_logs = apply_vip_commands(&vip_cmds);

        st.history.push(prev_running.clone());
        st.running = next_running;
        st.sync_runtime_entries();

        if let Some(secs) = confirm_secs {
            st.pending_confirm = Some(PendingConfirm {
                revert_to: prev_running,
                deadline: Instant::now() + Duration::from_secs(secs),
            });
        } else {
            st.pending_confirm = None;
        }

        apply_res = reload_kernel_from_state(&mut st);
    }

    for log in dhcp_logs {
        println!("  {} {}", "→".cyan(), log);
    }
    for log in vip_logs {
        println!("  {} {}", "→".cyan(), log);
    }

    match apply_res {
        Ok(msg) => {
            crate::unikernel::persist_to_storage(shared);
            println!("  {} {}", "✔".green().bold(), msg.green());
            if let Some(secs) = confirm_secs {
                println!(
                    "  {} Safety rollback timer active for {}s! Type {} to keep changes.",
                    "🔒".yellow(),
                    secs,
                    "confirm".bold().yellow()
                );
            }
            let _ = run_all_probes_once(shared).await;
        }
        Err(e) => {
            eprintln!("  {} {}", "✖ Apply failed:".red().bold(), e);
        }
    }
}

fn handle_confirm(shared: &SharedState) {
    let mut st = shared.write().unwrap();
    if st.pending_confirm.take().is_some() {
        println!(
            "  {} Configuration confirmed! Safety rollback timer cancelled.",
            "✔".green().bold()
        );
    } else {
        println!("  (No pending commit-confirm timer is active)");
    }
}

fn handle_rollback(args: &[&str], shared: &SharedState) {
    let steps: usize = args
        .first()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let mut st = shared.write().unwrap();
    if st.history.is_empty() {
        eprintln!("  No previous commits in history to rollback to.");
        return;
    }

    let target_idx = st.history.len().saturating_sub(steps);
    st.history.truncate(target_idx + 1);
    let restored = st.history.pop().unwrap();
    let old_running = st.running.clone();

    let vip_cmds = generate_vip_commands(&old_running, &restored);
    let _ = apply_vip_commands(&vip_cmds);

    st.running = restored.clone();
    st.candidate = restored;
    st.pending_confirm = None;
    let _ = reload_kernel_from_state(&mut st);

    println!(
        "  {} Rolled back {} revision(s) and re-applied running configuration.",
        "✔".green().bold(),
        steps
    );
}

fn handle_save(args: &[&str], shared: &SharedState) {
    let mut st = shared.write().unwrap();
    let path = args
        .first()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| st.config_path.clone());
    let content = st.candidate.format_nftyfile();
    match fs::write(&path, &content) {
        Ok(_) => {
            st.last_disk_nftyfile = content;
            println!(
                "  {} Saved configuration to {}",
                "✔".green().bold(),
                path.display()
            );
        }
        Err(e) => eprintln!(
            "  {} Failed to save to {}: {}",
            "✖".red().bold(),
            path.display(),
            e
        ),
    }
}

fn handle_load(args: &[&str], shared: &SharedState) {
    let path = {
        let st = shared.read().unwrap();
        args.first()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| st.config_path.clone())
    };
    match fs::read_to_string(&path) {
        Ok(raw) => match parse_nftyfile(&raw) {
            Ok(cfg) => {
                let mut st = shared.write().unwrap();
                st.candidate = cfg;
                st.sync_runtime_entries();
                println!(
                    "  {} Loaded candidate configuration from {}",
                    "✔".green().bold(),
                    path.display()
                );
            }
            Err(e) => eprintln!(
                "  {} Parse error in {}: {}",
                "✖".red().bold(),
                path.display(),
                e
            ),
        },
        Err(e) => eprintln!(
            "  {} Could not read {}: {}",
            "✖".red().bold(),
            path.display(),
            e
        ),
    }
}

fn set_drain_state(shared: &SharedState, endpoint: &str, drained: bool) {
    let mut st = shared.write().unwrap();
    let mut matched = Vec::new();
    for svc in st
        .running
        .services
        .values()
        .chain(st.candidate.services.values())
    {
        for b in &svc.backends {
            if b.endpoint() == endpoint || b.ip.to_string() == endpoint {
                if !matched.contains(&b.endpoint()) {
                    matched.push(b.endpoint());
                }
            }
        }
    }
    if matched.is_empty() {
        matched.push(endpoint.to_string());
    }

    for ep in &matched {
        st.runtime.entry(ep.clone()).or_default().drained = drained;
        if drained {
            println!(
                "  {} Drained backend {} (removed from active nftables map)",
                "✔".yellow().bold(),
                ep.bold()
            );
        } else {
            println!(
                "  {} Enabled backend {} (restored to active nftables map)",
                "✔".green().bold(),
                ep.bold()
            );
        }
    }
    if !st.running.services.is_empty() {
        let _ = reload_kernel_from_state(&mut st);
    }
}

pub fn print_status_table(shared: &SharedState) {
    let st = shared.read().unwrap();
    let cfg = if !st.running.vips.is_empty()
        || !st.running.services.is_empty()
        || !st.running.gateways.is_empty()
    {
        &st.running
    } else {
        &st.candidate
    };

    if cfg.vips.is_empty() && cfg.services.is_empty() && cfg.gateways.is_empty() {
        println!(
            "No VIPs, services, or gateways configured. Run 'scan' to discover services or 'configure' -> 'vip <name>'."
        );
        return;
    }

    println!(
        "{:<22} {:<13} {:<28} {:<30} {:<22} {}",
        "SERVICE / VIP / GW".bold().underline(),
        "STRATEGY".bold().underline(),
        "VIP / MODE".bold().underline(),
        "BACKEND / WG TUNNEL".bold().underline(),
        "HEALTH (LATENCY)".bold().underline(),
        "TRAFFIC".bold().underline()
    );

    // Show standalone VIPs that have no services attached yet
    for (vip_key, vip_cfg) in &cfg.vips {
        let has_svcs = cfg.services.values().any(|s| s.belongs_to_vip(vip_key));
        if !has_svcs {
            let status_str = if vip_cfg.dhcp {
                if let Some(ip) = vip_cfg.leased_ip {
                    format!("LEASED ({})", ip).green().to_string()
                } else {
                    "DHCP PENDING".yellow().to_string()
                }
            } else {
                "READY (empty VIP)".cyan().to_string()
            };
            println!(
                "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                format!("vip:{}", vip_key).yellow().bold(),
                "-",
                vip_cfg.to_string(),
                "(no services yet)",
                status_str,
                "-"
            );
        }
    }

    for svc in cfg.services.values() {
        let active_eps: Vec<String> = st
            .active_backends_for_service(&svc.backends)
            .into_iter()
            .map(|b| b.endpoint())
            .collect();

        let vip_mode = match &svc.vip {
            Some(v) => format!("{}/{}", v, svc.mode),
            None => format!("-/{}", svc.mode),
        };

        let mut host_badge = svc
            .hostname
            .as_deref()
            .map(|h| format!(" [{}]", h))
            .unwrap_or_default();
        if let Some(cf_host) = svc.cloudflare.as_deref() {
            if svc.cloudflare_auth.is_empty() && svc.auth.is_empty() {
                host_badge.push_str(&format!(" [cf:{}]", cf_host));
            } else {
                host_badge.push_str(&format!(" [cf:{} 🔒]", cf_host));
            }
        } else if !svc.auth.is_empty() {
            host_badge.push_str(" [🔒]");
        }

        if svc.backends.is_empty() {
            println!(
                "{:<22} {:<13} {:<28} {:<30} {:<22} {}",
                svc.key.yellow(),
                svc.balance.to_string(),
                vip_mode,
                format!("(none){}", host_badge),
                "-",
                "-"
            );
            continue;
        }

        for (idx, b) in svc.backends.iter().enumerate() {
            let ep = b.endpoint();
            let rt = st.runtime.get(&ep).cloned().unwrap_or_default();
            let is_active = active_eps.contains(&ep);

            let mut ep_label = match &b.host {
                Some(h) if !b.ip.is_unspecified() => format!("{}:{} ({})", h, b.port, b.ip),
                _ => ep.clone(),
            };
            if idx == 0 && !host_badge.is_empty() {
                ep_label.push_str(&host_badge);
            }
            if b.backup {
                ep_label.push_str(" [backup]");
            }
            if b.weight != 1 {
                ep_label.push_str(&format!(" (w={})", b.weight));
            }

            let health_col = if rt.drained {
                "DRAINED (paused)".yellow().to_string()
            } else {
                match rt.health {
                    HealthState::Up => {
                        let ms = rt
                            .latency_ms
                            .map(|m| format!(" {:.1}ms", m))
                            .unwrap_or_default();
                        format!("UP{}", ms).green().to_string()
                    }
                    HealthState::Down => "DOWN (unreachable)".red().to_string(),
                    HealthState::Unknown => {
                        if is_active {
                            "READY (active)".cyan().to_string()
                        } else {
                            "STANDBY".bright_black().to_string()
                        }
                    }
                }
            };

            let traffic_col = format!("{} pkts / {} B", rt.packets, rt.bytes);

            if idx == 0 {
                println!(
                    "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                    svc.key.yellow().bold(),
                    svc.balance.to_string(),
                    vip_mode,
                    ep_label,
                    health_col,
                    traffic_col
                );
            } else {
                println!(
                    "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                    "", "", "", ep_label, health_col, traffic_col
                );
            }
        }
    }

    for gw in cfg.gateways.values() {
        let mode_suffix = if gw.tunnels.is_empty() { "direct-gw" } else { "wg-gw" };
        let vip_mode = match &gw.vip {
            Some(v) => format!("{}/{}", v, mode_suffix),
            None => format!("-/{}", mode_suffix),
        };
        let gw_title = format!("gw:{}", gw.key);
        let svcs_label = if gw.services.is_empty() {
            String::new()
        } else {
            let names: Vec<String> = gw.services.iter().map(|s| s.to_string()).collect();
            format!(" [{}]", names.join(","))
        };
        if gw.tunnels.is_empty() {
            println!(
                "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                gw_title.magenta().bold(),
                "direct",
                vip_mode,
                format!("host (eth0){}", svcs_label),
                "UP (direct)".green().to_string(),
                "-"
            );
            continue;
        }
        for (idx, t) in gw.tunnels.iter().enumerate() {
            let ep = if idx == 0 {
                format!("{}{}", t.endpoint_key(), svcs_label)
            } else {
                t.endpoint_key()
            };
            let rt = st.runtime.get(&t.endpoint_key()).cloned().unwrap_or_default();
            let health_col = match rt.health {
                HealthState::Up => {
                    let ms = rt
                        .latency_ms
                        .map(|m| format!(" {:.1}ms", m))
                        .unwrap_or_default();
                    format!("UP{}", ms).green().to_string()
                }
                HealthState::Down => "DOWN (unreachable)".red().to_string(),
                HealthState::Unknown => "READY (active)".cyan().to_string(),
            };
            let traffic_col = format!("{} pkts / {} B", rt.packets, rt.bytes);
            if idx == 0 {
                println!(
                    "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                    gw_title.magenta().bold(),
                    gw.balance.to_string(),
                    vip_mode,
                    ep,
                    health_col,
                    traffic_col
                );
            } else {
                println!(
                    "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
                    "", "", "", ep, health_col, traffic_col
                );
            }
        }
    }
}

fn print_context_help(level: &ShellLevel) {
    match level {
        ShellLevel::Operational => {
            println!("{}", "Operational Mode Commands:".bold().cyan());
            println!("  {:<26} Discover live LXD/LAN containers & open ports", "scan [host|subnet]".yellow());
            println!("  {:<26} Adopt discovered service into a DHCP or static VIP", "adopt <# | name> [vip X]".yellow());
            println!("  {:<26} Bootstrap VIP + base SSH service config", "bootstrap <ip[/24]>...".yellow());
            println!("  {:<26} Enter configuration mode", "configure".yellow());
            println!("  {:<26} Show service, gateway & backend health table", "status".yellow());
            println!("  {:<26} Show live active conntrack flows & bandwidth", "flows".yellow());
            println!("  {:<26} List saved WireGuard configs (/data/wg)", "wg".yellow());
            println!("  {:<26} Open nano to paste/edit a WireGuard .conf", "wg add <name>".yellow());
            println!("  {:<26} Paste a WireGuard .conf directly in CLI", "wg paste <name>".yellow());
            println!("  {:<26} Cloudflare Tunnel & DNS status / API token setup", "cf [status|token <KEY>]".yellow());
            println!("  {:<26} Open live interactive TUI dashboard", "watch".yellow());
            println!("  {:<26} Run active health probes right now", "probe".yellow());
            println!("  {:<26} Show Nftyfile configuration", "show".yellow());
            println!("  {:<26} Show allow-lists & resolved hosts", "show allow".yellow());
            println!("  {:<26} Show compiled nftables ruleset", "show nft".yellow());
            println!("  {:<26} Drain backend from load balancer", "drain <ip:port>".yellow());
            println!("  {:<26} Re-enable drained backend", "enable <ip:port>".yellow());
            println!("  {:<26} Change nfty login password", "password".yellow());
            println!("  {:<26} Exit nfty", "exit".yellow());
        }
        ShellLevel::ConfigRoot => {
            println!("{}", "Config Root Commands (nfty(config)#):".bold().cyan());
            println!(
                "  {:<32} Discover live LXD/LAN containers & open ports",
                "scan [host|subnet]".yellow()
            );
            println!(
                "  {:<32} Adopt discovered service (e.g. 'adopt 1' or 'adopt sonarr vip 192.168.1.4')",
                "adopt <# | name> [vip <vip>]".yellow()
            );
            println!(
                "  {:<32} Create/enter a static or DHCP VIP container (e.g. 'vip 192.168.1.4' or 'vip sonarr')",
                "vip <ipv4[/cidr]|name>".yellow()
            );
            println!(
                "  {:<32} Create/enter a Virtual Gateway (static IP or DHCP, e.g. 'gateway 192.168.1.10' or 'gateway mullvad')",
                "gateway <ipv4[/cidr]|name>".yellow()
            );
            println!("  {:<32} Bootstrap VIP + base SSH service config", "bootstrap <ip[/24]>...".yellow());
            println!(
                "  {:<32} Enter global allow-list block (supports wildcards e.g. '*.office.lan', '192.168.1.*')",
                "allow [pattern...]".yellow()
            );
            println!(
                "  {:<32} Register/update hostname -> IP mapping for wildcard rules",
                "host <hostname> <ipv4>".yellow()
            );
            println!("  {:<32} Delete a VIP, gateway, service, or allow entry", "no <vip|gateway|service|allow> <target>".yellow());
            println!("  {:<32} Show candidate configuration", "show".yellow());
            println!("  {:<32} Show live active conntrack flows", "flows".yellow());
            println!("  {:<32} List saved WireGuard configs (/data/wg)", "wg".yellow());
            println!("  {:<32} Open nano to paste/edit a WireGuard .conf", "wg add <name>".yellow());
            println!("  {:<32} Paste a WireGuard .conf directly in CLI", "wg paste <name>".yellow());
            println!("  {:<32} Cloudflare Tunnel & DNS setup (e.g. 'cf token <API_TOKEN>')", "cf [status|token|sync|logs]".yellow());
            println!("  {:<32} Show allow-lists & resolved hosts", "show allow".yellow());
            println!("  {:<32} Show generated nftables ruleset", "show nft".yellow());
            println!("  {:<32} Compare candidate vs running config", "diff".yellow());
            println!("  {:<32} Validate config & nftables dry-run", "test".yellow());
            println!("  {:<32} Apply candidate config to kernel", "apply / commit".yellow());
            println!("  {:<32} Apply with auto-rollback timer (e.g. 60s)", "apply confirm <secs>".yellow());
            println!("  {:<32} Confirm a pending timed apply", "confirm".yellow());
            println!("  {:<32} Rollback to previous committed config", "rollback [N]".yellow());
            println!("  {:<32} Save config to Nftyfile", "save [path]".yellow());
            println!("  {:<32} Exit back to operational mode", "exit / ..".yellow());
        }
        ShellLevel::Vip(k) => {
            println!(
                "{}",
                format!("VIP '{}' Commands (nfty(config-vip:{})#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Map listen port to backend (e.g. '80 to sonarr:8989')", "<port> to <host:port>".yellow());
            println!("  {:<32} Add/enter backend service on matching port (e.g. 'gamble:9090')", "<host_or_ip:port>".yellow());
            println!("  {:<32} Enable local nfty SSH shell on this VIP", "ssh:22 (or 'ssh')".yellow());
            println!("  {:<32} Lease VIP via DHCP + register hostname with UDM DNS", "dhcp [eth0|off]".yellow());
            println!("  {:<32} Set 802.1Q VLAN tag (e.g. 'vlan 20')", "vlan <1-4094>".yellow());
            println!("  {:<32} Set NIC interface / subnet CIDR (e.g. 'interface eth1/24')", "interface <iface[/prefix]>".yellow());
            println!("  {:<32} Expose via Cloudflare Tunnel & DNS (e.g. 'cloudflare-dns app.domain.com')", "cloudflare-dns <fqdn>".yellow());
            println!("  {:<32} Remove VLAN, DHCP, Cloudflare, SSH, or a forwarded service", "no <vlan|dhcp|cloudflare-dns|ssh:22|<target>>".yellow());
            println!("  {:<32} Show this VIP block", "show".yellow());
            println!("  {:<32} Return to config root", ".. / up / exit / top".yellow());
        }
        ShellLevel::VipService(k) => {
            println!(
                "{}",
                format!("VIP '{}' Forwarded Services Mode (nfty(config-vip:{}-service)#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Create/enter backend service (e.g. 'plex:32400' or 'gamble:9090')", "<host_or_ip:port>".yellow());
            println!("  {:<32} Create/enter service by listen port (e.g. '80' or '53/udp')", "<port[/proto]>".yellow());
            println!("  {:<32} Remove a service from this VIP", "no <target>".yellow());
            println!("  {:<32} Return to VIP {} prompt", ".. / up / exit".yellow(), k);
        }
        ShellLevel::GlobalAllow => {
            println!("{}", "Global Allow-List Mode (nfty(config-allow)#):".bold().cyan());
            println!("  {:<32} Allow wildcard domain (e.g. '*.office.lan')", "<*.domain.tld>".yellow());
            println!("  {:<32} Allow IP wildcard (e.g. '192.168.1.*')", "<a.b.c.*>".yellow());
            println!("  {:<32} Allow hostname or CIDR (e.g. 'admin.lan' or '10.0.0.0/8')", "<host|cidr>".yellow());
            println!("  {:<32} Remove allow entry", "no <pattern>".yellow());
            println!("  {:<32} Return to config root", ".. / up / exit".yellow());
        }
        ShellLevel::Service(k) => {
            println!(
                "{}",
                format!("Service '{}' Settings (nfty(config-service:{})#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Override external VIP listen port (e.g. 'port 80')", "port <1-65535>".yellow());
            println!("  {:<32} Set protocol ('tcp', 'udp', or 'both')", "proto <tcp|udp|both>".yellow());
            println!("  {:<32} Enter backend targets prompt ('to' sub-level)", "to".yellow());
            println!("  {:<32} Add backend directly in one line", "to <ip|host[:port]> [weight N] [backup]".yellow());
            println!("  {:<32} Announce mDNS (*.local) + route HTTP Host / TLS SNI", "hostname <name.local>".yellow());
            println!("  {:<32} Expose via Cloudflare Tunnel & DNS (e.g. 'cloudflare-dns app.domain.com')", "cloudflare-dns <fqdn>".yellow());
            println!("  {:<32} Require Auth on Cloudflare Tunnel ('nfty', 'user:pass', or 'you@email.com')", "cloudflare-auth <rule...>".yellow());
            println!("  {:<32} Load balance strategy", "balance <round-robin|sticky>".yellow());
            println!("  {:<32} Bind Virtual IP to NIC (e.g. 'vip eth0/21')", "vip <interface[/prefix]>".yellow());
            println!("  {:<32} Active health check", "check <tcp|http /path|ping> [5s]".yellow());
            println!("  {:<32} Per-IP DDoS/rate limit guard", "limit <100/sec|600/min> [burst N] [per-ip]".yellow());
            println!("  {:<32} Client IP mode (nat masquerade vs transparent)", "mode <nat|transparent>".yellow());
            println!("  {:<32} Enter source host/wildcard allowlist prompt", "allow [pattern...]".yellow());
            println!("  {:<32} Remove a directive or backend", "no <vip|hostname|check|limit|allow|to <ip>>".yellow());
            println!("  {:<32} Show this service block", "show".yellow());
            println!("  {:<32} Go up one level / jump to config root", ".. / exit / top".yellow());
        }
        ShellLevel::ServiceTo(k) => {
            println!(
                "{}",
                format!("Service '{}' Backend Target Mode (nfty(config-service:{}-to)#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Add backend (e.g. 'plex:32400' or '192.168.1.60:9000')", "<ip|host[:port]>".yellow());
            println!("  {:<32} Add weighted backend", "<ip|host[:port]> weight <1-100>".yellow());
            println!("  {:<32} Add failover standby backend", "<ip|host[:port]> backup".yellow());
            println!("  {:<32} Remove a backend", "no <ip|host[:port]>".yellow());
            println!("  {:<32} Go back to service {} prompt", ".. / up / exit".yellow(), k);
            println!("  {:<32} Jump back to config root", "top".yellow());
        }
        ShellLevel::ServiceAllow(k) => {
            println!(
                "{}",
                format!("Service '{}' Source Allowlist Mode (nfty(config-service:{}-allow)#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Allow wildcard domain, IP wildcard, host, or CIDR (e.g. '*.office.lan', '192.168.1.*')", "<pattern>".yellow());
            println!("  {:<32} Remove source pattern", "no <pattern>".yellow());
            println!("  {:<32} Go back to service {} prompt", ".. / up / exit".yellow(), k);
        }
        ShellLevel::Gateway(k) => {
            println!(
                "{}",
                format!("Virtual Gateway '{}' Commands (nfty(config-gateway:{})#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Enable local HTTP/HTTPS Privoxy on this gateway", "privoxy:8118 (or 'privoxy')".yellow());
            println!("  {:<32} Enable local SOCKS5 proxy on this gateway", "socks5:1080 (or 'socks5')".yellow());
            println!("  {:<32} Enable local nfty SSH shell on this gateway", "ssh:22 (or 'ssh')".yellow());
            println!("  {:<32} Enter optional WireGuard tunnels sub-level", "tunnels".yellow());
            println!("  {:<32} Add an optional WireGuard tunnel config directly", "tunnel <mullvad-us-sea-001.conf> [weight N]".yellow());
            println!("  {:<32} Bind Virtual Gateway IP to NIC (e.g. 'vip eth0/21')", "vip <interface[/prefix]>".yellow());
            println!("  {:<32} Announce mDNS name (e.g. 'hostname vpn.local')", "hostname <name.local>".yellow());
            println!("  {:<32} Per-flow load balance strategy across tunnels", "balance <round-robin|sticky>".yellow());
            println!("  {:<32} Toggle WAN leak kill-switch when tunnels are used", "killswitch <on|off>".yellow());
            println!("  {:<32} Remove a tunnel, service, or directive", "no <privoxy|socks5|ssh|tunnel <name>|vip|killswitch>".yellow());
            println!("  {:<32} Show this gateway block", "show".yellow());
            println!("  {:<32} Go up one level / jump to config root", ".. / top".yellow());
        }
        ShellLevel::GatewayService(k) => {
            println!(
                "{}",
                format!("Gateway '{}' Services Mode (nfty(config-gateway:{}-service)#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Enable HTTP/HTTPS Privoxy on this gateway", "privoxy:8118 (or 'privoxy')".yellow());
            println!("  {:<32} Enable SOCKS5 proxy on this gateway", "socks5:1080 (or 'socks5')".yellow());
            println!("  {:<32} Enable nfty SSH shell on this gateway IP", "ssh:22 (or 'ssh')".yellow());
            println!("  {:<32} Disable a gateway service", "no <privoxy|socks5|ssh>".yellow());
            println!("  {:<32} Return to gateway {} prompt", ".. / up / exit".yellow(), k);
        }
        ShellLevel::GatewayTunnels(k) => {
            println!(
                "{}",
                format!("Gateway '{}' WireGuard Tunnels Mode (nfty(config-gateway:{}-tunnels)#):", k, k)
                    .bold()
                    .cyan()
            );
            println!("  {:<32} Open nano to paste new WireGuard config & attach it", "add <name> / nano <name>".yellow());
            println!("  {:<32} Paste WireGuard config inline & attach it", "paste <name>".yellow());
            println!("  {:<32} Add tunnel from /data/wg/<file> (opens nano if new)", "<mullvad-us-sea-001.conf> [weight N]".yellow());
            println!("  {:<32} Add inline tunnel", "<wg0> address <ip/32> privkey <k> peer <pub> endpoint <ip:port>".yellow());
            println!("  {:<32} Remove a tunnel", "no <name>".yellow());
            println!("  {:<32} Return to gateway {} prompt", ".. / up / exit".yellow(), k);
        }
    }
}
