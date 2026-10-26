use super::ShellLevel;
use crate::state::SharedState;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context as RlContext, Helper};
use std::fs;
use std::sync::{Arc, Mutex};

pub struct NftyHelper {
    pub(crate) level: Arc<Mutex<ShellLevel>>,
    pub(crate) state: SharedState,
}

impl NftyHelper {
    pub fn new(level: Arc<Mutex<ShellLevel>>, state: SharedState) -> Self {
        Self { level, state }
    }

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

    fn ssh_pub_files(&self) -> Vec<String> {
        let mut list = Vec::new();
        let dir = crate::ssh::ssh_keys_dir();
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".pub") {
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
        let cmd0 = words
            .first()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let cmd1 = words
            .get(1)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        // Global argument completions that apply at any shell level
        if word_idx == 1 {
            match cmd0.as_str() {
                "show" => {
                    let list = vec![
                        "running",
                        "candidate",
                        "all",
                        "nft",
                        "allow",
                        "hosts",
                        "vips",
                        "dns",
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
                "dns" => {
                    let lvl_now = self.level.lock().unwrap().clone();
                    let list = if lvl_now == ShellLevel::Operational {
                        vec!["status", "test", "config", "reload"]
                    } else {
                        vec![
                            "status",
                            "test",
                            "config",
                            "reload",
                            "domain",
                            "upstream",
                            "forward",
                            "a",
                            "aaaa",
                            "address",
                            "cname",
                            "txt",
                            "srv",
                            "mx",
                            "ptr",
                            "route",
                            "bypass",
                            "block",
                            "blocklist",
                            "auto-vips",
                            "auto-hosts",
                            "health-aware",
                        ]
                    };
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
                    let list = vec!["list", "add", "edit", "paste", "show", "rm", "status"];
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
                "ssh" | "ssh-key" | "ssh-keys" => {
                    let list = vec!["list", "add", "edit", "paste", "vi", "show", "rm", "key"];
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
                    for svc in st
                        .running
                        .services
                        .values()
                        .chain(st.candidate.services.values())
                    {
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
        } else if (word_idx == 2 || word_idx == 3)
            && matches!(cmd0.as_str(), "ssh" | "ssh-key" | "ssh-keys")
        {
            if word_idx == 2 && matches!(cmd1.as_str(), "key" | "keys") {
                let list = vec!["list", "add", "edit", "paste", "vi", "show", "rm"];
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
            let files = self.ssh_pub_files();
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
                "dns",
                "wg",
                "ssh",
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
                "dns",
                "scan",
                "adopt",
                "bootstrap",
                "allow",
                "host",
                "no",
                "show",
                "flows",
                "wg",
                "ssh",
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
            (ShellLevel::Dns, 0) => vec![
                "listen",
                "domain",
                "cache-size",
                "auto-vips",
                "auto-hosts",
                "health-aware",
                "all-servers",
                "bogus-priv",
                "domain-needed",
                "upstream",
                "forward",
                "a",
                "aaaa",
                "address",
                "cname",
                "txt",
                "srv",
                "mx",
                "ptr",
                "route",
                "bypass",
                "block",
                "blocklist",
                "raw",
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
            (ShellLevel::Dns, 1) if cmd0 == "no" => vec![
                "listen",
                "upstream",
                "forward",
                "a",
                "aaaa",
                "address",
                "cname",
                "txt",
                "srv",
                "mx",
                "ptr",
                "route",
                "bypass",
                "block",
                "blocklist",
                "raw",
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
                    "dns".to_string(),
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
                    "dns:53",
                    "api:9090",
                    "web:8000",
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
                list.push("api:9090".to_string());
                list.push("web:8000".to_string());
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
                "key",
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
            (ShellLevel::Service(_), 1) if cmd0 == "key" => vec![
                "new ro".to_string(),
                "new rw".to_string(),
                "new".to_string(),
            ],
            (ShellLevel::Service(_), 2) if cmd0 == "key" => {
                vec!["ro".to_string(), "rw".to_string()]
            }
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
                "*@example.com".to_string(),
                "you@example.com".to_string(),
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
                    "key".to_string(),
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
                "dns:53",
                "api:9090",
                "web:8000",
                "key",
                "forward",
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
            (ShellLevel::Gateway(_), 1) if cmd0 == "key" => vec![
                "new ro".to_string(),
                "new rw".to_string(),
                "new".to_string(),
            ],
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
                    "dns".to_string(),
                    "api".to_string(),
                    "key".to_string(),
                    "forward".to_string(),
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
                "dns:53",
                "api:9090",
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
            (ShellLevel::GatewayApi(_, _), 0) => vec![
                "key",
                "port",
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
            (ShellLevel::GatewayApi(_, _), 1) if cmd0 == "key" => vec![
                "new ro".to_string(),
                "new rw".to_string(),
                "new".to_string(),
            ],
            (ShellLevel::GatewayApi(_, _), 2) if cmd0 == "key" => {
                vec!["ro".to_string(), "rw".to_string()]
            }
            (ShellLevel::GatewayApi(_, _), 1) if cmd0 == "no" => {
                vec!["key".to_string()]
            }
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
