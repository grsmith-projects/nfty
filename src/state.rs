use crate::ast::{Backend, Config};
use crate::parser::{expand_ip_wildcard_to_cidr, wildcard_host_matches};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthState {
    Up,
    Down,
    Unknown,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Up => "UP",
            HealthState::Down => "DOWN",
            HealthState::Unknown => "UNCHECKED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRuntime {
    pub health: HealthState,
    pub drained: bool,
    pub latency_ms: Option<f64>,
    pub last_error: Option<String>,
    #[serde(skip)]
    pub last_checked: Option<Instant>,
    pub packets: u64,
    pub bytes: u64,
    pub pps: f64,
    pub bps: f64,
}

impl Default for BackendRuntime {
    fn default() -> Self {
        Self {
            health: HealthState::Unknown,
            drained: false,
            latency_ms: None,
            last_error: None,
            last_checked: None,
            packets: 0,
            bytes: 0,
            pps: 0.0,
            bps: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingConfirm {
    pub revert_to: Config,
    pub deadline: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub index: usize,
    pub host: Option<String>,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub service_name: String,
    pub banner: String,
    pub latency_ms: f64,
}

impl DiscoveredService {
    pub fn target_spec(&self) -> String {
        match &self.host {
            Some(h) => format!("{}:{}", h, self.port),
            None => format!("{}:{}", self.ip, self.port),
        }
    }

    pub fn suggested_vip_name(&self) -> String {
        let lower_svc = self.service_name.to_ascii_lowercase();
        if !matches!(lower_svc.as_str(), "http" | "https" | "tcp" | "ssh" | "dns" | "unknown") {
            return lower_svc
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
        }
        if let Some(h) = &self.host {
            let base = h.split('.').next().unwrap_or(h);
            return format!("{}-{}", base, self.port);
        }
        format!("svc-{}", self.port)
    }
}

#[derive(Debug)]
pub struct AppState {
    pub running: Config,
    pub candidate: Config,
    pub history: Vec<Config>,
    pub config_path: PathBuf,
    /// Keyed by "ip:port" (e.g., "10.0.1.60:9000")
    pub runtime: BTreeMap<String, BackendRuntime>,
    /// Live DNS & Host cache mapping hostname -> resolved IPv4 addresses.
    /// Automatically kept updated by background DNS/hosts resolver + API registrations.
    pub resolved_hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    /// Discovered LAN/LXD container services from the most recent `scan`
    pub discovered_services: Vec<DiscoveredService>,
    pub pending_confirm: Option<PendingConfirm>,
    pub last_applied_nft: String,
    pub last_disk_nftyfile: String,
    pub kernel_applied: bool,
    pub api_bind: Option<String>,
    pub controller_is_authoritative: bool,
}

pub type SharedState = Arc<RwLock<AppState>>;

impl AppState {
    pub fn new(initial: Config, config_path: PathBuf) -> Self {
        let initial_txt = initial.format_nftyfile();
        let mut s = Self {
            running: initial.clone(),
            candidate: initial,
            history: Vec::new(),
            config_path,
            runtime: BTreeMap::new(),
            resolved_hosts: BTreeMap::new(),
            discovered_services: Vec::new(),
            pending_confirm: None,
            last_applied_nft: String::new(),
            last_disk_nftyfile: initial_txt,
            kernel_applied: false,
            api_bind: None,
            controller_is_authoritative: false,
        };
        s.sync_runtime_entries();
        s
    }

    pub fn controller_ipc_addr(&self) -> Option<String> {
        if let Some(ref bind) = self.api_bind {
            if !bind.trim().is_empty() {
                return Some(bind.clone());
            }
        }
        self.running
            .api_ports()
            .into_iter()
            .chain(self.candidate.api_ports())
            .next()
            .map(|p| format!("127.0.0.1:{}", p))
    }

    /// Returns the committed configuration, including when it is empty.
    pub fn active_config(&self) -> &Config {
        &self.running
    }

    /// Refreshes an unmodified candidate from disk without claiming it was applied.
    pub fn sync_from_disk_if_changed(&mut self) {
        let path = self.config_path.clone();
        if !path.exists() {
            return;
        }

        if let Ok(raw) = std::fs::read_to_string(&path) {
            if raw != self.last_disk_nftyfile {
                if let Ok(mut parsed) = crate::parser::parse_nftyfile(&raw) {
                    // Preserve active DHCP leases on VIPs and Gateways
                    for (k, old_v) in &self.running.vips {
                        if let Some(lip) = old_v.leased_ip {
                            if let Some(new_v) = parsed.vips.get_mut(k) {
                                new_v.leased_ip = Some(lip);
                            }
                            for svc in parsed.services.values_mut() {
                                if svc.belongs_to_vip(k) && svc.listen_ip.is_none() {
                                    svc.listen_ip = Some(lip);
                                }
                            }
                        }
                    }
                    for (k, old_gw) in &self.running.gateways {
                        if let Some(old_v) = &old_gw.vip {
                            if let Some(lip) = old_v.leased_ip {
                                if let Some(new_gw) = parsed.gateways.get_mut(k) {
                                    new_gw.listen_ip = lip;
                                    if let Some(nv) = &mut new_gw.vip {
                                        nv.leased_ip = Some(lip);
                                    }
                                }
                            }
                        }
                    }
                    let candidate_unmodified =
                        self.candidate.format_nftyfile() == self.running.format_nftyfile();
                    if candidate_unmodified {
                        self.candidate = parsed;
                    }
                    self.last_disk_nftyfile = raw;
                    self.sync_runtime_entries();
                }
            }
        }
    }

    pub fn sync_runtime_entries(&mut self) {
        for svc in self
            .running
            .services
            .values()
            .chain(self.candidate.services.values())
        {
            for b in &svc.backends {
                self.runtime.entry(b.endpoint()).or_default();
            }
        }
        for gw in self
            .running
            .gateways
            .values()
            .chain(self.candidate.gateways.values())
        {
            for t in &gw.tunnels {
                self.runtime.entry(t.endpoint_key()).or_default();
            }
        }
    }

    pub fn set_host_mapping(&mut self, host: &str, ips: &[Ipv4Addr]) {
        if ips.is_empty() {
            self.resolved_hosts.remove(host);
        } else {
            self.resolved_hosts.insert(host.to_string(), ips.to_vec());
        }
        if let Some(&first_ip) = ips.first() {
            for config in [&mut self.running, &mut self.candidate] {
                for svc in config.services.values_mut() {
                    for backend in &mut svc.backends {
                        if backend.host.as_deref().map(|name| name.eq_ignore_ascii_case(host)) == Some(true) {
                            backend.ip = first_ip;
                        }
                    }
                }
                for gateway in config.gateways.values_mut() {
                    for forward in &mut gateway.forwards {
                        if forward.backend.host.as_deref().map(|name| name.eq_ignore_ascii_case(host)) == Some(true) {
                            forward.backend.ip = first_ip;
                        }
                    }
                }
            }
        }
        self.sync_runtime_entries();
    }

    pub fn has_runtime_endpoint(&self, endpoint: &str) -> bool {
        [&self.running, &self.candidate].iter().any(|config| {
            config.services.values().any(|svc| {
                svc.backends.iter().any(|backend| backend.endpoint() == endpoint)
            }) || config.gateways.values().any(|gateway| {
                gateway.tunnels.iter().any(|tunnel| tunnel.endpoint_key() == endpoint)
            })
        })
    }

    /// Expands a service's allow-list + global allow-list (including IP wildcards, hostnames,
    /// and wildcard host patterns like `*.office.lan`) into concrete IPv4/CIDR elements for nftables.
    pub fn expand_allow_elements(&self, svc_allow: &[String], global_allow: &[String]) -> Vec<String> {
        let mut out = BTreeSet::new();
        for entry in global_allow.iter().chain(svc_allow.iter()) {
            if let Some(cidr) = expand_ip_wildcard_to_cidr(entry) {
                out.insert(cidr);
                continue;
            }
            // Otherwise it's a hostname or wildcard hostname pattern
            for (host, ips) in &self.resolved_hosts {
                if wildcard_host_matches(entry, host) {
                    for ip in ips {
                        out.insert(ip.to_string());
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    /// Checks if a client IPv4 address is permitted by a service's allow-list (used by userspace/unikernel dataplane)
    pub fn is_ip_allowed(&self, client_ip: Ipv4Addr, svc_allow: &[String], global_allow: &[String]) -> bool {
        if svc_allow.is_empty() && global_allow.is_empty() {
            return true;
        }
        let elements = self.expand_allow_elements(svc_allow, global_allow);
        for el in elements {
            if ip_matches_cidr(client_ip, &el) {
                return true;
            }
        }
        false
    }

    pub fn active_backends_for_service<'a>(&self, backends: &'a [Backend]) -> Vec<&'a Backend> {
        let is_eligible = |b: &Backend| -> bool {
            if let Some(rt) = self.runtime.get(&b.endpoint()) {
                if rt.drained || rt.health == HealthState::Down {
                    return false;
                }
            }
            true
        };

        let primaries: Vec<&Backend> = backends
            .iter()
            .filter(|b| !b.backup && is_eligible(b))
            .collect();
        if !primaries.is_empty() {
            return primaries;
        }

        let backups: Vec<&Backend> = backends
            .iter()
            .filter(|b| b.backup && is_eligible(b))
            .collect();
        if !backups.is_empty() {
            return backups;
        }

        Vec::new()
    }
}

pub fn ip_matches_cidr(ip: Ipv4Addr, cidr_or_ip: &str) -> bool {
    if cidr_or_ip == "0.0.0.0/0" {
        return true;
    }
    if let Some((net_str, prefix_str)) = cidr_or_ip.split_once('/') {
        if let (Ok(net_ip), Ok(prefix)) = (net_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>()) {
            if prefix == 0 {
                return true;
            }
            if prefix >= 32 {
                return ip == net_ip;
            }
            let mask = !0u32 << (32 - prefix);
            return (u32::from(ip) & mask) == (u32::from(net_ip) & mask);
        }
    } else if let Ok(target_ip) = cidr_or_ip.parse::<Ipv4Addr>() {
        return ip == target_ip;
    }
    false
}
