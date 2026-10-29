use crate::ast::Config;
use crate::state::SharedState;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CF_CONFIG_PATH: &str = "/data/cloudflare.json";
const CF_PID_FILE: &str = "/run/cloudflared.pid";
const CF_LOG_FILE: &str = "/run/cloudflared.log";
const CF_PAUSED_FILE: &str = "/run/nfty-cloudflare.paused";
static CF_RECONCILE_GENERATION: AtomicU64 = AtomicU64::new(0);
static CF_RECONCILE_LOCK: Mutex<()> = Mutex::new(());
struct CloudflareQueueState {
    config: Config,
    pending: bool,
    failed: bool,
}
static CF_LAST_QUEUED_CONFIG: Mutex<Option<CloudflareQueueState>> = Mutex::new(None);

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
    /// Hostnames whose Access policies were successfully reconciled.
    #[serde(default)]
    pub protected_access_hosts: BTreeSet<String>,
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
            protected_access_hosts: BTreeSet::new(),
            last_status: None,
        }
    }
}

pub fn load_cloudflare_config() -> Result<CloudflareConfig> {
    match fs::read_to_string(CF_CONFIG_PATH) {
        Ok(raw) => serde_json::from_str(&raw).context("Failed to parse Cloudflare configuration"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CloudflareConfig::default()),
        Err(e) => Err(e).context("Failed to read Cloudflare configuration"),
    }
}

pub fn save_cloudflare_config(cfg: &CloudflareConfig) -> Result<()> {
    fs::create_dir_all("/data")?;
    let json_str = serde_json::to_string_pretty(cfg)?;
    crate::unikernel::write_atomic(Path::new(CF_CONFIG_PATH), json_str.as_bytes())
}

fn resume_cloudflare_supervision() -> Result<()> {
    match fs::remove_file(CF_PAUSED_FILE) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("Failed to resume Cloudflare supervision"),
    }
}

fn load_cloudflare_config_or_stop() -> Result<CloudflareConfig> {
    match load_cloudflare_config() {
        Ok(config) => Ok(config),
        Err(error) => {
            if let Err(stop_error) = stop_cloudflared_daemon() {
                bail!("{}; connector stop failed: {}", error, stop_error);
            }
            Err(error.context("Cloudflare connector stopped"))
        }
    }
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

/// Discovers Cloudflare Account ID and Zone list (`zone_name -> zone_id`) using the API token.
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

/// Tunnel origin for a service. Email-protected hosts fail closed until their Access policy is confirmed.
fn cloudflare_upstream(svc: &crate::ast::Service, cf_cfg: &CloudflareConfig) -> String {
    let access_pending = !svc.cloudflare_auth.is_empty()
        && !svc
            .cloudflare
            .as_ref()
            .is_some_and(|host| cf_cfg.protected_access_hosts.contains(&host.to_ascii_lowercase()));
    if access_pending {
        "http_status:403".to_string()
    } else if let Some(b) = svc.backends.first() {
        let scheme = match b.port {
            443 | 8443 => "https",
            22 => "ssh",
            _ => "http",
        };
        format!("{}://{}:{}", scheme, b.ip, b.port)
    } else if let Some(lip) = svc.listen_ip {
        format!("http://{}:{}", lip, svc.port)
    } else {
        format!("http://127.0.0.1:{}", svc.port)
    }
}

pub fn collect_cloudflare_routes(config: &Config) -> Result<Vec<(String, String, String)>> {
    let cf_cfg = load_cloudflare_config()?;
    Ok(collect_cloudflare_routes_with_config(config, &cf_cfg))
}

pub(crate) fn collect_cloudflare_routes_with_config(
    config: &Config,
    cf_cfg: &CloudflareConfig,
) -> Vec<(String, String, String)> {
    config
        .services
        .values()
        .filter_map(|svc| {
            let cf_host = svc.cloudflare.as_ref()?;
            Some((svc.key.clone(), cf_host.clone(), cloudflare_upstream(svc, cf_cfg)))
        })
        .collect()
}

pub fn cloudflared_running_pid() -> Option<u32> {
    let pid = fs::read_to_string(CF_PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())?;
    let exe_is_cloudflared = fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .and_then(|path| path.file_name().map(|name| name == "cloudflared"))
        .unwrap_or(false);
    if exe_is_cloudflared {
        return Some(pid);
    }
    None
}

pub fn stop_cloudflared_daemon() -> Result<()> {
    if let Some(pid) = cloudflared_running_pid() {
        unsafe {
            if libc::kill(pid as i32, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to stop cloudflared {}", pid));
            }
        }
        for _ in 0..40 {
            if cloudflared_running_pid() != Some(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if cloudflared_running_pid() == Some(pid) {
            bail!("cloudflared {} did not stop", pid);
        }
    }
    match fs::remove_file(CF_PID_FILE) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("Failed to remove cloudflared PID file"),
    }
    Ok(())
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
        let _ = fs::write(
            "/etc/resolv.conf",
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\n",
        );
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

    let mut child = Command::new(bin)
        .env("TUNNEL_TOKEN", tunnel_token.trim())
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
        ])
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_err))
        .spawn()
        .with_context(|| "Failed to spawn cloudflared daemon")?;

    let pid = child.id();
    if let Err(e) = fs::write(CF_PID_FILE, format!("{}\n", pid)) {
        if let Err(cleanup) = child.kill() {
            bail!("Cannot record cloudflared PID: {}; failed to stop child: {}", e, cleanup);
        }
        let _ = child.wait();
        return Err(e).context("Cannot record cloudflared PID");
    }
    let child = Arc::new(Mutex::new(child));
    let reaper_child = child.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("nfty-cloudflared-reaper".to_string())
        .spawn(move || {
            match reaper_child.lock() {
                Ok(mut child) => {
                    if let Err(e) = child.wait() {
                        eprintln!("nfty: failed to reap cloudflared: {}", e);
                    }
                }
                Err(_) => eprintln!("nfty: cloudflared reaper lock is poisoned"),
            }
        })
    {
        let mut child = child.lock().map_err(|_| anyhow::anyhow!("cloudflared child lock is poisoned"))?;
        if child.try_wait()?.is_none() {
            child.kill().context("Failed to stop cloudflared after reaper startup failed")?;
            child.wait().context("Failed to reap cloudflared after reaper startup failed")?;
        }
        match fs::remove_file(CF_PID_FILE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("Failed to remove cloudflared PID after reaper startup failed"),
        }
        return Err(error).context("Failed to start cloudflared reaper");
    }
    Ok(pid)
}

/// Reconciles Cloudflare Tunnel, ingress rules, DNS CNAME records, and the local `cloudflared` daemon.
pub fn reconcile_cloudflare_tunnel(config: &Config) -> Result<Vec<String>> {
    resume_cloudflare_supervision()?;
    let generation = {
        let mut last = CF_LAST_QUEUED_CONFIG
            .lock()
            .map_err(|_| anyhow::anyhow!("Cloudflare queue lock is poisoned"))?;
        *last = Some(CloudflareQueueState { config: config.clone(), pending: true, failed: false });
        CF_RECONCILE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
    };
    let result = reconcile_cloudflare_generation(config, generation);
    if result.is_ok() {
        complete_cloudflare_reconcile(config, generation);
    } else {
        mark_failed_cloudflare_reconcile(config, generation);
    }
    result
}

pub(crate) fn update_cloudflare_config_and_reconcile<F>(
    config: &Config,
    update: F,
) -> Result<Vec<String>>
where
    F: FnOnce(&mut CloudflareConfig),
{
    resume_cloudflare_supervision()?;
    let generation = {
        let mut last = CF_LAST_QUEUED_CONFIG
            .lock()
            .map_err(|_| anyhow::anyhow!("Cloudflare queue lock is poisoned"))?;
        *last = Some(CloudflareQueueState { config: config.clone(), pending: true, failed: false });
        CF_RECONCILE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
    };
    let result = (|| {
        let _guard = CF_RECONCILE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("Cloudflare supervisor lock is poisoned"))?;
        if generation != CF_RECONCILE_GENERATION.load(Ordering::SeqCst) {
            bail!("Cloudflare reconciliation superseded by a newer configuration");
        }
        let mut cf_cfg = load_cloudflare_config_or_stop()?;
        update(&mut cf_cfg);
        save_cloudflare_config(&cf_cfg)?;
        reconcile_cloudflare_locked(config)
    })();
    if result.is_ok() {
        complete_cloudflare_reconcile(config, generation);
    } else {
        mark_failed_cloudflare_reconcile(config, generation);
    }
    result
}

pub(crate) fn prepare_cloudflare_config_update() -> Result<()> {
    let _guard = CF_RECONCILE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("Cloudflare supervisor lock is poisoned"))?;
    let mut last = CF_LAST_QUEUED_CONFIG
        .lock()
        .map_err(|_| anyhow::anyhow!("Cloudflare queue lock is poisoned"))?;
    CF_RECONCILE_GENERATION.fetch_add(1, Ordering::SeqCst);
    *last = None;
    drop(last);
    stop_cloudflared_daemon()
}

fn mark_failed_cloudflare_reconcile(config: &Config, generation: u64) {
    match CF_LAST_QUEUED_CONFIG.lock() {
        Ok(mut last) => {
            if generation == CF_RECONCILE_GENERATION.load(Ordering::SeqCst)
                && last.as_ref().map(|state| &state.config) == Some(config)
            {
                if let Some(state) = last.as_mut() {
                    state.pending = false;
                    state.failed = true;
                }
            }
        }
        Err(_) => eprintln!("nfty: Cloudflare queue lock is poisoned"),
    }
}

fn complete_cloudflare_reconcile(config: &Config, generation: u64) {
    match CF_LAST_QUEUED_CONFIG.lock() {
        Ok(mut last) => {
            if generation == CF_RECONCILE_GENERATION.load(Ordering::SeqCst) {
                if let Some(state) = last.as_mut().filter(|state| &state.config == config) {
                    state.pending = false;
                    state.failed = false;
                }
            }
        }
        Err(_) => eprintln!("nfty: Cloudflare queue lock is poisoned"),
    }
}

pub(crate) fn queue_cloudflare_reconcile(config: Config) -> Result<()> {
    if Path::new(CF_PAUSED_FILE).exists() {
        return Ok(());
    }
    let generation = {
        let mut last = CF_LAST_QUEUED_CONFIG
            .lock()
            .map_err(|_| anyhow::anyhow!("Cloudflare queue lock is poisoned"))?;
        if let Some(state) = last.as_ref().filter(|state| state.config == config) {
            let has_routes = config.services.values().any(|service| service.cloudflare.is_some());
            if state.pending
                || (!state.failed && (!has_routes || cloudflared_running_pid().is_some()))
            {
                return Ok(());
            }
        }
        *last = Some(CloudflareQueueState { config: config.clone(), pending: true, failed: false });
        CF_RECONCILE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
    };
    let worker_config = config.clone();
    let worker = std::thread::Builder::new().name("nfty-cloudflare".to_string()).spawn(move || {
        match reconcile_cloudflare_generation(&worker_config, generation) {
            Ok(logs) => {
                complete_cloudflare_reconcile(&worker_config, generation);
                for log in logs {
                    eprintln!("nfty: {}", log);
                }
            }
            Err(e) => {
                mark_failed_cloudflare_reconcile(&worker_config, generation);
                eprintln!("nfty: Cloudflare reconciliation failed: {:#}", e);
            }
        }
    });
    if let Err(e) = worker {
        mark_failed_cloudflare_reconcile(&config, generation);
        return Err(e).context("Failed to start Cloudflare reconciliation worker");
    }
    Ok(())
}

pub(crate) async fn run_cloudflare_supervisor(shared: SharedState) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if unsafe { libc::geteuid() != 0 } {
            continue;
        }
        if Path::new(CF_PAUSED_FILE).exists() {
            continue;
        }
        {
            let st = shared.read().unwrap();
            let config = st.active_config();
            let has_routes = config.services.values().any(|service| service.cloudflare.is_some());
            let should_retry = match CF_LAST_QUEUED_CONFIG.lock() {
                Ok(last) => last.as_ref()
                    .map(|state| {
                        if state.config != *config {
                            return true;
                        }
                        !state.pending
                            && (state.failed || (has_routes && cloudflared_running_pid().is_none()))
                    })
                    .unwrap_or(has_routes),
                Err(_) => {
                    eprintln!("nfty: Cloudflare queue lock is poisoned");
                    false
                }
            };
            if should_retry {
                if let Err(e) = queue_cloudflare_reconcile(config.clone()) {
                    eprintln!("nfty: cannot restart Cloudflare reconciliation: {:#}", e);
                }
            }
        }
    }
}

fn reconcile_cloudflare_generation(config: &Config, generation: u64) -> Result<Vec<String>> {
    let Ok(_guard) = CF_RECONCILE_LOCK.lock() else {
        bail!("Cloudflare supervisor lock is poisoned");
    };
    if generation != CF_RECONCILE_GENERATION.load(Ordering::SeqCst) {
        bail!("Cloudflare reconciliation superseded by a newer configuration");
    }
    if Path::new(CF_PAUSED_FILE).exists() {
        return Ok(vec!["Cloudflare connector is manually stopped".to_string()]);
    }
    reconcile_cloudflare_locked(config)
}

fn reconcile_cloudflare_locked(config: &Config) -> Result<Vec<String>> {
    let mut logs = Vec::new();
    let mut cf_cfg = load_cloudflare_config_or_stop()?;
    let routes = collect_cloudflare_routes_with_config(config, &cf_cfg);
    if config.services.values().any(|svc| {
        svc.cloudflare.is_some() && !svc.cloudflare_auth.is_empty()
    }) {
        stop_cloudflared_daemon()?;
    }

    if routes.is_empty() && cf_cfg.managed_dns_records.is_empty() {
        if cloudflared_running_pid().is_some() {
            stop_cloudflared_daemon()?;
            logs.push(
                "Cloudflare: stopped cloudflared daemon (no cloudflare-dns services active)"
                    .to_string(),
            );
        }
        return Ok(logs);
    }

    if let Some(api_token) = cf_cfg.api_token.clone() {
        match reconcile_with_cf_api(config, &api_token, &routes, &mut cf_cfg) {
            Ok(mut api_logs) => {
                cf_cfg.last_status = Some("OK (synced with Cloudflare API)".to_string());
                if let Err(e) = save_cloudflare_config(&cf_cfg) {
                    if let Err(stop_error) = stop_cloudflared_daemon() {
                        bail!("Cannot save Cloudflare configuration: {}; connector stop failed: {}", e, stop_error);
                    }
                    return Err(e.context("Cloudflare connector stopped: cannot save configuration"));
                }
                logs.append(&mut api_logs);
            }
            Err(e) => {
                let err_msg = format!("ERROR: {}", e);
                cf_cfg.last_status = Some(err_msg);
                let save_error = save_cloudflare_config(&cf_cfg).err();
                if let Err(stop_error) = stop_cloudflared_daemon() {
                    bail!("Cloudflare API sync failed: {}; connector stop failed: {}", e, stop_error);
                }
                if let Some(save_error) = save_error {
                    bail!("Cloudflare API sync failed: {}; status could not be saved: {}", e, save_error);
                }
                return Err(e.context("Cloudflare API sync failed; connector stopped"));
            }
        }
    } else if config.services.values().any(|svc| {
        svc.cloudflare.is_some() && svc.cloudflare_auth.iter().any(|rule| rule.contains('@'))
    }) {
        stop_cloudflared_daemon()?;
        bail!("Cloudflare connector stopped: email policies cannot be verified without an API token");
    } else if !routes.is_empty() && cf_cfg.tunnel_token.is_none() {
        bail!("Cloudflare services are configured, but no API token or tunnel token is set");
    }

    if Path::new(CF_PAUSED_FILE).exists() {
        stop_cloudflared_daemon()?;
        logs.push("Cloudflare connector is manually stopped".to_string());
    } else if routes.is_empty() {
        stop_cloudflared_daemon()?;
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
                return Err(e.context("Failed to start cloudflared"));
            }
        }
    } else {
        bail!("Cloudflare reconciliation did not provide a tunnel token");
    }

    Ok(logs)
}

fn reconcile_with_cf_api(
    config: &Config,
    api_token: &str,
    _routes: &[(String, String, String)],
    cf_cfg: &mut CloudflareConfig,
) -> Result<Vec<String>> {
    let mut logs = Vec::new();
    cf_cfg.protected_access_hosts.clear();
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
                let mut allowed_idps: Vec<String> =
                    cf_api_request("GET", &idps_path, api_token, None)
                        .ok()
                        .and_then(|resp| {
                            resp.get("result")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter(|item| {
                                            item.get("type").and_then(|t| t.as_str())
                                                != Some("cloudflare")
                                        })
                                        .filter_map(|item| {
                                            item.get("id")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string())
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
                    if let Ok(created_idp) =
                        cf_api_request("POST", &idps_path, api_token, Some(otp_body))
                    {
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
                    if cf_cfg.managed_access_apps.get(hostname) != Some(&aid) {
                        bail!("Refusing to modify unmanaged Cloudflare Access application for '{}'", hostname);
                    }
                    let put_app = format!("accounts/{}/access/apps/{}", account_id, aid);
                    cf_api_request("PUT", &put_app, api_token, Some(app_body))?;
                    aid
                } else {
                    let created_app =
                        cf_api_request("POST", &apps_path, api_token, Some(app_body))?;
                    created_app
                        .get("result")
                        .and_then(|r| r.get("id"))
                        .and_then(|v| v.as_str())
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("Cloudflare Access application creation returned no id"))?
                        .to_string()
                };

                if !app_id.is_empty() {
                    cf_cfg
                        .managed_access_apps
                        .insert(hostname.clone(), app_id.clone());
                    let pols_path =
                        format!("accounts/{}/access/apps/{}/policies", account_id, app_id);
                    let policies = cf_api_request("GET", &pols_path, api_token, None)?;
                    let policies = policies.get("result")
                        .and_then(|v| v.as_array())
                        .ok_or_else(|| anyhow::anyhow!("Cloudflare returned an invalid Access policy list"))?;
                    if policies.len() > 1 || policies.iter().any(|policy| {
                        policy.get("name").and_then(|v| v.as_str()) != Some("nfty allow policy")
                    }) {
                        bail!("Refusing to modify additional or unmanaged Access policies for '{}'", hostname);
                    }
                    let existing_pol_id = policies.first()
                        .map(|item| item.get("id").and_then(|v| v.as_str())
                            .filter(|id| !id.is_empty())
                            .map(str::to_string)
                            .ok_or_else(|| anyhow::anyhow!("Cloudflare Access policy has no id")))
                        .transpose()?;
                    let pol_body = serde_json::json!({
                        "name": "nfty allow policy",
                        "decision": "allow",
                        "include": include_objs,
                        "precedence": 1
                    });
                    if let Some(pid) = existing_pol_id {
                        let put_pol = format!("{}/{}", pols_path, pid);
                        cf_api_request("PUT", &put_pol, api_token, Some(pol_body))?;
                    } else {
                        cf_api_request("POST", &pols_path, api_token, Some(pol_body))?;
                    }
                    cf_cfg.protected_access_hosts.insert(hostname.to_ascii_lowercase());
                    logs.push(format!(
                        "Cloudflare Access: synced Zero-Trust policy for {} ({:?})",
                        hostname, email_rules
                    ));
                }
            }
            Err(e) => {
                cf_cfg.access_api_enabled = Some(false);
                return Err(e.context(format!("Cloudflare Access unavailable for '{}'", hostname)));
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
                cf_api_request("DELETE", &del_path, api_token, None)?;
                logs.push(format!(
                    "Cloudflare Access: removed Access Application for '{}'",
                    stale
                ));
            }
        }
    }

    // Recompute after Access sync so unconfirmed email-protected hosts route to 403.
    let effective_routes = collect_cloudflare_routes_with_config(config, cf_cfg);
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
            cf_api_request("DELETE", &del_path, api_token, None)?;
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
        None | Some("status") => {
            let cf_cfg = load_cloudflare_config()?;
            let st = shared.read().unwrap();
            let cfg = st.active_config();
            let routes = collect_cloudflare_routes_with_config(cfg, &cf_cfg);
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
                            if s.cloudflare_auth.is_empty() {
                                "open (none)".dimmed().to_string()
                            } else {
                                format!("🔒 {}", s.cloudflare_auth.join(", "))
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
        Some("token") => {
            if args.len() < 2 {
                bail!("Usage: cf token <CLOUDFLARE_API_TOKEN> [ACCOUNT_ID]");
            }
            let api_token = args[1].trim().to_string();
            let explicit_acct = args.get(2).map(|s| s.trim().to_string());
            println!("Verifying Cloudflare API token...");
            let (disc_acct, zones) = discover_cf_account_and_zones(&api_token)?;
            let st = shared.read().unwrap();
            let account = explicit_acct.or(disc_acct);
            let logs = update_cloudflare_config_and_reconcile(st.active_config(), move |cf_cfg| {
                cf_cfg.api_token = Some(api_token);
                if let Some(a) = account {
                    cf_cfg.account_id = Some(a);
                }
            })?;
            let cf_cfg = load_cloudflare_config()?;
            println!(
                "  {} Saved Cloudflare API token in {} (Account: {}, Zones discovered: {:?})",
                "✔".green().bold(),
                CF_CONFIG_PATH.bold(),
                cf_cfg.account_id.as_deref().unwrap_or("pending"),
                zones.keys().collect::<Vec<_>>()
            );
            for log in logs {
                println!("  {} {}", "→".cyan(), log);
            }
            Ok(())
        }
        Some("tunnel-token") => {
            if args.len() < 2 {
                bail!("Usage: cf tunnel-token <EYJH...>");
            }
            let st = shared.read().unwrap();
            let tunnel_token = args[1].trim().to_string();
            let logs = update_cloudflare_config_and_reconcile(st.active_config(), move |cf_cfg| {
                cf_cfg.tunnel_token = Some(tunnel_token);
            })?;
            for log in logs {
                println!("  {} {}", "→".cyan(), log);
            }
            println!(
                "  {} Saved Cloudflare tunnel connector token",
                "✔".green().bold()
            );
            Ok(())
        }
        Some("sync") => {
            let st = shared.read().unwrap();
            let logs = reconcile_cloudflare_tunnel(st.active_config())?;
            if logs.is_empty() {
                println!("  (No Cloudflare Tunnel routes configured)");
            } else {
                for l in logs {
                    println!("  {} {}", "→".cyan(), l);
                }
            }
            Ok(())
        }
        Some("logs") => {
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
        Some("stop") | Some("clear") => {
            let _st = shared.write().unwrap();
            crate::unikernel::write_atomic(Path::new(CF_PAUSED_FILE), b"paused\n")
                .context("Failed to pause Cloudflare supervision")?;
            prepare_cloudflare_config_update()?;
            if sub.as_deref() != Some("stop") {
                match fs::remove_file(CF_CONFIG_PATH) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).context("Failed to clear Cloudflare configuration"),
                }
                println!(
                    "  {} Stopped cloudflared and cleared {}",
                    "✔".green().bold(),
                    CF_CONFIG_PATH
                );
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
