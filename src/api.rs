use crate::ast::Service;
use crate::compiler::{
    apply_vip_commands, compile_nft_ruleset, generate_vip_commands, reload_kernel_from_state,
    validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once};
use crate::parser::{parse_nftyfile, validate_allow_entry};
use crate::repl::{handle_line, ShellLevel};
use crate::state::SharedState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct AllowListRequest {
    /// Optional service key (e.g. "9000" or "192.168.1.240:443"). If omitted, applies to global allow-list.
    pub service: Option<String>,
    /// List of hostnames, wildcard hostnames ("*.office.lan"), IP wildcards ("192.168.1.*"), or CIDRs
    pub hosts: Vec<String>,
    /// Whether to immediately apply changes to running config & kernel nftables (defaults to true)
    #[serde(default = "default_true")]
    pub apply: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct HostRegistrationRequest {
    pub host: String,
    pub ips: Vec<Ipv4Addr>,
}

#[derive(Debug, Deserialize)]
pub struct CliExecRequest {
    pub command: String,
}

#[derive(Debug, Deserialize)]
pub struct BackendToggleRequest {
    pub backend: String,
}

#[derive(Debug, Deserialize)]
pub struct WgUploadRequest {
    pub name: String,
    pub config: String,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfigRequest {
    pub api_token: Option<String>,
    pub account_id: Option<String>,
    pub tunnel_name: Option<String>,
    pub tunnel_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AllowStatusResponse {
    pub global_allow: Vec<String>,
    pub service_allow: BTreeMap<String, Vec<String>>,
    pub resolved_hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    pub expanded_service_sets: BTreeMap<String, Vec<String>>,
}

pub fn spawn_api_server(shared: SharedState, bind_addr: String) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(_) => return,
        };
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let st = shared.clone();
                tokio::spawn(async move {
                    let _ = handle_http_connection(stream, st).await;
                });
            }
        }
    });
}

async fn handle_http_connection(mut stream: TcpStream, shared: SharedState) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (header_part, body_part) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let request_line = header_part.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_json(&mut stream, 400, &json!({"error": "Malformed HTTP request"})).await?;
        return Ok(());
    }
    let method = parts[0].to_ascii_uppercase();
    let full_path = parts[1];
    let (path, _query) = full_path.split_once('?').unwrap_or((full_path, ""));

    if method == "GET" && matches!(path, "/" | "/ui" | "/dashboard" | "/index.html") {
        send_html(&mut stream, 200, READONLY_DASHBOARD_HTML).await?;
        return Ok(());
    }

    let (status, resp_val) = route_api_request(&method, path, body_part.trim(), &shared).await;
    if matches!(method.as_str(), "POST" | "PUT" | "DELETE") && status == 200 {
        crate::unikernel::persist_to_storage(&shared);
    }
    send_json(&mut stream, status, &resp_val).await?;
    Ok(())
}

pub async fn route_api_request(
    method: &str,
    path: &str,
    body: &str,
    shared: &SharedState,
) -> (u16, serde_json::Value) {
    if let Ok(mut st) = shared.write() {
        st.sync_from_disk_if_changed();
    }
    match (method, path) {
        ("GET", "/api/v1/status") | ("GET", "/status") => {
            let flows = crate::features::read_active_flows(shared);
            let wg_configs = crate::features::list_saved_wg_configs();
            let st = shared.read().unwrap();
            let cfg = if !st.running.services.is_empty()
                || !st.running.gateways.is_empty()
                || !st.running.global_allow.is_empty()
            {
                &st.running
            } else {
                &st.candidate
            };
            let nft = compile_nft_ruleset(cfg, Some(&st));
            let mut active_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (k, svc) in &cfg.services {
                active_map.insert(
                    k.clone(),
                    st.active_backends_for_service(&svc.backends)
                        .into_iter()
                        .map(|b| b.endpoint())
                        .collect(),
                );
            }
            (
                200,
                json!({
                    "running": st.running,
                    "candidate": st.candidate,
                    "active_config": cfg,
                    "nftyfile": cfg.format_nftyfile(),
                    "runtime": st.runtime,
                    "active_backends": active_map,
                    "resolved_hosts": st.resolved_hosts,
                    "flows": flows,
                    "wg_configs": wg_configs,
                    "kernel_applied": st.kernel_applied,
                    "nft_ruleset": nft,
                }),
            )
        }
        ("GET", "/api/v1/flows") => {
            let flows = crate::features::read_active_flows(shared);
            (200, json!({"ok": true, "flows": flows}))
        }
        ("GET", "/api/v1/scan") | ("POST", "/api/v1/scan") => {
            let filter = if body.is_empty() { None } else { Some(body) };
            let discovered = crate::features::scan_network_services(filter, shared);
            (200, json!({"ok": true, "discovered": discovered}))
        }
        ("GET", "/api/v1/wg") => {
            let wg_configs = crate::features::list_saved_wg_configs();
            (200, json!({"ok": true, "wg_configs": wg_configs}))
        }
        ("GET", "/api/v1/cloudflare") | ("GET", "/api/v1/cf") => {
            let cf = crate::features::load_cloudflare_config();
            let routes = {
                let st = shared.read().unwrap();
                let cfg = if !st.running.services.is_empty() {
                    &st.running
                } else {
                    &st.candidate
                };
                crate::features::collect_cloudflare_routes(cfg)
            };
            (
                200,
                json!({
                    "ok": true,
                    "api_token_configured": cf.api_token.as_ref().map(|t| !t.is_empty()).unwrap_or(false),
                    "account_id": cf.account_id,
                    "tunnel_name": cf.tunnel_name,
                    "tunnel_id": cf.tunnel_id,
                    "daemon_running": crate::features::cloudflared_running_pid().is_some(),
                    "daemon_pid": crate::features::cloudflared_running_pid(),
                    "provisioned_hostnames": cf.managed_dns_records.keys().collect::<Vec<_>>(),
                    "routes": routes,
                }),
            )
        }
        ("POST", "/api/v1/cloudflare") | ("POST", "/api/v1/cf") => {
            let req: CloudflareConfigRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut cf = crate::features::load_cloudflare_config();
            if let Some(tok) = req.api_token {
                cf.api_token = Some(tok.trim().to_string());
            }
            if let Some(acc) = req.account_id {
                cf.account_id = Some(acc.trim().to_string());
            }
            if let Some(name) = req.tunnel_name {
                cf.tunnel_name = name.trim().to_string();
            }
            if let Some(tt) = req.tunnel_token {
                cf.tunnel_token = Some(tt.trim().to_string());
            }
            if let Err(e) = crate::features::save_cloudflare_config(&cf) {
                return (500, json!({"ok": false, "error": e.to_string()}));
            }
            let cfg = {
                let st = shared.read().unwrap();
                if !st.running.services.is_empty() {
                    st.running.clone()
                } else {
                    st.candidate.clone()
                }
            };
            let logs = crate::features::reconcile_cloudflare_tunnel(&cfg);
            (200, json!({"ok": true, "logs": logs}))
        }
        ("POST", "/api/v1/wg") => {
            let req: WgUploadRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            match crate::features::save_wg_config_file(&req.name, &req.config) {
                Ok((filename, parsed)) => (
                    200,
                    json!({
                        "ok": true,
                        "filename": filename,
                        "parsed": parsed,
                    }),
                ),
                Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
            }
        }
        ("GET", "/api/v1/config") => {
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "running": st.running,
                    "candidate": st.candidate,
                    "nftyfile_running": st.running.format_nftyfile(),
                    "nftyfile_candidate": st.candidate.format_nftyfile(),
                }),
            )
        }
        ("PUT", "/api/v1/config") => match parse_nftyfile(body) {
            Ok(mut cfg) => {
                {
                    let mut st = shared.write().unwrap();
                    let prev = st.running.clone();
                    let _ = crate::compiler::reconcile_dhcp_and_vlan_vips(&mut cfg);
                    let vip_cmds = generate_vip_commands(&prev, &cfg);
                    let _ = apply_vip_commands(&vip_cmds);
                    st.history.push(prev);
                    st.candidate = cfg.clone();
                    st.running = cfg;
                    st.sync_runtime_entries();
                    let _ = reload_kernel_from_state(&mut st);
                }
                refresh_allowlist_hosts(shared).await;
                let st = shared.read().unwrap();
                (
                    200,
                    json!({
                        "ok": true,
                        "running": st.running,
                    }),
                )
            }
            Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
        },
        ("GET", "/api/v1/nft") => {
            let st = shared.read().unwrap();
            let cfg = if !st.running.services.is_empty() {
                &st.running
            } else {
                &st.candidate
            };
            (
                200,
                json!({
                    "nft": compile_nft_ruleset(cfg, Some(&st))
                }),
            )
        }
        ("GET", "/api/v1/allow") => {
            let st = shared.read().unwrap();
            let cfg = if !st.running.services.is_empty() {
                &st.running
            } else {
                &st.candidate
            };
            let mut service_allow = BTreeMap::new();
            let mut expanded_service_sets = BTreeMap::new();
            for (k, svc) in &cfg.services {
                service_allow.insert(k.clone(), svc.allow.clone());
                expanded_service_sets.insert(
                    k.clone(),
                    st.expand_allow_elements(&svc.allow, &cfg.global_allow),
                );
            }
            let resp = AllowStatusResponse {
                global_allow: cfg.global_allow.clone(),
                service_allow,
                resolved_hosts: st.resolved_hosts.clone(),
                expanded_service_sets,
            };
            (200, serde_json::to_value(resp).unwrap())
        }
        // Add or replace allow-list entries (supports wildcards like "*.office.lan", "192.168.1.*", hostnames, CIDRs)
        ("POST", "/api/v1/allow") | ("PUT", "/api/v1/allow") => {
            let req: AllowListRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let replace_mode = method == "PUT";
            let mut validated = Vec::new();
            for h in &req.hosts {
                match validate_allow_entry(h) {
                    Ok(v) => validated.push(v),
                    Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
                }
            }

            {
                let mut st = shared.write().unwrap();
                if let Some(svc_key) = &req.service {
                    let Some(svc) = st.candidate.services.get_mut(svc_key) else {
                        return (
                            404,
                            json!({"ok": false, "error": format!("Service '{}' not found", svc_key)}),
                        );
                    };
                    if replace_mode {
                        svc.allow = validated.clone();
                    } else {
                        for v in validated {
                            if !svc.allow.contains(&v) {
                                svc.allow.push(v);
                            }
                        }
                    }
                } else if replace_mode {
                    st.candidate.global_allow = validated;
                } else {
                    for v in validated {
                        if !st.candidate.global_allow.contains(&v) {
                            st.candidate.global_allow.push(v);
                        }
                    }
                }

                if req.apply {
                    st.running = st.candidate.clone();
                    let _ = reload_kernel_from_state(&mut st);
                }
            }

            // Immediately run DNS & wildcard host resolution and update nftables
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "global_allow": st.running.global_allow,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        ("DELETE", "/api/v1/allow") => {
            let req: AllowListRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let targets: Vec<String> = req
                .hosts
                .iter()
                .map(|h| validate_allow_entry(h).unwrap_or_else(|_| h.to_ascii_lowercase()))
                .collect();

            {
                let mut st = shared.write().unwrap();
                if let Some(svc_key) = &req.service {
                    if let Some(svc) = st.candidate.services.get_mut(svc_key) {
                        svc.allow.retain(|x| !targets.contains(x));
                    }
                } else {
                    st.candidate.global_allow.retain(|x| !targets.contains(x));
                }
                if req.apply {
                    st.running = st.candidate.clone();
                    let _ = reload_kernel_from_state(&mut st);
                }
            }
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "global_allow": st.running.global_allow,
                }),
            )
        }
        // Register or update a hostname -> IP mapping (e.g. for wildcard rules like `*.office.lan`)
        ("POST", "/api/v1/allow/hosts") | ("PUT", "/api/v1/allow/hosts") => {
            let req: HostRegistrationRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let host = req.host.trim().to_ascii_lowercase();
            {
                let mut st = shared.write().unwrap();
                if req.ips.is_empty() {
                    st.resolved_hosts.remove(&host);
                } else {
                    st.resolved_hosts.insert(host.clone(), req.ips.clone());
                }
                if !st.running.services.is_empty() {
                    let _ = reload_kernel_from_state(&mut st);
                }
            }
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "host": host,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        ("POST", "/api/v1/allow/refresh") => {
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        // 1:1 CLI command execution over HTTP API
        ("POST", "/api/v1/cli") => {
            let req: CliExecRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let level = Arc::new(Mutex::new(ShellLevel::ConfigRoot));
            for cmd in req.command.lines().flat_map(|l| l.split(';')) {
                let trimmed = cmd.trim();
                if !trimmed.is_empty() {
                    handle_line(trimmed, &level, shared).await;
                }
            }
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "candidate": st.candidate,
                    "running": st.running,
                    "nftyfile": st.candidate.format_nftyfile(),
                }),
            )
        }
        ("POST", "/api/v1/apply") => {
            let report = {
                let st = shared.read().unwrap();
                validate_config(&st.candidate, Some(&st))
            };
            if !report.valid {
                return (400, serde_json::to_value(report).unwrap());
            }
            {
                let mut st = shared.write().unwrap();
                let prev = st.running.clone();
                let next = st.candidate.clone();
                let vip_cmds = generate_vip_commands(&prev, &next);
                let _ = apply_vip_commands(&vip_cmds);
                st.history.push(prev);
                st.running = next;
                st.sync_runtime_entries();
                let _ = reload_kernel_from_state(&mut st);
            }
            refresh_allowlist_hosts(shared).await;
            let _ = run_all_probes_once(shared).await;
            (200, json!({"ok": true, "message": "Configuration applied"}))
        }
        ("POST", "/api/v1/probe") => {
            let outcomes = run_all_probes_once(shared).await;
            (200, json!({"ok": true, "outcomes": outcomes}))
        }
        ("POST", "/api/v1/drain") => {
            let req: BackendToggleRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut st = shared.write().unwrap();
            st.runtime.entry(req.backend.clone()).or_default().drained = true;
            let _ = reload_kernel_from_state(&mut st);
            (200, json!({"ok": true, "backend": req.backend, "drained": true}))
        }
        ("POST", "/api/v1/enable") => {
            let req: BackendToggleRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut st = shared.write().unwrap();
            st.runtime.entry(req.backend.clone()).or_default().drained = false;
            let _ = reload_kernel_from_state(&mut st);
            (200, json!({"ok": true, "backend": req.backend, "drained": false}))
        }
        ("GET", "/api/v1/services") => {
            let st = shared.read().unwrap();
            (200, json!({"services": st.candidate.services}))
        }
        _ if path.starts_with("/api/v1/services/") => {
            let key = path.trim_start_matches("/api/v1/services/");
            match method {
                "GET" => {
                    let st = shared.read().unwrap();
                    match st.candidate.services.get(key) {
                        Some(svc) => (200, serde_json::to_value(svc).unwrap()),
                        None => (404, json!({"error": "Service not found"})),
                    }
                }
                "PUT" | "POST" => match serde_json::from_str::<Service>(body) {
                    Ok(svc) => {
                        let mut st = shared.write().unwrap();
                        st.candidate.services.insert(svc.key.clone(), svc.clone());
                        st.running.services.insert(svc.key.clone(), svc);
                        st.sync_runtime_entries();
                        let _ = reload_kernel_from_state(&mut st);
                        (200, json!({"ok": true, "key": key}))
                    }
                    Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
                },
                "DELETE" => {
                    let mut st = shared.write().unwrap();
                    st.candidate.services.remove(key);
                    st.running.services.remove(key);
                    let _ = reload_kernel_from_state(&mut st);
                    (200, json!({"ok": true, "deleted": key}))
                }
                _ => (405, json!({"error": "Method not allowed"})),
            }
        }
        _ => (404, json!({"error": format!("Endpoint {} {} not found", method, path)})),
    }
}

async fn send_json(
    stream: &mut TcpStream,
    status: u16,
    val: &serde_json::Value,
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_string_pretty(val)?;
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn send_html(stream: &mut TcpStream, status: u16, html: &str) -> Result<()> {
    let status_text = if status == 200 { "OK" } else { "Error" };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        html.len(),
        html
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

const READONLY_DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nfty — L4 Service Load Balancer & Health Dashboard</title>
<style>
  :root {
    --bg: #0b0f19;
    --panel: #111827;
    --panel-alt: #1f2937;
    --border: #2e3a4e;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --cyan: #06b6d4;
    --green: #10b981;
    --red: #ef4444;
    --amber: #f59e0b;
    --purple: #8b5cf6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, monospace;
    padding: 24px;
    line-height: 1.5;
  }
  .container { max-width: 1360px; margin: 0 auto; }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 18px;
    margin-bottom: 22px;
    border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.02em; color: #fff; }
  .badge-ro {
    background: rgba(6, 182, 212, 0.15);
    color: var(--cyan);
    border: 1px solid rgba(6, 182, 212, 0.4);
    font-size: 0.75rem;
    padding: 3px 10px;
    border-radius: 999px;
    font-weight: 600;
  }
  .refresh-meta { font-size: 0.82rem; color: var(--muted); display: flex; align-items: center; gap: 8px; }
  .pulse {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green);
  }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
  }
  .card .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .card .val { font-size: 1.85rem; font-weight: 700; margin-top: 4px; }
  .section {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 24px;
    overflow: hidden;
  }
  .section-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 0.95rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(255,255,255,0.02);
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th, td { padding: 12px 18px; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
  }
  .pill-up { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.35); }
  .pill-down { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.35); }
  .pill-drain { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.35); }
  .pill-unknown { background: rgba(156, 163, 175, 0.15); color: var(--muted); border: 1px solid rgba(156, 163, 175, 0.3); }
  .tag {
    display: inline-block;
    background: var(--panel-alt);
    border: 1px solid var(--border);
    padding: 2px 8px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.78rem;
    margin: 2px;
  }
  .grid-2 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(480px, 1fr));
    gap: 20px;
  }
  pre {
    padding: 18px;
    overflow-x: auto;
    font-family: "JetBrains Mono", "Fira Code", monospace;
    font-size: 0.83rem;
    color: #e5e7eb;
    background: #080b12;
    min-height: 240px;
  }
  .empty { padding: 32px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>nfty</h1>
      <span class="badge-ro">READ-ONLY LIVE STATUS &amp; CONFIG VIEW</span>
    </div>
    <div class="refresh-meta">
      <span class="pulse"></span>
      <span id="last-updated">Connecting...</span>
    </div>
  </header>

  <div class="cards">
    <div class="card">
      <div class="label">Configured Services</div>
      <div class="val" id="stat-services" style="color: var(--cyan)">0</div>
    </div>
    <div class="card">
      <div class="label">Backends UP</div>
      <div class="val" id="stat-up" style="color: var(--green)">0</div>
    </div>
    <div class="card">
      <div class="label">Backends DOWN</div>
      <div class="val" id="stat-down" style="color: var(--red)">0</div>
    </div>
    <div class="card">
      <div class="label">Backends DRAINED</div>
      <div class="val" id="stat-drained" style="color: var(--amber)">0</div>
    </div>
    <div class="card">
      <div class="label">Allow-List Hosts Resolved</div>
      <div class="val" id="stat-hosts" style="color: var(--purple)">0</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span>L4 Services, Virtual Hostnames (mDNS/SNI) &amp; WireGuard Virtual Gateways</span>
    </div>
    <div id="services-table-wrap">
      <div class="empty">Loading services...</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span>Live Active Conntrack Flows (Real-Time Client &amp; Tunnel Connections)</span>
    </div>
    <div id="flows-table-wrap">
      <div class="empty">Loading active flows...</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="section">
      <div class="section-header">
        <span>Active Nftyfile Configuration</span>
      </div>
      <pre id="nftyfile-box"># Empty Nftyfile</pre>
    </div>

    <div class="section">
      <div class="section-header">
        <span>Compiled Kernel nftables Ruleset (table ip nfty)</span>
      </div>
      <pre id="nft-box"></pre>
    </div>
  </div>
</div>

<script>
async function refreshDashboard() {
  try {
    const res = await fetch('/api/v1/status');
    const data = await res.json();
    const cfg = data.active_config || { services: {}, gateways: {}, global_allow: [] };
    const services = Object.values(cfg.services || {});
    const gateways = Object.values(cfg.gateways || {});
    const runtime = data.runtime || {};
    const activeMap = data.active_backends || {};
    const resolvedHosts = data.resolved_hosts || {};
    const flows = data.flows || [];

    let up = 0, down = 0, drained = 0;
    let rowsHtml = '';

    for (const svc of services) {
      const activeEps = activeMap[svc.key] || [];
      const vipStr = svc.vip ? `${svc.vip.interface}/${svc.vip.prefix_len}` : 'any';
      const hostBadge = svc.hostname ? ` <span class="tag" style="border-color:var(--purple);color:var(--purple)">mDNS/SNI: ${svc.hostname}</span>` : '';
      const checkStr = svc.check
        ? (svc.check.kind.type === 'http'
            ? `http ${svc.check.kind.path} (${svc.check.interval_secs}s)`
            : `${svc.check.kind.type} (${svc.check.interval_secs}s)`)
        : 'tcp (default)';
      const limitStr = svc.limit ? `${svc.limit.rate}/${svc.limit.unit}` : 'none';
      const allowRules = [...(cfg.global_allow || []), ...(svc.allow || [])];
      const allowTags = allowRules.length
        ? allowRules.map(a => `<span class="tag">${a}</span>`).join('')
        : '<span style="color:var(--muted)">any</span>';

      const backends = svc.backends || [];
      if (backends.length === 0) {
        rowsHtml += `<tr>
          <td><strong>${svc.key}</strong> <span class="tag">${svc.proto}</span>${hostBadge}</td>
          <td><span class="tag">${vipStr}</span> <span class="tag">mode:${svc.mode}</span></td>
          <td><span class="tag">${svc.balance}</span> <span class="tag">limit:${limitStr}</span></td>
          <td>${allowTags}</td>
          <td colspan="4" style="color:var(--muted)">No backends configured</td>
        </tr>`;
        continue;
      }

      backends.forEach((b, idx) => {
        const ep = b.host ? `${b.host}(${b.ip}):${b.port}` : `${b.ip}:${b.port}`;
        const rt = runtime[ep] || { health: 'UNKNOWN', drained: false, packets: 0, bytes: 0, pps: 0 };
        const isRouting = activeEps.includes(ep);

        let pill = '';
        if (rt.drained) {
          drained++;
          pill = `<span class="pill pill-drain">● DRAINED</span>`;
        } else if (rt.health === 'UP') {
          up++;
          const lat = rt.latency_ms != null ? ` (${rt.latency_ms.toFixed(1)}ms)` : '';
          pill = `<span class="pill pill-up">● UP${lat}</span>`;
        } else if (rt.health === 'DOWN') {
          down++;
          const err = rt.last_error ? ` title="${rt.last_error}"` : '';
          pill = `<span class="pill pill-down"${err}>● DOWN</span>`;
        } else {
          pill = `<span class="pill pill-unknown">● UNCHECKED</span>`;
        }

        const roleTag = b.backup
          ? `<span class="tag" style="color:var(--amber)">backup (w=${b.weight})</span>`
          : `<span class="tag">primary (w=${b.weight})</span>`;

        const routeBadge = isRouting
          ? `<span class="tag" style="border-color:var(--green);color:var(--green)">ROUTING</span>`
          : `<span class="tag" style="color:var(--muted)">STANDBY/EXCLUDED</span>`;

        rowsHtml += `<tr>
          <td>${idx === 0 ? `<strong>${svc.key}</strong> <span class="tag">${svc.proto}</span>${hostBadge}` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">vip:${vipStr}</span> <span class="tag">mode:${svc.mode}</span>` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">${svc.balance}</span> <span class="tag">chk:${checkStr}</span> <span class="tag">limit:${limitStr}</span>` : ''}</td>
          <td>${idx === 0 ? allowTags : ''}</td>
          <td><strong>${ep}</strong> ${roleTag}</td>
          <td>${pill}</td>
          <td>${routeBadge}</td>
          <td><code>${rt.packets} pkts / ${rt.bytes} B (${(rt.pps || 0).toFixed(0)} pps)</code></td>
        </tr>`;
      });
    }

    for (const gw of gateways) {
      const vipStr = gw.vip ? `${gw.vip.interface}/${gw.vip.prefix_len}` : 'any';
      const ksTag = gw.killswitch
        ? `<span class="tag" style="border-color:var(--green);color:var(--green)">killswitch:on</span>`
        : `<span class="tag" style="color:var(--amber)">killswitch:off</span>`;
      const gwSvcs = (gw.services || []).map(s => `<span class="tag" style="border-color:var(--blue);color:var(--blue)">${s.kind}:${s.port}</span>`).join(' ');
      const tunnels = gw.tunnels || [];
      if (tunnels.length === 0) {
        up++;
        rowsHtml += `<tr>
          <td><strong>gw:${gw.key}</strong> <span class="tag">direct</span> ${gwSvcs}</td>
          <td><span class="tag">vip:${vipStr}</span></td>
          <td><span class="tag">direct (host eth0)</span></td>
          <td><span style="color:var(--muted)">any</span></td>
          <td><strong>host (eth0)</strong></td>
          <td><span class="pill pill-up">● UP (DIRECT)</span></td>
          <td><span class="tag" style="border-color:var(--green);color:var(--green)">ROUTING</span></td>
          <td><code>direct host gateway</code></td>
        </tr>`;
        continue;
      }
      tunnels.forEach((t, idx) => {
        const ep = `wg:${t.name}(${t.iface})`;
        const rt = runtime[ep] || { health: 'UNKNOWN', drained: false, packets: 0, bytes: 0, pps: 0 };
        let pill = '';
        if (rt.health === 'UP') {
          up++;
          const lat = rt.latency_ms != null ? ` (${rt.latency_ms.toFixed(1)}ms)` : '';
          pill = `<span class="pill pill-up">● UP${lat}</span>`;
        } else if (rt.health === 'DOWN') {
          down++;
          pill = `<span class="pill pill-down">● DOWN</span>`;
        } else {
          pill = `<span class="pill pill-unknown">● READY</span>`;
        }
        rowsHtml += `<tr>
          <td>${idx === 0 ? `<strong>gw:${gw.key}</strong> <span class="tag">wg-ecmp</span>` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">vip:${vipStr}</span> ${ksTag}` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">${gw.balance}</span>` : ''}</td>
          <td>${idx === 0 ? '<span style="color:var(--muted)">LAN</span>' : ''}</td>
          <td><strong>${ep}</strong> <span class="tag">w=${t.weight || 1}</span></td>
          <td>${pill}</td>
          <td><span class="tag" style="border-color:var(--green);color:var(--green)">ECMP TUNNEL</span></td>
          <td><code>${rt.packets} pkts / ${rt.bytes} B</code></td>
        </tr>`;
      });
    }

    document.getElementById('stat-services').textContent = services.length + gateways.length;
    document.getElementById('stat-up').textContent = up;
    document.getElementById('stat-down').textContent = down;
    document.getElementById('stat-drained').textContent = drained;
    document.getElementById('stat-hosts').textContent = Object.keys(resolvedHosts).length;

    const wrap = document.getElementById('services-table-wrap');
    if (services.length === 0 && gateways.length === 0) {
      wrap.innerHTML = `<div class="empty">No services or gateways configured yet. Connect via SSH (<code>ssh nfty@&lt;ip&gt;</code>) or CLI to add a service.</div>`;
    } else {
      wrap.innerHTML = `<table>
        <thead>
          <tr>
            <th>Service / Gateway</th>
            <th>VIP / Mode</th>
            <th>Strategy / Check / Limit</th>
            <th>Allow-List</th>
            <th>Backend / WG Tunnel</th>
            <th>Health Status</th>
            <th>Verdict Map</th>
            <th>Traffic</th>
          </tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>`;
    }

    const flowsWrap = document.getElementById('flows-table-wrap');
    if (flows.length === 0) {
      flowsWrap.innerHTML = `<div class="empty">No active conntrack flows right now.</div>`;
    } else {
      const flowRows = flows.slice(0, 25).map(f => `<tr>
        <td><span class="tag">${f.proto}</span></td>
        <td><span class="pill ${f.state === 'ESTABLISHED' ? 'pill-up' : 'pill-unknown'}">${f.state}</span></td>
        <td><code>${f.src}:${f.sport}</code></td>
        <td><strong>${f.dst}:${f.dport}</strong></td>
        <td><code style="color:var(--green)">${f.nat_target || 'direct'}</code></td>
        <td><code>${f.mark !== '0' ? '0x' + f.mark : '-'}</code></td>
        <td><code>${f.packets} pkts / ${f.bytes} B</code></td>
      </tr>`).join('');
      flowsWrap.innerHTML = `<table>
        <thead>
          <tr>
            <th>Proto</th>
            <th>State</th>
            <th>Client (Source)</th>
            <th>VIP / Destination</th>
            <th>NAT Target / Tunnel</th>
            <th>FW Mark</th>
            <th>Traffic</th>
          </tr>
        </thead>
        <tbody>${flowRows}</tbody>
      </table>`;
    }

    document.getElementById('nftyfile-box').textContent = data.nftyfile || '# Empty Nftyfile';
    document.getElementById('nft-box').textContent = data.nft_ruleset || '';
    document.getElementById('last-updated').textContent = 'Live • Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('last-updated').textContent = 'Reconnecting...';
  }
}
refreshDashboard();
setInterval(refreshDashboard, 2000);
</script>
</body>
</html>
"#;
