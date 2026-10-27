pub mod cloudflare;
pub mod dns;
pub mod flows;
pub mod gateway_proxy;
pub mod scanner;
pub mod vhost_mdns;
pub mod wireguard;

pub use cloudflare::{
    check_http_basic_auth, cloudflared_running_pid, collect_cloudflare_routes,
    handle_cf_cli_command, load_cloudflare_config, reconcile_cloudflare_tunnel,
    sanitize_authenticated_http_request, save_cloudflare_config, service_uses_local_cf_auth_proxy,
    start_or_ensure_cloudflared_daemon, stop_cloudflared_daemon, CloudflareConfig,
    CF_LOCAL_AUTH_PORT,
};
pub use dns::{
    compile_dnsmasq_config, dnsmasq_running_pid, handle_dns_cli_command, print_dns_status,
    reconcile_dnsmasq, run_dns_lookup_test, run_dns_supervisor, stop_dnsmasq_daemon,
};
pub use flows::{print_flows_table, read_active_flows, ConntrackFlow};
pub use gateway_proxy::run_gateway_proxy_supervisor;
pub use scanner::{
    print_scan_table, scan_network_services_async, COMMON_CONTAINER_HOSTNAMES, SCAN_PORTS,
};
pub use vhost_mdns::extract_host_or_sni;
pub use wireguard::{
    apply_wireguard_gateways, edit_wg_config_interactive, handle_wg_cli_command,
    list_saved_wg_configs, normalize_wg_filename, parse_wg_conf_str, paste_wg_config_interactive,
    probe_wg_tunnel, resolve_tunnel_config, save_wg_config_file, ParsedWgConf,
};

use crate::state::SharedState;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub(crate) async fn read_http_headers(stream: &mut TcpStream, deadline: Duration) -> Result<Vec<u8>> {
    tokio::time::timeout(deadline, async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                anyhow::bail!("Incomplete HTTP headers");
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if pos + 4 > 64 * 1024 {
                    anyhow::bail!("HTTP headers exceed 64KB limit");
                }
                return Ok(buf);
            }
            if buf.len() > 64 * 1024 {
                anyhow::bail!("HTTP headers exceed 64KB limit");
            }
        }
    })
    .await
    .context("HTTP header deadline exceeded")?
}

/// Spawns background network daemons for mDNS responder, L7 HTTP/SNI virtual host proxy,
/// Cloudflare local Basic-Auth gate, and WireGuard gateway Privoxy/SOCKS5 listeners.
pub fn spawn_advanced_feature_daemons(shared: SharedState) {
    let shared_mdns = shared.clone();
    tokio::task::spawn_blocking(move || {
        vhost_mdns::run_mdns_responder_loop(shared_mdns);
    });

    let shared_http = shared.clone();
    tokio::spawn(async move {
        vhost_mdns::run_l7_virtual_host_listener(shared_http, 80).await;
    });

    let shared_tls = shared.clone();
    tokio::spawn(async move {
        vhost_mdns::run_l7_virtual_host_listener(shared_tls, 443).await;
    });

    let shared_cf_auth = shared.clone();
    tokio::spawn(async move {
        cloudflare::run_cf_auth_proxy_listener(shared_cf_auth).await;
    });

    let shared_cloudflare = shared.clone();
    tokio::spawn(async move {
        cloudflare::run_cloudflare_supervisor(shared_cloudflare).await;
    });

    let shared_gw_proxies = shared.clone();
    tokio::spawn(async move {
        gateway_proxy::run_gateway_proxy_supervisor(shared_gw_proxies).await;
    });

    let shared_dns = shared;
    tokio::spawn(async move {
        dns::run_dns_supervisor(shared_dns).await;
    });
}

pub fn spawn_mdns_and_sni_router(shared: SharedState) {
    spawn_advanced_feature_daemons(shared);
}

/// Lists non-loopback IPv4 addresses bound to `eth0`, VLAN subinterfaces (`eth0.*`), and macvlan interfaces (`mv-*`).
pub(crate) fn list_vlan_iface_ips() -> Vec<Ipv4Addr> {
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
