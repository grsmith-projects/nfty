pub mod cloudflare;
pub mod dns;
pub mod flows;
pub mod gateway_proxy;
pub mod vhost_mdns;
pub mod wireguard;

pub use cloudflare::{
    cloudflared_running_pid, collect_cloudflare_routes, handle_cf_cli_command,
    load_cloudflare_config, reconcile_cloudflare_tunnel, save_cloudflare_config,
    start_or_ensure_cloudflared_daemon, stop_cloudflared_daemon, CloudflareConfig,
};
pub use dns::{
    compile_dnsmasq_config, dnsmasq_running_pid, handle_dns_cli_command, print_dns_status,
    reconcile_dnsmasq, run_dns_lookup_test, run_dns_supervisor, stop_dnsmasq_daemon,
};
pub use flows::{print_flows_table, read_active_flows, ConntrackFlow};
pub use gateway_proxy::{is_forbidden_proxy_destination, run_gateway_proxy_supervisor};
pub use vhost_mdns::extract_host_or_sni;
pub use wireguard::{
    apply_wireguard_gateways, build_client_wg_conf, delete_stored_client_peer,
    ensure_gateway_server_keys, generate_wg_keypair, generate_wg_psk,
    handle_wg_cli_command, list_saved_wg_configs, load_stored_client_peer, normalize_wg_filename,
    parse_wg_conf_str, paste_wg_config_interactive, probe_wg_tunnel, render_qr_unicode,
    resolve_tunnel_config, save_stored_client_peer, save_wg_config_file, validate_wg_key_base64,
    ParsedWgConf, StoredWgClientPeer, StoredWgServerKeys,
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

/// Spawns background daemons: mDNS responder, L7 HTTP/SNI virtual host proxy,
/// Cloudflare tunnel supervisor, and DNS supervisor.
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
