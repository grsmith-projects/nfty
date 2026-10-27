pub mod completer;
pub mod debug;
pub mod help;
pub mod status;

pub use completer::NftyHelper;
pub use help::print_context_help;
pub use status::{handle_show, print_config_diff, print_status, print_status_table};

use crate::ast::{DnsConfig, Gateway, GatewayService, GatewayServiceKind, Service};
use crate::compiler::{
    apply_config, update_host_mapping, validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once};
use crate::parser::{
    apply_dns_directive, apply_gateway_directive, apply_gateway_service_directive,
    apply_service_directive, create_or_find_vip_service_by_key, parse_backend,
    parse_gateway_service, parse_ip_and_optional_cidr, parse_nftyfile, parse_service_spec,
    parse_vip, parse_vip_header, parse_vlan_id, parse_wg_tunnel, remove_backend_from_service,
    upsert_gateway_service, validate_allow_entry, validate_host_mapping_name,
};
use crate::state::{HealthState, PendingConfirm, SharedState};
use crate::tui::run_watch_dashboard;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellLevel {
    Operational,
    Debug,
    ConfigRoot,
    GlobalAllow,
    Dns,
    Vip(String),
    VipService(String),
    Service(String),
    ServiceTo(String),
    ServiceAllow(String),
    Gateway(String),
    GatewayTunnels(String),
    GatewayService(String),
    GatewayApi(String, u16),
}

impl ShellLevel {
    pub fn prompt(&self) -> String {
        match self {
            ShellLevel::Operational => "nfty> ".to_string(),
            ShellLevel::Debug => "nfty(debug)# ".to_string(),
            ShellLevel::ConfigRoot => "nfty(config)# ".to_string(),
            ShellLevel::GlobalAllow => "nfty(config-allow)# ".to_string(),
            ShellLevel::Dns => "nfty(config-dns)# ".to_string(),
            ShellLevel::Vip(k) => format!("nfty(config-vip:{})# ", k),
            ShellLevel::VipService(k) => format!("nfty(config-vip:{}-service)# ", k),
            ShellLevel::Service(k) => format!("nfty(config-service:{})# ", k),
            ShellLevel::ServiceTo(k) => format!("nfty(config-service:{}-to)# ", k),
            ShellLevel::ServiceAllow(k) => format!("nfty(config-service:{}-allow)# ", k),
            ShellLevel::Gateway(k) => format!("nfty(config-gateway:{})# ", k),
            ShellLevel::GatewayTunnels(k) => format!("nfty(config-gateway:{}-tunnels)# ", k),
            ShellLevel::GatewayService(k) => format!("nfty(config-gateway:{}-service)# ", k),
            ShellLevel::GatewayApi(k, p) => format!("nfty(config-gateway:{}-api:{})# ", k, p),
        }
    }
}

pub async fn run_repl(shared: SharedState) -> Result<()> {
    let level = Arc::new(Mutex::new(ShellLevel::Operational));
    let helper = NftyHelper::new(level.clone(), shared.clone());

    let mut rl = Editor::new()?;
    rl.set_helper(Some(helper));

    let (api_bind, api_ports) = {
        let st = shared.read().unwrap();
        (st.api_bind.clone(), st.active_config().api_ports())
    };
    println!(
        "{}",
        "Welcome to nfty — L4 Service Load Balancer & Port Router for nftables"
            .bold()
            .cyan()
    );
    if let Some(bind) = api_bind {
        println!(
            "1:1 Control API listening on {} (endpoints: /api/v1/allow, /api/v1/cli, /api/v1/status)",
            format!("http://{}", bind).green().bold()
        );
    } else if !api_ports.is_empty() {
        let ports_str = api_ports
            .iter()
            .map(|p| format!(":{}", p))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "Control API / Web UI enabled on VIP listener port(s) {}",
            ports_str.green().bold()
        );
    }
    println!(
        "Type {} to enter config mode, {} for troubleshooting tools, {} for live status, {} for live TUI, or {} for help.\n",
        "configure".yellow(),
        "debug".magenta(),
        "status".green(),
        "watch".cyan(),
        "?".cyan()
    );
    if std::path::Path::new("/run/nfty-ephemeral-storage").exists() {
        println!(
            "{}\n",
            "WARNING: No persistent virtual disk is mounted at /data — configuration is running in ephemeral RAM and will be lost on reboot. Attach a virtual disk to persist changes."
                .yellow()
                .bold()
        );
    }

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
                    | ShellLevel::GatewayApi(_, _)
                    | ShellLevel::GlobalAllow
                    | ShellLevel::Dns => {
                        *lvl = ShellLevel::ConfigRoot;
                        println!("^C (returned to config root)");
                    }
                    ShellLevel::ConfigRoot | ShellLevel::Debug => {
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
    match handle_line_checked(line, level, shared).await {
        Ok(quit) => quit,
        Err(e) => {
            eprintln!("{} {:#}", "Error:".red().bold(), e);
            false
        }
    }
}

pub async fn handle_line_checked(
    line: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<bool> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(false);
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
            return Ok(false);
        }
        "quit" => return Ok(true),
        "bootstrap" => {
            handle_bootstrap(&tokens[1..], shared)?;
            return Ok(false);
        }
        "password" | "passwd" => {
            crate::ssh::interactive_change_password(false)?;
            return Ok(false);
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
                ShellLevel::GatewayTunnels(k)
                | ShellLevel::GatewayService(k)
                | ShellLevel::GatewayApi(k, _) => ShellLevel::Gateway(k.clone()),
                ShellLevel::Vip(_)
                | ShellLevel::Gateway(_)
                | ShellLevel::GlobalAllow
                | ShellLevel::Dns => {
                    ShellLevel::ConfigRoot
                }
                ShellLevel::ConfigRoot | ShellLevel::Debug => ShellLevel::Operational,
                ShellLevel::Operational => ShellLevel::Operational,
            };
            return Ok(false);
        }
        "top" => {
            let mut lvl = level.lock().unwrap();
            if *lvl == ShellLevel::Debug {
                *lvl = ShellLevel::Operational;
            } else if *lvl != ShellLevel::Operational {
                *lvl = ShellLevel::ConfigRoot;
            }
            return Ok(false);
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
                ShellLevel::GatewayTunnels(k)
                | ShellLevel::GatewayService(k)
                | ShellLevel::GatewayApi(k, _) => {
                    *lvl = ShellLevel::Gateway(k.clone());
                }
                ShellLevel::Vip(_)
                | ShellLevel::Gateway(_)
                | ShellLevel::GlobalAllow
                | ShellLevel::Dns => {
                    *lvl = ShellLevel::ConfigRoot;
                }
                ShellLevel::ConfigRoot | ShellLevel::Debug => {
                    *lvl = ShellLevel::Operational;
                }
                ShellLevel::Operational => return Ok(true),
            }
            return Ok(false);
        }
        "scan" | "discover" => {
            let filter = tokens.get(1).copied();
            println!(
                "{}",
                "Scanning LXD / LAN neighbors for active services...".cyan()
            );
            let discovered = crate::features::scan_network_services_async(filter, shared).await?;
            crate::features::print_scan_table(&discovered, shared);
            return Ok(false);
        }
        "adopt" => {
            handle_adopt(&tokens[1..], level, shared).await?;
            return Ok(false);
        }
        "status" => {
            print_status_table(shared);
            return Ok(false);
        }
        "flows" | "conntrack" => {
            crate::features::print_flows_table(shared);
            return Ok(false);
        }
        "wg" | "wireguard"
            if cur_level != ShellLevel::Debug
                || matches!(
                    tokens.get(1).copied(),
                    Some("add" | "paste" | "edit" | "rm" | "list")
                ) =>
        {
            match crate::features::handle_wg_cli_command(&tokens[1..]) {
                Ok(Some(saved_filename)) => {
                    if let ShellLevel::Gateway(gw_key) | ShellLevel::GatewayTunnels(gw_key) =
                        &cur_level
                    {
                        let mut st = shared.write().unwrap();
                        if let Some(gw) = st.candidate.gateways.get_mut(gw_key) {
                            let t = parse_wg_tunnel(&[saved_filename.as_str()], &gw.key)?;
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
                        st.sync_runtime_entries();
                    }
                }
                Ok(None) => {}
                Err(e) => return Err(e),
            }
            return Ok(false);
        }
        "ssh-key" | "ssh-keys" | "authorized-keys" => {
            crate::ssh::handle_ssh_cli_command(&tokens[1..])?;
            return Ok(false);
        }
        "ssh"
            if matches!(
                cur_level,
                ShellLevel::Operational
                    | ShellLevel::ConfigRoot
                    | ShellLevel::GlobalAllow
                    | ShellLevel::Dns
            ) || (tokens.len() >= 2 && tokens[1].parse::<u16>().is_err()) =>
        {
            crate::ssh::handle_ssh_cli_command(&tokens[1..])?;
            return Ok(false);
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
            crate::features::handle_cf_cli_command(&tokens[1..], shared)?;
            return Ok(false);
        }
        "dns"
            if (cur_level == ShellLevel::Operational && tokens.len() == 1)
                || (tokens.len() >= 2
                    && matches!(
                        tokens[1].to_ascii_lowercase().as_str(),
                        "status" | "test" | "lookup" | "query" | "config" | "reload" | "flush"
                    )) =>
        {
            crate::features::handle_dns_cli_command(&tokens[1..], shared)?;
            return Ok(false);
        }
        "watch" => {
            run_watch_dashboard(shared.clone()).await?;
            return Ok(false);
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
            return Ok(false);
        }
        "host" => {
            handle_host_mapping(&tokens[1..], shared)?;
            return Ok(false);
        }
        "drain" => {
            if tokens.len() < 2 {
                bail!("Usage: drain <ip:port>");
            }
            set_drain_state(shared, tokens[1], true)?;
            return Ok(false);
        }
        "enable" => {
            if tokens.len() < 2 {
                bail!("Usage: enable <ip:port>");
            }
            set_drain_state(shared, tokens[1], false)?;
            return Ok(false);
        }
        "show" => {
            handle_show(&tokens[1..], &cur_level, shared);
            return Ok(false);
        }
        "diff" | "compare" => {
            print_config_diff(shared);
            return Ok(false);
        }
        "test" | "validate" | "check-config" => {
            if !handle_validate(shared) {
                bail!("Configuration validation failed");
            }
            return Ok(false);
        }
        "apply" | "commit" => {
            handle_apply(&tokens[1..], shared).await?;
            return Ok(false);
        }
        "confirm" | "keep" => {
            handle_confirm(shared)?;
            return Ok(false);
        }
        "rollback" => {
            handle_rollback(&tokens[1..], shared)?;
            return Ok(false);
        }
        "save" => {
            handle_save(&tokens[1..], shared)?;
            return Ok(false);
        }
        "load" => {
            handle_load(&tokens[1..], shared)?;
            return Ok(false);
        }
        "ping" => {
            debug::run_ping_command(&tokens[1..])?;
            return Ok(false);
        }
        "traceroute" | "tracepath" => {
            debug::run_traceroute_command(&tokens[1..])?;
            return Ok(false);
        }
        "arping" => {
            debug::run_arping_command(&tokens[1..])?;
            return Ok(false);
        }
        "debug" | "troubleshoot" | "diag" => {
            if tokens.len() == 1 {
                *level.lock().unwrap() = ShellLevel::Debug;
            } else {
                let sub = tokens[1..].join(" ");
                debug::handle_debug_command(&sub, level, shared).await?;
            }
            return Ok(false);
        }
        _ => {}
    }

    match cur_level {
        ShellLevel::Operational => match cmd.as_str() {
            "configure" | "conf" | "config" | "edit" => {
                *level.lock().unwrap() = ShellLevel::ConfigRoot;
            }
            "vip" | "service" | "gateway" | "allow" | "dns" => {
                *level.lock().unwrap() = ShellLevel::ConfigRoot;
                handle_config_root_command(trimmed, level, shared)?;
            }
            _ => {
                bail!(
                    "Unknown command '{}'. Type {} to enter configuration mode, {} for troubleshooting, or {} for help.",
                    cmd,
                    "configure".yellow(),
                    "debug".magenta(),
                    "?".cyan()
                );
            }
        },
        ShellLevel::Debug => {
            debug::handle_debug_command(trimmed, level, shared).await?;
        }
        ShellLevel::ConfigRoot => {
            handle_config_root_command(trimmed, level, shared)?;
        }
        ShellLevel::GlobalAllow => {
            handle_global_allow_command(trimmed, shared)?;
        }
        ShellLevel::Dns => {
            handle_dns_level_command(trimmed, level, shared)?;
        }
        ShellLevel::Vip(vip_key) => {
            handle_vip_level_command(&vip_key, trimmed, level, shared)?;
        }
        ShellLevel::VipService(vip_key) => {
            handle_vip_service_command(&vip_key, trimmed, level, shared)?;
        }
        ShellLevel::Service(svc_key) => {
            handle_service_level_command(&svc_key, trimmed, level, shared)?;
        }
        ShellLevel::ServiceTo(svc_key) => {
            handle_service_to_command(&svc_key, trimmed, level, shared)?;
        }
        ShellLevel::ServiceAllow(svc_key) => {
            handle_service_allow_command(&svc_key, trimmed, shared)?;
        }
        ShellLevel::Gateway(gw_key) => {
            handle_gateway_level_command(&gw_key, trimmed, level, shared)?;
        }
        ShellLevel::GatewayTunnels(gw_key) => {
            handle_gateway_tunnels_command(&gw_key, trimmed, level, shared)?;
        }
        ShellLevel::GatewayService(gw_key) => {
            handle_gateway_service_command(&gw_key, trimmed, level, shared)?;
        }
        ShellLevel::GatewayApi(gw_key, port) => {
            handle_gateway_api_command(&gw_key, port, trimmed, level, shared)?;
        }
    }

    Ok(false)
}

fn handle_host_mapping(args: &[&str], shared: &SharedState) -> Result<()> {
    if args.len() < 2 {
        bail!("Usage: host <hostname> <ipv4> [ipv4...] (e.g. 'host laptop.office.lan 192.168.1.77')");
    }
    let host = validate_host_mapping_name(args[0])?;
    let mut ips = Vec::new();
    for a in &args[1..] {
        let ip: Ipv4Addr = a
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}'", a))?;
        ips.push(ip);
    }
    let mut st = shared.write().unwrap();
    update_host_mapping(&mut st, &host, &ips)?;
    crate::unikernel::persist_host_mapping(&host, &ips)
        .context("Host mapping was updated but could not be persisted")?;
    drop(st);
    crate::unikernel::notify_controller_host_mapping(shared, &host, &ips)
        .context("Host mapping was updated and saved, but controller synchronization failed")?;
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
        } else if args[idx]
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
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

        let allow_list_errors = st.candidate.control_allow_list_errors();
        if !allow_list_errors.is_empty() {
            bail!(
                "Not applied: every web:/api: listener requires an IP allow-list\n  {}",
                allow_list_errors.join("\n  ")
            );
        }

        let report = validate_config(&st.candidate, Some(&st));
        if !report.valid {
            bail!("Configuration is invalid: {}", report.errors.join("; "));
        }
        let next = st.candidate.clone();
        vip_logs = apply_config(&mut st, next)?.logs;
    }

    crate::unikernel::persist_and_notify_controller(shared)?;

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
        if let Some(dns_cfg) = parsed.dns {
            println!("  {} Updated dns block", "✔".green().bold());
            st.candidate.dns = Some(dns_cfg);
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
        "dns" => {
            {
                let mut st = shared.write().unwrap();
                st.candidate.dns.get_or_insert_with(DnsConfig::default);
            }
            if tokens.len() == 1 {
                *level.lock().unwrap() = ShellLevel::Dns;
            } else {
                handle_dns_level_command(&tokens[1..].join(" "), level, shared)?;
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
            let mut idx = 2;
            while idx < tokens.len() {
                match tokens[idx].to_ascii_lowercase().as_str() {
                    "dhcp" => {
                        idx += 1;
                        if idx < tokens.len()
                            && !matches!(
                                tokens[idx].to_ascii_lowercase().as_str(),
                                "vlan" | "service" | "services" | "ssh" | "dns" | "api"
                            )
                            && !tokens[idx].starts_with("ssh:")
                            && !tokens[idx].starts_with("dns:")
                            && !tokens[idx].starts_with("api:")
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
                                "vlan" | "service" | "services" | "tunnel" | "tunnels" | "api"
                            )
                            && !tokens[idx].starts_with("api:")
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
                handle_gateway_level_command(&key, &rest, level, shared)?;
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
                bail!("Usage: no <vip|gateway|service|allow|dns> [target]");
            }
            if tokens[1].eq_ignore_ascii_case("dns") {
                let mut st = shared.write().unwrap();
                if tokens.len() == 2 {
                    st.candidate.dns = None;
                    println!("  {} Removed global dns block", "✔".green().bold());
                } else {
                    let dns_cfg = st.candidate.dns.get_or_insert_with(DnsConfig::default);
                    let rest = format!("no {}", tokens[2..].join(" "));
                    apply_dns_directive(dns_cfg, &rest)?;
                    println!(
                        "  {} [dns] {}",
                        "✔".green().bold(),
                        rest.bold()
                    );
                }
                return Ok(());
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

fn handle_dns_level_command(
    trimmed: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    let first_lower = tokens[0].to_ascii_lowercase();
    if matches!(first_lower.as_str(), "vip" | "gateway" | "service") {
        *level.lock().unwrap() = ShellLevel::ConfigRoot;
        return handle_config_root_command(trimmed, level, shared);
    }

    let mut st = shared.write().unwrap();
    let dns_cfg = st.candidate.dns.get_or_insert_with(DnsConfig::default);
    apply_dns_directive(dns_cfg, trimmed)?;
    println!("  {} [dns] {}", "✔".green().bold(), trimmed.bold());
    Ok(())
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
        "dns" => {
            let spec = if tokens.len() >= 2 && tokens[1].parse::<u16>().is_ok() {
                format!("dns:{}", tokens[1])
            } else {
                "dns:53".to_string()
            };
            let mut st = shared.write().unwrap();
            let _ = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, &spec)?;
            st.sync_runtime_entries();
            println!(
                "  {} [vip {}] + {}",
                "✔".green().bold(),
                vip_key.cyan(),
                spec.bold()
            );
            return Ok(());
        }
        "api" | "web" => {
            let prefix = if first_lower == "web" { "web" } else { "api" };
            let default_port = if first_lower == "web" { 8000 } else { 9090 };
            let (spec, rest_start) = if tokens.len() >= 2 && tokens[1].parse::<u16>().is_ok() {
                (format!("{}:{}", prefix, tokens[1]), 2)
            } else {
                (format!("{}:{}", prefix, default_port), 1)
            };
            let svc_key = {
                let mut st = shared.write().unwrap();
                let k = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, &spec)?;
                st.sync_runtime_entries();
                k
            };
            if tokens.len() <= rest_start {
                *level.lock().unwrap() = ShellLevel::Service(svc_key.clone());
                println!(
                    "  {} [vip {}] + {} ({})",
                    "✔".green().bold(),
                    vip_key.cyan(),
                    spec.bold(),
                    svc_key
                );
            } else {
                let rest_cmd = tokens[rest_start..].join(" ");
                handle_service_level_command(&svc_key, &rest_cmd, level, shared)?;
            }
            return Ok(());
        }
        _ if first_lower.starts_with("api:") || first_lower.starts_with("web:") => {
            let svc_key = {
                let mut st = shared.write().unwrap();
                let k = create_or_find_vip_service_by_key(&mut st.candidate, vip_key, tokens[0])?;
                st.sync_runtime_entries();
                k
            };
            if tokens.len() == 1 {
                *level.lock().unwrap() = ShellLevel::Service(svc_key.clone());
                println!(
                    "  {} [vip {}] + {} ({})",
                    "✔".green().bold(),
                    vip_key.cyan(),
                    tokens[0].bold(),
                    svc_key
                );
            } else {
                let rest_cmd = tokens[1..].join(" ");
                handle_service_level_command(&svc_key, &rest_cmd, level, shared)?;
            }
            return Ok(());
        }
        _ if first_lower.starts_with("ssh:") || first_lower.starts_with("dns:") => {
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
                println!(
                    "  {} [vip {}] Removed VLAN tag",
                    "✔".green().bold(),
                    vip_key.cyan()
                );
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
                println!(
                    "  {} [vip {}] Disabled DHCP",
                    "✔".green().bold(),
                    vip_key.cyan()
                );
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

pub async fn handle_adopt(
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

    let need_auto_scan = {
        let st = shared.read().unwrap();
        st.discovered_services.is_empty() && !raw_target.contains(':')
    };
    if need_auto_scan {
        crate::features::scan_network_services_async(None, shared).await?;
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
            "Could not find '{}' in discovered services. Run 'scan' first or specify '<host>:<port>' (e.g. 'adopt app-backend:8989').",
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
        let prev_keys_len = svc.api_keys.len();
        if let Err(e) = apply_service_directive(&mut svc, trimmed) {
            st.candidate.services.insert(svc_key.to_string(), svc);
            return Err(e);
        }
        let updated_key = svc.key.clone();
        let label = svc.display_name();
        let added_key = if svc.api_keys.len() > prev_keys_len {
            svc.api_keys.last().cloned()
        } else {
            None
        };
        st.candidate.services.insert(updated_key.clone(), svc);
        st.sync_runtime_entries();
        if let Some(ak) = added_key {
            println!(
                "  {} [service {} ({})] key {} ({})",
                "✔".green().bold(),
                label.cyan(),
                updated_key,
                ak.key.green().bold(),
                ak.scope.as_str().yellow().bold()
            );
        } else {
            println!(
                "  {} [service {} ({})] {}",
                "✔".green().bold(),
                label.cyan(),
                updated_key,
                trimmed
            );
        }
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
        "balance" | "check" | "vip" | "mode" | "limit" | "allow" | "service" | "key"
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

    let first_lower = tokens[0].to_ascii_lowercase();
    match first_lower.as_str() {
        "tunnels" | "to" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::GatewayTunnels(gw_key.to_string());
            return Ok(());
        }
        "service" | "services" if tokens.len() == 1 => {
            *level.lock().unwrap() = ShellLevel::GatewayService(gw_key.to_string());
            return Ok(());
        }
        "api" | "web" | _
            if first_lower == "api"
                || first_lower.starts_with("api:")
                || first_lower == "web"
                || first_lower.starts_with("web:") =>
        {
            let (spec, rest_start) = if (first_lower == "api" || first_lower == "web")
                && tokens.len() >= 2
                && tokens[1].parse::<u16>().is_ok()
            {
                (format!("{}:{}", first_lower, tokens[1]), 2)
            } else if first_lower == "api" {
                ("api:9090".to_string(), 1)
            } else if first_lower == "web" {
                ("web:8000".to_string(), 1)
            } else {
                (tokens[0].to_string(), 1)
            };
            let gs = parse_gateway_service(&spec)?;
            let kind = gs.kind;
            let port = gs.port;
            {
                let mut st = shared.write().unwrap();
                let gw = st
                    .candidate
                    .gateways
                    .get_mut(gw_key)
                    .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;
                upsert_gateway_service(gw, gs);
                st.sync_runtime_entries();
            }
            if tokens.len() <= rest_start {
                *level.lock().unwrap() = ShellLevel::GatewayApi(gw_key.to_string(), port);
                println!(
                    "  {} [gateway {}] + {}:{}",
                    "✔".green().bold(),
                    gw_key.cyan(),
                    kind,
                    port
                );
            } else {
                let rest_cmd = tokens[rest_start..].join(" ");
                handle_gateway_api_command(gw_key, port, &rest_cmd, level, shared)?;
            }
            return Ok(());
        }
        "gateway" => {
            return handle_config_root_command(trimmed, level, shared);
        }
        _ => {}
    }

    let mut st = shared.write().unwrap();
    let generated_key = {
        let gw = st
            .candidate
            .gateways
            .get_mut(gw_key)
            .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;
        apply_gateway_directive(gw, trimmed)?;
        if first_lower == "key" || first_lower == "api-key" || first_lower == "apikey" {
            gw.services
                .iter()
                .find(|s| s.kind == GatewayServiceKind::Api)
                .and_then(|gs| gs.api_keys.last().map(|ak| (gs.port, ak.clone())))
        } else {
            None
        }
    };
    st.sync_runtime_entries();
    if let Some((port, ak)) = generated_key {
        println!(
            "  {} [gateway {} -> api:{}] key {} ({})",
            "✔".green().bold(),
            gw_key.cyan(),
            port,
            ak.key.green().bold(),
            ak.scope.as_str().yellow().bold()
        );
        return Ok(());
    }
    println!(
        "  {} [gateway {}] {}",
        "✔".green().bold(),
        gw_key.cyan(),
        trimmed
    );
    Ok(())
}

fn handle_gateway_api_command(
    gw_key: &str,
    port: u16,
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
        "tunnels"
            | "tunnel"
            | "vip"
            | "hostname"
            | "balance"
            | "killswitch"
            | "check"
            | "allow"
            | "gateway"
            | "service"
            | "services"
            | "forward"
            | "privoxy"
            | "socks5"
            | "ssh"
            | "dns"
    ) || first_lower.starts_with("privoxy:")
        || first_lower.starts_with("socks5:")
        || first_lower.starts_with("ssh:")
        || first_lower.starts_with("dns:")
    {
        *level.lock().unwrap() = ShellLevel::Gateway(gw_key.to_string());
        return handle_gateway_level_command(gw_key, trimmed, level, shared);
    }

    let mut st = shared.write().unwrap();
    let gw = st
        .candidate
        .gateways
        .get_mut(gw_key)
        .ok_or_else(|| anyhow::anyhow!("Gateway '{}' no longer exists", gw_key))?;
    let gs = if let Some(existing) = gw.services.iter_mut().find(|s| {
        matches!(s.kind, GatewayServiceKind::Api | GatewayServiceKind::Web) && s.port == port
    }) {
        existing
    } else if let Some(existing) = gw
        .services
        .iter_mut()
        .find(|s| matches!(s.kind, GatewayServiceKind::Api | GatewayServiceKind::Web))
    {
        existing
    } else {
        gw.services
            .push(GatewayService::new(GatewayServiceKind::Api, port));
        gw.services.last_mut().unwrap()
    };

    let added = apply_gateway_service_directive(gs, trimmed)?;
    let new_port = gs.port;
    st.sync_runtime_entries();
    if new_port != port {
        *level.lock().unwrap() = ShellLevel::GatewayApi(gw_key.to_string(), new_port);
    }
    if let Some((ak, _generated)) = added {
        println!(
            "  {} [gateway {} -> api:{}] key {} ({})",
            "✔".green().bold(),
            gw_key.cyan(),
            new_port,
            ak.key.green().bold(),
            ak.scope.as_str().yellow().bold()
        );
    } else {
        println!(
            "  {} [gateway {} -> api:{}] {}",
            "✔".green().bold(),
            gw_key.cyan(),
            new_port,
            trimmed
        );
    }
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
        "tunnels"
            | "tunnel"
            | "vip"
            | "hostname"
            | "balance"
            | "killswitch"
            | "check"
            | "allow"
            | "gateway"
    ) {
        *level.lock().unwrap() = ShellLevel::Gateway(gw_key.to_string());
        return handle_gateway_level_command(gw_key, trimmed, level, shared);
    }

    if first_lower == "api"
        || first_lower.starts_with("api:")
        || first_lower == "web"
        || first_lower.starts_with("web:")
    {
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
            bail!("Usage: no <privoxy|socks5|ssh|dns|api>");
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
        let kind = gs.kind;
        let port = gs.port;
        upsert_gateway_service(gw, gs);
        println!(
            "  {} [gateway {} -> service] + {}",
            "✔".green().bold(),
            gw_key.cyan(),
            label.bold()
        );
        if kind == GatewayServiceKind::Api {
            *level.lock().unwrap() = ShellLevel::GatewayApi(gw_key.to_string(), port);
        }
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
            bail!(
                "Usage: {} <tunnel-name> (e.g. '{} mullvad-us-sea-001')",
                first_lower,
                first_lower
            );
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
        let t = parse_wg_tunnel(&[saved_filename.as_str()], &gw.key)?;
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

    let mut effective_tokens: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
    if tokens.len() == 1 || (tokens.len() == 3 && tokens[1].eq_ignore_ascii_case("weight")) {
        let filename = crate::features::normalize_wg_filename(tokens[0])?;
        let full_path = std::path::Path::new("/data/wg").join(&filename);
        if !full_path.exists() {
            if let Some(saved_name) =
                crate::features::edit_wg_config_interactive(&filename, Some("nano"))?
            {
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

    let ref_tokens: Vec<&str> = effective_tokens.iter().map(|s| s.as_str()).collect();
    let t = parse_wg_tunnel(&ref_tokens, &gw.key)?;
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

async fn handle_apply(args: &[&str], shared: &SharedState) -> Result<()> {
    refresh_allowlist_hosts(shared).await;

    if !handle_validate(shared) {
        bail!("Apply aborted due to validation errors");
    }

    let mut confirm_secs: Option<u64> = None;
    if !args.is_empty() {
        if args[0].eq_ignore_ascii_case("confirm") {
            if args.len() > 2 {
                bail!("Usage: apply [confirm [seconds]]");
            }
            let secs = match args.get(1) {
                Some(raw) => raw.trim_end_matches('s').parse::<u64>()
                    .with_context(|| format!("Invalid confirmation timeout '{}'", raw))?,
                None => 60,
            };
            confirm_secs = Some(secs.max(5));
        } else {
            if args.len() > 1 {
                bail!("Usage: apply [confirm [seconds]]");
            }
            let secs = args[0].trim_end_matches('s').parse::<u64>()
                .with_context(|| format!("Invalid confirmation timeout '{}'", args[0]))?;
            confirm_secs = Some(secs.max(5));
        }
    }

    let (result, delegated_to_controller) = {
        let mut st = shared.write().unwrap();
        if st.pending_confirm.is_some() {
            bail!("Confirm or roll back the pending trial before applying another configuration");
        }
        if confirm_secs.is_some() && !st.controller_is_authoritative {
            bail!("Confirmed apply requires a long-running appliance or daemon controller");
        }
        let prev_running = st.running.clone();
        let next_running = st.candidate.clone();
        if !st.controller_is_authoritative && crate::unikernel::pid1_is_nfty() {
            st.running = next_running;
            st.sync_runtime_entries();
            (
                crate::compiler::ApplyResult {
                    message: "Applied configuration via appliance controller".to_string(),
                    logs: Vec::new(),
                },
                Some(prev_running),
            )
        } else {
            let result = apply_config(&mut st, next_running)?;
            if let Some(secs) = confirm_secs {
                st.pending_confirm = Some(PendingConfirm {
                    revert_to: prev_running,
                    deadline: Instant::now() + Duration::from_secs(secs),
                });
            }
            (result, None)
        }
    };
    for log in result.logs {
        println!("  {} {}", "→".cyan(), log);
    }
    if let Err(e) = crate::unikernel::persist_and_notify_controller(shared) {
        if let Some(prev_running) = delegated_to_controller {
            let mut st = shared.write().unwrap();
            st.running = prev_running;
            st.sync_runtime_entries();
        }
        return Err(e);
    }
    if let Some(prev_running) = delegated_to_controller {
        let mut st = shared.write().unwrap();
        st.history.push(prev_running);
        st.sync_from_disk_if_changed();
    }
    println!("  {} {}", "✔".green().bold(), result.message.green());
    if let Some(secs) = confirm_secs {
        println!(
            "  {} Safety rollback timer active for {}s! Type {} to keep changes.",
            "🔒".yellow(),
            secs,
            "confirm".bold().yellow()
        );
    }
    let _ = run_all_probes_once(shared).await;
    Ok(())
}

fn handle_confirm(shared: &SharedState) -> Result<()> {
    let mut st = shared.write().unwrap();
    let Some(pending) = st.pending_confirm.take() else {
        bail!("No pending commit-confirm timer is active");
    };
    if let Err(e) = crate::unikernel::persist_state(&mut st) {
        st.pending_confirm = Some(pending);
        return Err(e.context("Confirmation was not persisted"));
    }
    println!(
        "  {} Configuration confirmed! Safety rollback timer cancelled.",
        "✔".green().bold()
    );
    Ok(())
}

fn handle_rollback(args: &[&str], shared: &SharedState) -> Result<()> {
    let steps = match args.first() {
        Some(raw) => raw.parse::<usize>().context("Invalid rollback revision count")?.max(1),
        None => 1,
    };

    let mut st = shared.write().unwrap();
    if st.history.is_empty() {
        bail!("No previous commits in history to rollback to");
    }

    let target_idx = st.history.len().saturating_sub(steps);
    let restored = st.history[target_idx].clone();
    apply_config(&mut st, restored.clone()).context("Rollback failed")?;
    st.history.truncate(target_idx);
    st.candidate = restored;
    st.pending_confirm = None;
    drop(st);
    crate::unikernel::persist_and_notify_controller(shared)?;

    println!(
        "  {} Rolled back {} revision(s) and re-applied running configuration.",
        "✔".green().bold(),
        steps
    );
    Ok(())
}

fn handle_save(args: &[&str], shared: &SharedState) -> Result<()> {
    let mut st = shared.write().unwrap();
    let path = args
        .first()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| st.config_path.clone());
    let content = st.candidate.format_nftyfile();
    if st.pending_confirm.is_some() && path == st.config_path {
        bail!("Confirm or roll back the pending trial before saving the active configuration");
    }
    crate::unikernel::write_atomic(&path, content.as_bytes())?;
    if path == st.config_path {
        st.last_disk_nftyfile = content;
    }
    println!(
        "  {} Saved configuration to {}",
        "✔".green().bold(),
        path.display()
    );
    Ok(())
}

fn handle_load(args: &[&str], shared: &SharedState) -> Result<()> {
    let path = {
        let st = shared.read().unwrap();
        args.first()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| st.config_path.clone())
    };
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let cfg = parse_nftyfile(&raw)
        .with_context(|| format!("Parse error in {}", path.display()))?;
    let mut st = shared.write().unwrap();
    st.candidate = cfg;
    st.sync_runtime_entries();
    println!(
        "  {} Loaded candidate configuration from {}",
        "✔".green().bold(),
        path.display()
    );
    Ok(())
}

fn set_drain_state(shared: &SharedState, endpoint: &str, drained: bool) -> Result<()> {
    let matched = {
        let st = shared.read().unwrap();
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
        matched
    };
    if matched.is_empty() {
        bail!("Backend '{}' not found", endpoint);
    }
    crate::unikernel::dispatch_backend_drain_state(shared, &matched, drained)?;
    for ep in &matched {
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
    Ok(())
}
