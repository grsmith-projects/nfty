use super::ShellLevel;
use crate::ast::Config;
use crate::compiler::{compile_nft_ruleset, generate_vip_commands};
use crate::state::{HealthState, SharedState};
use colored::Colorize;
use similar::{ChangeTag, TextDiff};

pub fn handle_show(args: &[&str], level: &ShellLevel, shared: &SharedState) {
    let st = shared.read().unwrap();
    if let Some(first) = args.first() {
        match first.to_ascii_lowercase().as_str() {
            "nft" | "nftables" | "rules" => {
                let cfg = if *level == ShellLevel::Operational {
                    st.active_config()
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
            "dns" => {
                let cfg = if *level == ShellLevel::Operational {
                    st.active_config()
                } else {
                    &st.candidate
                };
                if let Some(dns) = &cfg.dns {
                    print!("{}", dns.format_block());
                } else {
                    println!("(No global dns block configured)");
                }
                return;
            }
            _ => {}
        }
    }

    match level {
        ShellLevel::Operational => {
            print!("{}", st.active_config().format_nftyfile());
        }
        ShellLevel::ConfigRoot | ShellLevel::GlobalAllow => {
            print!("{}", st.candidate.format_nftyfile());
        }
        ShellLevel::Dns => {
            if let Some(dns) = &st.candidate.dns {
                print!("{}", dns.format_block());
            } else {
                println!("(No dns block configured)");
            }
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
        ShellLevel::Gateway(k)
        | ShellLevel::GatewayTunnels(k)
        | ShellLevel::GatewayService(k)
        | ShellLevel::GatewayApi(k, _) => {
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

pub fn print_config_diff(shared: &SharedState) {
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

pub fn print_status_table(shared: &SharedState) {
    let st = shared.read().unwrap();
    let cfg = st.active_config();

    if cfg.vips.is_empty()
        && cfg.services.is_empty()
        && cfg.gateways.is_empty()
        && !cfg.has_any_dns_enabled()
    {
        println!(
            "No VIPs, services, gateways, or DNS configured. Run 'scan' to discover services or 'configure' -> 'vip <name>'."
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
        let mode_suffix = if gw.tunnels.is_empty() {
            "direct-gw"
        } else {
            "wg-gw"
        };
        let vip_mode = match &gw.vip {
            Some(v) => format!("{}/{}", v, mode_suffix),
            None => format!("-/{}", mode_suffix),
        };
        let gw_title = format!("gw:{}", gw.key);
        let mut gw_badges: Vec<String> = gw.services.iter().map(|s| s.to_string()).collect();
        for fwd in &gw.forwards {
            gw_badges.push(format!("fwd:{}->{}", fwd.listen_port, fwd.backend));
        }
        let svcs_label = if gw_badges.is_empty() {
            String::new()
        } else {
            format!(" [{}]", gw_badges.join(","))
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

    if cfg.has_any_dns_enabled() {
        let dns = cfg.dns.clone().unwrap_or_default();
        let pid_state = if crate::features::dnsmasq_running_pid().is_some() {
            "UP (dnsmasq)".green().to_string()
        } else {
            "READY (dnsmasq)".cyan().to_string()
        };
        let upstreams = if dns.upstreams.is_empty() {
            "(none)".to_string()
        } else {
            dns.upstreams.join(",")
        };
        let rules_summary = format!(
            "upstreams={} recs={} nftsets={}",
            upstreams,
            dns.records.len(),
            dns.nft_rules.len()
        );
        let dom_label = dns.domain.as_deref().unwrap_or("lan");
        println!(
            "{:<22} {:<13} {:<28} {:<30} {:<31} {}",
            "dns:53".cyan().bold(),
            if dns.all_servers {
                "all-servers"
            } else {
                "failover"
            },
            format!("domain:.{}", dom_label),
            rules_summary,
            pid_state,
            "-"
        );
    }
}

pub fn print_status(shared: &SharedState) {
    print_status_table(shared);
}
