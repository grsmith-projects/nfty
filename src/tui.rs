use crate::compiler::compile_nft_ruleset;
use crate::health::{poll_kernel_counters, run_all_probes_once};
use crate::state::{HealthState, SharedState};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::io;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct FlatBackendRow {
    service_key: String,
    vip_mode: String,
    strategy_limit: String,
    endpoint: String,
    role_weight: String,
    status_str: String,
    status_color: Color,
    traffic_str: String,
    in_active_map: bool,
}

struct TerminalCleanupGuard;

impl Drop for TerminalCleanupGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub async fn run_watch_dashboard(shared: SharedState) -> Result<()> {
    // Run an initial probe pass before opening TUI
    let _ = run_all_probes_once(&shared).await;

    enable_raw_mode()?;
    let _cleanup_guard = TerminalCleanupGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut show_nft_pane = true;
    let mut status_banner =
        String::from("Press 'd' to drain, 'e' to enable, 'p' to probe now, 'n' to toggle nft view, 'q' to quit");
    let mut last_probe = Instant::now();

    let res = loop {
        if last_probe.elapsed() >= Duration::from_secs(3) {
            poll_kernel_counters(&shared, 3.0);
            let _ = run_all_probes_once(&shared).await;
            last_probe = Instant::now();
        }

        let (rows, nft_preview, summary_line) = build_dashboard_data(&shared);
        if !rows.is_empty() {
            let sel = table_state.selected().unwrap_or(0);
            if sel >= rows.len() {
                table_state.select(Some(rows.len() - 1));
            }
        }

        terminal.draw(|f| {
            let chunks = if show_nft_pane {
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Percentage(52),
                        Constraint::Percentage(40),
                        Constraint::Length(3),
                    ])
                    .split(f.area())
            } else {
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(10),
                        Constraint::Length(3),
                    ])
                    .split(f.area())
            };

            // 1. Header
            let header = Paragraph::new(Line::from(vec![
                Span::styled(
                    " nfty live dashboard ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(&summary_line, Style::default().fg(Color::White)),
            ]))
            .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(header, chunks[0]);

            // 2. Services & Backends Table
            let header_cells = [
                "SERVICE",
                "VIP / MODE",
                "BALANCE / LIMIT",
                "BACKEND",
                "ROLE",
                "HEALTH (LATENCY)",
                "ACTIVE IN NFT",
                "TRAFFIC",
            ]
            .iter()
            .map(|h| {
                Cell::from(*h).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            });
            let table_header = Row::new(header_cells).height(1).bottom_margin(1);

            let table_rows = rows.iter().map(|r| {
                let active_cell = if r.in_active_map {
                    Cell::from("YES (routing)").style(Style::default().fg(Color::Green))
                } else {
                    Cell::from("NO (excluded)").style(Style::default().fg(Color::DarkGray))
                };
                Row::new(vec![
                    Cell::from(r.service_key.clone()).style(Style::default().fg(Color::Yellow)),
                    Cell::from(r.vip_mode.clone()),
                    Cell::from(r.strategy_limit.clone()),
                    Cell::from(r.endpoint.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
                    Cell::from(r.role_weight.clone()),
                    Cell::from(r.status_str.clone()).style(Style::default().fg(r.status_color)),
                    active_cell,
                    Cell::from(r.traffic_str.clone()),
                ])
            });

            let table = Table::new(
                table_rows,
                [
                    Constraint::Length(18),
                    Constraint::Length(16),
                    Constraint::Length(22),
                    Constraint::Length(20),
                    Constraint::Length(12),
                    Constraint::Length(20),
                    Constraint::Length(15),
                    Constraint::Min(16),
                ],
            )
            .header(table_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("L4 Services & Backend Pool (Use ↑/↓ to select)"),
            )
            .row_highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

            f.render_stateful_widget(table, chunks[1], &mut table_state);

            // 3. Optional live nftables ruleset preview
            let footer_idx = if show_nft_pane {
                let nft_box = Paragraph::new(nft_preview)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Compiled Kernel nftables Ruleset (Live Verdict Maps)"),
                    )
                    .style(Style::default().fg(Color::Gray))
                    .wrap(Wrap { trim: false });
                f.render_widget(nft_box, chunks[2]);
                3
            } else {
                2
            };

            // 4. Footer controls
            let footer = Paragraph::new(status_banner.as_str())
                .style(Style::default().fg(Color::LightCyan))
                .block(Block::default().borders(Borders::ALL).title("Controls"));
            f.render_widget(footer, chunks[footer_idx]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !rows.is_empty() {
                                let i = match table_state.selected() {
                                    Some(i) => (i + 1) % rows.len(),
                                    None => 0,
                                };
                                table_state.select(Some(i));
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !rows.is_empty() {
                                let i = match table_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            rows.len() - 1
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                table_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('d') => {
                            if let Some(sel) = table_state.selected() {
                                if let Some(row) = rows.get(sel) {
                                    let ep = row.endpoint.clone();
                                    status_banner = match crate::unikernel::dispatch_backend_drain_state(
                                        &shared,
                                        &[ep.clone()],
                                        true,
                                    ) {
                                        Ok(()) => format!("Drained backend {} and updated nftables map", ep),
                                        Err(e) => format!("Failed to drain {}: {:#}", ep, e),
                                    };
                                }
                            }
                        }
                        KeyCode::Char('e') => {
                            if let Some(sel) = table_state.selected() {
                                if let Some(row) = rows.get(sel) {
                                    let ep = row.endpoint.clone();
                                    status_banner = match crate::unikernel::dispatch_backend_drain_state(
                                        &shared,
                                        &[ep.clone()],
                                        false,
                                    ) {
                                        Ok(()) => format!("Enabled backend {} and updated nftables map", ep),
                                        Err(e) => format!("Failed to enable {}: {:#}", ep, e),
                                    };
                                }
                            }
                        }
                        KeyCode::Char('p') => {
                            let _ = run_all_probes_once(&shared).await;
                            last_probe = Instant::now();
                            status_banner = "Active health probes completed.".to_string();
                        }
                        KeyCode::Char('n') => {
                            show_nft_pane = !show_nft_pane;
                        }
                        _ => {}
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn build_dashboard_data(shared: &SharedState) -> (Vec<FlatBackendRow>, String, String) {
    let st = shared.read().unwrap();
    let cfg = st.active_config();

    let mut rows = Vec::new();
    let mut up_count = 0;
    let mut down_count = 0;
    let mut drained_count = 0;

    for svc in cfg.services.values() {
        let active_set: Vec<String> = st
            .active_backends_for_service(&svc.backends)
            .into_iter()
            .map(|b| b.endpoint())
            .collect();

        let vip_mode = match &svc.vip {
            Some(v) => format!("vip:{} / {}", v, svc.mode),
            None => format!("any / {}", svc.mode),
        };
        let strategy_limit = match &svc.limit {
            Some(l) => format!("{} ({}/{})", svc.balance, l.rate, l.unit),
            None => format!("{}", svc.balance),
        };

        for b in &svc.backends {
            let ep = b.endpoint();
            let rt = st.runtime.get(&ep).cloned().unwrap_or_default();
            let (status_str, status_color) = if rt.drained {
                drained_count += 1;
                ("DRAINED".to_string(), Color::Yellow)
            } else {
                match rt.health {
                    HealthState::Up => {
                        up_count += 1;
                        let lat = rt
                            .latency_ms
                            .map(|ms| format!(" ({:.1}ms)", ms))
                            .unwrap_or_default();
                        (format!("UP{}", lat), Color::Green)
                    }
                    HealthState::Down => {
                        down_count += 1;
                        ("DOWN".to_string(), Color::Red)
                    }
                    HealthState::Unknown => ("UNCHECKED".to_string(), Color::Gray),
                }
            };

            let role_weight = if b.backup {
                format!("backup w={}", b.weight)
            } else {
                format!("primary w={}", b.weight)
            };

            let traffic_str = format!(
                "{} pkts / {} B ({:.0} pps)",
                rt.packets, rt.bytes, rt.pps
            );

            rows.push(FlatBackendRow {
                service_key: svc.key.clone(),
                vip_mode: vip_mode.clone(),
                strategy_limit: strategy_limit.clone(),
                endpoint: ep.clone(),
                role_weight,
                status_str,
                status_color,
                traffic_str,
                in_active_map: active_set.contains(&ep),
            });
        }
    }

    let confirm_note = if let Some(pc) = &st.pending_confirm {
        let rem = pc.deadline.saturating_duration_since(Instant::now()).as_secs();
        format!(" | ⚠ CONFIRM PENDING ({}s left)", rem)
    } else {
        String::new()
    };

    let summary_line = format!(
        "Services: {} | Backends UP: {} | DOWN: {} | DRAINED: {}{}",
        cfg.services.len(),
        up_count,
        down_count,
        drained_count,
        confirm_note
    );

    let nft_preview = compile_nft_ruleset(cfg, Some(&st));
    (rows, nft_preview, summary_line)
}
