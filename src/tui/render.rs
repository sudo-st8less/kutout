// render

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::net::iface::format_mac;
use crate::tui::app::{App, InputMode, LogKind, Panel};
use crate::tui::theme;

pub fn draw(frame: &mut Frame, app: &App) {
    let size = frame.size();

    let bg_block = Block::default().style(
        ratatui::style::Style::default().bg(theme::BG_DARK),
    );
    frame.render_widget(bg_block, size);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    draw_header(frame, app, chunks[0]);
    draw_body(frame, app, chunks[1]);
    draw_status(frame, app, chunks[2]);
}

// "the master observes the world but trusts his inner vision." — tao te ching, 12

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let banner = vec![Line::from(vec![
        Span::styled(" kutout ", theme::title_style()),
        Span::styled("// ", theme::text_dim()),
        Span::styled(&app.iface_name, theme::header_style()),
        Span::styled(" @ ", theme::text_dim()),
        Span::styled(app.our_ip.to_string(), theme::text_normal()),
        Span::styled(" -> gw ", theme::text_dim()),
        Span::styled(app.gateway_ip.to_string(), theme::text_normal()),
        Span::styled("  |  ", theme::text_dim()),
        Span::styled(
            format!("pkts: {}", app.packets_total),
            theme::text_normal(),
        ),
        Span::styled("  ", theme::text_dim()),
        Span::styled(
            format!("creds: {}", app.creds_total),
            if app.creds_total > 0 {
                theme::cred_style()
            } else {
                theme::text_normal()
            },
        ),
        Span::styled("  ", theme::text_dim()),
        Span::styled(
            format!("poisons: {}", app.poisons.len()),
            if app.poisons.is_empty() {
                theme::text_normal()
            } else {
                theme::success_style()
            },
        ),
        Span::styled("  ", theme::text_dim()),
        Span::styled(
            format!("dns: {}", app.dns_rule_count),
            if app.dns_rule_count > 0 {
                theme::cred_style()
            } else {
                theme::text_normal()
            },
        ),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::active_border())
        .style(ratatui::style::Style::default().bg(theme::BG_PANEL));

    let para = Paragraph::new(banner).block(block);
    frame.render_widget(para, area);
}

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(45),
            Constraint::Percentage(55),
        ])
        .split(area);

    draw_hosts(frame, app, chunks[0]);
    draw_log(frame, app, chunks[1]);
}

fn draw_hosts(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_panel == Panel::Hosts;
    let border_style = if is_active {
        theme::active_border()
    } else {
        theme::panel_border()
    };

    let title = format!(" hosts ({}) ", app.hosts.len());
    let block = Block::default()
        .title(Span::styled(title, theme::header_style()))
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(ratatui::style::Style::default().bg(theme::BG_PANEL));

    let header = Row::new(vec![
        Cell::from("ip").style(theme::header_style()),
        Cell::from("mac").style(theme::header_style()),
        Cell::from("status").style(theme::header_style()),
    ]);

    let rows: Vec<Row> = app
        .hosts
        .iter()
        .enumerate()
        .map(|(i, host)| {
            let poison = app.poisons.iter().find(|p| p.target_ip == host.ip);
            let status = match poison {
                Some(p) if p.kill_mode => "killed",
                Some(_) => "poisoned",
                None if host.ip == app.gateway_ip => "gateway",
                None => "",
            };

            let status_style = match status {
                "killed" => theme::kill_style(),
                "poisoned" => theme::success_style(),
                "gateway" => theme::header_style(),
                _ => theme::text_dim(),
            };

            let row_style = if i == app.host_scroll {
                theme::selected_style()
            } else {
                theme::text_normal()
            };

            Row::new(vec![
                Cell::from(host.ip.to_string()),
                Cell::from(format_mac(&host.mac)),
                Cell::from(Span::styled(status, status_style)),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(18),
            Constraint::Min(8),
        ],
    )
    .header(header)
    .block(block);

    frame.render_widget(table, area);
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_panel == Panel::Log;
    let border_style = if is_active {
        theme::active_border()
    } else {
        theme::panel_border()
    };

    let title = format!(" events ({}) ", app.log.len());
    let block = Block::default()
        .title(Span::styled(title, theme::header_style()))
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(ratatui::style::Style::default().bg(theme::BG_PANEL));

    let inner_height = area.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let start = total.saturating_sub(inner_height);

    let lines: Vec<Line> = app
        .log
        .iter()
        .skip(start)
        .map(|entry| {
            let (prefix, style) = match entry.kind {
                LogKind::Credential => (" cred ", theme::cred_style()),
                LogKind::Kill => (" kill ", theme::kill_style()),
                LogKind::DnsQuery => ("  dns ", ratatui::style::Style::default().fg(theme::PROTO_DNS)),
                LogKind::DnsSpoof => (" spof ", theme::cred_style()),
                LogKind::PacketForward => ("  pkt ", theme::text_dim()),
                LogKind::Info => (" info ", theme::text_normal()),
                LogKind::Error => ("  err ", theme::kill_style()),
            };

            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(" ", theme::text_dim()),
                Span::styled(&entry.message, theme::text_normal()),
            ])
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::panel_border())
        .style(ratatui::style::Style::default().bg(theme::BG_PANEL));

    let keys = match app.input_mode {
        InputMode::DnsInput => vec![Line::from(vec![
            Span::styled(" dns rule (domain=ip): ", theme::header_style()),
            Span::styled(&app.input_buffer, theme::text_normal()),
            Span::styled("_", theme::cred_style()),
            Span::styled("    ", theme::text_dim()),
            Span::styled("enter", theme::cred_style()),
            Span::styled(" add  ", theme::text_dim()),
            Span::styled("esc", theme::cred_style()),
            Span::styled(" cancel", theme::text_dim()),
        ])],
        InputMode::Normal => vec![Line::from(vec![
            Span::styled(" q", theme::cred_style()),
            Span::styled(" quit  ", theme::text_dim()),
            Span::styled("s", theme::cred_style()),
            Span::styled(" scan  ", theme::text_dim()),
            Span::styled("p", theme::cred_style()),
            Span::styled(" poison  ", theme::text_dim()),
            Span::styled("x", theme::cred_style()),
            Span::styled(" kill  ", theme::text_dim()),
            Span::styled("d", theme::cred_style()),
            Span::styled(" dns  ", theme::text_dim()),
            Span::styled("c", theme::cred_style()),
            Span::styled(" cure  ", theme::text_dim()),
            Span::styled("  |  ", theme::text_dim()),
            Span::styled(&app.status_message, theme::text_normal()),
        ])],
    };

    let para = Paragraph::new(keys).block(block);
    frame.render_widget(para, area);
}
