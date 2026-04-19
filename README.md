# kutout

Rust MITM proxy/scanner/poisoner/responder for pentesting from linux. <br>
Works on CLI or TUI. Requires root.

![TUI screenshot](img/tui.png)

### rust because:
- performant low-latency packet handling
- borrow checker prevents buffer overflows
- single binary.```cargo build --release``` gives you one 3.3MB stripped bin.
- no py interpreter, no pip dependencies, no venv. drop it on the target & run it.

## Tooling:
- arp scanning: discover live hosts on the local subnet
- arp poisoning: bidirectional mitm between targets and gateway, with automatic restoration on exit
- packet forwarding: observe all traffic flowing through the poisoned path
- credential sniffing: cleartext creds from ftp, http basic, http post, telnet, smtp, pop3, imap
- ntlmv2 capture: netntlmv2 hashes harvested from http-ntlm traffic, formatted as hashcat mode 5600
- dns spoofing: redirect domain lookups to arbitrary ips with wildcard and subdomain matching
- name poisoning: llmnr (udp/5355), mdns (udp/5353), nbt-ns (udp/137) responder + rogue http ntlm server
- safe mode: config-driven cidr/mac exclusions + printer autodetect. never poison the dc or the fax machine
- kill mode: selectively drop all traffic for individual hosts via iptables
- pcap capture: write raw frames to libpcap files for offline analysis
- engagement artifacts: jsonl event stream + summary.json + hosts.csv + credentials.csv on exit
- interactive tui: live scanning, poisoning, kill, dns, responder toggle, and mid-session export
- cli mode: 1337 hax0rz only. scriptable one-shot commands. works over pivot

---

## You need Rust on the box:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

gives you rustc, cargo, and rustup.
restart the shell after install

## Build:

```
cargo build --release
```

BIN at `target/release/kutout`
3.3 MB
requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN`.

---

## CLI commands

```bash
sudo ./kutout ifaces                     # list interfaces
sudo ./kutout scan                       # discover hosts
sudo ./kutout scan -r 10.0.0.0/24        # scan a specific range
sudo ./kutout poison 192.168.1.42 -s     # mitm + sniff creds + ntlm hashes
sudo ./kutout poison all -k              # blackhole all traffic
sudo ./kutout responder                  # llmnr/mdns/nbt-ns + rogue http, no arp
sudo ./kutout live                       # interactive tui
```

## CLI modes

### Scan: ARP sweep to find live hosts.

```bash
sudo ./kutout scan -i eth0 -r 192.168.1.0/28 -t 5
```

### Poison: ARP poison a target and observe traffic.

```bash
sudo ./kutout poison 192.168.1.42 -g .1 -s -o capture.pcap
sudo ./kutout poison 192.168.1.42 -d "*.corp.com=10.0.0.1" -d "login.site.com=10.0.0.1"
sudo ./kutout poison 192.168.1.42 -k                         # kill mode
sudo ./kutout poison 192.168.1.42 -s --out-dir ./engagement  # + jsonl/csv artifacts
```

#### Flags:
`-s` sniff creds + ntlm hashes <br>
`-k` kill mode <br>
`-o` pcap output <br>
`-d` dns spoof rule (repeatable) <br>
`-g` gateway override <br>
`--out-dir` engagement artifact dir

### Responder: name poisoning + rogue NTLM auth. No ARP touching.

```bash
sudo ./kutout responder --out-dir ./engagement
sudo ./kutout responder --no-mdns --no-http                  # selective
```

Answers llmnr/mdns/nbt-ns queries with your ip. Serves a 401 NTLM challenge over http. Captured hashes land as hashcat mode 5600 lines in `credentials.csv`.

### Live: Interactive TUI. Scan, poison, spoof DNS, toggle responder, watch events in real time.

```bash
sudo ./kutout live -i wlan0 --out-dir ./engagement
```

---

## TUI keybinds

| key | action |
|-----|--------|
| s | scan subnet |
| p | poison selected host (refused if safe-mode excluded) |
| x | toggle kill mode (iptables) |
| d | add dns spoof rule |
| r | toggle responder (llmnr/mdns/nbt-ns/http) |
| e | export summary snapshot (requires --out-dir) |
| c | cure all (arp + firewall + responder) |
| tab | switch panel |
| j/k | scroll |
| q | quit |

---

## Config

`kutout.toml` in cwd, or `~/.config/kutout/config.toml`, or `-c <path>`. CLI flags override config.

```toml
interface = "eth0"
out_dir = "./engagements/acme"
log_file = "./kutout.log"
log_level = "info"

[safe_mode]
excluded_cidrs = ["10.0.0.1/32", "192.168.1.240/28"]
excluded_macs = ["aa:bb:cc:dd:ee:ff"]
printer_probe = true                # tcp-connect 9100/515/631

[[dns_spoofs]]
domain = "*.phish.com"
ip = "10.0.0.100"

[responder]
match_names = ["wpad", "*.corp"]
exclude_names = ["dc01.corp"]
```

---

## Artifacts (--out-dir)

On clean exit kutout writes:

```
events.jsonl         one pentest event per line (full timeline)
summary.json         aggregate: hosts, creds, dns rules, counters, duration
hosts.csv            ip,mac
credentials.csv      ts_us,kind,proto,src,dst,detail
```

Pipe captured hashes to `hashcat -m 5600` and go.

---

What you can see through TLS: DNS queries, connection metadata, traffic patterns. Cleartext protocols (FTP, HTTP, Telnet, SMTP, POP3, IMAP) trigger auto credential logging. NTLM-over-HTTP hashes are captured whenever a victim hits your IP. DNS and name poisoning redirect targets to you regardless of encryption.

---

## map

```
src/
  main.rs                cli, tui event loop, session management
  config.rs              kutout.toml loader, precedence, resolve()
  events.rs              pentestevent taxonomy, sinks (stdout/jsonl/channel/fanout)
  safe_mode.rs           cidr/mac exclusions, printer tcp-probe
  summary.rs             engagement artifact aggregator (json + csv writers)
  net/iface.rs           interface detection, gateway, ip_forward, cidr parsing
  net/arp.rs             arp scan, bidirectional poison, restore
  net/forwarding.rs      packet observer, credential sniffing, dns + ntlmssp capture
  net/firewall.rs        iptables kill mode (KUTOUT chain management)
  attacks/dns_spoof.rs   dns wire format parsing, response forging, wildcard matching
  attacks/name_poison.rs llmnr/mdns/nbt-ns listeners + rfc 1002 nbt encoding
  attacks/ntlmssp.rs     ntlmssp parsing + hashcat mode 5600 formatter
  attacks/rogue_http.rs  http ntlm auth server, captures netntlmv2
  capture/pcap.rs        libpcap file writer
  tui/app.rs             application state, input modes, event handling
  tui/render.rs          layout, host table, event log, status bar
  tui/theme.rs           color scheme
```
