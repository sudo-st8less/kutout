# kutout

Rust MITM swiss-army knife for pentesting from linux. <br>
Works on CLI or TUI. Requires root.
small, fast, capable

![TUI screenshot](img/tui.png)

What you can see through TLS: DNS queries, connection metadata, traffic patterns. Cleartext protocols (FTP, HTTP, Telnet, SMTP, POP3, IMAP) trigger auto credential logging. NTLM-over-HTTP hashes are captured whenever a victim hits your IP. DNS and name poisoning redirect targets to you regardless of encryption. <br> <br>

### Rust because:
- performant low-latency packet handling
- single binary.```cargo build --release``` gives you one 3.3MB stripped bin.
- no py interpreter, pip dependencies, or venv

### Tooling:
- arp scanning: discover live hosts on the local subnet
- arp poisoning: bidirectional mitm between targets and gateway, with automatic restoration on exit
- dns spoofing: redirect domain lookups to arbitrary ips with wildcard and subdomain matching
- name poisoning: llmnr (udp/5355), mdns (udp/5353), nbt-ns (udp/137) responder + rogue http ntlm server
- ntlmv2 capture: netntlmv2 hashes harvested from http-ntlm traffic, formatted as hashcat mode 5600
- safe mode: config-driven cidr/mac exclusions + printer autodetect. never poison the dc or the fax machine
- packet forwarding: observe all traffic flowing through the poisoned path
- credential sniffing: cleartext creds from ftp, http basic, http post, telnet, smtp, pop3, imap
- kill mode: drop all traffic for individual hosts via iptables
- pcap capture: write raw frames to libpcap files
- engagement export: jsonl event stream + summary.json + hosts.csv + credentials.csv on exit
- cli mode: 1337 h4x, scriptable one-shot commands, can work over pivot

---

### You need Rust to build:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

gives you rustc, cargo, and rustup.
restart the shell after install

### Build:

```
cargo build --release
```

BIN at `target/release/kutout`
3.3 M
requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN`.

---

### Live Mode / TUI:

```bash
sudo ./kutout live -i wlan0 --out-dir ./engagement
```

---

### CLI commands

```bash
sudo ./kutout ifaces                     # list interfaces
sudo ./kutout scan                       # discover hosts
sudo ./kutout scan -r 10.0.0.0/24        # scan a specific range
sudo ./kutout poison 192.168.1.42 -s     # mitm + sniff creds + ntlm hashes
sudo ./kutout poison all -k              # blackhole all traffic
sudo ./kutout responder                  # llmnr/mdns/nbt-ns + rogue http, no arp
sudo ./kutout live                       # interactive tui
```

### CLI modes

#### Scan: ARP sweep to find live hosts.

```bash
sudo ./kutout scan -i eth0 -r 192.168.1.0/28 -t 5
```

#### Poison: ARP poison a target and observe traffic.

```bash
sudo ./kutout poison 192.168.1.42 -g .1 -s -o capture.pcap
sudo ./kutout poison 192.168.1.42 -d "*.corp.com=10.0.0.1" -d "login.site.com=10.0.0.1"
sudo ./kutout poison 192.168.1.42 -k                         # kill mode
sudo ./kutout poison 192.168.1.42 -s --out-dir ./engagement  # + jsonl/csv artifacts
```
##### Flags:
`-s` sniff creds + ntlm hashes <br>
`-k` kill mode <br>
`-o` pcap output <br>
`-d` dns spoof rule (repeatable) <br>
`-g` gateway override <br>
`--out-dir` engagement artifact dir

#### Responder: name poisoning + rogue NTLM auth. No ARP touching.

```bash
sudo ./kutout responder --out-dir ./engagement
sudo ./kutout responder --no-mdns --no-http                  # selective
```

Answers llmnr/mdns/nbt-ns queries with your ip.
Serves a 401 NTLM challenge over http.
Captured hashes land as hashcat mode 5600 lines in `credentials.csv`.


---

### Config

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

### Artifacts (--out-dir)

On clean exit kutout writes:

```
events.jsonl         one pentest event per line (full timeline)
summary.json         aggregate: hosts, creds, dns rules, counters, duration
hosts.csv            ip,mac
credentials.csv      ts_us,kind,proto,src,dst,detail
```

