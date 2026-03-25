# kutout

Rust MITM Proxy/Scanner/Poisoner for pentesting from linux.
Works on CLI or TUI. Requires root.

rust because:
- performant low-latency packet handling
- borrow checker prevents buffer overflows
- single binary.```cargo build --release``` gives you one 2.7MB stripped binary. no python interpreter, no
pip dependencies, no virtualenv. drop it on the target & run it.

## Tooling:
- arp scanning: discover live hosts on the local subnet                                                    
- arp poisoning: bidirectional mitm between targets and gateway, with automatic restoration on exit        
- packet forwarding: observe all traffic flowing through the poisoned path                                 
- credential sniffing: extract cleartext creds from ftp, http basic auth, http post forms, telnet, smtp,   
  pop3, imap                                                                                                  
- dns spoofing: redirect domain lookups to arbitrary ips with wildcard and subdomain matching              
- kill mode: selectively drop all traffic for individual hosts via iptables                                
- pcap capture: write raw frames to libpcap files for offline analysis                                     
- interactive tui: live scanning, poisoning, kill toggling, dns rule injection, event log, and per-target  
  stats in a single terminal sesh                                                                          
- cli mode: 1337 hax0rz only. scriptable one-shot commands for scan, poison, and interface listing. works over pivot

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
2.7 MB 
requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN`.

---

## CLI commands

```bash
sudo ./kutout ifaces                   # list interfaces
sudo ./kutout scan                     # discover hosts
sudo ./kutout scan -r 10.0.0.0/24      # scan a specific range
sudo ./kutout poison 192.168.1.42 -s   # mitm + sniff credentials
sudo ./kutout poison all -k            # blackhole all traffic
sudo ./kutout live                     # interactive tui
```

## CLI modes

**scan** -- ARP sweep to find live hosts.

```bash
sudo ./kutout scan -i eth0 -r 192.168.1.0/28 -t 5
```

**poison** -- ARP poison a target and observe traffic.

```bash
sudo ./kutout poison 192.168.1.42 -g .1 -s -o capture.pcap
sudo ./kutout poison 192.168.1.42 -d "*.corp.com=10.0.0.1" -d "login.site.com=10.0.0.1"
sudo ./kutout poison 192.168.1.42 -k   # kill mode: drop instead of forward
```

Flags: `-s` sniff credentials, `-k` kill mode, `-o` pcap output, `-d` dns spoof rule (repeatable), `-g` gateway override.

**live** -- Interactive TUI. Scan, poison, spoof DNS, toggle kill mode, watch events in real time.

```bash
sudo ./kutout live -i wlan0
```

## TUI keybinds

| key | action |
|-----|--------|
| s | scan subnet |
| p | poison selected host |
| x | toggle kill mode (iptables) |
| d | add dns spoof rule |
| c | cure all (restore ARP + firewall) |
| tab | switch panel |
| j/k | scroll |
| q | quit |

## how the heck?

1. ARP poisoning tricks the target and gateway into routing traffic through your machine
2. The kernel forwards packets via `ip_forward` (managed automatically, restored on exit)
3. An AF_PACKET observer reads transiting packets for credential sniffing, DNS logging, and pcap capture
4. DNS spoofing injects forged A-record responses that race the real upstream reply
5. Kill mode adds per-target iptables DROP rules in a dedicated KUTOUT chain (cleaned up on exit)

What you can see through TLS: DNS queries, connection metadata, traffic patterns. Cleartext protocols (FTP, HTTP, Telnet, SMTP, POP3, IMAP) trigger auto credential logging. DNS spoofing redirects targets to your IP regardless of encryption.

---

## map

```
src/
  main.rs                cli, tui event loop, session management
  net/iface.rs           interface detection, gateway, ip_forward, cidr parsing
  net/arp.rs             arp scan, bidirectional poison, restore
  net/forwarding.rs      packet observer, credential sniffing, dns spoof injection
  net/firewall.rs        iptables kill mode (KUTOUT chain management)
  attacks/dns_spoof.rs   dns wire format parsing, response forging, wildcard matching
  capture/pcap.rs        libpcap file writer
  tui/app.rs             application state, input modes, event handling
  tui/render.rs          layout, host table, event log, status bar
  tui/theme.rs           color scheme
```

