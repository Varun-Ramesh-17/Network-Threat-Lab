# Scenario 01 — Port Scan Traffic Analysis

**Assessor:** Varun Ramesh  
**Date:** 2026-06-27  
**Tool:** tshark (Wireshark CLI) + Nmap 7.98  
**Capture File:** `portscan_capture.pcap`  
**Target:** scanme.nmap.org (45.33.32.156)  
**Source:** 172.23.199.164 (Kali WSL — attack machine)  
**MITRE ATT&CK:** T1046 — Network Service Discovery  

---

## What Happened

An Nmap SYN scan (`-sS`) was executed against scanme.nmap.org while tshark captured all traffic on eth0. The capture reveals the complete port scan lifecycle — host discovery, SYN probes, and target responses — visible at the packet level.

---

## Packet-by-Packet Analysis

### Phase 1 — Host Discovery (Packets 1–5)

Before scanning ports, Nmap checks if the host is alive:

```
1  172.23.199.164 → 45.33.32.156  ICMP  Echo (ping) request   ttl=40
2  172.23.199.164 → 45.33.32.156  TCP   45945 → 443 [SYN]
3  172.23.199.164 → 45.33.32.156  TCP   45945 → 80  [ACK]
4  172.23.199.164 → 45.33.32.156  ICMP  Timestamp request      ttl=52
5  45.33.32.156   → 172.23.199.164 ICMP Echo (ping) reply
```

**What this shows:**
- Nmap sends multiple probe types simultaneously — ICMP ping, TCP SYN to 443, TCP ACK to 80, ICMP timestamp
- This is Nmap's default host discovery behaviour — it uses multiple methods to confirm the host is up even if one probe type is blocked by a firewall
- Packet 5 confirms the host responded to ICMP — host is alive, scan proceeds

**Detection opportunity:** Multiple different probe types from the same source IP within milliseconds is a strong host discovery IOC. A legitimate user wouldn't send ICMP ping + TCP SYN + TCP ACK simultaneously.

---

### Phase 2 — SYN Scan (Packets 6 onwards)

Once the host is confirmed alive, Nmap begins the SYN scan — sending SYN packets to hundreds of ports:

```
6   172.23.199.164 → 45.33.32.156  TCP  46201 → 1025  [SYN]
7   172.23.199.164 → 45.33.32.156  TCP  46201 → 3389  [SYN]
8   172.23.199.164 → 45.33.32.156  TCP  46201 → 53    [SYN]
9   172.23.199.164 → 45.33.32.156  TCP  46201 → 21    [SYN]
10  172.23.199.164 → 45.33.32.156  TCP  46201 → 22    [SYN]
...
```

**Key observation:** All SYN packets share the same source port (46201) but target different destination ports rapidly. This is the SYN scan signature — one source port, many destination ports, high speed.

---

### Phase 3 — Target Responses Reveal Port States

The responses tell us everything about each port:

**Port 22 — OPEN (SSH confirmed):**
```
10  172.23.199.164 → 45.33.32.156  TCP  46201 → 22   [SYN]
20  45.33.32.156   → 172.23.199.164 TCP  22 → 46201   [SYN, ACK]   ← port is OPEN
21  172.23.199.164 → 45.33.32.156  TCP  46201 → 22   [RST]         ← Nmap resets (stealth)
```

This is the **SYN scan stealth mechanism** — Nmap sends SYN, gets SYN-ACK confirming port is open, then immediately sends RST to tear down the connection without completing the handshake. The connection never fully establishes, making it harder to log at the application level.

**Closed ports — RST,ACK response:**
```
16  45.33.32.156 → 172.23.199.164  TCP  256  → 46201  [RST, ACK]
17  45.33.32.156 → 172.23.199.164  TCP  53   → 46201  [RST, ACK]
18  45.33.32.156 → 172.23.199.164  TCP  3389 → 46201  [RST, ACK]
19  45.33.32.156 → 172.23.199.164  TCP  1025 → 46201  [RST, ACK]
```

RST,ACK = port is closed. The host actively rejects the connection.

---

## Port State Summary from Capture

| Port | Response from Target | State | Service |
|---|---|---|---|
| 22 | SYN,ACK → then RST'd by scanner | **OPEN** | SSH |
| 80 | SYN,ACK (from host discovery phase) | **OPEN** | HTTP |
| 21 | RST,ACK | Closed | FTP |
| 53 | RST,ACK | Closed | DNS |
| 111 | RST,ACK | Closed | RPC |
| 113 | RST,ACK | Closed | Ident |
| 135 | RST,ACK | Closed | MSRPC |
| 139 | RST,ACK | Closed | NetBIOS |
| 256 | RST,ACK | Closed | — |
| 1025 | RST,ACK | Closed | — |
| 3306 | RST,ACK | Closed | MySQL |
| 3389 | RST,ACK | Closed | RDP |
| 8888 | RST,ACK | Closed | — |

---

## IOC Summary — What a SOC Analyst Would Flag

| IOC | Value | Significance |
|---|---|---|
| High-volume SYN packets | 40+ SYNs in <1 second | Port scan in progress |
| Single source port, many dest ports | 46201 → multiple | Classic SYN scan signature |
| Mixed probe types at start | ICMP + TCP SYN + TCP ACK simultaneously | Nmap host discovery |
| SYN followed immediately by RST | Port 22 sequence | Stealth SYN scan (-sS flag) |
| No completed TCP handshakes | No SYN→SYN-ACK→ACK sequence | Half-open scan — evading basic logging |

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence in Capture |
|---|---|---|
| Network Service Discovery | T1046 | SYN probes to 40+ ports |
| Active Scanning: Scanning IP Blocks | T1595.001 | ICMP + TCP host discovery probes |

---

## Detection Rule (SOC Context)

If this traffic appeared on a monitored network, the following rule would trigger:

```
ALERT: Potential Port Scan Detected
Condition: Single source IP sends SYN packets to >20 destination ports 
           within a 5-second window
Threshold: >20 unique destination ports
Action: Alert SOC Tier 1, correlate with auth logs, check threat intel for source IP
Priority: Medium (external source) / High (internal source — lateral movement)
```

---

## Raw Capture

See: [`../../captures/portscan_capture.pcap`](../../captures/portscan_capture.pcap)  
Readable output: [`portscan_tshark_output.txt`](./portscan_tshark_output.txt)

---

*Capture conducted from Kali Linux (WSL) on 2026-06-27. Target: scanme.nmap.org — authorised public scanning target.*
