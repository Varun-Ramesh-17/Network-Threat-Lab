# 🔬 Network Threat Lab

> Wireshark-based network traffic analysis, attack simulation, and IOC detection — mapped to MITRE ATT&CK.

---

## Overview

This project documents my home lab work in network threat detection. I simulated real-world attack scenarios, captured traffic with Wireshark, and practised identifying Indicators of Compromise (IOCs) from the attacker's perspective — critical for understanding both detection and evasion.

**Key results:**
- 500+ packets captured and analysed across 10+ attack scenarios
- ~90% IOC detection accuracy across all simulations
- All findings mapped to MITRE ATT&CK tactics and techniques

---

## Lab Environment

| Component | Details |
|---|---|
| Traffic Capture | Wireshark |
| Attack Simulation | Manual + Kali Linux tools |
| Analysis Framework | MITRE ATT&CK |
| OS | Kali Linux, Windows Server (VMs) |

---

## Attack Scenarios Simulated

| # | Scenario | MITRE Tactic | IOC Detected |
|---|---|---|---|
| 1 | Port scan (SYN sweep) | TA0043 Reconnaissance | High volume SYN packets, no ACK |
| 2 | DNS enumeration | TA0043 Reconnaissance | Abnormal DNS query volume |
| 3 | SMB lateral movement | TA0008 Lateral Movement | Unusual SMB traffic between hosts |
| 4 | C2 beaconing (simulated) | TA0011 Command & Control | Regular outbound intervals, beacon pattern |
| 5 | Credential brute force | TA0006 Credential Access | Repeated failed auth events |
| 6 | Data exfiltration (simulated) | TA0010 Exfiltration | Large outbound transfer, unusual destination |
| 7 | ARP spoofing | TA0043 Reconnaissance | Duplicate ARP replies, MAC conflict |
| 8 | ICMP flood | TA0040 Impact | Abnormal ICMP volume from single source |
| 9 | FTP plaintext credential capture | TA0006 Credential Access | Cleartext credentials in packet stream |
| 10 | HTTP anomaly (user-agent) | TA0001 Initial Access | Non-standard user-agent strings |

---

## Sample IOC Analysis

### Scenario: C2 Beaconing Pattern

**What I observed in Wireshark:**
- Regular outbound HTTP requests at consistent 30-second intervals
- Destination: single external IP (simulated C2)
- Packet size: uniform (~400 bytes per request)
- No variation in timing — textbook beacon behaviour

**MITRE Mapping:**
- Tactic: Command and Control (TA0011)
- Technique: Application Layer Protocol: Web Protocols (T1071.001)

**Detection Logic:**
```
Alert: Consistent outbound connection intervals < 60s
Threshold: 10+ identical-sized packets to same destination
Action: Escalate for threat hunting review
```

---

### Scenario: Abnormal DNS Behaviour

**What I observed:**
- Single host generating 200+ DNS queries in 5 minutes
- Queries targeting random subdomains of same root domain
- Pattern consistent with DNS tunnelling or C2 domain generation

**MITRE Mapping:**
- Tactic: Command and Control (TA0011)
- Technique: DNS (T1071.004)

---

## Key Takeaways

1. **Timing patterns matter** — C2 beaconing is often invisible in content but obvious in timing
2. **DNS is noisy by design** — but volume + randomness = anomaly worth investigating
3. **Lateral movement leaves SMB breadcrumbs** — authentication events + unusual source hosts
4. **Baseline first** — IOC detection only works when you know what normal looks like

---

## Files in This Repo

```
Network-Threat-Lab/
├── README.md               ← This file
├── scenarios/
│   ├── 01-port-scan.md
│   ├── 02-dns-enum.md
│   ├── 04-c2-beaconing.md
│   └── ...
├── screenshots/            ← Wireshark captures (annotated)
└── mitre-mapping-table.md  ← Full MITRE ATT&CK reference
```

---

## Tools Used

- **Wireshark** — packet capture and analysis
- **Kali Linux** — attack simulation environment
- **MITRE ATT&CK Navigator** — technique mapping

---

*Part of my cybersecurity portfolio. See also: [Vuln-Scan-Reports](../Vuln-Scan-Reports) · [SOC-Playbooks](../SOC-Playbooks)*
