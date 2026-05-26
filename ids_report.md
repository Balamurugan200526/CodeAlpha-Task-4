# Network Intrusion Detection System — Report
## CodeAlpha Cybersecurity Internship — Task 4

**Tool Built:** Python-based IDS using Scapy  
**Platform:** Windows 11  
**Language:** Python 3  
**Libraries:** Scapy, Collections, Datetime  
**Date:** 2024  

---

## Overview

A custom **Network Intrusion Detection System (IDS)** was built using Python and Scapy to monitor live network traffic, apply detection rules, generate real-time alerts, and save logs for analysis.

This IDS performs the same core functions as enterprise tools like Snort and Suricata — packet capture, rule-based detection, and alerting — implemented entirely in Python.

---

## Detection Rules Implemented

### Rule 1 — Port Scan Detection
**Severity:** HIGH  
**Trigger:** One source IP contacts more than 10 unique destination ports

**How it works:** Tracks all destination ports contacted by each source IP in a dictionary. When the unique port count exceeds the threshold, an alert fires.

**Why it matters:** Port scanning is almost always the first step in a network attack. Attackers use tools like Nmap to discover open services before exploiting them.

**Alert Example:**
```
[ALERT] [HIGH] [PORT SCAN DETECTED] 192.168.1.50 -> 192.168.1.1 | 
Source scanned 10 unique ports (Threshold: 10)
```

---

### Rule 2 — ICMP Flood Detection
**Severity:** MEDIUM  
**Trigger:** More than 20 ICMP packets received from one source IP

**How it works:** Counts ICMP packets per source IP. A high volume of ICMP Echo Requests (pings) indicates a ping flood or DoS attempt.

**Why it matters:** ICMP floods can overwhelm network devices and cause denial of service. Also used in Smurf attacks.

**Alert Example:**
```
[ALERT] [MEDIUM] [ICMP FLOOD DETECTED] 10.0.0.5 -> 192.168.1.1 | 
Received 20 ICMP packets from source (Threshold: 20)
```

---

### Rule 3 — SSH Brute Force Detection
**Severity:** HIGH  
**Trigger:** More than 5 TCP SYN packets to port 22 from one source IP

**How it works:** Monitors all TCP packets destined for port 22 (SSH). Counts SYN flags (new connection attempts) per source IP. A high count indicates repeated login attempts.

**Why it matters:** SSH brute force is one of the most common server attacks. Attackers try thousands of username/password combinations to gain shell access.

**Alert Example:**
```
[ALERT] [HIGH] [SSH BRUTE FORCE DETECTED] 45.33.32.156 -> 192.168.1.10 | 
5 SSH SYN packets from source (Threshold: 5)
```

---

### Rule 4 — HTTP Flood Detection
**Severity:** MEDIUM  
**Trigger:** More than 30 HTTP requests to port 80/443 from one source IP

**How it matters:** HTTP floods are a layer-7 DoS attack where attackers send massive numbers of HTTP requests to overwhelm a web server.

**Alert Example:**
```
[ALERT] [MEDIUM] [HTTP FLOOD DETECTED] 192.168.1.50 -> 192.168.1.1 | 
30 HTTP requests from source (Threshold: 30)
```

---

### Rule 5 — Suspicious Port Traffic
**Severity:** HIGH  
**Trigger:** Any traffic detected to known malicious or high-risk ports

| Port | Service | Risk |
|---|---|---|
| 23 | Telnet | Unencrypted remote access |
| 445 | SMB | WannaCry, EternalBlue exploitation |
| 1433 | MSSQL | Database attack target |
| 3389 | RDP | Remote Desktop brute force |
| 4444 | Metasploit | Default reverse shell listener |
| 5900 | VNC | Unencrypted remote desktop |
| 6667 | IRC | Botnet C2 communication |
| 31337 | Back Orifice | Classic backdoor/RAT port |

**Alert Example:**
```
[ALERT] [HIGH] [SUSPICIOUS PORT TRAFFIC] 192.168.1.50 -> 192.168.1.1 | 
Traffic to port 4444 — Metasploit default listener
```

---

### Rule 6 — Large Packet Detection
**Severity:** LOW  
**Trigger:** Any packet exceeding 1400 bytes

**Why it matters:** Unusually large packets can indicate DoS fragmentation attacks or data exfiltration attempts sending large chunks of data out of the network.

**Alert Example:**
```
[ALERT] [LOW] [LARGE PACKET DETECTED] 192.168.1.1 -> 8.8.8.8 | 
Packet size: 1500 bytes (threshold: 1400 bytes)
```

---

## Sample IDS Output

```
============================================================
  NETWORK INTRUSION DETECTION SYSTEM
  CodeAlpha Cybersecurity Internship — Task 4
============================================================
  Detection Rules Active:
   [1] Port Scan Detection     (threshold: 10 ports)
   [2] ICMP Flood Detection    (threshold: 20 packets)
   [3] SSH Brute Force         (threshold: 5 attempts)
   [4] HTTP Flood Detection    (threshold: 30 requests)
   [5] Suspicious Port Traffic (8 known dangerous ports)
   [6] Large Packet Detection  (threshold: 1400 bytes)
============================================================
  Capturing 200 packets...
  Press Ctrl+C to stop

[PKT] TCP 192.168.29.36 -> 146.75.122.172:80 | Flags:S | Size:60
[PKT] UDP 192.168.29.249 -> 192.168.29.255:5775 | Size:80
[PKT] ICMP 192.168.29.1 -> 192.168.29.36 | Echo Request (Ping)
[ALERT] [HIGH] [SUSPICIOUS PORT TRAFFIC] 192.168.1.50 -> 192.168.1.1 | Port 4444 — Metasploit listener

============================================================
  INTRUSION DETECTION SYSTEM — SESSION SUMMARY
============================================================
  Total Alerts Generated : 3
  HIGH   Severity : 2
  MEDIUM Severity : 1
  LOW    Severity : 0

  Log saved to    : ids_alerts.log

  Alert Breakdown:
   - SUSPICIOUS PORT TRAFFIC: 2 alert(s)
   - ICMP FLOOD DETECTED: 1 alert(s)
============================================================
```

---

## Architecture

```
Live Network Traffic
        |
        v
  Scapy Packet Sniffer
        |
        v
  Packet Parser (IP/TCP/UDP/ICMP)
        |
        v
  +-----------------------+
  | Rule Engine           |
  | - Port Scan Detection |
  | - ICMP Flood          |
  | - SSH Brute Force     |
  | - HTTP Flood          |
  | - Suspicious Ports    |
  | - Large Packets       |
  +-----------------------+
        |
        v
  Alert Generator
  (Terminal + Log File)
        |
        v
  ids_alerts.log + Session Summary
```

---

## Comparison: This IDS vs Snort

| Feature | This Python IDS | Snort |
|---|---|---|
| Packet capture | Scapy | libpcap |
| Rule engine | Python code | Snort rule syntax |
| Port scan detection | Yes | Yes |
| Brute force detection | Yes | Yes |
| Real-time alerts | Yes | Yes |
| Log file | Yes (.log) | Yes (.log) |
| Platform | Windows/Linux | Linux (mainly) |
| Setup difficulty | Easy | Complex |

---

## Conclusion

The Python IDS successfully monitors live network traffic and detects 6 categories of suspicious activity in real time. All alerts are color-coded by severity in the terminal and saved to `ids_alerts.log` for later review. This project demonstrates the core principles of network intrusion detection used in enterprise security tools like Snort and Suricata.

---

*Report prepared as part of CodeAlpha Cybersecurity Internship — Task 4: Network Intrusion Detection System*
