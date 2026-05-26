# 🛡️ Network Intrusion Detection System — CodeAlpha Internship Task 4

!\[Python](https://img.shields.io/badge/Python-3.x-blue)
!\[Scapy](https://img.shields.io/badge/Library-Scapy-green)
!\[Rules](https://img.shields.io/badge/Detection%20Rules-6-red)
!\[Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
!\[Status](https://img.shields.io/badge/Status-Completed-brightgreen)
!\[Internship](https://img.shields.io/badge/Company-CodeAlpha-orange)

A **Python-based Network Intrusion Detection System (IDS)** built using Scapy. Monitors live network traffic, applies 6 detection rules, generates real-time color-coded alerts, and saves all alerts to a log file — same core functionality as Snort/Suricata, running natively on Windows.

\---

## 📋 Table of Contents

* [About the Project](#about-the-project)
* [Detection Rules](#detection-rules)
* [Files in this Repository](#files-in-this-repository)
* [Technologies Used](#technologies-used)
* [How to Run](#how-to-run)
* [Sample Output](#sample-output)
* [What I Learned](#what-i-learned)

\---

## 📖 About the Project

This project is **Task 4** of the CodeAlpha Cybersecurity Internship. The goal was to set up a Network Intrusion Detection System that:

* Monitors live network traffic continuously
* Applies detection rules to identify suspicious activity
* Generates real-time alerts for detected threats
* Saves all alerts to a log file for review
* Provides a session summary with alert counts by severity

Since the setup is on **Windows**, this IDS was implemented in Python using Scapy — which provides the same packet capture and analysis capabilities as Snort/Suricata, with zero complex configuration needed.

\---

## 🔍 Detection Rules

|#|Rule|Severity|Trigger Condition|
|-|-|-|-|
|1|Port Scan Detection|🔴 HIGH|1 source IP hits 10+ unique ports|
|2|ICMP Flood Detection|🟡 MEDIUM|20+ ICMP packets from 1 source|
|3|SSH Brute Force|🔴 HIGH|5+ SYN packets to port 22|
|4|HTTP Flood Detection|🟡 MEDIUM|30+ requests to port 80/443|
|5|Suspicious Port Traffic|🔴 HIGH|Traffic to ports 23,445,4444,3389,etc|
|6|Large Packet Detection|🟢 LOW|Packet size exceeds 1400 bytes|

\---

## 📁 Files in this Repository

|File|Description|
|-|-|
|`ids.py`|Main IDS — captures packets and applies all detection rules|
|`ids\\\\\\\_alerts.log`|Auto-generated log file with all alerts from the session|
|`ids\\\\\\\_report.md`|Full IDS report with rule explanations and sample output|
|`README.md`|This file|

\---

## 🛠 Technologies Used

|Tool|Purpose|
|-|-|
|Python 3|Core programming language|
|Scapy|Live packet capture and analysis|
|Npcap (Windows)|Packet capture driver for Windows|
|Collections|defaultdict for efficient traffic tracking|
|Datetime|Timestamps for all alerts|

\---

## ▶️ How to Run

**Step 1 — Clone the repository**

```bash
git clone https://github.com/Balamurugan200526/CodeAlpha\\\\\\\_NetworkIDS.git
cd CodeAlpha\\\\\\\_NetworkIDS
```

**Step 2 — Install Scapy**

```bash
pip install scapy
```

**Step 3 — Install Npcap (Windows only)**

Download from https://npcap.com/#download  
Install with ✅ "WinPcap API-compatible mode" checked

**Step 4 — Run as Administrator (Windows)**

```bash
# Open CMD as Administrator, then:
python ids.py
```

**Step 5 — Run with sudo (Linux)**

```bash
sudo python3 ids.py
```

**Step 6 — View the alert log**

```bash
# Windows
type ids\\\\\\\_alerts.log

# Linux
cat ids\\\\\\\_alerts.log
```

Press `Ctrl+C` to stop. A full session summary is printed automatically.

\---

## 📊 Sample Output

```
============================================================
  NETWORK INTRUSION DETECTION SYSTEM
  CodeAlpha Cybersecurity Internship — Task 4
============================================================
  Detection Rules Active:
   \\\\\\\[1] Port Scan Detection     (threshold: 10 ports)
   \\\\\\\[2] ICMP Flood Detection    (threshold: 20 packets)
   \\\\\\\[3] SSH Brute Force         (threshold: 5 attempts)
   \\\\\\\[4] HTTP Flood Detection    (threshold: 30 requests)
   \\\\\\\[5] Suspicious Port Traffic (8 known dangerous ports)
   \\\\\\\[6] Large Packet Detection  (threshold: 1400 bytes)
============================================================

\\\\\\\[PKT] TCP 192.168.29.36 -> 146.75.122.172:80 | Flags:S | Size:60
\\\\\\\[PKT] UDP 192.168.29.249 -> 192.168.29.255:5775 | Size:80
\\\\\\\[ALERT] \\\\\\\[HIGH] \\\\\\\[PORT SCAN DETECTED] 192.168.1.5 -> 192.168.1.1 | 10 unique ports scanned
\\\\\\\[ALERT] \\\\\\\[HIGH] \\\\\\\[SUSPICIOUS PORT TRAFFIC] 192.168.1.5 -> 192.168.1.1 | Port 4444 — Metasploit default listener

============================================================
  INTRUSION DETECTION SYSTEM — SESSION SUMMARY
============================================================
  Total Alerts Generated : 2
  HIGH   Severity : 2
  MEDIUM Severity : 0
  LOW    Severity : 0
  Log saved to    : ids\\\\\\\_alerts.log
============================================================
```

\---

## 📚 What I Learned

* How network-based intrusion detection systems work at the packet level
* How to detect port scans, brute force attacks, and floods using traffic patterns
* How Snort and Suricata apply rule-based detection to network traffic
* How to use Python Scapy to build a real security monitoring tool
* How to implement stateful tracking (counting packets per source IP)
* How real-world attacks like port scanning, SSH brute force, and ICMP floods look at the network level
* The importance of alert logging and session summaries in SOC (Security Operations)

\---

## ⚠️ Disclaimer

This tool is built for **educational purposes only** as part of the CodeAlpha Cybersecurity Internship. Only monitor networks you own or have explicit permission to monitor. Unauthorized network monitoring is illegal and unethical.

\---

## 👤 Author

* **Name:** Balamurugan S
* **Internship:** CodeAlpha Cybersecurity Internship
* **LinkedIn:** https://www.linkedin.com/in/balamurugan-s-468387337
* **GitHub:**

\---

> ⭐ If you found this helpful, give the repo a star!

