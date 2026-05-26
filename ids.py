# ============================================================
# NETWORK INTRUSION DETECTION SYSTEM (IDS)
# CodeAlpha Cybersecurity Internship — Task 4
# Built using Python + Scapy
# Platform: Windows / Linux
# Run as Administrator (Windows) or sudo (Linux)
# ============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import os

# ============================================================
# CONFIGURATION
# ============================================================
LOG_FILE = "ids_alerts.log"     # File to save all alerts
PACKET_COUNT = 200              # How many packets to capture (0 = infinite)

# Thresholds for detection rules
PORT_SCAN_THRESHOLD   = 10      # ports hit in window = port scan
ICMP_FLOOD_THRESHOLD  = 20      # ICMP packets in window = flood
SSH_BRUTE_THRESHOLD   = 5       # SSH attempts in window = brute force
HTTP_FLOOD_THRESHOLD  = 30      # HTTP requests in window = flood

# Tracking dictionaries (in-memory counters)
port_scan_tracker  = defaultdict(set)      # src_ip -> set of ports contacted
icmp_tracker       = defaultdict(int)      # src_ip -> icmp count
ssh_tracker        = defaultdict(int)      # src_ip -> ssh attempt count
http_tracker       = defaultdict(int)      # src_ip -> http request count
alert_log          = []                    # All alerts in memory

# ============================================================
# COLORS FOR TERMINAL OUTPUT
# ============================================================
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ============================================================
# ALERT FUNCTION
# ============================================================
def trigger_alert(level, rule_name, src_ip, dst_ip, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    color = RED if level == "HIGH" else YELLOW if level == "MEDIUM" else GREEN

    alert_msg = (
        f"[{timestamp}] "
        f"[{level}] "
        f"[{rule_name}] "
        f"{src_ip} -> {dst_ip} | {details}"
    )

    # Print to terminal with color
    print(f"{color}{BOLD}[ALERT]{RESET} {color}{alert_msg}{RESET}")

    # Save to log file
    with open(LOG_FILE, "a") as f:
        f.write(alert_msg + "\n")

    # Store in memory
    alert_log.append({
        "time": timestamp,
        "level": level,
        "rule": rule_name,
        "src": src_ip,
        "dst": dst_ip,
        "details": details
    })


# ============================================================
# RULE 1: PORT SCAN DETECTION
# Detects if one IP contacts too many different ports
# ============================================================
def detect_port_scan(src_ip, dst_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)
    unique_ports = len(port_scan_tracker[src_ip])

    if unique_ports == PORT_SCAN_THRESHOLD:
        trigger_alert(
            level="HIGH",
            rule_name="PORT SCAN DETECTED",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"Source scanned {unique_ports} unique ports (Threshold: {PORT_SCAN_THRESHOLD})"
        )
    elif unique_ports > PORT_SCAN_THRESHOLD and unique_ports % 5 == 0:
        trigger_alert(
            level="HIGH",
            rule_name="PORT SCAN ONGOING",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"Scan continues — {unique_ports} ports scanned so far"
        )


# ============================================================
# RULE 2: ICMP FLOOD DETECTION
# Detects excessive ping/ICMP packets from one source
# ============================================================
def detect_icmp_flood(src_ip, dst_ip):
    icmp_tracker[src_ip] += 1
    count = icmp_tracker[src_ip]

    if count == ICMP_FLOOD_THRESHOLD:
        trigger_alert(
            level="MEDIUM",
            rule_name="ICMP FLOOD DETECTED",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"Received {count} ICMP packets from source (Threshold: {ICMP_FLOOD_THRESHOLD})"
        )
    elif count > ICMP_FLOOD_THRESHOLD and count % 10 == 0:
        trigger_alert(
            level="MEDIUM",
            rule_name="ICMP FLOOD ONGOING",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"ICMP flood continues — {count} packets so far"
        )


# ============================================================
# RULE 3: SSH BRUTE FORCE DETECTION
# Detects repeated connection attempts to port 22
# ============================================================
def detect_ssh_brute_force(src_ip, dst_ip, flags):
    # Only count SYN packets (new connection attempts)
    if flags == "S":
        ssh_tracker[src_ip] += 1
        count = ssh_tracker[src_ip]

        if count == SSH_BRUTE_THRESHOLD:
            trigger_alert(
                level="HIGH",
                rule_name="SSH BRUTE FORCE DETECTED",
                src_ip=src_ip,
                dst_ip=dst_ip,
                details=f"{count} SSH SYN packets from source (Threshold: {SSH_BRUTE_THRESHOLD})"
            )
        elif count > SSH_BRUTE_THRESHOLD and count % 3 == 0:
            trigger_alert(
                level="HIGH",
                rule_name="SSH BRUTE FORCE ONGOING",
                src_ip=src_ip,
                dst_ip=dst_ip,
                details=f"Brute force continues — {count} attempts so far"
            )


# ============================================================
# RULE 4: HTTP FLOOD DETECTION
# Detects excessive HTTP requests to port 80/443
# ============================================================
def detect_http_flood(src_ip, dst_ip):
    http_tracker[src_ip] += 1
    count = http_tracker[src_ip]

    if count == HTTP_FLOOD_THRESHOLD:
        trigger_alert(
            level="MEDIUM",
            rule_name="HTTP FLOOD DETECTED",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"{count} HTTP requests from source (Threshold: {HTTP_FLOOD_THRESHOLD})"
        )


# ============================================================
# RULE 5: SUSPICIOUS PORT DETECTION
# Flags traffic to known malicious/dangerous ports
# ============================================================
SUSPICIOUS_PORTS = {
    23:   "Telnet (unencrypted remote access)",
    445:  "SMB (commonly exploited - WannaCry, EternalBlue)",
    1433: "MSSQL (database attack target)",
    3389: "RDP (Remote Desktop brute force target)",
    4444: "Metasploit default listener",
    5900: "VNC (remote access, often unencrypted)",
    6667: "IRC (used by botnets for C2 communication)",
    31337: "Elite / Back Orifice backdoor port",
}

def detect_suspicious_port(src_ip, dst_ip, dst_port):
    if dst_port in SUSPICIOUS_PORTS:
        trigger_alert(
            level="HIGH",
            rule_name="SUSPICIOUS PORT TRAFFIC",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"Traffic to port {dst_port} — {SUSPICIOUS_PORTS[dst_port]}"
        )


# ============================================================
# RULE 6: LARGE PACKET DETECTION
# Oversized packets can indicate DoS or data exfiltration
# ============================================================
def detect_large_packet(src_ip, dst_ip, size):
    if size > 1400:
        trigger_alert(
            level="LOW",
            rule_name="LARGE PACKET DETECTED",
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=f"Packet size: {size} bytes (threshold: 1400 bytes) — possible DoS or exfiltration"
        )


# ============================================================
# MAIN PACKET PROCESSING FUNCTION
# Called for every captured packet
# ============================================================
def process_packet(packet):
    if IP not in packet:
        return

    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    pkt_len = len(packet)

    # --- TCP Packet Analysis ---
    if TCP in packet:
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        flags    = packet[TCP].flags

        # Convert flags to string
        flag_str = str(flags)

        # Log every packet (non-alert)
        print(f"{BLUE}[PKT]{RESET} TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags:{flag_str} | Size:{pkt_len}")

        # Apply detection rules
        detect_port_scan(src_ip, dst_ip, dst_port)
        detect_large_packet(src_ip, dst_ip, pkt_len)

        if dst_port == 22:
            detect_ssh_brute_force(src_ip, dst_ip, flag_str)

        if dst_port in (80, 443, 8080, 8443):
            detect_http_flood(src_ip, dst_ip)

        detect_suspicious_port(src_ip, dst_ip, dst_port)

    # --- UDP Packet Analysis ---
    elif UDP in packet:
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
        print(f"{GREEN}[PKT]{RESET} UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Size:{pkt_len}")

        detect_suspicious_port(src_ip, dst_ip, dst_port)
        detect_large_packet(src_ip, dst_ip, pkt_len)

    # --- ICMP Packet Analysis ---
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        type_name = "Echo Request (Ping)" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type {icmp_type}"
        print(f"{YELLOW}[PKT]{RESET} ICMP {src_ip} -> {dst_ip} | {type_name} | Size:{pkt_len}")

        detect_icmp_flood(src_ip, dst_ip)
        detect_large_packet(src_ip, dst_ip, pkt_len)


# ============================================================
# SUMMARY REPORT
# ============================================================
def print_summary():
    print("\n" + "="*60)
    print(f"{BOLD}  INTRUSION DETECTION SYSTEM — SESSION SUMMARY{RESET}")
    print("="*60)
    print(f"  Total Alerts Generated : {len(alert_log)}")

    high   = sum(1 for a in alert_log if a['level'] == 'HIGH')
    medium = sum(1 for a in alert_log if a['level'] == 'MEDIUM')
    low    = sum(1 for a in alert_log if a['level'] == 'LOW')

    print(f"  {RED}HIGH   Severity : {high}{RESET}")
    print(f"  {YELLOW}MEDIUM Severity : {medium}{RESET}")
    print(f"  {GREEN}LOW    Severity : {low}{RESET}")
    print(f"\n  Log saved to    : {LOG_FILE}")
    print("="*60)

    if alert_log:
        print(f"\n{BOLD}  Alert Breakdown:{RESET}")
        rule_counts = defaultdict(int)
        for a in alert_log:
            rule_counts[a['rule']] += 1
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"   - {rule}: {count} alert(s)")

    print("\n  IDS Session Complete.\n")


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    # Clear old log
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    print("="*60)
    print(f"{BOLD}  NETWORK INTRUSION DETECTION SYSTEM{RESET}")
    print(f"  CodeAlpha Cybersecurity Internship — Task 4")
    print("="*60)
    print(f"  Detection Rules Active:")
    print(f"   [1] Port Scan Detection     (threshold: {PORT_SCAN_THRESHOLD} ports)")
    print(f"   [2] ICMP Flood Detection    (threshold: {ICMP_FLOOD_THRESHOLD} packets)")
    print(f"   [3] SSH Brute Force         (threshold: {SSH_BRUTE_THRESHOLD} attempts)")
    print(f"   [4] HTTP Flood Detection    (threshold: {HTTP_FLOOD_THRESHOLD} requests)")
    print(f"   [5] Suspicious Port Traffic (8 known dangerous ports)")
    print(f"   [6] Large Packet Detection  (threshold: 1400 bytes)")
    print("="*60)
    print(f"  Capturing {PACKET_COUNT if PACKET_COUNT > 0 else 'unlimited'} packets...")
    print(f"  Press Ctrl+C to stop\n")

    try:
        sniff(
            prn=process_packet,
            count=PACKET_COUNT,
            store=0
        )
    except KeyboardInterrupt:
        print("\n  Stopping IDS...")
    finally:
        print_summary()
