#!/usr/bin/env python3
"""
network_asset_scanner.py

Multithreaded Network Asset Discovery & Reporting Tool
- ARP host discovery (requires root/administrator on many OSes)
- Reverse DNS hostname resolution
- Multithreaded TCP port scanning
- CSV + HTML report generation and an audit log

Author: allu
Usage (example):
  sudo python3 network_asset_scanner.py --range 192.168.1.0/24 --ports 22,80,443 --threads 100 --output results

Legal: This tool is intended for authorized network discovery only. Always get permission.
"""

import argparse
import csv
import datetime
import socket
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict

# scapy import — used for ARP discovery
try:
    from scapy.all import ARP, Ether, srp, conf
except Exception as e:
    print("Error importing scapy. Install with: pip install scapy")
    raise

# -------------------------
# Helper functions
# -------------------------
def require_root():
    """Warn and continue if not running as root on Unix-like OSes."""
    if os.name != "nt":
        if os.geteuid() != 0:
            print("WARNING: ARP host discovery typically requires root privileges.")
            print("Continue anyway? (y/N): ", end="")
            ans = input().strip().lower()
            if ans != "y":
                sys.exit("Run the script with sudo/root permissions or skip ARP discovery.")
    else:
        # On Windows, a privileged prompt is recommended
        print("On Windows: run from an Administrator PowerShell/Command Prompt for best results.")

def arp_scan(network_range: str, timeout: float = 2.0) -> List[Dict]:
    """
    Perform ARP scan for given CIDR range (e.g. "192.168.1.0/24").
    Returns list of dicts: {'ip': str, 'mac': str}
    """
    conf.verb = 0
    print(f"[+] Sending ARP requests to {network_range} (timeout {timeout}s)...")
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    answered = srp(packet, timeout=timeout, verbose=False)[0]
    devices = []
    for snd, rcv in answered:
        devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    print(f"[+] Found {len(devices)} device(s) via ARP.")
    return devices

def try_reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """Try to get hostname via reverse DNS; returns '' if none."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""

def scan_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Attempt TCP connect to port. Return True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def scan_ports_multithreaded(ip: str, ports: List[int], threads: int = 50) -> List[int]:
    """Scan ports on a single host using a thread pool."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(threads, len(ports) or 1)) as executor:
        future_to_port = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    open_ports.sort()
    return open_ports

def make_csv(path: Path, records: List[Dict]):
    """Write CSV report."""
    fieldnames = ["timestamp", "ip", "mac", "hostname", "open_ports"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({
                "timestamp": r.get("timestamp", ""),
                "ip": r.get("ip", ""),
                "mac": r.get("mac", ""),
                "hostname": r.get("hostname", ""),
                "open_ports": ",".join(str(p) for p in r.get("open_ports", []))
            })

def make_html(path: Path, records: List[Dict], title: str):
    """Create a simple HTML report."""
    now = datetime.datetime.utcnow().isoformat() + "Z"
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>{title}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f3f4f6; }}
    tr:nth-child(even) {{ background: #fbfbfb; }}
    .small {{ font-size: 0.9rem; color: #555; }}
    .badge {{ display:inline-block; padding:4px 8px; border-radius:8px; background:#eef; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p class="small">Generated: {now} (UTC)</p>
  <table>
    <thead>
      <tr><th>#</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Open Ports</th><th>Scanned At (UTC)</th></tr>
    </thead>
    <tbody>
"""
    for i, r in enumerate(records, 1):
        open_ports = ", ".join(str(p) for p in r.get("open_ports", [])) or "&mdash;"
        hostname = r.get("hostname") or "&mdash;"
        html += f"<tr><td>{i}</td><td>{r.get('ip')}</td><td>{r.get('mac','&mdash;')}</td><td>{hostname}</td><td>{open_ports}</td><td>{r.get('timestamp')}</td></tr>\n"

    html += """
    </tbody>
  </table>
  <p class="small">Note: This report was generated by an authorized scan. Use only on networks you own or have permission to scan.</p>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")

def audit_log(path: Path, message: str):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{ts} {message}\n")

# -------------------------
# Main scanning workflow
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery & Reporting Tool (authorized use only)")
    parser.add_argument("--range", "-r", required=True, help="Target network range (CIDR) e.g. 192.168.1.0/24")
    parser.add_argument("--ports", "-p", default="22,80,443,3389,139,445,8080", help="Comma-separated ports to check")
    parser.add_argument("--threads", "-t", type=int, default=200, help="Threads for port scanning (per-host pool limit)")
    parser.add_argument("--output", "-o", default="scan_results", help="Output basename (csv/html/log will be created)")
    parser.add_argument("--arp-timeout", type=float, default=2.0, help="ARP request timeout in seconds")
    parser.add_argument("--no-arp", action="store_true", help="Skip ARP discovery (useful if not root); requires manual hostlist with --hosts")
    parser.add_argument("--hosts", help="Comma-separated list of hosts to scan (skip ARP). Example: 10.0.0.5,10.0.0.10")
    args = parser.parse_args()

    # Legal notice and consent
    print("LEGAL & ETHICS NOTICE:")
    print("  This tool is intended for authorized network administration and testing ONLY.")
    print("  Do you have permission to scan the target network? (y/N): ", end="")
    consent = input().strip().lower()
    if consent != "y":
        sys.exit("Consent not given. Exiting.")

    require_root()

    ports = []
    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except Exception:
        sys.exit("Invalid ports list provided.")

    out_base = Path(args.output)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    csv_path = out_base.with_suffix(".csv")
    html_path = out_base.with_suffix(".html")
    log_path = out_base.with_suffix(".log")

    started = datetime.datetime.utcnow().isoformat() + "Z"
    audit_log(log_path, f"Scan started: range={args.range} ports={ports} threads={args.threads}")

    # Discover hosts
    hosts = []
    if args.no_arp:
        if not args.hosts:
            sys.exit("When --no-arp is used, you must supply --hosts.")
        hosts = [{"ip": h.strip(), "mac": ""} for h in args.hosts.split(",") if h.strip()]
    else:
        try:
            hosts = arp_scan(args.range, timeout=args.arp_timeout)
        except PermissionError:
            print("ARP scan failed due to permissions. Re-run as root or use --no-arp with --hosts.")
            sys.exit(1)

    if not hosts:
        print("No hosts discovered. Exiting.")
        audit_log(log_path, "No hosts discovered.")
        sys.exit(0)

    records = []
    total = len(hosts)
    print(f"[+] Beginning port scanning on {total} host(s)...")
    t0 = time.time()
    # We'll scan hosts serially but ports per-host with threads (keeps footprint reasonable).
    for idx, h in enumerate(hosts, 1):
        ip = h.get("ip")
        mac = h.get("mac", "")
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        print(f"[{idx}/{total}] Scanning {ip} ...", end="", flush=True)
        hostname = try_reverse_dns(ip)
        open_ports = scan_ports_multithreaded(ip, ports, threads=args.threads)
        print(f" found {len(open_ports)} open port(s).")
        rec = {
            "timestamp": ts,
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "open_ports": open_ports
        }
        records.append(rec)
        audit_log(log_path, f"Host scanned: {ip} hostname={hostname or '-'} mac={mac or '-'} open_ports={open_ports}")

    dur = time.time() - t0
    audit_log(log_path, f"Scan finished in {dur:.1f}s. Hosts: {len(records)}")

    # Output reports
    make_csv(csv_path, records)
    make_html(html_path, records, title=f"Network Asset Report - {args.range}")
    print(f"[+] CSV report: {csv_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] Audit log: {log_path}")
    print("[+] Done. Remember: keep scans authorized and documented.")

if __name__ == "__main__":
    main()
