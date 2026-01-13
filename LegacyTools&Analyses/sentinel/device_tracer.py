#!/usr/bin/env python3
"""
sentinel.device_tracer
Scans the local subnet, maps MAC ⇒ IP, and flags anything
not in the allow‑list.  Until the M4 Mac arrives, ICMP‑based
hosts are skipped to avoid permission errors (Option 2).
"""
import os, re, subprocess, ipaddress, json, pathlib, sys

ALLOW_LIST = {
    "F6-C4-E6-68-03-75", "BA-B4-80-7B-3B-E3", "8C-26-0A-2A-3B-C6",
    "C0-BF-BE-72-61-77", "90-6A-BE-DD-D1-67", "90-6A-EB-DD-D1-64",
    "34-2F-BD-5E-1C-75", "A4-CF-99-AF-26-14", "AC-BC-B5-E3-73-16",
    "AC-BC-B5-DE-92-EE", "EE-8F-B7-D6-F4-F0",
}

NETWORK = os.getenv("SENTINEL_NET", "192.168.1.0/24")
ARP_CMD  = ["arp", "-a"]             # portable fallback
NMAP_CMD = ["nmap", "-sn", NETWORK]  # only used after Mac Mini

def scan_subnet():
    # lightweight option‑2 scan (no raw ICMP if ICMP restricted)
    for line in subprocess.check_output(ARP_CMD, text=True).splitlines():
        m = re.search(r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})", line)
        if m:
            mac = m.group(1).upper().replace(":", "-")
            ip  = re.search(r"\((.*?)\)", line).group(1)
            yield mac, ip

def main(out_file="sentinel_logs/devices/latest_scan.json"):
    pathlib.Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    seen, unknown = {}, {}
    for mac, ip in scan_subnet():
        (seen if mac in ALLOW_LIST else unknown)[mac] = ip
    result = {"seen": seen, "unknown": unknown}
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"✅  Seen: {len(seen)}   ⚠️  Unknown: {len(unknown)}  → {out_file}")

if __name__ == "__main__":
    main()
