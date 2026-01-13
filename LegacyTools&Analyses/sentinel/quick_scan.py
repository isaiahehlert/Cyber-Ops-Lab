#!/usr/bin/env python3
from scapy.all import Ether, ARP, srp
import argparse, json, datetime, pathlib

ALLOW = {
 "F6-C4-E6-68-03-75","BA-B4-80-7B-3B-E3","8C-26-0A-2A-3B-C6",
 "C0-BF-BE-72-61-77","90-6A-BE-DD-D1-67","90-6A-EB-DD-D1-64",
 "34-2F-BD-5E-1C-75","A4-CF-99-AF-26-14","AC-BC-B5-E3-73-16",
 "AC-BC-B5-DE-92-EE","EE-8F-B7-D6-F4-F0"
}

def sweep(net, timeout):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),
                 timeout=timeout, verbose=0)
    seen, dup_ip, unknown = {}, {}, []
    for _, r in ans:
        mac, ip = r.hwsrc.upper(), r.psrc
        if mac in seen: dup_ip.setdefault(seen[mac], []).append(ip)
        seen[mac] = ip
        if mac not in ALLOW: unknown.append((mac, ip))
    return seen, unknown, dup_ip

def main():
    p = argparse.ArgumentParser(description="Fast ARP census (1 packet)")
    p.add_argument("--net", default="10.0.0.0/24",
                   help="Subnet, e.g. 192.168.1.0/24")
    p.add_argument("--timeout", type=float, default=1,
                   help="Listen seconds (default 1)")
    args = p.parse_args()

    seen, unknown, dup_ip = sweep(args.net, args.timeout)
    print(f"🌐  {len(seen)} devices  ({len(unknown)} unknown)")
    for mac,ip in unknown: print(f"⚠️  {mac:17} {ip}")
    for ip, ips in dup_ip.items(): print(f"⚠️  Duplicate IP {ip}: {', '.join(ips)}")

    ts = datetime.datetime.now().strftime("%F_%H-%M-%S")
    out = pathlib.Path("sentinel_reports")
    out.mkdir(exist_ok=True)
    (out/f"quick_report_{ts}.json").write_text(
        json.dumps({"seen":seen,"unknown":unknown,"dup_ip":dup_ip}, indent=2))
    print(f"📝  JSON → {out}/")
if __name__ == "__main__":
    main()
