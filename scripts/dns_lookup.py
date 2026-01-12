#!/usr/bin/env python3
import argparse
import socket
import sys
from typing import List, Tuple


def resolve(domain: str, timeout: float = 2.0) -> Tuple[List[str], List[str]]:
    """
    Resolve domain to IPv4 (A) and IPv6 (AAAA) using getaddrinfo.
    Returns (ipv4_list, ipv6_list).
    """
    socket.setdefaulttimeout(timeout)

    ipv4 = set()
    ipv6 = set()

    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise RuntimeError(f"DNS lookup failed for {domain}: {e}") from e

    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if family == socket.AF_INET:
            ipv4.add(ip)
        elif family == socket.AF_INET6:
            ipv6.add(ip)

    return sorted(ipv4), sorted(ipv6)


def reverse_lookup(ip: str) -> str:
    """Optional reverse DNS."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror):
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS lookup (A/AAAA) using system resolver.")
    parser.add_argument("target", help="Domain to resolve (e.g., example.com)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout seconds (default: 2.0)")
    parser.add_argument("--reverse", action="store_true", help="Attempt reverse DNS on resolved IPs")
    args = parser.parse_args()

    try:
        ipv4, ipv6 = resolve(args.target, timeout=args.timeout)
    except RuntimeError as e:
        print(f"[-] {e}")
        return 1

    print(f"[*] Target: {args.target}")
    print(f"[*] Timeout: {args.timeout}s\n")

    if not ipv4 and not ipv6:
        print("[*] No results.")
        return 2

    if ipv4:
        print("[+] IPv4 (A):")
        for ip in ipv4:
            rdns = f" ({reverse_lookup(ip)})" if args.reverse else ""
            print(f"    - {ip}{rdns}")

    if ipv6:
        print("\n[+] IPv6 (AAAA):")
        for ip in ipv6:
            rdns = f" ({reverse_lookup(ip)})" if args.reverse else ""
            print(f"    - {ip}{rdns}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
