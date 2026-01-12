#!/usr/bin/env python3
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except (socket.timeout, OSError):
        return False

def resolve_host(host: str) -> str:
    """Resolve hostname to an IP for nicer output (optional)."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Unable to resolve host: {host}")

def validate_ports(start: int, end: int) -> None:
    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
        raise ValueError("Ports must be in range 1–65535.")
    if end < start:
        raise ValueError("End port must be >= start port.")

def port_scan(host: str, start: int, end: int, timeout: float, workers: int) -> list[int]:
    open_ports = []
    ports = range(start, end + 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for f in as_completed(futures):
            port = futures[f]
            if f.result():
                open_ports.append(port)

    return sorted(open_ports)

def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner (connect scan)."
    )
    parser.add_argument("host", help="Target hostname or IP (e.g., 127.0.0.1 or example.com)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Max concurrent workers (default: 200)")
    args = parser.parse_args()

    validate_ports(args.start, args.end)

    ip = resolve_host(args.host)
    print(f"[*] Target: {args.host} ({ip})")
    print(f"[*] Scanning TCP ports {args.start}-{args.end} | timeout={args.timeout}s | workers={args.workers}\n")

    open_ports = port_scan(args.host, args.start, args.end, args.timeout, args.workers)

    if open_ports:
        for p in open_ports:
            print(f"[+] OPEN: {p}/tcp")
        print(f"\n[*] Done. Open ports found: {len(open_ports)}")
    else:
        print("[*] Done. No open ports found in that range.")

if __name__ == "__main__":
    main()
