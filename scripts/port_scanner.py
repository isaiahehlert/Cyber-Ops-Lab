#!/usr/bin/env python3
import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP port is open (connect scan)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except (socket.timeout, OSError):
        return False


def resolve_host(host: str) -> str:
    """Resolve hostname to an IPv4 address for scanning/output."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Unable to resolve host: {host}") from e


def validate_ports(start: int, end: int) -> None:
    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
        raise ValueError("Ports must be in range 1–65535.")
    if end < start:
        raise ValueError("End port must be >= start port.")


def safe_workers(requested: int, total_ports: int) -> int:
    """
    Keep worker count sane:
    - never exceed total ports
    - cap high defaults to reduce local exhaustion / noisy scans
    """
    if requested < 1:
        raise ValueError("Workers must be >= 1.")
    return max(1, min(requested, total_ports, 200))


def service_name(port: int) -> str:
    """Best-effort service name lookup (e.g., 80 -> http)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def port_scan(host: str, start: int, end: int, timeout: float, workers: int) -> list[int]:
    open_ports: list[int] = []
    ports = range(start, end + 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for f in as_completed(futures):
            port = futures[f]
            if f.result():
                open_ports.append(port)

    return sorted(open_ports)


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner (connect scan).")
    parser.add_argument("host", help="Target hostname or IP (e.g., 127.0.0.1 or example.com)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Max concurrent workers (default: 100)")
    parser.add_argument("--services", action="store_true", help="Show best-effort service names for open ports")
    args = parser.parse_args()

    validate_ports(args.start, args.end)

    ip = resolve_host(args.host)
    total_ports = args.end - args.start + 1
    workers = safe_workers(args.workers, total_ports)

    print(f"[*] Target: {args.host} ({ip})")
    print(f"[*] Scanning TCP ports {args.start}-{args.end} | timeout={args.timeout}s | workers={workers}")

    start_time = time.time()
    try:
        open_ports = port_scan(ip, args.start, args.end, args.timeout, workers)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Partial results may be incomplete.")
        return 130

    elapsed = time.time() - start_time
    print()

    if open_ports:
        for p in open_ports:
            if args.services:
                svc = service_name(p)
                if svc:
                    print(f"[+] OPEN: {p}/tcp ({svc})")
                else:
                    print(f"[+] OPEN: {p}/tcp")
            else:
                print(f"[+] OPEN: {p}/tcp")

        print(f"\n[*] Done. Open ports found: {len(open_ports)} | scanned={total_ports} | time={elapsed:.2f}s")
    else:
        print(f"[*] Done. No open ports found in that range | scanned={total_ports} | time={elapsed:.2f}s")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
