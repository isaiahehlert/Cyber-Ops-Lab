#!/usr/bin/env python3
import argparse
import requests
import socket
import time
from datetime import datetime, timezone


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def apache_ts_now():
    now = datetime.now(timezone.utc)
    return now.strftime("%d/%b/%Y:%H:%M:%S +0000")


def main():
    parser = argparse.ArgumentParser(description="Simulate DDoS-style HTTP burst events against Sentinel demo.")
    parser.add_argument("--target", required=True, help="Mac Mini IP or hostname")
    parser.add_argument("--port", type=int, default=8080, help="Sentinel API port")
    parser.add_argument("--count", type=int, default=12, help="Number of HTTP events")
    parser.add_argument("--path", default="/login", help="Path to target")
    args = parser.parse_args()

    source_ip = get_local_ip()
    url = f"http://{args.target}:{args.port}/api/ingest/http-event"

    print(f"[*] Sending {args.count} HTTP burst events from {source_ip} to {url}")

    for i in range(args.count):
        line = f'{source_ip} - - [{apache_ts_now()}] "GET {args.path} HTTP/1.1" 200 123'
        r = requests.post(url, json={"line": line}, timeout=5)
        print(f"[{i+1}/{args.count}] {r.status_code}")
        time.sleep(0.03)

    print("[*] Done.")


if __name__ == "__main__":
    main()
