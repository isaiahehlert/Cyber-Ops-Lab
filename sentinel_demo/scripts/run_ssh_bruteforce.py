#!/usr/bin/env python3
import argparse
import requests
import socket
import time


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Simulate SSH brute force events against Sentinel demo.")
    parser.add_argument("--target", required=True, help="Mac Mini IP or hostname")
    parser.add_argument("--port", type=int, default=8080, help="Sentinel API port")
    parser.add_argument("--count", type=int, default=8, help="Number of failed attempts")
    parser.add_argument("--user", default="admin", help="Username to target")
    args = parser.parse_args()

    source_ip = get_local_ip()
    url = f"http://{args.target}:{args.port}/api/ingest/auth-event"

    print(f"[*] Sending {args.count} failed SSH auth events from {source_ip} to {url}")

    for i in range(args.count):
        line = f"Mar 10 09:44:{i:02d} host sshd[{100+i}]: Failed password for invalid user {args.user} from {source_ip} port {42000+i} ssh2"
        r = requests.post(url, json={"line": line}, timeout=5)
        print(f"[{i+1}/{args.count}] {r.status_code}")
        time.sleep(0.15)

    print("[*] Done.")


if __name__ == "__main__":
    main()
