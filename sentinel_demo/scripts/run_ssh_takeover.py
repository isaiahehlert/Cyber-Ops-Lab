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
    parser = argparse.ArgumentParser(description="Simulate SSH takeover sequence against Sentinel demo.")
    parser.add_argument("--target", required=True, help="Mac Mini IP or hostname")
    parser.add_argument("--port", type=int, default=8080, help="Sentinel API port")
    parser.add_argument("--fail-count", type=int, default=10, help="Number of failed attempts before success")
    parser.add_argument("--user", default="admin", help="Username to target")
    args = parser.parse_args()

    source_ip = get_local_ip()
    url = f"http://{args.target}:{args.port}/api/ingest/auth-event"

    print(f"[*] Sending takeover sequence from {source_ip} to {url}")

    for i in range(args.fail_count):
        line = f"Mar 10 09:45:{i:02d} host sshd[{200+i}]: Failed password for invalid user {args.user} from {source_ip} port {43000+i} ssh2"
        r = requests.post(url, json={"line": line}, timeout=5)
        print(f"[fail {i+1}/{args.fail_count}] {r.status_code}")
        time.sleep(0.12)

    success_line = f"Mar 10 09:45:59 host sshd[999]: Accepted password for {args.user} from {source_ip} port 43999 ssh2"
    r = requests.post(url, json={"line": success_line}, timeout=5)
    print(f"[success] {r.status_code}")

    print("[*] Done.")


if __name__ == "__main__":
    main()
