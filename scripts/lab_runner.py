#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]  # assumes scripts/ is inside repo root
SCRIPTS = ROOT / "scripts"


def run_script(script_name: str, args: list[str] | None = None) -> int:
    """Run a script safely and return its exit code."""
    script_path = SCRIPTS / script_name
    if not script_path.exists():
        print(f"[-] Missing script: {script_path}")
        return 2

    cmd = ["python3", str(script_path)]
    if args:
        cmd.extend(args)

    try:
        return subprocess.run(cmd, check=False).returncode
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130


def run_dns_lookup() -> None:
    target = input("Enter domain (e.g., example.com): ").strip()
    if not target:
        print("[-] No domain entered.")
        return
    rc = run_script("dns_lookup.py", [target])
    print(f"[*] dns_lookup exit code: {rc}")


def run_port_scanner() -> None:
    host = input("Enter host (e.g., 127.0.0.1 or example.com): ").strip()
    if not host:
        print("[-] No host entered.")
        return

    start = input("Start port (default 1): ").strip() or "1"
    end = input("End port (default 1024): ").strip() or "1024"
    timeout = input("Timeout seconds (default 0.5): ").strip() or "0.5"

    args = [host, "-s", start, "-e", end, "-t", timeout, "--services"]
    rc = run_script("port_scanner.py", args)
    print(f"[*] port_scanner exit code: {rc}")


def run_ai_detector() -> None:
    print("\nAI/Bot Detector Mode:")
    print("1) Manual Input")
    print("2) Analyze Log File")
    sub_choice = input("Choose mode: ").strip()

    if sub_choice == "1":
        rc = run_script("ai_detector.py")
        print(f"[*] ai_detector exit code: {rc}")
        return

    if sub_choice == "2":
        path = input("Enter path to log file (e.g., logs/sample.log): ").strip()
        if not path:
            print("[-] No path provided.")
            return

        log_path = (ROOT / path).resolve() if not Path(path).is_absolute() else Path(path)
        if not log_path.exists():
            print(f"[-] File not found: {log_path}")
            return

        rc = run_script("ai_detector.py", [str(log_path)])
        print(f"[*] ai_detector exit code: {rc}")
        return

    print("[-] Invalid selection.")


def main() -> int:
    while True:
        print("\n🧪 Cyber Ops Lab Launcher")
        print("1) DNS Lookup")
        print("2) Port Scanner")
        print("3) AI/Bot Detector")
        print("4) Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            run_dns_lookup()
        elif choice == "2":
            run_port_scanner()
        elif choice == "3":
            run_ai_detector()
        elif choice == "4":
            print("[*] Exiting...")
            return 0
        else:
            print("[-] Invalid choice. Try again.")


if __name__ == "__main__":
    raise SystemExit(main())
