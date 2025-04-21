import re
from datetime import datetime

QUARANTINE_FILE = "tools/quarantine.txt"

def load_allowlist():
    allowlist = {}
    try:
        with open("tools/allowlist.txt", "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) == 2:
                    key, name = parts
                    allowlist[key.strip().upper()] = name.strip()
    except FileNotFoundError:
        print("[!] Allowlist not found.")
    return allowlist

def load_quarantine_list():
    try:
        with open(QUARANTINE_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def extract_ip(line):
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    return match.group() if match else None

def run_analysis(log_file="flagged_lines.txt"):
    allowlist = load_allowlist()
    quarantine = load_quarantine_list()
    flagged = []

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("[!] Log file not found.")
        return

    for idx, line in enumerate(lines, 1):
        ip = extract_ip(line)
        if ip is None:
            continue  # Skip lines without an IP

        is_quarantined = ip in quarantine

        if any(k in line.lower() for k in ["sqlmap", "curl", "python-requests", "api/login"]):
            if is_quarantined:
                print(f"[⚠️] Suppressed alert from quarantined IP {ip} on line {idx}")
            else:
                device = allowlist.get(ip.upper(), ip)
                alert = f"[!] Suspicious pattern on line {idx} from {device}: {line.strip()}"
                flagged.append(alert)

    if flagged:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = f"sentinel_reports/report_flagged_traffic_{timestamp}.log"
        with open(path, "w") as out:
            out.write("\n".join(flagged))
        print("\n🚨 Threats detected! Report saved to:", path)
    else:
        print("✅ No unquarantined threats found.")

if __name__ == "__main__":
    run_analysis()
