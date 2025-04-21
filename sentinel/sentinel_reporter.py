import os
from datetime import datetime

REPORT_DIR = "sentinel_reports"
SUMMARY_FILE = f"sentinel_reports/summary_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

def summarize_reports():
    if not os.path.exists(REPORT_DIR):
        print("[!] Report directory not found.")
        return

    files = [f for f in os.listdir(REPORT_DIR) if f.startswith("report_")]
    if not files:
        print("[+] No reports to summarize.")
        return

    with open(SUMMARY_FILE, "w") as summary:
        summary.write("🛡️ Sentinel Daily Threat Summary\n")
        summary.write(f"Generated: {datetime.now()}\n")
        summary.write("="*40 + "\n\n")
        
        for file in sorted(files):
            path = os.path.join(REPORT_DIR, file)
            summary.write(f"--- {file} ---\n")
            with open(path, "r") as f:
                summary.write(f.read())
            summary.write("\n")

    print(f"[✅] Summary saved to: {SUMMARY_FILE}")

if __name__ == "__main__":
    summarize_reports()
