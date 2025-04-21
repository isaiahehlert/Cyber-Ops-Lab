import os

FLAGGED_DIR = "flagged_logs"

def show_alerts():
    if not os.path.exists(FLAGGED_DIR):
        print("[!] No flagged logs directory found.")
        return

    files = sorted(os.listdir(FLAGGED_DIR))
    if not files:
        print("[+] No active threats found.")
        return

    print("\n🛑 Threat Alert Summary 🛑\n")

    for file in files:
        path = os.path.join(FLAGGED_DIR, file)
        print(f"\n--- {file} ---")
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                print(line.strip())

        # Save a permanent copy in reports
        with open(f"sentinel_reports/report_{file}", "w") as report:
            report.writelines(lines)

    print("\n📢 ALERT: Threats detected in your network traffic.")
    print("Please investigate flagged logs for suspicious activity.")

if __name__ == "__main__":
    show_alerts()
