import time
import subprocess

def run_scan():
    print("\n🔎 Running device scan...")
    subprocess.run(["python3", "sentinel/sentinel_scanner.py"])

def run_logger():
    print("\n📡 Generating traffic logs...")
    subprocess.run(["python3", "sentinel/sentinel_logger.py"])

def run_detector():
    print("\n🧠 Scanning traffic logs for threats...")
    subprocess.run(["python3", "sentinel/sentinel_detector.py"])
    print("\n🔔 Running alert system...")
    subprocess.run(["python3", "sentinel/sentinel_alerts.py"])


def main():
    print("""
  ╔════════════════════════════════════════╗
  ║      🛡️ Sentinel Cyber Ops Launcher      ║
  ╚════════════════════════════════════════╝
  [1] Run Full Scan (Devices → Traffic → Detect)
  [2] Just Scan Devices
  [3] Just Log Simulated Traffic
  [4] Just Run AI Detector
  [5] Exit
    """)

    while True:
        choice = input("👉 Choose an option: ")

        if choice == "1":
            run_scan()
            run_logger()
            run_detector()
        elif choice == "2":
            run_scan()
        elif choice == "3":
            run_logger()
        elif choice == "4":
            run_detector()
        elif choice == "5":
            print("👋 Exiting Sentinel...")
            break
        else:
            print("⚠️ Invalid option. Try again.")

if __name__ == "__main__":
    main()
