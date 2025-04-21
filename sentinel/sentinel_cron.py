import time
import subprocess

def run_full_sentinel_cycle():
    print("\n🚨 Auto-Running Full Sentinel Scan...")
    subprocess.run(["python3", "sentinel/sentinel_scanner.py"])
    subprocess.run(["python3", "sentinel/sentinel_logger.py"])
    subprocess.run(["python3", "sentinel/sentinel_detector.py"])
    subprocess.run(["python3", "sentinel/sentinel_alerts.py"])

if __name__ == "__main__":
    # Run every 15 minutes
    while True:
        run_full_sentinel_cycle()
        print("⏱️ Waiting 15 minutes before next run...\n")
        time.sleep(900)  # 900 seconds = 15 minutes
