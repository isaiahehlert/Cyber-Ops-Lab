import datetime
import os

# Simulated traffic logs for MVP (replace with tshark/tcpdump later)
FAKE_LOG_ENTRIES = [
    "User-Agent: curl/7.68.0 from 192.168.1.15 to 172.217.3.110",
    "POST /api/login HTTP/1.1 from 192.168.1.25 to 192.168.1.1",
    "User-Agent: python-requests from 192.168.1.34 to 8.8.8.8",
    "GET /images/logo.png HTTP/1.1 from 192.168.1.10 to 104.21.92.30",
    "User-Agent: Mozilla/5.0 from 192.168.1.50 to 172.217.3.110"
]

def save_traffic_log():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"logs/traffic/traffic_{timestamp}.log"
    os.makedirs("logs/traffic", exist_ok=True)

    with open(filename, "w") as f:
        for entry in FAKE_LOG_ENTRIES:
            f.write(entry + "\n")

    print(f"[+] Simulated traffic log saved to {filename}")

if __name__ == "__main__":
    save_traffic_log()
