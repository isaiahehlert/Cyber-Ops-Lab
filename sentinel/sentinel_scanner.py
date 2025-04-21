import subprocess
import datetime
import os

# Auto-detects your subnet based on common home network range
def get_local_subnet():
    try:
        result = subprocess.check_output("hostname -I", shell=True).decode().strip()
        first_ip = result.split()[0]
        base_ip = ".".join(first_ip.split(".")[:3])
        return f"{base_ip}.0/24"
    except Exception as e:
        print(f"[!] Could not detect local subnet: {e}")
        return None

def run_nmap_scan(subnet):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = f"logs/devices/devices_{timestamp}.txt"
    
    print(f"[+] Scanning network: {subnet}")
    try:
        result = subprocess.check_output(f"nmap -sn {subnet}", shell=True).decode()
        os.makedirs("logs/devices", exist_ok=True)
        with open(output_file, "w") as f:
            f.write(result)
        print(f"[+] Scan complete. Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Scan failed: {e}")

if __name__ == "__main__":
    subnet = get_local_subnet()
    if subnet:
        run_nmap_scan(subnet)
