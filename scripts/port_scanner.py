import socket
import threading

# Scan a single port
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        sock.close()
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")

# Scan a range of ports using threads
def port_scanner(ip, start_port, end_port):
    print(f"[*] Scanning {ip} from port {start_port} to {end_port}...\n")
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        t.start()

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ")
    try:
        start = int(input("Start port: "))
        end = int(input("End port: "))
        port_scanner(target_ip, start, end)
    except ValueError:
        print("[!] Invalid port range")
