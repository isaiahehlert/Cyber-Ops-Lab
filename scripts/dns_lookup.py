import socket

def dns_lookup(domain):
    try:
        result = socket.gethostbyname(domain)
        print(f"[+] {domain} resolves to {result}")
    except socket.gaierror:
        print(f"[-] DNS lookup failed for {domain}")

if __name__ == "__main__":
    target = input("Enter domain to look up: ")
    dns_lookup(target)
