# 🛡️ Cyber-Ops-Lab
![Sentient Sentinel Shield](assets/full_color.jpeg)

A private repository of tools, logs, and documentation used in cybersecurity research, testing, and learning.

## 📁 Directories

- `scripts/`: Python tools for recon, scanning, and parsing
- `logs/`: Packet captures, system events, traffic analysis
- `tools/`: Helpers & wrappers for utilities like Nmap
- `references/`: Cheat sheets and study notes (Linux, regex, vulnerabilities)

## 🚧 Status
Project under active development. Tools and references are being added progressively.
---

## 🔍 Tools

### `dns_lookup.py`
Resolves domain names to IP addresses using Python’s `socket` module.

- **Usage:**  
  Run in terminal → `python3 scripts/dns_lookup.py`
- **Example Input:** `openai.com`  
- **Example Output:** `[+] openai.com resolves to 104.18.30.5`
- **Dependencies:** None

---

### `port_scanner.py`
Scans a given IP for open TCP ports in a specified range using multi-threading.

- **Usage:**  
  Run in terminal → `python3 scripts/port_scanner.py`
- **Example Input:**  
  IP: `127.0.0.1`  
  Ports: `20 to 100`
- **Example Output:** `[+] Port 22 is OPEN`
- **Dependencies:** None
