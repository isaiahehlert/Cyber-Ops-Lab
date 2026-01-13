# 🛡️ Common Vulnerabilities Cheat Sheet

A tactical list of common cybersecurity vulnerabilities and misconfigurations used in CTFs, pentesting, and red team ops.

---

## 🔓 Privilege Escalation

- SUID Binaries (`find / -perm -4000 2>/dev/null`)
- Writable `/etc/passwd` or shadow files
- Misconfigured cron jobs (running as root)
- Abused capabilities (`getcap -r / 2>/dev/null`)

---

## 🔌 Network Vulnerabilities

- Open FTP (port 21) with anonymous login
- SMB shares without auth (`smbclient -L <target>`)
- Outdated SSL/TLS (`nmap --script ssl-enum-ciphers`)
- Open Redis or MongoDB ports with no auth

---

## 📦 Web Vulnerabilities

- SQL Injection (e.g. `' OR 1=1--`)
- XSS (Reflected & Stored)
- LFI/RFI (e.g. `../../etc/passwd`)
- Exposed admin panels, dev environments

---

## 🗃️ Misconfigurations

- Docker socket exposed (`/var/run/docker.sock`)
- Jenkins, Grafana, or Git open to the internet
- Default credentials (e.g., admin/admin)
- Hardcoded secrets in source code

---

## 🧠 Recon Tools

- `nmap -sC -sV -oA recon <target>`
- `enum4linux`, `linpeas`, `pspy`
- `whatweb`, `nikto`, `dirb`, `gobuster`
- Searchsploit + CVE lookup

---

> Tip: Pair this list with live enumeration for maximum effect.
