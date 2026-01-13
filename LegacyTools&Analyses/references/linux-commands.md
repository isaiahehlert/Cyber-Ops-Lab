# 🐧 Linux Commands Cheat Sheet

Quick reference for common Linux commands used in cybersecurity, auditing, and system operations.

---

## 🔎 System Info

```bash
uname -a           # Kernel version
hostnamectl        # Hostname and system info
whoami             # Current user
id                 # User/group info

ls -la             # List all files in long format
cd /path           # Change directory
pwd                # Print current working directory
mkdir newfolder    # Create directory
rm -rf folder/     # Delete folder (careful!)

chmod 755 file     # Set execute/read permissions
chown user:group file  # Change owner

ip a               # Show IP addresses
ping 8.8.8.8       # Ping test
netstat -tuln      # Show open ports
curl ifconfig.me   # Show public IP address

ps aux             # Show running processes
top                # Live process viewer
journalctl -xe     # System logs
dmesg              # Kernel log

who                # Who is logged in
last               # Last logins
history            # Command history
find / -perm -4000 2>/dev/null  # Find SUID files (priv esc)
