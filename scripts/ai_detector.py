import re

# Patterns to flag potential bot or AI-driven traffic
SUSPICIOUS_PATTERNS = [
    r"sqlmap",               # SQL injection tool
    r"python-requests",      # Bot framework
    r"curl|wget",            # CLI request tools
    r"nmap|masscan",         # Network scanners
    r"nikto|gobuster",       # Recon tools
    r"dirb|ffuf",            # Fuzzers
    r"\bPOST\b.*login",      # Login brute-force attempts
    r"(\/admin|\/\.env)",    # Sensitive endpoint targeting
]

def analyze_line(line):
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def run_analysis(log_lines):
    print("Running AI/Bot signature detection...\n")
    for i, line in enumerate(log_lines):
        if analyze_line(line):
            print(f"[!] Suspicious pattern detected on line {i + 1}:\n{line.strip()}\n")

if __name__ == "__main__":
    print("Paste your log lines (Ctrl+D to finish):")
    try:
        lines = []
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass

    run_analysis(lines)
