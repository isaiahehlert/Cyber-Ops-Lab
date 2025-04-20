import re
import sys

# Patterns to flag potential bot or AI-driven traffic
SUSPICIOUS_PATTERNS = [
    r"sqlmap",
    r"python-requests",
    r"curl|wget",
    r"nmap|masscan",
    r"nikto|gobuster",
    r"dirb|ffuf",
    r"\bPOST\b.*login",
    r"(\/admin|\/\.env)"
]

def analyze_line(line):
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def run_analysis(lines, output_file=None):
    print("\nRunning AI/Bot signature detection...\n")
    flagged = []

    for i, line in enumerate(lines):
        if analyze_line(line):
            result = f"[!] Suspicious pattern detected on line {i + 1}:\n{line.strip()}\n"
            print(result)
            flagged.append(result)

    if output_file and flagged:
        with open(output_file, "w") as f:
            f.writelines(flagged)
        print(f"\n✅ Results saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # Run with file input
        filepath = sys.argv[1]
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
            run_analysis(lines, output_file="flagged_lines.txt")
        except FileNotFoundError:
            print(f"[!] File not found: {filepath}")
    else:
        # Manual input fallback
        print("Paste your log lines (Ctrl+D to finish):")
        try:
            lines = []
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass

        run_analysis(lines)
