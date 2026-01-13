# ✨ Regex Guide for Cybersecurity

Common regular expressions and pattern-matching tricks for log parsing, forensics, and filtering malicious inputs.

---

## 🧠 Basics

- . — any character  
- * — zero or more  
- + — one or more  
- ? — optional  
- ^ — start of line  
- $ — end of line  
- \ — escape special characters  

---

## 🔍 Useful Patterns

IP Addresses:  
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b

Email Addresses:  
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

URLs:  
https?:\/\/[^\s]+

Timestamps:  
\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}

Suspicious Shell Commands:  
(\bcat\b|\bwget
