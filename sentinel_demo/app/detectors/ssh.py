from collections import Counter, defaultdict


def severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def analyze_ssh(ssh_logs, fail_threshold=5, takeover_fail_threshold=10):
    failures_by_ip = Counter()
    successes_by_ip = Counter()
    users_by_ip = defaultdict(set)

    for line in ssh_logs or []:
        lower = line.lower()

        ip = None
        if " from " in lower:
            try:
                ip = line.split(" from ", 1)[1].split()[0]
            except Exception:
                ip = None

        if not ip:
            continue

        if "failed password" in lower or "invalid user" in lower or "authentication failure" in lower:
            failures_by_ip[ip] += 1
            if " for " in line:
                try:
                    user = line.split(" for ", 1)[1].split()[0]
                    users_by_ip[ip].add(user)
                except Exception:
                    pass

        elif "accepted password" in lower or "accepted publickey" in lower:
            successes_by_ip[ip] += 1

    detections = []

    for ip, fail_count in failures_by_ip.items():
        if fail_count < fail_threshold:
            continue

        distinct_users = len(users_by_ip[ip])
        succ = successes_by_ip.get(ip, 0)

        score = 40
        evidence = [f"{fail_count} failed SSH auth attempts from {ip} (>= {fail_threshold})"]

        if distinct_users >= 5:
            score += 20
            evidence.append(f"spray pattern across {distinct_users} usernames")
        elif distinct_users >= 2:
            score += 10
            evidence.append(f"multiple usernames targeted ({distinct_users})")

        detection_type = "ssh_bruteforce"

        if succ >= 1 and fail_count >= takeover_fail_threshold:
            score += 30
            evidence.append("failures followed by successful login (possible takeover)")
            detection_type = "ssh_takeover"

        detections.append({
            "type": detection_type,
            "severity": severity(score),
            "score": score,
            "source_ip": ip,
            "metrics": {
                "failed_attempts": fail_count,
                "successful_logins": succ,
                "distinct_usernames_targeted": distinct_users,
            },
            "evidence": evidence,
            "recommended_actions": [
                "Rate-limit SSH and enable fail2ban.",
                "Disable password auth where possible.",
                "Restrict SSH to VPN or allowlisted IPs.",
                "Review successful login activity and rotate credentials if compromise is suspected.",
            ],
        })

    return detections
