from collections import Counter, defaultdict
from dateutil import parser as dtparser


def severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def parse_access_line(line):
    try:
        ip = line.split()[0]
        ts = line.split("[", 1)[1].split("]", 1)[0]
        path = line.split('"')[1].split()[1]
        status = int(line.split('"')[2].split()[0])
        dt = dtparser.parse(ts.replace(":", " ", 1))
        return dt, ip, status, path
    except Exception:
        return None


def analyze_access(access_logs, ip_req_threshold=5, total_req_threshold=10):
    parsed = []
    for line in access_logs or []:
        item = parse_access_line(line)
        if item:
            parsed.append(item)

    if not parsed:
        return []

    per_second_total = Counter()
    per_second_ip = defaultdict(Counter)
    path_counts = Counter()
    status_bucket = Counter()

    for ts, ip, status, path in parsed:
        sec = ts.replace(microsecond=0)
        per_second_total[sec] += 1
        per_second_ip[ip][sec] += 1
        path_counts[path] += 1
        status_bucket[status // 100] += 1

    peak_sec, peak_rps = max(per_second_total.items(), key=lambda kv: kv[1])

    if peak_rps < total_req_threshold:
        return []

    top_ip = None
    top_ip_rps = 0
    for ip, ctr in per_second_ip.items():
        rps = ctr.get(peak_sec, 0)
        if rps > top_ip_rps:
            top_ip_rps = rps
            top_ip = ip

    total = len(parsed)
    four_xx = status_bucket.get(4, 0)
    five_xx = status_bucket.get(5, 0)
    err_ratio = (four_xx + five_xx) / total if total else 0.0

    score = 40
    evidence = [f"peak burst {peak_rps} req/sec at {peak_sec.isoformat()} (>= {total_req_threshold})"]

    if top_ip and top_ip_rps >= ip_req_threshold:
        score += 25
        evidence.append(f"{top_ip} sent {top_ip_rps} req/sec at peak (>= {ip_req_threshold})")

    if err_ratio >= 0.3 and total >= 20:
        score += 10
        evidence.append(f"high error ratio {(err_ratio * 100):.0f}% (4xx/5xx)")

    return [{
        "type": "ddos_spike",
        "severity": severity(score),
        "score": score,
        "metrics": {
            "total_requests": total,
            "peak_second": peak_sec.isoformat(),
            "peak_rps": peak_rps,
            "top_ip_at_peak": top_ip,
            "top_ip_rps_at_peak": top_ip_rps,
            "top_paths": [p for p, _ in path_counts.most_common(3)],
            "http_4xx": four_xx,
            "http_5xx": five_xx,
            "error_ratio": round(err_ratio, 3),
        },
        "evidence": evidence,
        "recommended_actions": [
            "Enable per-IP and global rate limiting.",
            "Add WAF rules for abusive paths.",
            "Protect hot endpoints like /login.",
        ],
    }]
