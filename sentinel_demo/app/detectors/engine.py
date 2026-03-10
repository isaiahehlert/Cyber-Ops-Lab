from .ssh import analyze_ssh
from .ddos import analyze_access


def run_detection(payload):
    ssh_logs = payload.get("ssh_logs", [])
    access_logs = payload.get("access_logs", [])

    ssh_fail_threshold = int(payload.get("ssh_fail_threshold", 5))
    ssh_takeover_fail_threshold = int(payload.get("ssh_takeover_fail_threshold", 10))
    ddos_ip_req_threshold = int(payload.get("ddos_ip_req_threshold", 5))
    ddos_total_req_threshold = int(payload.get("ddos_total_req_threshold", 10))

    detections = []
    detections.extend(analyze_ssh(ssh_logs, ssh_fail_threshold, ssh_takeover_fail_threshold))
    detections.extend(analyze_access(access_logs, ddos_ip_req_threshold, ddos_total_req_threshold))

    max_score = max([d.get("score", 0) for d in detections], default=0)

    overall = "clean"
    if max_score >= 80:
        overall = "high_risk"
    elif max_score >= 40:
        overall = "suspicious"
    elif max_score >= 10:
        overall = "low_signal"

    summary = {}
    for d in detections:
        summary[d["type"]] = summary.get(d["type"], 0) + 1

    return {
        "overall": overall,
        "detections": detections,
        "summary": summary,
        "thresholds": {
            "ssh_fail_threshold": ssh_fail_threshold,
            "ssh_takeover_fail_threshold": ssh_takeover_fail_threshold,
            "ddos_ip_req_threshold": ddos_ip_req_threshold,
            "ddos_total_req_threshold": ddos_total_req_threshold,
        },
        "notes": [
            "Heuristic detection intended for triage.",
            "This tool reports findings and suggested actions.",
        ],
    }
