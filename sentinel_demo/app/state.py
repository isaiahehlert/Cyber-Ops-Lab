from datetime import datetime, timezone


def fresh_state():
    return {
        "overall": "clean",
        "detections": [],
        "detection_history": [],
        "summary": {},
        "thresholds": {
            "ssh_fail_threshold": 5,
            "ssh_takeover_fail_threshold": 10,
            "ddos_ip_req_threshold": 5,
            "ddos_total_req_threshold": 10,
        },
        "notes": ["Monitoring for auth and HTTP telemetry."],
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "monitoring",
        "recent_auth_events": [],
        "recent_http_events": [],
        "alert_banner": None,
    }


app_state = fresh_state()
