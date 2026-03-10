from fastapi import APIRouter, Request
from datetime import datetime, timezone
from pathlib import Path
import json

from .state import app_state, fresh_state
from .detectors.engine import run_detection

router = APIRouter()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _apply_fresh_state():
    fresh = fresh_state()
    app_state.clear()
    app_state.update(fresh)
    return app_state


def _history_key(detection):
    return (
        detection.get("type"),
        detection.get("source_ip") or detection.get("metrics", {}).get("top_ip_at_peak"),
        detection.get("score"),
        tuple(detection.get("evidence", [])),
    )


def _append_history(new_detections, source):
    existing_keys = {_history_key(d) for d in app_state.get("detection_history", [])}

    for d in new_detections:
        key = _history_key(d)
        if key in existing_keys:
            continue

        history_item = dict(d)
        history_item["detected_at"] = _now()
        history_item["source"] = source
        app_state["detection_history"].append(history_item)
        existing_keys.add(key)

    app_state["detection_history"] = app_state["detection_history"][-50:]


def _recompute_state(source: str):
    payload = {
        "ssh_logs": app_state.get("recent_auth_events", []),
        "access_logs": app_state.get("recent_http_events", []),
        "ssh_fail_threshold": app_state["thresholds"]["ssh_fail_threshold"],
        "ssh_takeover_fail_threshold": app_state["thresholds"]["ssh_takeover_fail_threshold"],
        "ddos_ip_req_threshold": app_state["thresholds"]["ddos_ip_req_threshold"],
        "ddos_total_req_threshold": app_state["thresholds"]["ddos_total_req_threshold"],
    }

    result = run_detection(payload)

    app_state["overall"] = result["overall"]
    app_state["detections"] = result["detections"]
    app_state["summary"] = result["summary"]
    app_state["notes"] = result["notes"]
    app_state["last_updated"] = _now()
    app_state["source"] = source

    _append_history(result["detections"], source)

    if result["detections"]:
        first = result["detections"][0]
        app_state["alert_banner"] = {
            "message": f"ALERT: {first['type']} detected",
            "severity": first.get("severity", "medium"),
            "timestamp": _now(),
        }
    else:
        app_state["alert_banner"] = None

    return result


@router.get("/api/health")
def health():
    return {"status": "ok", "time": _now()}


@router.get("/api/state")
def state():
    return app_state


@router.post("/api/reset")
def reset():
    _apply_fresh_state()
    return {"status": "reset", "state": app_state}


@router.post("/api/replay/{fixture_name}")
def replay_fixture(fixture_name: str):
    fixture_path = Path("sentinel_demo/fixtures") / f"{fixture_name}.json"
    if not fixture_path.exists():
        return {"error": "fixture not found"}

    if fixture_name == "clean":
        _apply_fresh_state()
        app_state["source"] = "fixture:clean"
        return app_state

    with open(fixture_path, "r") as f:
        payload = json.load(f)

    app_state["recent_auth_events"] = payload.get("ssh_logs", [])
    app_state["recent_http_events"] = payload.get("access_logs", [])

    if "ssh_fail_threshold" in payload:
        app_state["thresholds"]["ssh_fail_threshold"] = int(payload["ssh_fail_threshold"])
    if "ssh_takeover_fail_threshold" in payload:
        app_state["thresholds"]["ssh_takeover_fail_threshold"] = int(payload["ssh_takeover_fail_threshold"])
    if "ddos_ip_req_threshold" in payload:
        app_state["thresholds"]["ddos_ip_req_threshold"] = int(payload["ddos_ip_req_threshold"])
    if "ddos_total_req_threshold" in payload:
        app_state["thresholds"]["ddos_total_req_threshold"] = int(payload["ddos_total_req_threshold"])

    return _recompute_state(f"fixture:{fixture_name}")


@router.post("/api/ingest/auth-event")
async def ingest_auth_event(request: Request):
    body = await request.json()
    line = body.get("line")
    if not line:
        return {"error": "missing line"}

    app_state["recent_auth_events"].append(line)
    app_state["recent_auth_events"] = app_state["recent_auth_events"][-500:]
    return _recompute_state("live:auth")


@router.post("/api/ingest/http-event")
async def ingest_http_event(request: Request):
    body = await request.json()
    line = body.get("line")
    if not line:
        return {"error": "missing line"}

    app_state["recent_http_events"].append(line)
    app_state["recent_http_events"] = app_state["recent_http_events"][-1000:]
    return _recompute_state("live:http")


@router.post("/api/clear-alert")
def clear_alert():
    app_state["alert_banner"] = None
    app_state["last_updated"] = _now()
    return {"status": "cleared"}
