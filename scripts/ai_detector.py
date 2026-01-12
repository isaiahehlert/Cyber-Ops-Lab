#!/usr/bin/env python3
"""
ai_detector.py — "Bot / automation" detector for web access logs (defensive, SOC-style)

What it does:
- Parses common web server access log lines (Apache/Nginx "combined" style).
- Aggregates behavior per IP + User-Agent.
- Assigns a suspicion score based on indicators (rate, UA keywords, error spikes, etc.).
- Prints a ranked summary and (optionally) writes a JSON report.

Notes:
- This is heuristic detection (not magic). Good for triage and lab workflows.
- Uses only Python stdlib.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# --- Heuristic keyword lists (tuned for defensive triage) ---
BOT_UA_KEYWORDS = [
    "bot", "crawler", "spider", "scrapy", "wget", "curl", "httpclient", "python-requests",
    "libwww", "java", "go-http-client", "axios", "okhttp", "headless", "phantomjs",
    "selenium", "playwright", "puppeteer",
]

# If you want to treat these as "known-good-ish" bots (optional allowlist), add here.
# Example: search engine crawlers; still bots, but may be expected in some environments.
KNOWN_BOT_HINTS = [
    "googlebot", "bingbot", "duckduckbot", "yandex", "baiduspider"
]

SUSPICIOUS_PATH_HINTS = [
    "/wp-admin", "/wp-login", "/xmlrpc.php", "/.env", "/admin", "/login", "/phpmyadmin",
    "/cgi-bin", "/actuator", "/.git", "/config", "/setup", "/server-status"
]


# --- Log parsing (Apache/Nginx Combined) ---
# Example combined:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "ref" "ua"
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+\S+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Timestamp in logs: 10/Oct/2000:13:55:36 -0700
LOG_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEvent:
    ip: str
    ts: datetime
    method: str
    path: str
    status: int
    size: int
    referrer: str
    ua: str


@dataclass
class EntityResult:
    ip: str
    total_requests: int
    first_seen: str
    last_seen: str
    duration_seconds: float
    req_per_min: float
    unique_paths: int
    unique_uas: int
    error_rate: float
    suspicious_path_hits: int
    ua_bot_keyword_hit: bool
    ua_known_bot_hint: bool
    empty_ua: bool
    score: int
    label: str
    reasons: List[str]


def parse_size(value: str) -> int:
    if value == "-" or value.strip() == "":
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def parse_line(line: str) -> Optional[LogEvent]:
    m = COMBINED_LOG_RE.match(line.strip())
    if not m:
        return None

    try:
        ts = datetime.strptime(m.group("time"), LOG_TIME_FMT)
    except Exception:
        return None

    ip = m.group("ip")
    method = m.group("method")
    path = m.group("path")
    status = int(m.group("status"))
    size = parse_size(m.group("size"))
    ref = m.group("referrer") or ""
    ua = m.group("ua") or ""

    return LogEvent(ip=ip, ts=ts, method=method, path=path, status=status, size=size, referrer=ref, ua=ua)


def iter_events(path: Path) -> Iterable[LogEvent]:
    with path.open("r", errors="replace") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                yield ev


def contains_keyword(text: str, keywords: List[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def label_from_score(score: int, suspicious: int, likely_bot: int) -> str:
    if score >= likely_bot:
        return "LIKELY_BOT"
    if score >= suspicious:
        return "SUSPICIOUS"
    return "LIKELY_HUMAN"


def analyze_entity(
    ip: str,
    times: List[datetime],
    paths: Counter,
    uas: Counter,
    statuses: Counter,
    suspicious: int,
    likely_bot: int,
    rate_warn: float,
    rate_high: float,
    error_warn: float,
    path_probe_warn: int,
) -> EntityResult:
    times_sorted = sorted(times)
    first_ts = times_sorted[0]
    last_ts = times_sorted[-1]
    duration = max((last_ts - first_ts).total_seconds(), 1.0)  # avoid div by zero
    total = len(times_sorted)

    rpm = (total / duration) * 60.0
    unique_paths = len(paths)
    unique_uas = len(uas)

    # Error rate: 4xx + 5xx / total
    errors = sum(count for status, count in statuses.items() if status >= 400)
    error_rate = errors / total if total else 0.0

    # Suspicious path hits
    susp_path_hits = 0
    for p, c in paths.items():
        pl = p.lower()
        if any(h in pl for h in SUSPICIOUS_PATH_HINTS):
            susp_path_hits += c

    # UA checks
    top_ua = uas.most_common(1)[0][0] if uas else ""
    empty_ua = (top_ua.strip() == "") or (top_ua.strip() == "-")
    ua_bot_kw = contains_keyword(top_ua, BOT_UA_KEYWORDS)
    ua_known_hint = contains_keyword(top_ua, KNOWN_BOT_HINTS)

    score = 0
    reasons: List[str] = []

    # --- Scoring rules (tweakable) ---
    # Request rate indicators
    if rpm >= rate_high:
        score += 35
        reasons.append(f"High request rate: {rpm:.1f} req/min (>= {rate_high})")
    elif rpm >= rate_warn:
        score += 20
        reasons.append(f"Elevated request rate: {rpm:.1f} req/min (>= {rate_warn})")

    # Very short burst with many requests is suspicious (automation bursts)
    if duration < 30 and total >= 25:
        score += 15
        reasons.append(f"Burst behavior: {total} requests in {duration:.1f}s")

    # Error rate indicators
    if error_rate >= error_warn:
        score += 20
        reasons.append(f"High error rate: {error_rate*100:.1f}% (>= {error_warn*100:.1f}%)")

    # Probing / scanning indicators
    if susp_path_hits >= path_probe_warn:
        score += 25
        reasons.append(f"Probing paths: {susp_path_hits} hits on common attack paths")

    # UA indicators
    if empty_ua:
        score += 10
        reasons.append("Empty or missing User-Agent")
    if ua_bot_kw:
        score += 25
        reasons.append("User-Agent contains common automation/bot keyword(s)")
    if unique_uas >= 5:
        score += 10
        reasons.append(f"High UA variability: {unique_uas} unique User-Agents")

    # If it looks like a known crawler, still a bot but maybe expected:
    if ua_known_hint:
        score += 10
        reasons.append("User-Agent hints a known crawler/bot")

    # Diversity / browsing-like behavior slightly reduces suspicion
    # (bots often hit few endpoints repeatedly)
    if unique_paths >= 20 and rpm < rate_warn:
        score = max(0, score - 10)
        reasons.append("Many unique paths at normal rate (more human-like browsing)")

    label = label_from_score(score, suspicious=suspicious, likely_bot=likely_bot)

    return EntityResult(
        ip=ip,
        total_requests=total,
        first_seen=first_ts.isoformat(),
        last_seen=last_ts.isoformat(),
        duration_seconds=duration,
        req_per_min=rpm,
        unique_paths=unique_paths,
        unique_uas=unique_uas,
        error_rate=error_rate,
        suspicious_path_hits=susp_path_hits,
        ua_bot_keyword_hit=ua_bot_kw,
        ua_known_bot_hint=ua_known_hint,
        empty_ua=empty_ua,
        score=score,
        label=label,
        reasons=reasons[:8],  # keep it readable
    )


def analyze_log_file(
    log_path: Path,
    suspicious: int,
    likely_bot: int,
    rate_warn: float,
    rate_high: float,
    error_warn: float,
    path_probe_warn: int,
    limit: int,
) -> Tuple[List[EntityResult], Dict[str, Any]]:
    times_by_ip: Dict[str, List[datetime]] = defaultdict(list)
    paths_by_ip: Dict[str, Counter] = defaultdict(Counter)
    uas_by_ip: Dict[str, Counter] = defaultdict(Counter)
    status_by_ip: Dict[str, Counter] = defaultdict(Counter)

    parsed = 0
    skipped = 0

    for ev in iter_events(log_path):
        parsed += 1
        times_by_ip[ev.ip].append(ev.ts)
        paths_by_ip[ev.ip][ev.path] += 1
        uas_by_ip[ev.ip][ev.ua] += 1
        status_by_ip[ev.ip][ev.status] += 1

    # Count skipped by rough estimate: total lines - parsed
    # (We avoid reading twice. If you want exact, we can count lines.)
    # We'll compute it by scanning file quickly only if small:
    try:
        total_lines = sum(1 for _ in log_path.open("r", errors="replace"))
        skipped = max(0, total_lines - parsed)
    except Exception:
        total_lines = None

    results: List[EntityResult] = []
    for ip in times_by_ip.keys():
        results.append(
            analyze_entity(
                ip=ip,
                times=times_by_ip[ip],
                paths=paths_by_ip[ip],
                uas=uas_by_ip[ip],
                statuses=status_by_ip[ip],
                suspicious=suspicious,
                likely_bot=likely_bot,
                rate_warn=rate_warn,
                rate_high=rate_high,
                error_warn=error_warn,
                path_probe_warn=path_probe_warn,
            )
        )

    results.sort(key=lambda r: (r.score, r.total_requests), reverse=True)
    if limit > 0:
        results = results[:limit]

    meta = {
        "log_file": str(log_path),
        "parsed_events": parsed,
        "total_lines": total_lines,
        "skipped_lines_estimate": skipped,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": {
            "suspicious_score": suspicious,
            "likely_bot_score": likely_bot,
            "rate_warn_req_min": rate_warn,
            "rate_high_req_min": rate_high,
            "error_warn_rate": error_warn,
            "path_probe_warn_hits": path_probe_warn,
        },
    }
    return results, meta


def print_results(results: List[EntityResult], meta: Dict[str, Any]) -> None:
    print(f"[*] File: {meta.get('log_file')}")
    print(f"[*] Parsed events: {meta.get('parsed_events')}")
    if meta.get("total_lines") is not None:
        print(f"[*] Total lines: {meta.get('total_lines')} | skipped (estimate): {meta.get('skipped_lines_estimate')}")
    print(f"[*] Generated: {meta.get('generated_at')}\n")

    if not results:
        print("[*] No entities to report.")
        return

    print("=== Top Suspects (ranked) ===")
    for r in results:
        print(f"\nIP: {r.ip}")
        print(f"  Label: {r.label} | Score: {r.score}")
        print(f"  Requests: {r.total_requests} | Req/min: {r.req_per_min:.1f} | Errors: {r.error_rate*100:.1f}%")
        print(f"  Unique paths: {r.unique_paths} | Unique UAs: {r.unique_uas} | Suspicious path hits: {r.suspicious_path_hits}")
        print(f"  First seen: {r.first_seen}")
        print(f"  Last seen : {r.last_seen}")
        if r.reasons:
            print("  Reasons:")
            for reason in r.reasons:
                print(f"    - {reason}")


def export_json(results: List[EntityResult], meta: Dict[str, Any], out_path: Path) -> None:
    payload = {
        "meta": meta,
        "results": [asdict(r) for r in results],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"\n[*] Wrote JSON report: {out_path}")


def manual_mode() -> int:
    print("AI/Bot Detector — Manual Mode")
    ua = input("Paste a User-Agent string (or leave blank): ").strip()
    path = input("Optional path you saw requested (or leave blank): ").strip()

    score = 0
    reasons: List[str] = []

    if not ua:
        score += 10
        reasons.append("Empty/missing User-Agent")
    else:
        if contains_keyword(ua, BOT_UA_KEYWORDS):
            score += 25
            reasons.append("User-Agent contains bot/automation keyword(s)")
        if contains_keyword(ua, KNOWN_BOT_HINTS):
            score += 10
            reasons.append("User-Agent hints known crawler/bot")

    if path:
        pl = path.lower()
        if any(h in pl for h in SUSPICIOUS_PATH_HINTS):
            score += 20
            reasons.append("Path matches common probing/attack endpoint")

    label = label_from_score(score, suspicious=30, likely_bot=60)
    print(f"\nResult: {label} | score={score}")
    if reasons:
        print("Reasons:")
        for r in reasons:
            print(f"  - {r}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Heuristic bot/automation detector for web access logs (defensive).")
    parser.add_argument("--file", type=str, help="Path to access log file (Apache/Nginx combined format).")
    parser.add_argument("--manual", action="store_true", help="Manual mode (analyze UA/path hints).")

    # thresholds / tuning
    parser.add_argument("--suspicious-score", type=int, default=35, help="Score >= this is labeled SUSPICIOUS (default: 35)")
    parser.add_argument("--likely-bot-score", type=int, default=65, help="Score >= this is labeled LIKELY_BOT (default: 65)")
    parser.add_argument("--rate-warn", type=float, default=30.0, help="req/min threshold for elevated rate (default: 30)")
    parser.add_argument("--rate-high", type=float, default=90.0, help="req/min threshold for high rate (default: 90)")
    parser.add_argument("--error-warn", type=float, default=0.35, help="error rate threshold (4xx/5xx) (default: 0.35)")
    parser.add_argument("--path-probe-warn", type=int, default=3, help="hits on suspicious paths threshold (default: 3)")

    parser.add_argument("--top", type=int, default=20, help="Show top N entities (default: 20; 0 = all)")
    parser.add_argument("--json-out", type=str, help="Write JSON report to this path.")
    args = parser.parse_args()

    if args.manual:
        return manual_mode()

    if not args.file:
        print("[-] Provide --file <logfile> or use --manual")
        return 2

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[-] File not found: {log_path}")
        return 2

    results, meta = analyze_log_file(
        log_path=log_path,
        suspicious=args.suspicious_score,
        likely_bot=args.likely_bot_score,
        rate_warn=args.rate_warn,
        rate_high=args.rate_high,
        error_warn=args.error_warn,
        path_probe_warn=args.path_probe_warn,
        limit=args.top,
    )

    print_results(results, meta)

    if args.json_out:
        export_json(results, meta, Path(args.json_out))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
