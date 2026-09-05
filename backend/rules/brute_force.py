from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session
from models.event import Event


MITRE_BRUTE_FORCE = "T1110"


def detect_brute_force(db: Session, events: List[dict], threshold: int = 5, window_seconds: int = 60) -> List[dict]:
    """Rule #1: Brute Force — same source_ip, 5+ failed logins, within 1 minute."""
    alerts = []
    failed_events = [e for e in events if e.get("status") == "failed" and e.get("event_type") == "authentication"]

    ip_groups = {}
    for event in failed_events:
        ip = event.get("source_ip")
        if ip:
            ip_groups.setdefault(ip, []).append(event)

    for ip, group in ip_groups.items():
        if len(group) < threshold:
            continue

        timestamps = []
        for e in group:
            ts = e.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
        if not timestamps:
            continue

        timestamps.sort()
        window_start = timestamps[0]
        window_end = window_start + timedelta(seconds=window_seconds)
        in_window = [t for t in timestamps if t <= window_end]

        if len(in_window) >= threshold:
            usernames = list(set(e.get("username") for e in group if e.get("username")))
            alerts.append({
                "title": f"Brute Force Attack from {ip}",
                "description": f"{len(in_window)} failed login attempts from {ip} targeting user(s): {', '.join(usernames)} within {window_seconds} seconds.",
                "severity": "high",
                "source_ip": ip,
                "username": ", ".join(usernames) if usernames else None,
                "rule_name": "brute_force",
                "mitre_technique": MITRE_BRUTE_FORCE,
                "mitre_tactic": "Credential Access",
                "event_count": len(in_window),
                "first_seen": timestamps[0],
                "last_seen": timestamps[-1],
            })

    return alerts
