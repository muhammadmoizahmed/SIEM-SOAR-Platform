from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session


MITRE_VALID_ACCOUNTS = "T1078"


def detect_suspicious_authentication(db: Session, events: List[dict], window_seconds: int = 300) -> List[dict]:
    """Rule #2: Suspicious Authentication — Failed + Failed + Successful login from same IP."""
    alerts = []
    auth_events = [e for e in events if e.get("event_type") == "authentication"]

    ip_groups = {}
    for event in auth_events:
        ip = event.get("source_ip")
        if ip:
            ip_groups.setdefault(ip, []).append(event)

    for ip, group in ip_groups.items():
        failed = [e for e in group if e.get("status") == "failed"]
        successful = [e for e in group if e.get("status") == "success"]

        if len(failed) < 2 or len(successful) < 1:
            continue

        timestamps = []
        for e in failed + successful:
            ts = e.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
        if not timestamps:
            continue

        timestamps.sort()
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        if time_span > window_seconds:
            continue

        usernames = list(set(e.get("username") for e in group if e.get("username")))
        alerts.append({
            "title": f"Suspicious Authentication Pattern from {ip}",
            "description": f"Failed logins followed by successful login from {ip}. User(s): {', '.join(usernames)}. Possible credential stuffing or account compromise.",
            "severity": "high",
            "source_ip": ip,
            "username": ", ".join(usernames) if usernames else None,
            "rule_name": "suspicious_authentication",
            "mitre_technique": MITRE_VALID_ACCOUNTS,
            "mitre_tactic": "Initial Access",
            "event_count": len(failed) + len(successful),
            "first_seen": timestamps[0],
            "last_seen": timestamps[-1],
        })

    return alerts
