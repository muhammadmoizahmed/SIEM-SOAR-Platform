from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session


MITRE_PASSWORD_SPRAY = "T1110.003"


def detect_password_spray(db: Session, events: List[dict], min_usernames: int = 10, window_seconds: int = 600) -> List[dict]:
    """Rule #3: Password Spray — 10+ unique usernames, same source IP, failed authentication."""
    alerts = []
    failed_auth = [e for e in events if e.get("status") == "failed" and e.get("event_type") == "authentication"]

    ip_groups = {}
    for event in failed_auth:
        ip = event.get("source_ip")
        if ip:
            ip_groups.setdefault(ip, []).append(event)

    for ip, group in ip_groups.items():
        usernames = set(e.get("username") for e in group if e.get("username"))
        if len(usernames) < min_usernames:
            continue

        timestamps = []
        for e in group:
            ts = e.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
        if not timestamps:
            continue

        timestamps.sort()
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        if time_span > window_seconds:
            continue

        alerts.append({
            "title": f"Password Spray Attack from {ip}",
            "description": f"{len(usernames)} unique usernames targeted with failed logins from {ip} within {int(time_span)} seconds. Usernames: {', '.join(list(usernames)[:10])}...",
            "severity": "critical",
            "source_ip": ip,
            "username": ", ".join(list(usernames)[:5]),
            "rule_name": "password_spray",
            "mitre_technique": MITRE_PASSWORD_SPRAY,
            "mitre_tactic": "Credential Access",
            "event_count": len(group),
            "first_seen": timestamps[0],
            "last_seen": timestamps[-1],
        })

    return alerts
