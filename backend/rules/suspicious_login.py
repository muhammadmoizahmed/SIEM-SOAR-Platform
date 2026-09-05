from typing import List
from sqlalchemy.orm import Session
from models.event import Event


SUSPICIOUS_PATTERNS = {
    "unusual_hours": {"start": 0, "end": 5},
    "admin_account": ["admin", "administrator", "root", "sa"],
}


def detect_suspicious_login(db: Session, events: List[dict]) -> List[dict]:
    alerts = []
    for event in events:
        if event.get("event_type") != "authentication":
            continue

        username = (event.get("username") or "").lower()
        source_ip = event.get("source_ip")
        ts = event.get("timestamp")
        reasons = []

        if username in SUSPICIOUS_PATTERNS["admin_account"]:
            reasons.append(f"Privileged account '{username}' used")

        if ts and hasattr(ts, "hour"):
            if SUSPICIOUS_PATTERNS["unusual_hours"]["start"] <= ts.hour <= SUSPICIOUS_PATTERNS["unusual_hours"]["end"]:
                reasons.append(f"Login at unusual hour ({ts.hour}:00)")

        if event.get("status") == "success" and not event.get("is_internal", True):
            reasons.append("Successful login from external IP")

        if reasons:
            alerts.append({
                "title": f"Suspicious Login - {username} from {source_ip}",
                "description": "; ".join(reasons),
                "severity": "medium",
                "source_ip": source_ip,
                "username": username,
                "rule_name": "suspicious_login",
                "event_count": 1,
                "first_seen": ts,
                "last_seen": ts,
            })

    return alerts
