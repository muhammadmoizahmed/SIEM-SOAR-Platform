from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session


MITRE_IMPOSSIBLE_LOGIN = "T1078"


def detect_impossible_login(db: Session, events: List[dict], max_seconds: int = 300) -> List[dict]:
    """Rule #4: Impossible Login — same user, different locations within short time."""
    alerts = []
    auth_events = [e for e in events if e.get("event_type") == "authentication" and e.get("status") == "success"]

    user_events = {}
    for event in auth_events:
        username = event.get("username")
        if username:
            user_events.setdefault(username, []).append(event)

    for username, group in user_events.items():
        if len(group) < 2:
            continue

        sorted_events = sorted(group, key=lambda e: e.get("timestamp") or datetime.min)

        for i in range(len(sorted_events)):
            for j in range(i + 1, len(sorted_events)):
                e1 = sorted_events[i]
                e2 = sorted_events[j]

                ts1 = e1.get("timestamp")
                ts2 = e2.get("timestamp")
                if not isinstance(ts1, datetime) or not isinstance(ts2, datetime):
                    continue

                time_diff = abs((ts2 - ts1).total_seconds())
                if time_diff > max_seconds:
                    continue

                loc1 = e1.get("geo_location", {})
                loc2 = e2.get("geo_location", {})
                country1 = loc1.get("country", "Unknown")
                country2 = loc2.get("country", "Unknown")

                if country1 != country2 and country1 != "Unknown" and country2 != "Unknown":
                    alerts.append({
                        "title": f"Impossible Login Detected for {username}",
                        "description": f"User '{username}' logged in from {country1} then {country2} within {int(time_diff)} seconds. Geographic impossibility.",
                        "severity": "critical",
                        "source_ip": e2.get("source_ip"),
                        "username": username,
                        "rule_name": "impossible_login",
                        "mitre_technique": MITRE_IMPOSSIBLE_LOGIN,
                        "mitre_tactic": "Initial Access",
                        "event_count": 2,
                        "first_seen": ts1,
                        "last_seen": ts2,
                    })
                    break

    return alerts
