"""Phase 13 — Risk Scoring Engine.

Score ranges:
0-20   Low
21-50  Medium
51-80  High
81-100 Critical
"""

from typing import Optional


def calculate_alert_risk_score(alert_data: dict) -> int:
    score = 0

    rule_scores = {
        "brute_force": 30,
        "suspicious_authentication": 35,
        "password_spray": 40,
        "impossible_login": 45,
        "suspicious_process": 35,
        "malware_detection": 50,
    }
    rule = alert_data.get("rule_name", "")
    score += rule_scores.get(rule, 10)

    severity_scores = {
        "critical": 30,
        "high": 20,
        "medium": 10,
        "low": 5,
    }
    score += severity_scores.get(alert_data.get("severity", "low"), 5)

    event_count = alert_data.get("event_count", 1)
    if event_count >= 50:
        score += 20
    elif event_count >= 20:
        score += 15
    elif event_count >= 10:
        score += 10
    elif event_count >= 5:
        score += 5

    return min(score, 100)


def calculate_event_risk_score(event: dict) -> int:
    score = 0
    if event.get("status") == "failed":
        score += 20
    if event.get("event_type") == "authentication" and event.get("status") == "failed":
        score += 15
    if not event.get("is_internal", True):
        score += 15
    severity = event.get("severity", "low")
    if severity in ("high", "critical"):
        score += 20
    if event.get("event_type") == "process":
        score += 10
    return min(score, 100)


def get_risk_level(score: int) -> str:
    if score >= 81:
        return "critical"
    elif score >= 51:
        return "high"
    elif score >= 21:
        return "medium"
    else:
        return "low"
