from typing import Optional
from sqlalchemy.orm import Session
from services.threat_intel import lookup_ip_threat_intel, lookup_geo
from services.risk_scoring import calculate_event_risk_score


def enrich_event(db: Session, event: dict) -> dict:
    """Enrich a normalized event with threat intel, geo, and risk score."""
    source_ip = event.get("source_ip")
    if source_ip:
        event["geo_location"] = lookup_geo(source_ip)
        event["ip_reputation"] = lookup_ip_threat_intel(source_ip)
        event["is_internal"] = is_internal_ip(source_ip)

    event["risk_score"] = calculate_event_risk_score(event)
    return event


def is_internal_ip(ip: str) -> bool:
    prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                "172.29.", "172.30.", "172.31.", "127."]
    return any(ip.startswith(p) for p in prefixes)
