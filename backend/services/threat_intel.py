"""Phase 12 — Threat Intelligence Service.

Simulated IOC database and IP reputation lookup.
"""
import json
import os
from typing import Optional
from sqlalchemy.orm import Session


KNOWN_MALICIOUS_IPS = {
    "203.0.113.50": {"reputation": "malicious", "score": 90, "source": "Simulated-Intel", "country": "Unknown"},
    "198.51.100.23": {"reputation": "malicious", "score": 85, "source": "Simulated-Intel", "country": "Unknown"},
    "192.0.2.100": {"reputation": "suspicious", "score": 60, "source": "Simulated-Intel", "country": "Unknown"},
    "45.33.32.156": {"reputation": "malicious", "score": 95, "source": "Simulated-Intel", "country": "Unknown"},
    "104.236.228.48": {"reputation": "suspicious", "score": 55, "source": "Simulated-Intel", "country": "Unknown"},
}

GEO_DATABASE = {
    "203.0.113.50": {"country": "Russia", "city": "Moscow", "org": "Evil Corp"},
    "198.51.100.23": {"country": "China", "city": "Beijing", "org": "APT Group"},
    "192.0.2.100": {"country": "North Korea", "city": "Pyongyang", "org": "Lazarus Group"},
    "45.33.32.156": {"country": "Iran", "city": "Tehran", "org": "Charming Kitten"},
    "104.236.228.48": {"country": "Brazil", "city": "Sao Paulo", "org": "Unknown"},
}

MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb924": {"type": "malware", "name": "SimulatedRAT", "severity": "critical"},
    "a1b2c3d4e5f6": {"type": "ransomware", "name": "SimulatedRansom", "severity": "critical"},
}

SUSPICIOUS_URLS = [
    "phishing-example.com",
    "malware-download.ru",
    "fake-bank-login.com",
]


def lookup_ip_threat_intel(ip: str) -> Optional[dict]:
    if ip in KNOWN_MALICIOUS_IPS:
        return KNOWN_MALICIOUS_IPS[ip]
    internal = ["192.168.", "10.", "172.16.", "127."]
    if any(ip.startswith(p) for p in internal):
        return {"reputation": "internal", "score": 0, "source": "private", "country": "Internal"}
    return {"reputation": "unknown", "score": 0, "source": "no-data", "country": "Unknown"}


def lookup_geo(ip: str) -> Optional[dict]:
    if ip in GEO_DATABASE:
        return GEO_DATABASE[ip]
    internal = ["192.168.", "10.", "172.16.", "127."]
    if any(ip.startswith(p) for p in internal):
        return {"country": "Internal", "city": "LAN", "org": "Private"}
    return {"country": "Unknown", "city": "Unknown", "org": "Unknown"}


def check_hash(hash_value: str) -> Optional[dict]:
    return MALICIOUS_HASHES.get(hash_value)


def check_url(url: str) -> Optional[dict]:
    for suspicious in SUSPICIOUS_URLS:
        if suspicious in url.lower():
            return {"status": "malicious", "reason": "Known phishing domain", "severity": "high"}
    return None


def get_all_iocs() -> dict:
    return {
        "malicious_ips": len(KNOWN_MALICIOUS_IPS),
        "malicious_hashes": len(MALICIOUS_HASHES),
        "suspicious_urls": len(SUSPICIOUS_URLS),
        "total_iocs": len(KNOWN_MALICIOUS_IPS) + len(MALICIOUS_HASHES) + len(SUSPICIOUS_URLS),
    }


def enrich_ip(ip: str) -> dict:
    threat = lookup_ip_threat_intel(ip)
    geo = lookup_geo(ip)
    return {
        "ip": ip,
        "threat_intel": threat,
        "geo": geo,
        "risk_score": threat.get("score", 0) if threat else 0,
    }
