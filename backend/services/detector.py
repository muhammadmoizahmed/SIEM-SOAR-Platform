from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from models.event import Event
from models.alert import Alert, AlertStatus
from rules.brute_force import detect_brute_force
from rules.suspicious_authentication import detect_suspicious_authentication
from rules.password_spray import detect_password_spray
from rules.impossible_login import detect_impossible_login
from rules.suspicious_process import detect_suspicious_process
from rules.malware import detect_malware_indicators
from services.risk_scoring import calculate_alert_risk_score


def run_detection(db: Session, events: List[dict]) -> List[dict]:
    """Run all 5 detection rules + malware against incoming events."""
    alerts = []

    rules = [
        detect_brute_force,
        detect_suspicious_authentication,
        detect_password_spray,
        detect_impossible_login,
        detect_suspicious_process,
        detect_malware_indicators,
    ]

    for rule_func in rules:
        try:
            rule_alerts = rule_func(db, events)
            alerts.extend(rule_alerts)
        except Exception:
            continue

    saved_alerts = []
    for alert_data in alerts:
        risk = calculate_alert_risk_score(alert_data)
        alert_data["risk_score"] = risk

        existing = (
            db.query(Alert)
            .filter(
                Alert.rule_name == alert_data["rule_name"],
                Alert.source_ip == alert_data.get("source_ip"),
                Alert.status.in_([AlertStatus.open, AlertStatus.investigating]),
            )
            .first()
        )
        if existing:
            existing.event_count += alert_data.get("event_count", 1)
            existing.last_seen = alert_data.get("last_seen", datetime.utcnow())
            existing.risk_score = max(existing.risk_score or 0, risk)
            db.commit()
            saved_alerts.append({"id": existing.id, "title": existing.title, "merged": True})
        else:
            alert_id = _generate_alert_id(db)
            alert = Alert(
                alert_id=alert_id,
                title=alert_data["title"],
                description=alert_data.get("description"),
                severity=alert_data["severity"],
                source_ip=alert_data.get("source_ip"),
                destination_ip=alert_data.get("destination_ip"),
                username=alert_data.get("username"),
                hostname=alert_data.get("hostname"),
                rule_name=alert_data["rule_name"],
                mitre_technique=alert_data.get("mitre_technique"),
                mitre_tactic=alert_data.get("mitre_tactic"),
                risk_score=risk,
                event_count=alert_data.get("event_count", 1),
                first_seen=alert_data.get("first_seen"),
                last_seen=alert_data.get("last_seen"),
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            saved_alerts.append({"id": alert.id, "alert_id": alert.alert_id, "title": alert.title})

    return saved_alerts


def _generate_alert_id(db: Session) -> str:
    last = db.query(Alert).order_by(Alert.id.desc()).first()
    if last and last.alert_id:
        num = int(last.alert_id.replace("ALT-", "")) + 1
    else:
        num = 1
    return f"ALT-{num:05d}"


def get_recent_alerts(db: Session, limit: int = 50) -> List[Alert]:
    return db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()


def get_alert_by_id(db: Session, alert_id: int) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def get_alert_by_alert_id(db: Session, alert_id: str) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.alert_id == alert_id).first()


def update_alert_status(db: Session, alert_id: int, status: str) -> Optional[Alert]:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.status = status
        db.commit()
        db.refresh(alert)
    return alert


def get_alert_stats(db: Session) -> dict:
    total = db.query(Alert).count()
    by_severity = {}
    for sev in ["critical", "high", "medium", "low"]:
        by_severity[sev] = db.query(Alert).filter(Alert.severity == sev).count()
    by_status = {}
    for status in AlertStatus:
        by_status[status.value] = db.query(Alert).filter(Alert.status == status).count()
    by_rule = {}
    for alert in db.query(Alert).all():
        by_rule[alert.rule_name] = by_rule.get(alert.rule_name, 0) + 1
    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_rule": by_rule,
    }


def get_mitre_techniques(db: Session) -> dict:
    techniques = {}
    for alert in db.query(Alert).filter(Alert.mitre_technique.isnot(None)).all():
        tech = alert.mitre_technique
        if tech not in techniques:
            techniques[tech] = {"count": 0, "tactic": alert.mitre_tactic}
        techniques[tech]["count"] += 1
    return techniques
