"""Phase 23 — Dashboard API."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.database import get_db
from models.event import Event
from models.alert import Alert
from models.incident import Incident
from services.detector import get_alert_stats, get_mitre_techniques
from services.incident_service import get_incident_stats
from services.threat_intel import get_all_iocs
from services.audit_service import get_audit_log_count
from services.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/")
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_events = db.query(Event).count()
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()

    alert_stats = get_alert_stats(db)
    incident_stats = get_incident_stats(db)
    mitre = get_mitre_techniques(db)
    iocs = get_all_iocs()

    top_ips = (
        db.query(Event.source_ip, func.count(Event.id).label("count"))
        .filter(Event.source_ip.isnot(None))
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )

    top_rules = (
        db.query(Alert.rule_name, func.count(Alert.id).label("count"))
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )

    return {
        "summary": {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
        },
        "alert_stats": alert_stats,
        "incident_stats": incident_stats,
        "mitre_techniques": mitre,
        "threat_intel": iocs,
        "audit_log_count": get_audit_log_count(db),
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_detection_rules": [{"rule": rule, "count": count} for rule, count in top_rules],
    }
