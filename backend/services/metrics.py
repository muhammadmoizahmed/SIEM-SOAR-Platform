"""Phase 21 — Metrics Service (MTTD, MTTR)."""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from models.event import Event
from models.alert import Alert
from models.incident import Incident


def calculate_metrics(db: Session) -> dict:
    """Calculate MTTD and MTTR across all alerts/incidents."""
    alerts = db.query(Alert).filter(Alert.first_seen.isnot(None), Alert.created_at.isnot(None)).all()
    incidents = db.query(Incident).filter(
        Incident.created_at.isnot(None), Incident.resolved_at.isnot(None)
    ).all()

    mttd_seconds = _calculate_mttd(alerts)
    mttr_seconds = _calculate_mttr(incidents)

    return {
        "mttd": {
            "seconds": round(mttd_seconds, 1),
            "formatted": _format_duration(mttd_seconds),
            "description": "Mean Time To Detect — time between first event and alert creation",
            "sample_size": len(alerts),
        },
        "mttr": {
            "seconds": round(mttr_seconds, 1),
            "formatted": _format_duration(mttr_seconds),
            "description": "Mean Time To Resolve — time between incident creation and resolution",
            "sample_size": len(incidents),
        },
        "event_stats": _event_stats(db),
        "alert_stats": _alert_stats(db),
        "incident_stats": _incident_stats(db),
    }


def _calculate_mttd(alerts) -> float:
    if not alerts:
        return 0.0
    times = []
    for a in alerts:
        if a.first_seen and a.created_at:
            diff = (a.created_at - a.first_seen).total_seconds()
            if diff >= 0:
                times.append(diff)
    return sum(times) / len(times) if times else 0.0


def _calculate_mttr(incidents) -> float:
    if not incidents:
        return 0.0
    times = []
    for i in incidents:
        if i.created_at and i.resolved_at:
            diff = (i.resolved_at - i.created_at).total_seconds()
            if diff >= 0:
                times.append(diff)
    return sum(times) / len(times) if times else 0.0


def _event_stats(db: Session) -> dict:
    total = db.query(Event).count()
    by_type = (
        db.query(Event.event_type, func.count(Event.id))
        .group_by(Event.event_type)
        .all()
    )
    by_source = (
        db.query(Event.source_type, func.count(Event.id))
        .group_by(Event.source_type)
        .all()
    )
    return {
        "total": total,
        "by_type": {t: c for t, c in by_type},
        "by_source": {s: c for s, c in by_source},
    }


def _alert_stats(db: Session) -> dict:
    total = db.query(Alert).count()
    by_severity = (
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    by_rule = (
        db.query(Alert.rule_name, func.count(Alert.id))
        .group_by(Alert.rule_name)
        .all()
    )
    return {
        "total": total,
        "by_severity": {s: c for s, c in by_severity},
        "by_rule": {r: c for r, c in by_rule},
    }


def _incident_stats(db: Session) -> dict:
    total = db.query(Incident).count()
    by_status = (
        db.query(Incident.status, func.count(Incident.id))
        .group_by(Incident.status)
        .all()
    )
    by_priority = (
        db.query(Incident.priority, func.count(Incident.id))
        .group_by(Incident.priority)
        .all()
    )
    return {
        "total": total,
        "by_status": {s.value: c for s, c in by_status},
        "by_priority": {p.value: c for p, c in by_priority},
    }


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"
