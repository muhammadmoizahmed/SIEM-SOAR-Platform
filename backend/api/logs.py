"""Phase 23 — Logs API with Auth and Audit."""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from models.event import Event
from services.collector import (
    parse_json_logs, parse_csv_logs, parse_text_logs,
    collect_and_normalize, collect_linux_logs, collect_nginx_logs,
)
from services.detector import run_detection
from services.enrichment import enrich_event
from services.audit_service import log_action
from services.auth import get_current_user, require_permission
from models.user import User

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    source_type: str = "json",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("upload_logs")),
):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    filename = file.filename.lower()

    normalized_events = []

    if filename.endswith(".json"):
        raw = parse_json_logs(text)
        normalized_events = collect_and_normalize(raw, source_type)
    elif filename.endswith(".csv"):
        raw = parse_csv_logs(text)
        normalized_events = collect_and_normalize(raw, source_type)
    elif filename.endswith(".log") or filename.endswith(".txt"):
        lines = parse_text_logs(text)
        if source_type == "linux":
            normalized_events = collect_linux_logs(lines)
        elif source_type == "nginx":
            normalized_events = collect_nginx_logs(lines)
        else:
            raw = [{"line": line} for line in lines]
            normalized_events = collect_and_normalize(raw, source_type)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format.")

    events_saved = 0
    for ev_data in normalized_events:
        enriched = enrich_event(db, ev_data)
        db_event = Event(
            timestamp=enriched["timestamp"],
            source_ip=enriched.get("source_ip"),
            destination_ip=enriched.get("destination_ip"),
            username=enriched.get("username"),
            event_type=enriched.get("event_type"),
            action=enriched.get("action"),
            status=enriched.get("status"),
            hostname=enriched.get("hostname"),
            severity=enriched.get("severity", "low"),
            raw_log=enriched.get("raw_log"),
            source_type=enriched.get("source_type", source_type),
        )
        db.add(db_event)
        events_saved += 1

    db.commit()
    alerts = run_detection(db, normalized_events)

    log_action(db, current_user.username, "UPLOAD_LOGS", "system", None,
               f"Uploaded {file.filename}: {events_saved} events, {len(alerts)} alerts", result="success")

    return {
        "filename": file.filename,
        "events_parsed": len(normalized_events),
        "events_saved": events_saved,
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


@router.get("/")
def list_events(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_events")),
):
    events = db.query(Event).order_by(Event.created_at.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source_ip": e.source_ip,
            "username": e.username,
            "event_type": e.event_type,
            "action": e.action,
            "status": e.status,
            "hostname": e.hostname,
            "severity": e.severity.value if e.severity else "low",
            "source_type": e.source_type,
        }
        for e in events
    ]


@router.get("/{event_id}")
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_events")),
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "username": event.username,
        "event_type": event.event_type,
        "action": event.action,
        "status": event.status,
        "hostname": event.hostname,
        "severity": event.severity.value if event.severity else "low",
        "source_type": event.source_type,
        "raw_log": event.raw_log,
    }
