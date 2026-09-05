"""Phase 21 — Metrics API."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.database import get_db
from services.metrics import calculate_metrics
from services.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("/")
def get_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return calculate_metrics(db)
