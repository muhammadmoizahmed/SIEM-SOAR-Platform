"""Phase 22 — User Model for Authentication & RBAC."""
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from database.database import Base
import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    soc_analyst = "soc_analyst"
    soc_manager = "soc_manager"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), nullable=False, default=UserRole.viewer)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))


ROLE_PERMISSIONS = {
    "admin": [
        "view_alerts", "investigate_alerts", "resolve_alerts",
        "execute_playbooks", "manage_incidents", "view_events",
        "upload_logs", "manage_users", "view_audit_logs", "view_dashboard",
        "manage_rules", "view_threat_intel",
    ],
    "soc_analyst": [
        "view_alerts", "investigate_alerts", "resolve_alerts",
        "execute_playbooks", "manage_incidents", "view_events",
        "upload_logs", "view_audit_logs", "view_dashboard", "view_threat_intel",
    ],
    "soc_manager": [
        "view_alerts", "investigate_alerts", "resolve_alerts",
        "execute_playbooks", "manage_incidents", "view_events",
        "view_audit_logs", "view_dashboard", "view_threat_intel",
    ],
    "viewer": [
        "view_alerts", "view_events", "view_dashboard", "view_threat_intel",
    ],
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, [])
