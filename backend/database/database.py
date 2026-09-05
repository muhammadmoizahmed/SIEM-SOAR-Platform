import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://blueshield:blueshield@localhost:5432/blueshield_soc"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models.user import User
    from models.event import Event
    from models.alert import Alert
    from models.incident import Incident
    from models.audit_log import AuditLog
    Base.metadata.create_all(bind=engine)


def init_default_data():
    from models.user import User
    from database.database import SessionLocal
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            from services.auth import create_user
            from models.user import UserRole
            create_user(db, "admin", "admin@blueshield.local", "admin123", UserRole.admin, "System Admin")
            create_user(db, "analyst", "analyst@blueshield.local", "analyst123", UserRole.soc_analyst, "SOC Analyst")
            create_user(db, "manager", "manager@blueshield.local", "manager123", UserRole.soc_manager, "SOC Manager")
            create_user(db, "viewer", "viewer@blueshield.local", "viewer123", UserRole.viewer, "Read Only User")
    finally:
        db.close()
