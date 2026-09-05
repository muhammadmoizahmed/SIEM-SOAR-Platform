from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from database.database import init_db, init_default_data
from api.auth import router as auth_router
from api.logs import router as logs_router
from api.alerts import router as alerts_router
from api.incidents import router as incidents_router
from api.playbooks import router as playbooks_router
from api.dashboard import router as dashboard_router
from api.threat_intel import router as threat_intel_router
from api.audit_logs import router as audit_logs_router
from api.metrics import router as metrics_router
import os

app = FastAPI(
    title="BlueShield SOC",
    description="Security Operations Center - SIEM + SOAR Platform",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(playbooks_router)
app.include_router(dashboard_router)
app.include_router(threat_intel_router)
app.include_router(audit_logs_router)
app.include_router(metrics_router)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


@app.on_event("startup")
def startup():
    init_db()
    init_default_data()


@app.get("/")
def root():
    return {
        "name": "BlueShield SOC",
        "version": "3.0.0",
        "status": "running",
        "phases": "20-25 Active",
        "endpoints": {
            "auth": "/api/auth/login",
            "dashboard": "/api/dashboard",
            "metrics": "/api/metrics",
            "logs": "/api/logs",
            "alerts": "/api/alerts",
            "incidents": "/api/incidents",
            "playbooks": "/api/playbooks",
            "threat_intel": "/api/threat-intel",
            "audit_logs": "/api/audit-logs",
            "ui": "/ui",
        },
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/ui")
def serve_ui():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "Frontend not found"}
