<div align="center">

# BlueShield SOC

### Security Operations Center — SIEM & SOAR Platform

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-24-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-15%20Passed-brightgreen?style=for-the-badge)](#testing)

A full-featured Security Operations Center platform with real-time log ingestion, detection engine, MITRE ATT&CK mapping, threat intelligence, incident management, and automated SOAR playbooks.

[Features](#features) • [Architecture](#architecture) • [Quick Start](#quick-start) • [API Reference](#api-reference) • [Testing](#testing) • [Project Description](PROJECT_DESCRIPTION.md)

</div>

---

## Overview

BlueShield SOC is an enterprise-grade SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation and Response) platform built for security operations teams. It ingests logs from multiple sources, normalizes them into a unified format, runs detection rules, correlates alerts into incidents, and automates response through playbooks — all with full audit logging and role-based access control.

---

## Features

### Log Collection & Normalization
- **Multi-source ingestion** — Windows Event Logs, Linux auth.log, Nginx/Apache access logs, firewall logs
- **Unified normalization** — All sources converted to a standard event schema
- **File upload** — JSON, CSV, and LOG file support via web interface
- **Real-time parsing** — Events stored and analyzed immediately on upload

### Detection Engine (6 Rules)

| Rule | MITRE ATT&CK | Severity | Description |
|------|-------------|----------|-------------|
| Brute Force | T1110 | HIGH | 5+ failed logins from same IP within 60 seconds |
| Suspicious Authentication | T1078 | HIGH | Failed → Failed → Success pattern from same IP |
| Password Spray | T1110.003 | CRITICAL | 10+ unique usernames targeted from single IP |
| Impossible Login | T1078 | CRITICAL | Same user authenticating from geographically distant locations |
| Suspicious Process | T1059/T1059.001 | MEDIUM–CRITICAL | PowerShell, cmd.exe, wscript.exe with suspicious flags |
| Malware Detection | T1059 | CRITICAL | Malware indicators in process execution |

### MITRE ATT&CK Mapping
Every alert is mapped to the relevant MITRE ATT&CK technique and tactic, enabling structured threat analysis and reporting.

### Risk Scoring
Dynamic risk scoring engine (0–100) based on detection rule severity, event frequency, internal vs. external origin, and threat intelligence matches.

### Threat Intelligence
Simulated IOC database with IP reputation, geo-location, hash and URL reputation checking, and risk enrichment on event ingestion.

### Incident Management
Alert correlation, priority classification (P1–P4), full lifecycle tracking (New → Investigating → Contained → Closed), and timeline view.

### SOAR (Security Orchestration, Automation & Response)

| Playbook | Trigger | Actions |
|----------|---------|---------|
| Brute Force | Brute force alert | Block IP, Disable user, Notify analyst, Isolate host |
| Suspicious IP | Suspicious auth alert | Threat intel, Risk score, Create incident, Simulated block |
| Malware | Malware detection | Extract hash, IOC lookup, Quarantine, Notify IR team |
| Phishing | Phishing alert | Extract URL/domain, Enrichment, URL block simulation |

### Audit Logging
Every analyst action is recorded for full accountability and compliance trail.

### Authentication & RBAC

| Role | Permissions |
|------|------------|
| Admin | Full access — manage users, rules, all operations |
| SOC Analyst | View/investigate alerts, execute playbooks, manage incidents |
| SOC Manager | View alerts, execute playbooks, manage incidents |
| Viewer | Read-only access to dashboard and alerts |

### Analyst Dashboard
Real-time event, alert, and incident counts with severity charts, top rules, top IPs, MITRE technique frequency, and MTTD/MTTR metrics.

---

## Architecture

```
                    LOG SOURCES
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
      Windows         Linux          Nginx
         │              │              │
         └──────────────┼──────────────┘
                        ▼
                  LOG COLLECTOR
                        │
                        ▼
                 NORMALIZATION
                        │
                        ▼
                  EVENT DATABASE
                        │
                        ▼
                DETECTION ENGINE
                        │
                 ┌──────┴──────┐
                 │             │
               NO            MATCH
                 │             │
              Store          ALERT
                               │
                               ▼
                         RISK ENGINE
                               │
                               ▼
                       THREAT INTEL
                               │
                               ▼
                           INCIDENT
                               │
                               ▼
                            SOAR
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
                 Notify      Block     Quarantine
                 Analyst    Simulation Simulation
                               │
                               ▼
                          AUDIT LOG
                               │
                               ▼
                         SOC DASHBOARD
```

### Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11, FastAPI, SQLAlchemy |
| Database | PostgreSQL 16 |
| Cache/Queue | Redis 7 |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Auth | JWT (python-jose), bcrypt |
| Containerization | Docker, Docker Compose |
| Reverse Proxy | Nginx |

---

## Quick Start

### Option 1 — Docker (Recommended)

#### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/) installed
- Git

```bash
# Clone the repository
git clone https://github.com/Muhammadmoizahmed/SIEM-SOAR-Platform.git
cd BlueShield-SOC

# Start all services
docker-compose up -d
```

| Service | URL |
|---------|-----|
| Frontend (UI) | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

---

### Option 2 — Manual Setup (Without Docker)

#### Prerequisites
- [Python 3.11+](https://python.org)
- [PostgreSQL 16](https://postgresql.org)
- [Redis 7+](https://redis.io)

```bash
# Clone the repository
git clone https://github.com/Muhammadmoizahmed/SIEM-SOAR-Platform.git
cd BlueShield-SOC

# Create PostgreSQL database
psql -U postgres -c "CREATE USER blueshield WITH PASSWORD 'blueshield';"
psql -U postgres -c "CREATE DATABASE blueshield_soc OWNER blueshield;"

# Install Python dependencies
pip install -r requirements.txt

# Start the backend
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Access
- **API Docs**: http://localhost:8000/docs
- **UI**: http://localhost:8000/ui

---

### Default Login Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |
| `analyst` | `analyst123` | SOC Analyst |
| `manager` | `manager123` | SOC Manager |
| `viewer` | `viewer123` | Viewer |

---

### Upload Sample Logs

Navigate to **Upload Logs** in the dashboard and upload files from the `sample_logs/` directory:

| File | Description |
|------|-------------|
| `test_bruteforce.json` | 5 failed logins → Brute Force Alert |
| `test_suspicious_auth.json` | Failed + Failed + Success → Suspicious Auth |
| `test_password_spray.json` | 12 usernames → Password Spray |
| `test_impossible_login.json` | Same user, 2 countries → Impossible Login |
| `test_suspicious_process.json` | PowerShell with flags → Malware Alert |
| `test_malware.json` | Suspicious process → Malware Detection |
| `windows.json` | Windows Event Logs |
| `linux.log` | Linux auth.log |
| `nginx.log` | Nginx access logs |
| `firewall.json` | Firewall deny/allow events |

---

## Project Structure

```
BlueShield-SOC/
├── backend/
│   ├── main.py                    # FastAPI application entry point
│   ├── api/
│   │   ├── auth.py                # Authentication endpoints (login, RBAC)
│   │   ├── alerts.py              # Alert CRUD + playbook execution
│   │   ├── incidents.py           # Incident management
│   │   ├── logs.py                # Log upload and event retrieval
│   │   ├── playbooks.py           # SOAR playbook management
│   │   ├── dashboard.py           # Dashboard statistics
│   │   ├── metrics.py             # MTTD/MTTR metrics
│   │   ├── audit_logs.py          # Audit trail
│   │   └── threat_intel.py        # Threat intelligence lookups
│   ├── models/
│   │   ├── user.py                # User model with RBAC roles
│   │   ├── event.py               # Normalized event model
│   │   ├── alert.py               # Alert model with MITRE fields
│   │   ├── incident.py            # Incident model with timeline
│   │   └── audit_log.py           # Audit log model
│   ├── services/
│   │   ├── auth.py                # JWT + password hashing + RBAC
│   │   ├── normalizer.py          # Log normalization (Windows/Linux/Nginx/Firewall)
│   │   ├── collector.py           # Log file parsing
│   │   ├── detector.py            # Detection engine orchestrator
│   │   ├── enrichment.py          # Event enrichment with threat intel
│   │   ├── threat_intel.py        # IOC database and IP reputation
│   │   ├── risk_scoring.py        # Risk scoring engine (0-100)
│   │   ├── incident_service.py    # Incident CRUD and correlation
│   │   ├── audit_service.py       # Audit logging service
│   │   ├── metrics.py             # MTTD/MTTR calculation
│   │   └── soar.py                # SOAR engine with simulated response
│   ├── rules/
│   │   ├── brute_force.py         # T1110 — Brute Force Detection
│   │   ├── suspicious_authentication.py  # T1078 — Suspicious Auth Pattern
│   │   ├── password_spray.py      # T1110.003 — Password Spraying
│   │   ├── impossible_login.py    # T1078 — Impossible Geographic Login
│   │   ├── suspicious_process.py  # T1059 — Suspicious Process Execution
│   │   └── malware.py             # Malware Indicator Detection
│   ├── database/
│   │   └── database.py            # PostgreSQL connection + session
│   └── Dockerfile
├── frontend/
│   └── index.html                 # SPA with login + 8 pages (CSS + JS inline)
├── sample_logs/
│   ├── test_bruteforce.json       # Brute force test data
│   ├── test_suspicious_auth.json  # Suspicious auth test data
│   ├── test_password_spray.json   # Password spray test data
│   ├── test_impossible_login.json # Impossible login test data
│   ├── test_suspicious_process.json # Suspicious process test data
│   ├── test_malware.json          # Malware detection test data
│   ├── windows.json               # Windows Event Logs
│   ├── linux.log                  # Linux auth.log
│   ├── nginx.log                  # Nginx access logs
│   └── firewall.json              # Firewall deny/allow events
├── playbooks/
│   ├── brute_force.json           # Brute Force response playbook
│   ├── suspicious_ip.json         # Suspicious IP response playbook
│   ├── malware.json               # Malware response playbook
│   └── phishing.json              # Phishing response playbook
├── tests/
│   └── test_all.py                # 15 comprehensive test cases
├── docker-compose.yml             # PostgreSQL + Redis + Backend + Frontend
├── nginx.conf                     # Reverse proxy configuration
├── requirements.txt               # Python dependencies
├── pytest.ini                     # Pytest configuration
├── .env                           # Environment variables
├── .gitignore                     # Git exclusions
├── README.md                      # This file
└── PROJECT_DESCRIPTION.md         # Complete file-by-file documentation
```

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login and receive JWT token |
| `GET` | `/api/auth/me` | Get current user profile |
| `POST` | `/api/auth/users` | Create new user (admin only) |
| `GET` | `/api/auth/users` | List all users (admin only) |
| `PUT` | `/api/auth/users/{id}/role` | Update user role (admin only) |

### Logs & Events
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/logs/upload` | Upload and parse log file |
| `GET` | `/api/logs/` | List all events |
| `GET` | `/api/logs/{id}` | Get event details |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts/` | List alerts (filterable by severity, status, rule) |
| `GET` | `/api/alerts/stats` | Alert statistics by severity/status/rule |
| `GET` | `/api/alerts/mitre` | MITRE technique frequency |
| `GET` | `/api/alerts/{id}` | Get alert details |
| `PATCH` | `/api/alerts/{id}` | Update alert status |
| `POST` | `/api/alerts/{id}/respond` | Execute playbook against alert |

### Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/incidents/` | List incidents |
| `GET` | `/api/incidents/stats` | Incident statistics |
| `GET` | `/api/incidents/{id}` | Get incident with timeline |
| `PATCH` | `/api/incidents/{id}` | Update status or assignment |
| `POST` | `/api/incidents/create-from-alerts` | Correlate alerts into incident |

### SOAR Playbooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/playbooks/` | List available playbooks |
| `GET` | `/api/playbooks/{name}` | Get playbook details |
| `POST` | `/api/playbooks/{name}/execute` | Execute playbook on alert |

### Dashboard & Metrics
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/` | Dashboard summary stats |
| `GET` | `/api/metrics/` | MTTD, MTTR, and event statistics |

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/threat-intel/ip/{ip}` | IP reputation and geo lookup |
| `GET` | `/api/threat-intel/hash/{hash}` | Hash reputation check |
| `GET` | `/api/threat-intel/url?url=` | URL reputation check |
| `GET` | `/api/threat-intel/iocs` | IOC summary statistics |

### Audit Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/audit-logs/` | List audit entries (filterable) |
| `GET` | `/api/audit-logs/count` | Total audit log count |
| `GET` | `/api/audit-logs/activity` | Analyst activity breakdown |

---

## Testing

### Run Tests

```bash
# With Docker
docker exec -it blueshield-backend python -m pytest tests/ -v

# Without Docker
cd BlueShield-SOC
pip install -r requirements.txt
python -m pytest tests/ -v
```

### Test Suite (15 Tests)

| # | Test | Description | Expected Result |
|---|------|-------------|-----------------|
| 1 | Brute Force Detection | 5 failed logins from same IP | Brute Force Alert |
| 2 | Threshold Check | 4 failed logins | No alert |
| 3 | Different IPs | 5 failures from different IPs | No brute force alert |
| 4 | Suspicious Auth | Failed + Failed + Success login | Suspicious Authentication |
| 5 | Malware Detection | Malware indicators in process | Malware Alert |
| 6 | Risk Score | Risk score calculation | Correct ranges (0-100) |
| 7 | Normalizer | Event normalization | All fields extracted |
| 8 | Alert ID | Alert ID generation | ALT-XXXXX format |
| 9 | Password Spray | 12 usernames, same IP | Password Spray detected |
| 10 | Impossible Login | Different countries, same user | Impossible Login detected |
| 11 | IOC Lookup | Known malicious IP lookup | High threat score |
| 12 | Audit Log | Audit log creation | Entries recorded |
| 13 | JWT Token | JWT token creation/decode | Valid payload |
| 14 | Password Hashing | Password hashing | bcrypt verify works |
| 15 | RBAC | Role permissions | Correct role access |

---

## Detection Rules Detail

### Brute Force (T1110)
```
Condition: same source_ip + 5 failed logins + within 60 seconds
Severity: HIGH
Response: Block IP simulation, disable user, notify SOC
```

### Suspicious Authentication (T1078)
```
Condition: Failed + Failed + Successful login from same IP within 5 minutes
Severity: HIGH
Response: Threat intel lookup, create incident
```

### Password Spray (T1110.003)
```
Condition: 10+ unique usernames + same source IP + failed authentication
Severity: CRITICAL
Response: Full SOAR playbook execution
```

### Impossible Login (T1078)
```
Condition: Same user authenticating from different countries within seconds
Severity: CRITICAL
Response: Account lockdown simulation
```

### Suspicious Process (T1059)
```
Condition: powershell.exe/cmd.exe/wscript.exe with suspicious flags
Severity: MEDIUM to CRITICAL (based on context)
Response: Host isolation simulation
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Detection Rule |
|-------------|---------------|----------------|
| T1110 | Brute Force | `brute_force` |
| T1110.003 | Password Spraying | `password_spray` |
| T1078 | Valid Accounts | `suspicious_authentication`, `impossible_login` |
| T1059 | Command and Scripting Interpreter | `suspicious_process` |
| T1059.001 | PowerShell | `suspicious_process` |

---

## Risk Scoring

| Score Range | Level | Description |
|------------|-------|-------------|
| 0–20 | Low | Normal activity, no immediate concern |
| 21–50 | Medium | Suspicious activity, monitoring recommended |
| 51–80 | High | Confirmed malicious pattern, investigation required |
| 81–100 | Critical | Active threat, immediate response needed |

**Scoring Factors:**
- Rule type (malware = +50, brute force = +30)
- Severity level (critical = +30, high = +20)
- Event count (50+ events = +20, 20+ = +15)
- External origin = +15

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://blueshield:blueshield@localhost:5432/blueshield_soc` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_SECRET` | `blueshield-soc-secret-key-change-in-production` | JWT signing key |

---

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built for Security Operations Teams**

SIEM • SOAR • MITRE ATT&CK • Threat Intelligence • Incident Response

</div>
