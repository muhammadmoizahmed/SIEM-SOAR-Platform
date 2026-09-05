# BlueShield SOC — Complete Project Description

## Project Purpose

BlueShield SOC is a **Security Operations Center (SOC) platform** that combines **SIEM** (Security Information and Event Management) and **SOAR** (Security Orchestration, Automation and Response) capabilities. It is designed for security analysts and blue team operations to:

- **Ingest logs** from multiple sources (Windows, Linux, Nginx, Firewall)
- **Detect threats** using rules mapped to MITRE ATT&CK framework
- **Correlate alerts** into incidents for investigation
- **Automate response** through SOAR playbooks
- **Track metrics** (MTTD, MTTR) for SOC performance
- **Maintain audit trails** for compliance

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | Python 3.11, FastAPI | REST API server |
| ORM | SQLAlchemy | Database models and queries |
| Database | PostgreSQL 16 | Persistent data storage |
| Cache | Redis 7 | Session/cache management |
| Auth | JWT (python-jose), bcrypt | Authentication and RBAC |
| Frontend | HTML, CSS, JavaScript | SOC Dashboard UI |
| Container | Docker, Docker Compose | Deployment |
| Reverse Proxy | Nginx | Frontend serving + API proxy |
| Testing | Pytest | Unit tests |

---

## Complete File Structure & Purpose

### Root Level Files

| File | Purpose |
|------|---------|
| `README.md` | Project documentation, setup instructions, API reference |
| `PROJECT_DESCRIPTION.md` | This file — complete project documentation |
| `requirements.txt` | Python dependencies (FastAPI, SQLAlchemy, psycopg2, bcrypt, etc.) |
| `docker-compose.yml` | Defines 4 services: PostgreSQL, Redis, Backend, Frontend |
| `nginx.conf` | Nginx reverse proxy config — serves frontend on port 3000, proxies API to backend |
| `pytest.ini` | Pytest configuration |
| `.env` | Environment variables (DATABASE_URL, REDIS_URL, JWT_SECRET) |
| `.gitignore` | Git exclusions (.env, __pycache__, venv, etc.) |

---

### `backend/` — Application Code

#### `backend/main.py`
**Purpose:** FastAPI application entry point.
- Creates the FastAPI app with CORS middleware
- Includes all 9 API routers (auth, logs, alerts, incidents, playbooks, dashboard, threat_intel, audit_logs, metrics)
- Serves the frontend UI at `/ui` endpoint
- On startup: creates database tables and default users

#### `backend/Dockerfile`
**Purpose:** Docker container configuration for the backend.
- Uses Python 3.11-slim base image
- Installs requirements
- Runs uvicorn server on port 8000

---

### `backend/api/` — REST API Endpoints

#### `backend/api/auth.py`
**Purpose:** Authentication and user management.
- `POST /api/auth/login` — Login with username/password, returns JWT token
- `GET /api/auth/me` — Get current user profile
- `POST /api/auth/users` — Create new user (admin only)
- `GET /api/auth/users` — List all users (admin only)
- `PUT /api/auth/users/{id}/role` — Update user role (admin only)

#### `backend/api/logs.py`
**Purpose:** Log file upload and event retrieval.
- `POST /api/logs/upload` — Upload JSON/CSV/LOG files, normalizes and stores events, runs detection
- `GET /api/logs/` — List all events with pagination
- `GET /api/logs/{id}` — Get single event details

#### `backend/api/alerts.py`
**Purpose:** Alert management and playbook execution.
- `GET /api/alerts/` — List alerts with filters (severity, status, rule, IP, username)
- `GET /api/alerts/stats` — Alert statistics by severity/status/rule
- `GET /api/alerts/mitre` — MITRE technique frequency
- `GET /api/alerts/{id}` — Get alert details
- `PATCH /api/alerts/{id}` — Update alert status
- `PUT /api/alerts/{id}/status` — Update alert status (alternative)
- `POST /api/alerts/{id}/respond` — Execute SOAR playbook on alert

#### `backend/api/incidents.py`
**Purpose:** Incident management and correlation.
- `GET /api/incidents/` — List all incidents
- `GET /api/incidents/stats` — Incident statistics by status/priority
- `GET /api/incidents/{id}` — Get incident with timeline
- `PATCH /api/incidents/{id}` — Update incident status/assignment
- `PUT /api/incidents/{id}/status` — Update incident status
- `PUT /api/incidents/{id}/assign` — Assign incident to analyst
- `POST /api/incidents/create-from-alerts` — Correlate multiple alerts into one incident

#### `backend/api/playbooks.py`
**Purpose:** SOAR playbook management.
- `GET /api/playbooks/` — List available playbooks
- `GET /api/playbooks/{name}` — Get playbook details
- `POST /api/playbooks/{name}/execute` — Execute playbook on alert
- `GET /api/playbooks/audit/log` — Audit log of playbook executions

#### `backend/api/dashboard.py`
**Purpose:** Dashboard summary statistics.
- `GET /api/dashboard/` — Returns total events/alerts/incidents, severity breakdown, top IPs, top rules, MITRE techniques, IOCs count

#### `backend/api/metrics.py`
**Purpose:** SOC performance metrics.
- `GET /api/metrics/` — MTTD (Mean Time To Detect), MTTR (Mean Time To Resolve), event stats, incident stats

#### `backend/api/threat_intel.py`
**Purpose:** Threat intelligence lookups.
- `GET /api/threat-intel/ip/{ip}` — IP reputation, geo-location, risk score
- `GET /api/threat-intel/hash/{hash}` — Hash reputation check
- `GET /api/threat-intel/url?url=` — URL reputation check
- `GET /api/threat-intel/iocs` — IOC summary (total IPs, hashes, URLs tracked)

#### `backend/api/audit_logs.py`
**Purpose:** Audit trail for compliance.
- `GET /api/audit-logs/` — List audit entries with filters
- `GET /api/audit-logs/count` — Total audit log count
- `GET /api/audit-logs/activity` — Analyst activity breakdown

---

### `backend/models/` — Database Models (SQLAlchemy)

#### `backend/models/user.py`
**Purpose:** User model with RBAC roles and permissions.
- **User table:** id, username, email, hashed_password, full_name, role, is_active, created_at, last_login
- **Roles:** admin, soc_analyst, soc_manager, viewer
- **Permissions:** 12 permissions (view_alerts, upload_logs, execute_playbooks, manage_users, etc.)
- `has_permission(role, permission)` — Checks if a role has a specific permission

#### `backend/models/event.py`
**Purpose:** Normalized event model (ingested logs).
- **Event table:** id, timestamp, source_ip, destination_ip, username, event_type, action, status, hostname, severity, raw_log, source_type, created_at
- **Severity enum:** low, medium, high, critical

#### `backend/models/alert.py`
**Purpose:** Alert model (generated by detection rules).
- **Alert table:** id, alert_id (ALT-XXXXX), title, description, severity, status, source_ip, destination_ip, username, hostname, rule_name, mitre_technique, mitre_tactic, risk_score, event_count, first_seen, last_seen, created_at
- **AlertStatus enum:** open, acknowledged, investigating, resolved, false_positive

#### `backend/models/incident.py`
**Purpose:** Incident model (correlated alerts).
- **Incident table:** id, incident_id (INC-XXXXX), title, description, status, priority, severity, assigned_to, source_ip, hostname, username, mitre_technique, risk_score, alert_ids, timeline, created_at, resolved_at
- **IncidentStatus enum:** new, open, triaged, investigating, contained, eradicated, recovered, closed, false_positive
- **IncidentPriority enum:** P1, P2, P3, P4

#### `backend/models/audit_log.py`
**Purpose:** Audit log model for compliance tracking.
- **AuditLog table:** id, timestamp, analyst, action, target_type, target_id, details, ip_address, result

---

### `backend/services/` — Business Logic

#### `backend/services/auth.py`
**Purpose:** JWT authentication, password hashing, RBAC enforcement.
- `hash_password(password)` — bcrypt hash
- `verify_password(plain, hashed)` — bcrypt verify
- `create_access_token(data)` — Create JWT with expiry (8 hours)
- `decode_token(token)` — Decode and validate JWT
- `authenticate_user(db, username, password)` — Login verification
- `create_user(db, username, email, password, role)` — Create new user
- `get_current_user(credentials)` — Extract user from JWT (used in Depends)
- `require_permission(permission)` — RBAC decorator (used in Depends)

#### `backend/services/collector.py`
**Purpose:** Parse uploaded log files into raw events.
- `parse_json_logs(content)` — Parse JSON files
- `parse_csv_logs(content)` — Parse CSV files
- `parse_text_logs(content)` — Parse plain text log files into lines
- `collect_and_normalize(raw_events, source_type)` — Route events to correct normalizer
- `collect_linux_logs(lines)` — Parse Linux auth.log lines
- `collect_nginx_logs(lines)` — Parse Nginx access log lines

#### `backend/services/normalizer.py`
**Purpose:** Convert raw logs from different sources into a unified event schema.
- `normalize_event(raw, source_type)` — Generic normalizer
- `normalize_windows_event(raw)` — Windows Event Log (EventID 4624/4625/4672/4688)
- `normalize_linux_event(line)` — Linux auth.log (Failed password / Accepted)
- `normalize_nginx_event(line)` — Nginx/Apache access log (status codes 401/403/500)
- `normalize_firewall_event(raw)` — Firewall deny/allow events
- `_parse_timestamp(ts)` — Parse multiple timestamp formats
- `_map_severity(sev)` — Map string to Severity enum

#### `backend/services/detector.py`
**Purpose:** Detection engine — runs all rules against incoming events.
- `run_detection(db, events)` — Execute all 6 rules, save alerts, merge duplicates
- `_generate_alert_id(db)` — Generate ALT-XXXXX format IDs
- `get_recent_alerts(db, limit)` — Get recent alerts
- `get_alert_by_id(db, id)` — Get alert by database ID
- `update_alert_status(db, id, status)` — Update alert status
- `get_alert_stats(db)` — Statistics by severity/status/rule
- `get_mitre_techniques(db)` — MITRE technique frequency

#### `backend/services/enrichment.py`
**Purpose:** Enrich events with threat intel and risk scores.
- `enrich_event(db, event)` — Add geo-location, IP reputation, risk score
- `is_internal_ip(ip)` — Check if IP is private (192.168.x, 10.x, 172.16-31.x)

#### `backend/services/threat_intel.py`
**Purpose:** Simulated IOC database and reputation lookups.
- `KNOWN_MALICIOUS_IPS` — 5 known malicious IPs with reputation scores
- `GEO_DATABASE` — Geo-location data for known IPs
- `MALICIOUS_HASHES` — 2 known malicious file hashes
- `SUSPICIOUS_URLS` — 3 known phishing domains
- `lookup_ip_threat_intel(ip)` — IP reputation lookup
- `lookup_geo(ip)` — Geo-location lookup
- `check_hash(hash)` — Hash reputation check
- `check_url(url)` — URL reputation check
- `get_all_iocs()` — IOC summary statistics
- `enrich_ip(ip)` — Combined IP lookup (threat intel + geo + risk)

#### `backend/services/risk_scoring.py`
**Purpose:** Dynamic risk scoring engine (0-100).
- `calculate_alert_risk_score(alert_data)` — Score based on rule type, severity, event count
- `calculate_event_risk_score(event)` — Score based on status, type, origin, severity
- `get_risk_level(score)` — Convert score to level (low/medium/high/critical)

**Scoring Factors:**
| Factor | Points |
|--------|--------|
| Rule type (malware) | +50 |
| Rule type (brute force) | +30 |
| Severity (critical) | +30 |
| Severity (high) | +20 |
| 50+ events | +20 |
| 20+ events | +15 |
| External origin | +15 |

#### `backend/services/incident_service.py`
**Purpose:** Incident CRUD and alert correlation.
- `create_incident_from_alerts(db, alert_ids, title)` — Correlate alerts into incident
- `get_incidents(db, skip, limit)` — List incidents
- `get_incident_by_id(db, id)` — Get incident details
- `update_incident_status(db, id, status)` — Update status, set resolved_at
- `assign_incident(db, id, assigned_to)` — Assign to analyst
- `get_incident_stats(db)` — Statistics by status/priority
- `_generate_incident_id(db)` — Generate INC-XXXXX format IDs
- `_severity_to_priority(severity)` — Map severity to P1-P4

#### `backend/services/soar.py`
**Purpose:** SOAR engine — automated playbook execution.
- `load_playbook(name)` — Load playbook JSON from disk
- `list_playbooks()` — List all available playbooks
- `execute_playbook(db, alert_id, playbook_name, analyst)` — Full playbook execution flow:
  1. Receive alert
  2. Extract source IP
  3. Threat intelligence lookup
  4. Calculate risk score
  5. Create incident
  6. Notify SOC team
  7. Execute playbook actions (block IP, disable user, quarantine, etc.)
- `_execute_action(db, alert, action, ip, analyst)` — Execute individual playbook action
- `_simulate_block_ip(ip)` — Simulated IP block
- `_simulate_disable_user(username)` — Simulated user disable
- `_simulate_isolate_host(host)` — Simulated host isolation
- `_simulate_quarantine(host)` — Simulated quarantine

#### `backend/services/metrics.py`
**Purpose:** SOC performance metrics calculation.
- `calculate_metrics(db)` — Full metrics calculation
- `_calculate_mttd(alerts)` — Mean Time To Detect (first_seen to alert creation)
- `_calculate_mttr(incidents)` — Mean Time To Resolve (incident creation to resolution)
- `_event_stats(db)` — Events by type and source
- `_alert_stats(db)` — Alerts by severity and rule
- `_incident_stats(db)` — Incidents by status and priority
- `_format_duration(seconds)` — Human-readable duration

#### `backend/services/audit_service.py`
**Purpose:** Audit logging for compliance.
- `log_action(db, analyst, action, target_type, target_id, details)` — Create audit entry
- `get_audit_logs(db, analyst, action, target_type, skip, limit)` — Query audit logs
- `get_audit_log_count(db)` — Total count
- `get_analyst_activity(db)` — Activity breakdown per analyst

---

### `backend/rules/` — Detection Rules

#### `backend/rules/brute_force.py`
**Purpose:** Brute Force Detection (MITRE T1110).
- **Condition:** Same source IP + 5+ failed logins + within 60 seconds
- **Severity:** HIGH
- **Response:** Block IP, disable user, notify SOC

#### `backend/rules/suspicious_authentication.py`
**Purpose:** Suspicious Authentication Pattern (MITRE T1078).
- **Condition:** Failed + Failed + Successful login from same IP within 5 minutes
- **Severity:** HIGH
- **Response:** Threat intel lookup, create incident

#### `backend/rules/password_spray.py`
**Purpose:** Password Spray Detection (MITRE T1110.003).
- **Condition:** 10+ unique usernames + same source IP + failed authentication within 10 minutes
- **Severity:** CRITICAL
- **Response:** Full SOAR playbook execution

#### `backend/rules/impossible_login.py`
**Purpose:** Impossible Geographic Login (MITRE T1078).
- **Condition:** Same user authenticating from different countries within 5 minutes
- **Severity:** CRITICAL
- **Response:** Account lockdown simulation

#### `backend/rules/suspicious_process.py`
**Purpose:** Suspicious Process Execution (MITRE T1059/T1059.001).
- **Condition:** powershell.exe, cmd.exe, wscript.exe with suspicious flags (-enc, bypass, etc.)
- **Severity:** MEDIUM to CRITICAL (based on context)
- **Response:** Host isolation simulation

#### `backend/rules/malware.py`
**Purpose:** Malware Indicator Detection.
- **Condition:** Suspicious file extensions (.exe, .bat, .ps1), suspicious paths, malware status
- **Severity:** CRITICAL
- **Response:** Quarantine, notify IR team

---

### `backend/database/` — Database Configuration

#### `backend/database/database.py`
**Purpose:** PostgreSQL connection and session management.
- Loads `.env` file for configuration
- Creates SQLAlchemy engine and session
- `get_db()` — Dependency for FastAPI (yields DB session)
- `init_db()` — Creates all database tables
- `init_default_data()` — Creates 4 default users (admin, analyst, manager, viewer)

---

### `frontend/` — SOC Dashboard UI

#### `frontend/index.html`
**Purpose:** Single-page application with everything inline (HTML + CSS + JS).
- **Login page** — Username/password form
- **Dashboard** — Stats cards, severity chart, top rules, top IPs, MITRE chart, recent alerts
- **Alerts** — Filterable table with Investigate/Respond buttons
- **Incidents** — Status cards, incident table with View button
- **Metrics** — MTTD/MTTR display, event charts
- **Playbooks** — Playbook cards with step-by-step flow
- **Threat Intel** — IOC stats, IP lookup tool
- **Upload Logs** — File upload with drag-and-drop
- **Audit Logs** — Activity trail table
- **Modals** — Alert detail view, Incident detail view with timeline

#### `frontend/styles.css`
**Purpose:** Original CSS file (now inline in index.html).

#### `frontend/app.js`
**Purpose:** Original JS file (now inline in index.html).

---

### `playbooks/` — SOAR Playbook Definitions

#### `playbooks/brute_force.json`
**Purpose:** Automated response for brute force attacks.
- **Actions:** Block IP → Disable user → Notify SOC → Isolate host
- **Escalation:** 30 minutes to SOC lead

#### `playbooks/suspicious_ip.json`
**Purpose:** Response for suspicious IP activity.
- **Actions:** Notify analyst → Block IP (if confirmed)
- **Escalation:** 15 minutes to SOC lead

#### `playbooks/malware.json`
**Purpose:** Automated response for malware detection.
- **Actions:** Isolate host → Notify IR team → Disable user
- **Escalation:** 5 minutes to IR lead (urgent)

#### `playbooks/phishing.json`
**Purpose:** Response for phishing attacks.
- **Actions:** Alert SOC → Disable clicked user
- **Escalation:** 10 minutes to SOC lead

---

### `sample_logs/` — Test Data

#### `sample_logs/windows.json`
**Purpose:** Windows Event Logs for brute force testing.
- 8 events with EventID 4625 (failed login) and 4624 (successful login)
- Tests brute force detection rule

#### `sample_logs/linux.log`
**Purpose:** Linux auth.log for SSH login testing.
- 9 lines with Failed password and Accepted password entries
- Tests Linux log normalization and brute force detection

#### `sample_logs/nginx.log`
**Purpose:** Nginx access logs for web attack testing.
- 9 lines with 401 (unauthorized) and 403 (forbidden) responses
- Tests web brute force detection

#### `sample_logs/firewall.json`
**Purpose:** Firewall deny/allow events.
- 7 events with deny and allow actions
- Tests firewall log normalization

#### `sample_logs/test_bruteforce.json`
**Purpose:** Simple brute force test (5 failed logins from same IP).

#### `sample_logs/test_suspicious_auth.json`
**Purpose:** Suspicious auth test (Failed + Failed + Success).

#### `sample_logs/test_password_spray.json`
**Purpose:** Password spray test (12 different usernames, same IP).

#### `sample_logs/test_impossible_login.json`
**Purpose:** Impossible login test (same user, 2 countries within 30 seconds).

#### `sample_logs/test_suspicious_process.json`
**Purpose:** Suspicious process test (PowerShell with encoded command).

#### `sample_logs/test_malware.json`
**Purpose:** Malware detection test (suspicious process after login).

---

### `tests/` — Test Suite

#### `tests/test_all.py`
**Purpose:** 15 comprehensive test cases covering all detection rules and services.

| Test | What It Tests |
|------|---------------|
| TEST 1 | Brute Force: 5 failed logins → alert generated |
| TEST 2 | Threshold: 4 failures → no alert |
| TEST 3 | Different IPs: no brute force from分散ed IPs |
| TEST 4 | Suspicious Auth: Failed+Failed+Success → alert |
| TEST 5 | Malware: Suspicious process indicators → alert |
| TEST 6 | Risk Score: Correct scoring ranges (0-100) |
| TEST 7 | Normalizer: All fields extracted correctly |
| TEST 8 | Alert ID: ALT-XXXXX format generation |
| TEST 9 | Password Spray: 12 usernames → alert |
| TEST 10 | Impossible Login: Different countries → alert |
| TEST 11 | IOC Lookup: Known malicious IP → high score |
| TEST 12 | Audit Log: Entries recorded correctly |
| TEST 13 | JWT Token: Creation and decode |
| TEST 14 | Password Hashing: bcrypt verify works |
| TEST 15 | RBAC: Correct role permissions |

---

## Data Flow

```
1. USER uploads log file (JSON/CSV/LOG)
         │
2. COLLECTOR parses file into raw events
         │
3. NORMALIZER converts to unified schema
         │
4. ENRICHMENT adds threat intel + geo + risk score
         │
5. EVENTS stored in PostgreSQL
         │
6. DETECTOR runs 6 rules against events
         │
7. ALERTS generated (if rule matches)
         │
8. RISK SCORE calculated (0-100)
         │
9. ALERT stored with MITRE mapping
         │
10. USER investigates alert (View → Status change)
         │
11. SOAR PLAYBOOK executed (Respond button)
         │
12. INCIDENT created from alert
         │
13. ACTIONS simulated (block IP, disable user, etc.)
         │
14. AUDIT LOG recorded for compliance
```

---

## Default Users

| Username | Password | Role | Capabilities |
|----------|----------|------|-------------|
| admin | admin123 | admin | Full access — manage users, rules, all operations |
| analyst | analyst123 | soc_analyst | View/investigate alerts, execute playbooks, upload logs |
| manager | manager123 | soc_manager | View alerts, execute playbooks, manage incidents |
| viewer | viewer123 | viewer | Read-only access to dashboard and alerts |

---

## API Endpoints Summary (20+)

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Auth | `/api/auth/login` | POST | Login |
| Auth | `/api/auth/me` | GET | Current user |
| Auth | `/api/auth/users` | GET/POST | User management |
| Logs | `/api/logs/upload` | POST | Upload log file |
| Logs | `/api/logs/` | GET | List events |
| Alerts | `/api/alerts/` | GET | List alerts |
| Alerts | `/api/alerts/stats` | GET | Alert stats |
| Alerts | `/api/alerts/mitre` | GET | MITRE frequency |
| Alerts | `/api/alerts/{id}/respond` | POST | Run playbook |
| Incidents | `/api/incidents/` | GET | List incidents |
| Incidents | `/api/incidents/stats` | GET | Incident stats |
| Incidents | `/api/incidents/create-from-alerts` | POST | Correlate alerts |
| Playbooks | `/api/playbooks/` | GET | List playbooks |
| Playbooks | `/api/playbooks/{name}/execute` | POST | Execute playbook |
| Dashboard | `/api/dashboard/` | GET | Dashboard data |
| Metrics | `/api/metrics/` | GET | MTTD/MTTR |
| Threat Intel | `/api/threat-intel/ip/{ip}` | GET | IP lookup |
| Threat Intel | `/api/threat-intel/hash/{hash}` | GET | Hash lookup |
| Threat Intel | `/api/threat-intel/url` | GET | URL lookup |
| Threat Intel | `/api/threat-intel/iocs` | GET | IOC summary |
| Audit | `/api/audit-logs/` | GET | Audit trail |
| Audit | `/api/audit-logs/activity` | GET | Analyst activity |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Detection Rule | Tactic |
|-------------|------|----------------|--------|
| T1110 | Brute Force | brute_force | Credential Access |
| T1110.003 | Password Spraying | password_spray | Credential Access |
| T1078 | Valid Accounts | suspicious_authentication, impossible_login | Initial Access |
| T1059 | Command and Scripting Interpreter | suspicious_process | Execution |
| T1059.001 | PowerShell | suspicious_process | Execution |

---

## Deployment

### Docker (Recommended)
```bash
docker-compose up -d
```
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- Swagger Docs: http://localhost:8000/docs
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### Manual (Without Docker)
```bash
pip install -r requirements.txt
# Set environment variables
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
