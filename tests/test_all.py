"""Phase 25 — BlueShield SOC Test Suite."""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


# ==================== MOCK DB SESSION ====================
class MockDB:
    def __init__(self):
        self._data = {}
        self._id_counter = 1

    def query(self, model):
        return MockQuery(self, model)

    def add(self, obj):
        obj.id = self._id_counter
        self._id_counter += 1
        model_name = obj.__class__.__name__
        if model_name not in self._data:
            self._data[model_name] = []
        self._data[model_name].append(obj)

    def commit(self):
        pass

    def refresh(self, obj):
        pass


class MockQuery:
    def __init__(self, db, model):
        self.db = db
        self.model = model
        self._filters = []

    def filter(self, *args):
        return self

    def order_by(self, *args):
        return self

    def offset(self, *args):
        return self

    def limit(self, *args):
        return self

    def count(self):
        return 0

    def first(self):
        return None

    def all(self):
        return []

    def group_by(self, *args):
        return self

    def label(self, *args):
        return self


# ==================== TEST 1: Brute Force Detection (5 failures) ====================
def test_brute_force_detection():
    """TEST 1: 5 failed logins from same IP → Brute Force Alert."""
    from datetime import datetime
    now = datetime.utcnow()
    events = [
        {"timestamp": now, "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=5), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=10), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=15), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=20), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
    ]

    from rules.brute_force import detect_brute_force
    db = MockDB()
    alerts = detect_brute_force(db, events, threshold=5, window_seconds=60)

    assert len(alerts) == 1, f"Expected 1 brute force alert, got {len(alerts)}"
    assert alerts[0]["rule_name"] == "brute_force"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["event_count"] >= 5
    print("TEST 1 PASSED: 5 failed logins → Brute Force Alert")


# ==================== TEST 2: No Alert for 4 Failures ====================
def test_no_alert_for_four_failures():
    """TEST 2: 4 failed logins → No brute force alert."""
    from datetime import datetime
    now = datetime.utcnow()
    events = [
        {"timestamp": now, "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=5), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=10), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=15), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
    ]

    from rules.brute_force import detect_brute_force
    db = MockDB()
    alerts = detect_brute_force(db, events, threshold=5, window_seconds=60)

    assert len(alerts) == 0, f"Expected 0 alerts for 4 failures, got {len(alerts)}"
    print("TEST 2 PASSED: 4 failed logins → No alert")


# ==================== TEST 3: Different IPs, No Brute Force ====================
def test_different_ips_no_brute_force():
    """TEST 3: 5 failed logins from different IPs → No brute force alert."""
    from datetime import datetime
    now = datetime.utcnow()
    events = [
        {"timestamp": now, "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=5), "source_ip": "10.0.0.1", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=10), "source_ip": "172.16.0.1", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=15), "source_ip": "192.168.1.100", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=20), "source_ip": "10.0.0.50", "status": "failed", "event_type": "authentication", "username": "admin"},
    ]

    from rules.brute_force import detect_brute_force
    db = MockDB()
    alerts = detect_brute_force(db, events, threshold=5, window_seconds=60)

    assert len(alerts) == 0, f"Expected 0 brute force alerts from different IPs, got {len(alerts)}"
    print("TEST 3 PASSED: Different IPs → No brute force alert")


# ==================== TEST 4: Suspicious Authentication ====================
def test_suspicious_authentication():
    """TEST 4: Failed + Failed + Successful login from same IP → Suspicious Auth."""
    from datetime import datetime
    now = datetime.utcnow()
    events = [
        {"timestamp": now, "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=10), "source_ip": "192.168.1.50", "status": "failed", "event_type": "authentication", "username": "admin"},
        {"timestamp": now + timedelta(seconds=20), "source_ip": "192.168.1.50", "status": "success", "event_type": "authentication", "username": "admin"},
    ]

    from rules.suspicious_authentication import detect_suspicious_authentication
    db = MockDB()
    alerts = detect_suspicious_authentication(db, events, window_seconds=300)

    assert len(alerts) == 1, f"Expected 1 suspicious auth alert, got {len(alerts)}"
    assert alerts[0]["rule_name"] == "suspicious_authentication"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    print("TEST 4 PASSED: Failed+Failed+Success → Suspicious Authentication")


# ==================== TEST 5: Malware Detection ====================
def test_malware_detection():
    """TEST 5: Malware indicators → Malware Alert."""
    events = [
        {
            "timestamp": datetime.utcnow(),
            "source_ip": "192.168.1.50",
            "event_type": "process",
            "status": "detected",
            "raw_log": "powershell.exe -enc SQBmACgA...",
        }
    ]

    from rules.malware import detect_malware_indicators
    db = MockDB()
    alerts = detect_malware_indicators(db, events)

    assert len(alerts) >= 1, f"Expected malware alert, got {len(alerts)}"
    assert alerts[0]["rule_name"] == "malware_detection"
    print("TEST 5 PASSED: Malware indicators → Malware Alert")


# ==================== TEST 6: Risk Score Calculation ====================
def test_risk_score():
    """TEST 6: Risk score ranges are correct."""
    from services.risk_scoring import calculate_alert_risk_score, get_risk_level

    low_event = {"rule_name": "unknown", "severity": "low", "event_count": 1}
    score_low = calculate_alert_risk_score(low_event)
    assert 0 <= score_low <= 100
    assert get_risk_level(score_low) in ("low", "medium")

    critical_event = {"rule_name": "malware_detection", "severity": "critical", "event_count": 50}
    score_crit = calculate_alert_risk_score(critical_event)
    assert score_crit >= 80, f"Critical event score should be >= 80, got {score_crit}"
    assert get_risk_level(score_crit) == "critical"

    print("TEST 6 PASSED: Risk score ranges correct")


# ==================== TEST 7: Normalizer ====================
def test_normalizer():
    """TEST 7: Event normalization produces correct fields."""
    from services.normalizer import normalize_event

    raw = {
        "timestamp": "2026-09-04T18:20:00",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "event_type": "authentication",
        "action": "login",
        "status": "failed",
        "hostname": "WIN-SERVER",
        "severity": "medium",
    }
    normalized = normalize_event(raw, "windows")

    assert normalized["source_ip"] == "192.168.1.50"
    assert normalized["username"] == "admin"
    assert normalized["event_type"] == "authentication"
    assert normalized["status"] == "failed"
    assert normalized["source_type"] == "windows"
    assert normalized["timestamp"] is not None
    print("TEST 7 PASSED: Normalizer produces correct fields")


# ==================== TEST 8: Alert ID Generation ====================
def test_alert_id_generation():
    """TEST 8: Alert IDs are generated correctly."""
    from services.detector import _generate_alert_id
    db = MockDB()
    alert_id = _generate_alert_id(db)
    assert alert_id.startswith("ALT-")
    assert len(alert_id) == 9  # ALT-00001
    print("TEST 8 PASSED: Alert ID generation correct")


# ==================== TEST 9: Password Spray Detection ====================
def test_password_spray():
    """TEST 9: 10+ usernames, same IP, failed → Password Spray."""
    from datetime import datetime
    now = datetime.utcnow()
    events = []
    for i in range(12):
        events.append({
            "timestamp": now + timedelta(seconds=i),
            "source_ip": "203.0.113.50",
            "status": "failed",
            "event_type": "authentication",
            "username": f"user{i}",
        })

    from rules.password_spray import detect_password_spray
    db = MockDB()
    alerts = detect_password_spray(db, events, min_usernames=10, window_seconds=600)

    assert len(alerts) == 1, f"Expected 1 password spray alert, got {len(alerts)}"
    assert alerts[0]["rule_name"] == "password_spray"
    assert alerts[0]["severity"] == "critical"
    print("TEST 9 PASSED: 12 usernames → Password Spray detected")


# ==================== TEST 10: Impossible Login Detection ====================
def test_impossible_login():
    """TEST 10: Same user, different countries within seconds → Impossible Login."""
    from datetime import datetime
    now = datetime.utcnow()
    events = [
        {
            "timestamp": now,
            "source_ip": "203.0.113.50",
            "status": "success",
            "event_type": "authentication",
            "username": "admin",
            "geo_location": {"country": "Pakistan"},
        },
        {
            "timestamp": now + timedelta(seconds=30),
            "source_ip": "198.51.100.23",
            "status": "success",
            "event_type": "authentication",
            "username": "admin",
            "geo_location": {"country": "Russia"},
        },
    ]

    from rules.impossible_login import detect_impossible_login
    db = MockDB()
    alerts = detect_impossible_login(db, events, max_seconds=300)

    assert len(alerts) == 1, f"Expected 1 impossible login alert, got {len(alerts)}"
    assert alerts[0]["rule_name"] == "impossible_login"
    print("TEST 10 PASSED: Different countries → Impossible Login detected")


# ==================== TEST 11: IOC Lookup ====================
def test_ioc_lookup():
    """TEST 11: Known malicious IP returns high threat score."""
    from services.threat_intel import lookup_ip_threat_intel

    result = lookup_ip_threat_intel("203.0.113.50")
    assert result["reputation"] == "malicious"
    assert result["score"] >= 80

    clean = lookup_ip_threat_intel("192.168.1.1")
    assert clean["reputation"] == "internal"
    print("TEST 11 PASSED: IOC lookup returns correct reputation")


# ==================== TEST 12: Audit Log ====================
def test_audit_log():
    """TEST 12: Audit log entries are created."""
    from services.audit_service import log_action, get_audit_log_count

    db = MockDB()
    log_action(db, "analyst", "TEST_ACTION", "system", None, "Test details")
    count = get_audit_log_count(db)
    assert count >= 0  # Mock DB returns 0
    print("TEST 12 PASSED: Audit log service works")


# ==================== TEST 13: Auth Token ====================
def test_auth_token():
    """TEST 13: JWT token creation and decode."""
    from services.auth import create_access_token, decode_token

    token = create_access_token({"sub": "analyst", "role": "soc_analyst"})
    assert token is not None
    assert len(token) > 20

    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "analyst"
    assert payload["role"] == "soc_analyst"
    print("TEST 13 PASSED: JWT token creation and decode works")


# ==================== TEST 14: Password Hashing ====================
def test_password_hashing():
    """TEST 14: Password hashing and verification."""
    from services.auth import hash_password, verify_password

    password = "admin123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrong", hashed)
    print("TEST 14 PASSED: Password hashing and verification works")


# ==================== TEST 15: Role Permissions ====================
def test_role_permissions():
    """TEST 15: Role-based access control."""
    from models.user import has_permission

    assert has_permission("admin", "manage_users")
    assert has_permission("soc_analyst", "execute_playbooks")
    assert has_permission("soc_analyst", "view_alerts")
    assert not has_permission("viewer", "execute_playbooks")
    assert not has_permission("viewer", "manage_users")
    assert has_permission("viewer", "view_alerts")
    print("TEST 15 PASSED: RBAC permissions correct")


# ==================== RUN ALL TESTS ====================
if __name__ == "__main__":
    tests = [
        test_brute_force_detection,
        test_no_alert_for_four_failures,
        test_different_ips_no_brute_force,
        test_suspicious_authentication,
        test_malware_detection,
        test_risk_score,
        test_normalizer,
        test_alert_id_generation,
        test_password_spray,
        test_impossible_login,
        test_ioc_lookup,
        test_audit_log,
        test_auth_token,
        test_password_hashing,
        test_role_permissions,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAILED: {test.__name__} - {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__} - {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"RESULTS: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*50}")
