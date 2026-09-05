from datetime import datetime
from typing import Optional
from models.event import Event, Severity


def normalize_event(raw_event: dict, source_type: str) -> dict:
    """Convert raw log events from any source into a normalized event format."""
    normalized = {
        "timestamp": _parse_timestamp(raw_event.get("timestamp")),
        "source_ip": raw_event.get("source_ip") or raw_event.get("src_ip"),
        "destination_ip": raw_event.get("destination_ip") or raw_event.get("dest_ip"),
        "username": raw_event.get("username") or raw_event.get("user"),
        "event_type": raw_event.get("event_type") or raw_event.get("type"),
        "action": raw_event.get("action"),
        "status": raw_event.get("status"),
        "hostname": raw_event.get("hostname") or raw_event.get("host"),
        "severity": _map_severity(raw_event.get("severity", "low")),
        "source_type": source_type,
        "raw_log": str(raw_event),
    }
    return normalized


def normalize_windows_event(raw_event: dict) -> dict:
    """Normalize Windows Event Log (JSON format from EVTX export)."""
    event_id = raw_event.get("EventID") or raw_event.get("event_id")
    event_type_map = {
        4624: ("authentication", "login", "success"),
        4625: ("authentication", "login", "failed"),
        4672: ("privilege_escalation", "assign_token", "success"),
        4688: ("process", "create", "success"),
    }
    event_type, action, status = event_type_map.get(
        event_id, ("unknown", "unknown", "unknown")
    )
    data = raw_event.get("EventData", {})
    return {
        "timestamp": _parse_timestamp(raw_event.get("TimeCreated") or raw_event.get("timestamp")),
        "source_ip": data.get("IpAddress"),
        "destination_ip": None,
        "username": data.get("TargetUserName") or data.get("SubjectUserName"),
        "event_type": event_type,
        "action": action,
        "status": status,
        "hostname": raw_event.get("Computer") or raw_event.get("hostname"),
        "severity": Severity.high if event_id == 4625 else Severity.medium,
        "source_type": "windows",
        "raw_log": str(raw_event),
    }


def normalize_linux_event(raw_line: str) -> Optional[dict]:
    """Normalize a single line from /var/log/auth.log."""
    import re
    pattern = r"^(?P<timestamp>\w+ \d+ [\d:]+) (?P<hostname>\S+) (?P<service>\S+): (?P<message>.+)$"
    match = re.match(pattern, raw_line)
    if not match:
        return None

    groups = match.groupdict()
    message = groups["message"]

    status = "failed"
    username = None
    source_ip = None

    if "Failed password" in message:
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", message)
        user_match = re.search(r"for (?:invalid user )?(\S+)", message)
        source_ip = ip_match.group(1) if ip_match else None
        username = user_match.group(1) if user_match else None
        status = "failed"
    elif "Accepted" in message:
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", message)
        user_match = re.search(r"for (\S+)", message)
        source_ip = ip_match.group(1) if ip_match else None
        username = user_match.group(1) if user_match else None
        status = "success"

    return {
        "timestamp": _parse_timestamp(groups["timestamp"]),
        "source_ip": source_ip,
        "destination_ip": None,
        "username": username,
        "event_type": "authentication",
        "action": "login",
        "status": status,
        "hostname": groups["hostname"],
        "severity": Severity.high if status == "failed" else Severity.low,
        "source_type": "linux",
        "raw_log": raw_line,
    }


def normalize_nginx_event(raw_line: str) -> Optional[dict]:
    """Normalize a single Nginx/Apache access log line."""
    import re
    pattern = r'(?P<source_ip>\S+) - (?P<username>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status_code>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    match = re.match(pattern, raw_line)
    if not match:
        return None

    groups = match.groupdict()
    status_code = int(groups["status_code"])
    status = "success" if status_code < 400 else "failed"
    event_type = "web_request"
    action = groups["method"]

    if status_code == 401 or status_code == 403:
        event_type = "authentication"
        action = "web_login"
        status = "failed"
    elif status_code >= 500:
        event_type = "server_error"

    return {
        "timestamp": _parse_timestamp(groups["timestamp"]),
        "source_ip": groups["source_ip"],
        "destination_ip": None,
        "username": groups["username"] if groups["username"] != "-" else None,
        "event_type": event_type,
        "action": action,
        "status": status,
        "hostname": None,
        "severity": Severity.medium if status_code >= 400 else Severity.low,
        "source_type": "nginx",
        "raw_log": raw_line,
    }


def normalize_firewall_event(raw_event: dict) -> dict:
    """Normalize firewall log event."""
    action = raw_event.get("action", "unknown")
    return {
        "timestamp": _parse_timestamp(raw_event.get("timestamp")),
        "source_ip": raw_event.get("src_ip") or raw_event.get("source_ip"),
        "destination_ip": raw_event.get("dest_ip") or raw_event.get("destination_ip"),
        "username": raw_event.get("username"),
        "event_type": "firewall",
        "action": action,
        "status": "blocked" if action.lower() in ("deny", "drop", "block") else "allowed",
        "hostname": raw_event.get("hostname"),
        "severity": Severity.high if action.lower() in ("deny", "drop", "block") else Severity.low,
        "source_type": "firewall",
        "raw_log": str(raw_event),
    }


def _parse_timestamp(ts_value) -> Optional[datetime]:
    if ts_value is None:
        return datetime.utcnow()
    if isinstance(ts_value, datetime):
        return ts_value
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(str(ts_value), fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _map_severity(sev) -> Severity:
    mapping = {
        "low": Severity.low,
        "medium": Severity.medium,
        "high": Severity.high,
        "critical": Severity.critical,
    }
    return mapping.get(str(sev).lower(), Severity.low)
