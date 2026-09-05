import json
import csv
import io
from typing import List
from services.normalizer import (
    normalize_event,
    normalize_windows_event,
    normalize_linux_event,
    normalize_nginx_event,
    normalize_firewall_event,
)


def parse_json_logs(content: str) -> List[dict]:
    """Parse uploaded JSON log file."""
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        return []


def parse_csv_logs(content: str) -> List[dict]:
    """Parse uploaded CSV log file."""
    reader = csv.DictReader(io.StringIO(content))
    return [row for row in reader]


def parse_text_logs(content: str) -> List[str]:
    """Parse plain text log file into lines."""
    return [line.strip() for line in content.splitlines() if line.strip()]


def collect_and_normalize(raw_events: List[dict], source_type: str) -> List[dict]:
    """Normalize raw events based on their source type."""
    normalized = []
    for event in raw_events:
        if source_type == "windows":
            norm = normalize_windows_event(event)
        elif source_type == "firewall":
            norm = normalize_firewall_event(event)
        else:
            norm = normalize_event(event, source_type)
        normalized.append(norm)
    return normalized


def collect_linux_logs(lines: List[str]) -> List[dict]:
    """Parse and normalize raw Linux auth.log lines."""
    normalized = []
    for line in lines:
        norm = normalize_linux_event(line)
        if norm:
            normalized.append(norm)
    return normalized


def collect_nginx_logs(lines: List[str]) -> List[dict]:
    """Parse and normalize raw Nginx access log lines."""
    normalized = []
    for line in lines:
        norm = normalize_nginx_event(line)
        if norm:
            normalized.append(norm)
    return normalized
