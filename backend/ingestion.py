"""
AuthGuard-X — Security Event Ingestion & Normalization Engine (Sprint 4)

Provides local-first log parsing, multi-format normalization, deterministic deduplication,
input validation, CSV formula injection defense, and realistic training telemetry ingestion.

Supported Formats:
1. Canonical CSV (Headers: timestamp, ip, attack, risk, username, dest_ip, hostname, outcome, behavior)
2. NDJSON (Newline-delimited JSON security event objects)
3. Windows Security Event Log (EventID 4624/4625 JSON structures)
4. Linux SSH Auth Logs (Syslog auth.log format: Failed/Accepted password/publickey)
5. Zeek Connection Logs (conn.log in JSON format: id.orig_h, id.resp_h, conn_state, service, etc.)
"""

import csv
import io
import json
import re
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_RECORDS_PER_BATCH = 5000

# Formula injection prefixes
CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')

# Syslog month mapping
MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# Linux SSH regex patterns
LINUX_SSH_PATTERNS = [
    # Failed password for invalid user <user> from <ip> port <port> ssh2
    # Failed password for <user> from <ip> port <port> ssh2
    re.compile(
        r'^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+'
        r'(?:(?P<hostname>\S+)\s+)?'
        r'sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    ),
    # Accepted password/publickey for <user> from <ip> port <port> ssh2
    re.compile(
        r'^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+'
        r'(?:(?P<hostname>\S+)\s+)?'
        r'sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    ),
    # Invalid user <user> from <ip> port <port>
    re.compile(
        r'^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+'
        r'(?:(?P<hostname>\S+)\s+)?'
        r'sshd\[\d+\]:\s+Invalid user (?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    ),
    # Connection closed by authenticating user <user> <ip> port <port>
    re.compile(
        r'^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+'
        r'(?:(?P<hostname>\S+)\s+)?'
        r'sshd\[\d+\]:\s+Connection closed by (?:authenticating user\s+)?(?P<username>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    )
]


def sanitize_csv_formula(value: Any) -> str:
    """Prepend single-quote to prevent CSV formula injection if value starts with =, +, -, @, \\t, \\r."""
    if value is None:
        return ""
    str_val = str(value)
    if str_val.startswith(CSV_FORMULA_PREFIXES):
        return "'" + str_val
    return str_val


def is_valid_ip(ip_str: str) -> bool:
    """Validate IPv4 or IPv6 address string."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.strip()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def normalize_timestamp(raw_time: Any, reference_year: Optional[int] = None) -> str:
    """
    Normalizes various timestamp formats into UTC format string 'YYYY-MM-DD HH:MM:SS'.
    Supports:
    - ISO 8601 strings (with or without 'T', 'Z', timezone offsets)
    - Syslog month-day strings (e.g., 'Oct 25 10:14:02')
    - Unix epoch integer/float (seconds or milliseconds)
    """
    if raw_time is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Numeric Unix timestamps (epoch)
    if isinstance(raw_time, (int, float)):
        # If milliseconds (greater than year 2100 in seconds: 4102444800)
        if raw_time > 4102444800:
            raw_time = raw_time / 1000.0
        dt = datetime.fromtimestamp(raw_time, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    s = str(raw_time).strip()
    if not s:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # If numeric string
    try:
        num = float(s)
        if num > 4102444800:
            num = num / 1000.0
        dt = datetime.fromtimestamp(num, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    # Try ISO formats
    # Standard: 2026-10-25 10:00:00 or 2026-10-25T10:00:00Z
    iso_clean = s.replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S"
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    try:
        dt = datetime.fromisoformat(iso_clean)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    # Syslog format: Oct 25 10:14:02 or Oct  5 10:14:02
    syslog_match = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$', s)
    if syslog_match:
        month_str, day_str, time_str = syslog_match.groups()
        month = MONTH_MAP.get(month_str, 1)
        day = int(day_str)
        year = reference_year or datetime.now(timezone.utc).year
        return f"{year:04d}-{month:02d}-{day:02d} {time_str}"

    # Fallback to current UTC time if unparseable
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def calculate_fingerprint(
    source_type: str,
    event_time: str,
    source_ip: str,
    dest_ip: Optional[str],
    username: Optional[str],
    attack_type: str,
    outcome: str
) -> str:
    """Calculates SHA-256 fingerprint for deterministic event deduplication."""
    key = f"{source_type}|{event_time}|{source_ip.strip()}|{(dest_ip or '').strip()}|{(username or '').strip()}|{attack_type.strip()}|{outcome.strip()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def map_risk_severity(risk: int) -> str:
    """Derive severity from 0-100 risk score."""
    if risk >= 80:
        return "critical"
    elif risk >= 60:
        return "high"
    elif risk >= 40:
        return "medium"
    elif risk >= 20:
        return "low"
    return "info"


def map_severity_risk(severity: str) -> int:
    """Derive risk score from severity string."""
    s = (severity or "").lower().strip()
    if s == "critical":
        return 90
    elif s == "high":
        return 75
    elif s == "medium":
        return 50
    elif s == "low":
        return 25
    return 10


def normalize_outcome(raw_outcome: Any) -> str:
    """Normalize raw outcome string/code to 'success', 'failure', 'blocked', or 'unknown'."""
    if raw_outcome is None:
        return "unknown"
    s = str(raw_outcome).lower().strip()
    if s in ("success", "successful", "ok", "allow", "allowed", "permit", "accepted", "4624", "sf"):
        return "success"
    if s in ("failure", "fail", "failed", "denied", "reject", "rejected", "4625", "rej", "rsto", "rstos0"):
        return "failure"
    if s in ("blocked", "block", "drop", "dropped", "s0"):
        return "blocked"
    return "unknown"


def detect_format(content: str, filename: str = "") -> str:
    """Auto-detect log format based on filename and content heuristics."""
    clean = content.strip()
    fname = (filename or "").lower()

    if fname.endswith(".csv"):
        return "canonical_csv"

    # Check if lines have sshd[
    if "sshd[" in clean:
        return "linux_ssh"

    # Check if JSON or NDJSON
    if clean.startswith(("[", "{")):
        # Check if Windows Event (contains 4624, 4625, EventID, SystemTime)
        if '"EventID"' in clean or '"4624"' in clean or '"4625"' in clean or '"TargetUserName"' in clean:
            return "windows_event"
        # Check if Zeek conn log (contains id.orig_h, conn_state, resp_h)
        if '"id.orig_h"' in clean or '"conn_state"' in clean or '"resp_h"' in clean:
            return "zeek_conn"
        # Check if NDJSON or standard JSON array
        first_line = clean.splitlines()[0].strip()
        if first_line.startswith("{") and not clean.startswith("["):
            return "ndjson"
        return "ndjson"

    # CSV header check
    first_line = clean.splitlines()[0] if clean.splitlines() else ""
    if "," in first_line and any(h in first_line.lower() for h in ("ip", "time", "attack", "risk", "user")):
        return "canonical_csv"

    return "canonical_csv"


class IngestionParser:
    """Parses and normalizes security logs from different structured formats."""

    @staticmethod
    def parse_canonical_csv(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse Canonical CSV format with flexible headers."""
        records = []
        errors = []
        reader = csv.DictReader(io.StringIO(content))

        # Check for empty or missing headers
        if not reader.fieldnames:
            return [], [{"record_index": 0, "error": "CSV is missing header row"}]

        # Standardize header lookup map
        field_map = {f.lower().strip(): f for f in reader.fieldnames}

        def get_col(row, *aliases, default=""):
            for a in aliases:
                k = a.lower().strip()
                if k in field_map:
                    val = row.get(field_map[k])
                    if val is not None and str(val).strip() != "":
                        return str(val).strip()
            return default

        for idx, row in enumerate(reader, start=1):
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            # Skip empty lines
            if not any(row.values()):
                continue

            ip = get_col(row, "source_ip", "ip", "src_ip", "orig_h")
            if not ip or not is_valid_ip(ip):
                errors.append({"record_index": idx, "error": f"Invalid or missing source IP address: '{ip}'"})
                continue

            raw_time = get_col(row, "timestamp", "time", "event_time", "datetime")
            event_time = normalize_timestamp(raw_time)

            attack = get_col(row, "attack", "attack_type", "event_type", "category", "signature", default="Security Event")
            category = get_col(row, "category", default="Authentication" if "auth" in attack.lower() or "login" in attack.lower() else "Security Telemetry")
            username = get_col(row, "username", "user", "target_user", "account", default="unknown")
            dest_ip = get_col(row, "dest_ip", "dst_ip", "resp_h", default="")
            hostname = get_col(row, "hostname", "host", "computer", default="sec-host")
            outcome = normalize_outcome(get_col(row, "outcome", "status", "result", default="unknown"))

            # Derive risk score and severity
            risk_raw = get_col(row, "risk", "risk_score", "score")
            severity_raw = get_col(row, "severity", "level")
            if risk_raw:
                try:
                    risk = max(0, min(100, int(risk_raw)))
                except ValueError:
                    risk = map_severity_risk(severity_raw)
            else:
                risk = map_severity_risk(severity_raw)
            severity = map_risk_severity(risk)

            behavior = get_col(row, "behavior", "details", "desc", default=f"{attack} from {ip}")

            record = {
                "source_type": "canonical_csv",
                "event_time": event_time,
                "category": category,
                "attack_type": attack,
                "username": username,
                "source_ip": ip,
                "dest_ip": dest_ip or None,
                "hostname": hostname,
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_record_ref": f"line_{idx}",
                "metadata": {k: v for k, v in row.items() if v}
            }
            records.append(record)

        return records, errors

    @staticmethod
    def parse_ndjson(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse NDJSON (newline-delimited JSON) format or standard JSON array."""
        records = []
        errors = []
        clean = content.strip()

        # Handle full JSON array
        if clean.startswith("[") and clean.endswith("]"):
            try:
                items = json.loads(clean)
                lines = [(i + 1, item) for i, item in enumerate(items)]
            except Exception as e:
                return [], [{"record_index": 0, "error": f"Invalid JSON array: {str(e)}"}]
        else:
            raw_lines = clean.splitlines()
            lines = []
            for idx, line in enumerate(raw_lines, start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    lines.append((idx, json.loads(line_str)))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed JSON: {str(e)}", "raw": line_str[:60]})

        for idx, item in lines:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            if not isinstance(item, dict):
                errors.append({"record_index": idx, "error": "Record is not a JSON object"})
                continue

            ip = item.get("source_ip") or item.get("ip") or item.get("src_ip") or item.get("client_ip")
            if not ip or not is_valid_ip(str(ip)):
                errors.append({"record_index": idx, "error": f"Invalid or missing source IP address: '{ip}'"})
                continue

            event_time = normalize_timestamp(item.get("timestamp") or item.get("time") or item.get("event_time"))
            attack = str(item.get("attack") or item.get("attack_type") or item.get("event_type") or "Security Alert")
            category = str(item.get("category") or "Security Telemetry")
            username = str(item.get("username") or item.get("user") or "unknown")
            dest_ip = str(item.get("dest_ip") or item.get("dst_ip") or "")
            hostname = str(item.get("hostname") or item.get("host") or "sec-host")
            outcome = normalize_outcome(item.get("outcome") or item.get("status"))

            risk_val = item.get("risk") or item.get("risk_score")
            severity_val = item.get("severity")
            try:
                risk = max(0, min(100, int(risk_val))) if risk_val is not None else map_severity_risk(severity_val)
            except (ValueError, TypeError):
                risk = map_severity_risk(severity_val)
            severity = map_risk_severity(risk)

            behavior = str(item.get("behavior") or item.get("details") or f"{attack} observed")

            records.append({
                "source_type": "ndjson",
                "event_time": event_time,
                "category": category,
                "attack_type": attack,
                "username": username,
                "source_ip": str(ip).strip(),
                "dest_ip": dest_ip.strip() if dest_ip else None,
                "hostname": hostname.strip(),
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_record_ref": f"line_{idx}",
                "metadata": item
            })

        return records, errors

    @staticmethod
    def parse_windows_event(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse Windows Security Event Log (JSON or NDJSON) for Event IDs 4624 & 4625.
        Extracts EventID, SystemTime, Computer, TargetUserName, IpAddress, LogonType, SubStatus.
        """
        records = []
        errors = []
        clean = content.strip()

        # Parse either JSON array, single JSON, or NDJSON
        items = []
        if clean.startswith("[") and clean.endswith("]"):
            try:
                items = [(i + 1, item) for i, item in enumerate(json.loads(clean))]
            except Exception as e:
                return [], [{"record_index": 0, "error": f"Invalid Windows JSON: {str(e)}"}]
        elif clean.startswith("{") and clean.endswith("}") and "\n{" not in clean:
            try:
                items = [(1, json.loads(clean))]
            except Exception as e:
                return [], [{"record_index": 1, "error": f"Invalid Windows JSON: {str(e)}"}]
        else:
            for idx, line in enumerate(clean.splitlines(), start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    items.append((idx, json.loads(line_str)))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed Windows event JSON: {str(e)}"})

        for idx, obj in items:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            # Handle wrapped Event structure: {"Event": {"System": {...}, "EventData": {...}}} or flat
            event_obj = obj.get("Event", obj)
            system = event_obj.get("System", {})
            event_data = event_obj.get("EventData", {})

            event_id = str(system.get("EventID", event_obj.get("EventID", "")))
            if not event_id:
                # Try finding event_id in event_data
                event_id = str(event_data.get("EventID", ""))

            if event_id not in ("4624", "4625"):
                errors.append({"record_index": idx, "error": f"Unsupported Windows EventID '{event_id}'. Only 4624 (Success) and 4625 (Failure) are supported."})
                continue

            # Extract SystemTime
            time_created = system.get("TimeCreated", {})
            if isinstance(time_created, dict):
                raw_time = time_created.get("@SystemTime") or time_created.get("SystemTime")
            else:
                raw_time = time_created or event_obj.get("TimeCreated") or event_obj.get("timestamp")
            event_time = normalize_timestamp(raw_time)

            # Computer/Hostname
            hostname = system.get("Computer") or event_obj.get("Computer") or "WIN-SRV-DC01"

            # Target user
            username = event_data.get("TargetUserName") or event_obj.get("TargetUserName") or event_obj.get("username") or "SYSTEM"

            # IP Address
            ip = event_data.get("IpAddress") or event_obj.get("IpAddress") or event_obj.get("source_ip")
            if not ip or ip in ("-", "127.0.0.1", "::1", ""):
                # If local or absent, assign standard local gateway or computer IP
                ip = "10.0.0.15"

            if not is_valid_ip(str(ip)):
                errors.append({"record_index": idx, "error": f"Invalid IP address in Windows event: '{ip}'"})
                continue

            logon_type = event_data.get("LogonType") or event_obj.get("LogonType") or "3"
            sub_status = event_data.get("SubStatus") or event_obj.get("SubStatus") or ""

            if event_id == "4625":
                outcome = "failure"
                attack = "Logon Failure (Windows 4625)"
                risk = 80
                severity = "high"
                behavior = f"Failed logon for {username} via LogonType {logon_type} (SubStatus: {sub_status or '0xC000006A'})"
            else:  # 4624
                outcome = "success"
                attack = "Logon Success (Windows 4624)"
                risk = 15
                severity = "low"
                behavior = f"Successful logon for {username} via LogonType {logon_type}"

            records.append({
                "source_type": "windows_event",
                "event_time": event_time,
                "category": "Authentication",
                "attack_type": attack,
                "username": username,
                "source_ip": str(ip).strip(),
                "dest_ip": "10.0.0.1",
                "hostname": str(hostname).strip(),
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_record_ref": f"EventID_{event_id}_line_{idx}",
                "metadata": {
                    "EventID": event_id,
                    "LogonType": logon_type,
                    "SubStatus": sub_status,
                    "TargetDomainName": event_data.get("TargetDomainName", "CORP"),
                    "WorkstationName": event_data.get("WorkstationName", hostname)
                }
            })

        return records, errors

    @staticmethod
    def parse_linux_ssh(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse Linux SSH authentication logs (syslog auth.log format).
        Extracts timestamp, host, username, source IP, port, and authentication outcome.
        """
        records = []
        errors = []
        lines = content.strip().splitlines()

        for idx, line in enumerate(lines, start=1):
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            matched = False
            for pattern in LINUX_SSH_PATTERNS:
                m = pattern.search(clean_line)
                if m:
                    matched = True
                    gd = m.groupdict()
                    raw_time = gd.get("timestamp")
                    event_time = normalize_timestamp(raw_time)
                    hostname = gd.get("hostname") or "linux-bastion"
                    username = gd.get("username") or "root"
                    ip = gd.get("ip")

                    if not ip or not is_valid_ip(ip):
                        errors.append({"record_index": idx, "error": f"Invalid IP in SSH log: '{ip}'"})
                        break

                    port = gd.get("port") or "22"
                    lower_line = clean_line.lower()

                    if "failed password" in lower_line or "invalid user" in lower_line:
                        outcome = "failure"
                        attack = "SSH Brute Force Attempt"
                        risk = 75
                        severity = "high"
                        behavior = f"SSH authentication failure for user {username} from port {port}"
                    elif "accepted" in lower_line:
                        outcome = "success"
                        attack = "SSH Logon Success"
                        risk = 20
                        severity = "low"
                        behavior = f"SSH session established for {username} from port {port}"
                    else:
                        outcome = "blocked"
                        attack = "SSH Connection Closed"
                        risk = 40
                        severity = "medium"
                        behavior = f"SSH connection terminated during authentication for {username}"

                    records.append({
                        "source_type": "linux_ssh",
                        "event_time": event_time,
                        "category": "Authentication",
                        "attack_type": attack,
                        "username": username,
                        "source_ip": ip,
                        "dest_ip": "192.168.1.10",
                        "hostname": hostname,
                        "outcome": outcome,
                        "severity": severity,
                        "risk_score": risk,
                        "behavior": behavior,
                        "source_record_ref": f"syslog_line_{idx}",
                        "metadata": {
                            "port": port,
                            "raw_message": clean_line
                        }
                    })
                    break

            if not matched and "sshd" in clean_line:
                errors.append({"record_index": idx, "error": "Unrecognized SSH syslog event structure", "raw": clean_line[:60]})

        return records, errors

    @staticmethod
    def parse_zeek_conn(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse Zeek connection logs (conn.log in JSON format).
        Extracts ts, id.orig_h, id.resp_h, id.resp_p, proto, service, conn_state, duration.
        """
        records = []
        errors = []
        clean = content.strip()

        items = []
        if clean.startswith("[") and clean.endswith("]"):
            try:
                items = [(i + 1, item) for i, item in enumerate(json.loads(clean))]
            except Exception as e:
                return [], [{"record_index": 0, "error": f"Invalid Zeek JSON array: {str(e)}"}]
        else:
            for idx, line in enumerate(clean.splitlines(), start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    items.append((idx, json.loads(line_str)))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed Zeek JSON: {str(e)}"})

        for idx, obj in items:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            if not isinstance(obj, dict):
                errors.append({"record_index": idx, "error": "Zeek record is not an object"})
                continue

            # Zeek id struct or flat
            id_struct = obj.get("id", {})
            orig_h = id_struct.get("orig_h") or obj.get("id.orig_h") or obj.get("orig_h")
            resp_h = id_struct.get("resp_h") or obj.get("id.resp_h") or obj.get("resp_h")
            resp_p = id_struct.get("resp_p") or obj.get("id.resp_p") or obj.get("resp_p")

            if not orig_h or not is_valid_ip(str(orig_h)):
                errors.append({"record_index": idx, "error": f"Invalid source IP in Zeek log: '{orig_h}'"})
                continue

            raw_time = obj.get("ts") or obj.get("timestamp")
            event_time = normalize_timestamp(raw_time)

            proto = str(obj.get("proto") or "tcp").lower()
            service = str(obj.get("service") or "-").lower()
            conn_state = str(obj.get("conn_state") or "SF").upper()

            # Analyze connection state
            # S0: Connection attempt seen, no reply (e.g. port scan)
            # REJ: Connection attempt rejected
            # SF: Normal establishment and termination
            if conn_state in ("S0", "S1", "RSTOS0"):
                outcome = "blocked"
                attack = "Port Scan / Recon Probe (Zeek S0)"
                risk = 65
                severity = "high"
                behavior = f"Incomplete {proto} handshake to port {resp_p} (State: {conn_state})"
            elif conn_state in ("REJ", "RSTR"):
                outcome = "failure"
                attack = "Connection Rejected (Zeek REJ)"
                risk = 50
                severity = "medium"
                behavior = f"Connection to {resp_h}:{resp_p} rejected by host"
            else:
                outcome = "success"
                attack = f"Zeek Established Connection ({service if service != '-' else proto})"
                risk = 15
                severity = "info"
                behavior = f"Completed {proto} flow ({conn_state}) with {resp_h}:{resp_p}"

            records.append({
                "source_type": "zeek_conn",
                "event_time": event_time,
                "category": "Network Connection",
                "attack_type": attack,
                "username": "network_flow",
                "source_ip": str(orig_h).strip(),
                "dest_ip": str(resp_h).strip() if resp_h else None,
                "hostname": f"zeek-sensor-01",
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_record_ref": f"zeek_conn_line_{idx}",
                "metadata": {
                    "proto": proto,
                    "service": service,
                    "conn_state": conn_state,
                    "resp_p": resp_p,
                    "orig_bytes": obj.get("orig_bytes", 0),
                    "resp_bytes": obj.get("resp_bytes", 0)
                }
            })

        return records, errors

    @classmethod
    def parse_content(cls, content: str, format_name: str = "auto", filename: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
        """
        Main entry point for parsing and normalizing log contents.
        Returns: (normalized_records, errors_list, detected_format)
        """
        if len(content.encode("utf-8")) > MAX_FILE_SIZE:
            return [], [{"record_index": 0, "error": f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024 * 1024)} MB"}], format_name

        fmt = format_name.lower().strip() if format_name and format_name != "auto" else detect_format(content, filename)

        if fmt == "canonical_csv":
            records, errors = cls.parse_canonical_csv(content)
        elif fmt == "ndjson":
            records, errors = cls.parse_ndjson(content)
        elif fmt == "windows_event":
            records, errors = cls.parse_windows_event(content)
        elif fmt == "linux_ssh":
            records, errors = cls.parse_linux_ssh(content)
        elif fmt == "zeek_conn":
            records, errors = cls.parse_zeek_conn(content)
        else:
            return [], [{"record_index": 0, "error": f"Unsupported log format: '{format_name}'"}], fmt

        return records, errors, fmt

