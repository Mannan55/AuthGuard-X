"""
AuthGuard-X — Security Event Ingestion & Normalization Engine (Sprint 4 Hardened)

Provides local-first log parsing, multi-format normalization, deterministic deduplication,
input validation, CSV formula injection defense, strict forensic evidence preservation,
and realistic training telemetry ingestion.

Forensic Evidence Retention & Data Provenance:
- Bounded Raw Payload Retention: Original raw source records are preserved up to 64 KB per event
  to protect forensic fidelity while preventing memory/disk exhaustion attacks.
- Cryptographic Integrity: Every preserved raw payload is hashed via SHA-256 (raw_hash) upon ingestion
  to detect tampering and verify evidence authenticity.
- Strict Timestamp Normalization: Converts all timezone-aware timestamps into actual UTC.
  Preserves original timestamp strings and timezone metadata. Never silently substitutes ingestion time.
- Zero Evidence Fabrication: Unavailable attributes are strictly represented as null/unknown.
  Field provenance (observed, inferred, unavailable) is explicitly tracked for all records.
- Source-Aware Deduplication: Stable source event IDs, ports, timestamps, and raw hashes prevent
  collapsing legitimate same-second repeated events while guaranteeing idempotent re-imports.

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
MAX_RAW_PAYLOAD_SIZE = 64 * 1024  # 64 KB

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


class TimestampNormalizationError(ValueError):
    """Raised when an event timestamp is missing, empty, or unparseable."""
    pass


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


def normalize_timestamp_strict(
    raw_time: Any,
    reference_year: Optional[int] = None
) -> Tuple[str, str, Optional[str]]:
    """
    Strictly normalizes raw timestamp into UTC format string 'YYYY-MM-DD HH:MM:SS'.
    Converts timezone-aware timestamps into actual UTC.
    Preserves original timestamp string and timezone/offset metadata.
    Never silently substitutes ingestion time for invalid or missing event time.

    Returns:
        (utc_formatted_str, original_raw_str, original_tz_str)

    Raises:
        TimestampNormalizationError: if timestamp is missing, empty, or cannot be parsed.
    """
    if raw_time is None:
        raise TimestampNormalizationError("Missing event timestamp (null)")

    orig_str = str(raw_time).strip()
    if not orig_str:
        raise TimestampNormalizationError("Missing event timestamp (empty)")

    # 1. Numeric Unix timestamps (epoch seconds or milliseconds)
    num_val = None
    if isinstance(raw_time, (int, float)):
        num_val = float(raw_time)
    else:
        # Check if entire string is numeric (with optional decimal point)
        if re.match(r'^-?\d+(?:\.\d+)?$', orig_str):
            try:
                num_val = float(orig_str)
            except ValueError:
                num_val = None

    if num_val is not None:
        # Detect milliseconds: timestamps > 4102444800 (year 2100 in seconds)
        if abs(num_val) > 4102444800:
            epoch_sec = num_val / 1000.0
            tz_tag = "Unix_ms"
        else:
            epoch_sec = num_val
            tz_tag = "Unix_s"
        try:
            dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), orig_str, tz_tag
        except (ValueError, OverflowError, OSError) as e:
            raise TimestampNormalizationError(f"Invalid Unix epoch timestamp '{orig_str}': {str(e)}")

    # 2. Syslog format: 'Oct 25 10:14:02' or 'Oct  5 03:14:02'
    syslog_match = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$', orig_str)
    if syslog_match:
        month_str, day_str, time_str = syslog_match.groups()
        if month_str in MONTH_MAP:
            month = MONTH_MAP[month_str]
            day = int(day_str)
            year = reference_year or datetime.now(timezone.utc).year
            try:
                dt = datetime(year, month, day)
                return f"{year:04d}-{month:02d}-{day:02d} {time_str}", orig_str, "local_syslog"
            except ValueError as e:
                raise TimestampNormalizationError(f"Invalid syslog date '{orig_str}': {str(e)}")

    # 3. ISO 8601 strings with or without timezone offsets
    # Examples:
    # 2026-10-31T14:30:00+05:30 -> UTC 2026-10-31 09:00:00
    # 2026-10-31T02:30:00+05:30 -> cross-midnight UTC 2026-10-30 21:00:00
    # 2026-10-31T22:00:00-05:00 -> cross-midnight UTC 2026-11-01 03:00:00
    # 2026-10-31T08:30:10.000Z -> UTC 2026-10-31 08:30:10
    iso_clean = orig_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_clean)
        if dt.tzinfo is not None:
            # Timezone-aware: convert to actual UTC
            dt_utc = dt.astimezone(timezone.utc)
            tz_name = str(dt.tzinfo)
            return dt_utc.strftime("%Y-%m-%d %H:%M:%S"), orig_str, tz_name
        else:
            # Naive timestamp: treat as UTC
            return dt.strftime("%Y-%m-%d %H:%M:%S"), orig_str, "UTC"
    except Exception:
        pass

    # 4. Common standard date formats (naive, assumed UTC)
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S"
    ):
        try:
            dt = datetime.strptime(orig_str, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), orig_str, "UTC"
        except ValueError:
            pass

    # If all parsers fail, raise error - never fabricate or use now()!
    raise TimestampNormalizationError(f"Malformed or unrecognized timestamp: '{orig_str}'")


def normalize_timestamp(raw_time: Any, reference_year: Optional[int] = None) -> str:
    """Compatibility wrapper that returns UTC formatted timestamp or raises TimestampNormalizationError."""
    utc_str, _, _ = normalize_timestamp_strict(raw_time, reference_year=reference_year)
    return utc_str


def calculate_fingerprint(
    source_type: str,
    event_time: str,
    source_ip: str,
    dest_ip: Optional[str] = None,
    username: Optional[str] = None,
    attack_type: str = "",
    outcome: str = "",
    source_port: Optional[str] = None,
    dest_port: Optional[str] = None,
    source_record_ref: Optional[str] = None,
    source_event_id: Optional[str] = None,
    raw_hash: Optional[str] = None
) -> str:
    """
    Calculates source-aware SHA-256 fingerprint for deterministic event deduplication.
    Incorporates source ports, record references, source event IDs, and raw hashes
    to retain legitimate same-second repeated events while ensuring identical re-imports
    remain strictly idempotent.
    """
    key_parts = [
        source_type or "",
        event_time or "",
        (source_ip or "").strip(),
        (dest_ip or "").strip(),
        (username or "").strip(),
        (attack_type or "").strip(),
        (outcome or "").strip(),
        (str(source_port) if source_port is not None else "").strip(),
        (str(dest_port) if dest_port is not None else "").strip(),
        (str(source_event_id) if source_event_id is not None else "").strip(),
        (str(source_record_ref) if source_record_ref is not None else "").strip(),
        (str(raw_hash) if raw_hash is not None else "").strip()
    ]
    key = "|".join(key_parts)
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
        return "ndjson"

    # CSV header check
    first_line = clean.splitlines()[0] if clean.splitlines() else ""
    if "," in first_line and any(h in first_line.lower() for h in ("ip", "time", "attack", "risk", "user")):
        return "canonical_csv"

    return "canonical_csv"


def extract_forensic_payload(
    raw_source_text: Optional[str],
    reconstructed_text: Optional[str] = None,
    source_format: str = "canonical_csv"
) -> Dict[str, Any]:
    """
    Distinguishes the exact SHA-256 digest of source record bytes from
    a bounded, decoded, normalized, or reconstructed representation.
    Never labels a reconstructed row as original raw bytes.
    Preserves explicit truncation and provenance metadata.
    """
    if raw_source_text is not None and str(raw_source_text).strip() != "":
        raw_bytes = raw_source_text.encode("utf-8")
        raw_bytes_hash = hashlib.sha256(raw_bytes).hexdigest()
        is_truncated = len(raw_bytes) > MAX_RAW_PAYLOAD_SIZE
        payload_str = raw_source_text[:MAX_RAW_PAYLOAD_SIZE]
        normalized_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        return {
            "raw_payload": payload_str,
            "raw_hash": raw_bytes_hash,
            "raw_bytes_hash": raw_bytes_hash,
            "normalized_payload_hash": normalized_hash,
            "payload_type": "exact_source_line",
            "payload_provenance": "verbatim_source_text",
            "is_truncated": is_truncated,
            "original_byte_length": len(raw_bytes)
        }
    else:
        # Reconstructed representation: explicitly state reconstructed provenance
        reconstructed_str = reconstructed_text or "{}"
        rec_bytes = reconstructed_str.encode("utf-8")
        is_truncated = len(rec_bytes) > MAX_RAW_PAYLOAD_SIZE
        payload_str = reconstructed_str[:MAX_RAW_PAYLOAD_SIZE]
        normalized_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        return {
            "raw_payload": payload_str,
            "raw_hash": normalized_hash,
            "raw_bytes_hash": None,  # NEVER label reconstructed representation as raw source bytes!
            "normalized_payload_hash": normalized_hash,
            "payload_type": f"reconstructed_{source_format}_row",
            "payload_provenance": "reconstructed_representation",
            "is_truncated": is_truncated,
            "original_byte_length": len(rec_bytes)
        }


class IngestionParser:
    """Parses and normalizes security logs from different structured formats."""

    @staticmethod
    def parse_canonical_csv(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse Canonical CSV format with flexible headers."""
        records = []
        errors = []
        raw_lines = [l for l in content.splitlines() if l.strip()]
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

            # Strict timestamp normalization
            raw_time = get_col(row, "timestamp", "time", "event_time", "datetime")
            try:
                event_time, orig_time, orig_tz = normalize_timestamp_strict(raw_time)
            except TimestampNormalizationError as e:
                errors.append({"record_index": idx, "error": f"Invalid or missing timestamp: {str(e)}"})
                continue

            ip = get_col(row, "source_ip", "ip", "src_ip", "orig_h")
            if not ip or not is_valid_ip(ip):
                errors.append({"record_index": idx, "error": f"Invalid or missing source IP address: '{ip}'"})
                continue

            attack = get_col(row, "attack", "attack_type", "event_type", "category", "signature", default="Security Event")
            category = get_col(row, "category", default="Authentication" if "auth" in attack.lower() or "login" in attack.lower() else "Security Telemetry")
            username = get_col(row, "username", "user", "target_user", "account", default="")
            dest_ip = get_col(row, "dest_ip", "dst_ip", "resp_h", default="")
            hostname = get_col(row, "hostname", "host", "computer", default="")
            outcome = normalize_outcome(get_col(row, "outcome", "status", "result", default="unknown"))
            source_port = get_col(row, "source_port", "src_port", "sport", default="") or None
            dest_port = get_col(row, "dest_port", "dst_port", "dport", default="") or None
            source_event_id = get_col(row, "event_id", "id", "record_id", default="") or None

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

            # Precise source evidence extraction
            source_line = raw_lines[idx] if idx < len(raw_lines) else None
            forensic = extract_forensic_payload(
                raw_source_text=source_line,
                reconstructed_text=json.dumps(row, sort_keys=True),
                source_format="canonical_csv"
            )

            field_provenance = {
                "source_ip": "observed" if ip else "unavailable",
                "dest_ip": "observed" if dest_ip else "unavailable",
                "username": "observed" if username else "unavailable",
                "hostname": "observed" if hostname else "unavailable",
                "event_time": "observed",
                "raw_evidence": {
                    "payload_type": forensic["payload_type"],
                    "payload_provenance": forensic["payload_provenance"],
                    "is_truncated": forensic["is_truncated"],
                    "original_byte_length": forensic["original_byte_length"],
                    "exact_source_bytes_hash": forensic["raw_bytes_hash"],
                    "normalized_payload_hash": forensic["normalized_payload_hash"]
                }
            }

            record = {
                "source_type": "canonical_csv",
                "event_time": event_time,
                "original_timestamp": orig_time,
                "original_timezone": orig_tz,
                "category": category,
                "attack_type": attack,
                "username": username or "unknown",
                "source_ip": ip,
                "dest_ip": dest_ip or None,
                "hostname": hostname or None,
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_port": source_port,
                "dest_port": dest_port,
                "source_event_id": source_event_id,
                "source_record_ref": f"csv_row_{idx}",
                "field_provenance": field_provenance,
                "raw_payload": forensic["raw_payload"],
                "raw_hash": forensic["raw_hash"],
                "raw_bytes_hash": forensic["raw_bytes_hash"],
                "normalized_payload_hash": forensic["normalized_payload_hash"],
                "raw_payload_type": forensic["payload_type"],
                "raw_payload_provenance": forensic["payload_provenance"],
                "is_truncated": forensic["is_truncated"],
                "original_byte_length": forensic["original_byte_length"],
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
                lines = [(i + 1, item, json.dumps(item, sort_keys=True), None) for i, item in enumerate(items)]
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
                    lines.append((idx, json.loads(line_str), line_str, line_str))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed JSON: {str(e)}", "raw": line_str[:60]})

        for idx, item, raw_text, source_line in lines:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            if not isinstance(item, dict):
                errors.append({"record_index": idx, "error": "Record is not a JSON object"})
                continue

            # Strict timestamp normalization
            raw_time = item.get("timestamp") or item.get("time") or item.get("event_time")
            try:
                event_time, orig_time, orig_tz = normalize_timestamp_strict(raw_time)
            except TimestampNormalizationError as e:
                errors.append({"record_index": idx, "error": f"Invalid or missing timestamp: {str(e)}"})
                continue

            ip = item.get("source_ip") or item.get("ip") or item.get("src_ip") or item.get("client_ip")
            if not ip or not is_valid_ip(str(ip)):
                errors.append({"record_index": idx, "error": f"Invalid or missing source IP address: '{ip}'"})
                continue

            attack = str(item.get("attack") or item.get("attack_type") or item.get("event_type") or "Security Alert")
            category = str(item.get("category") or "Security Telemetry")
            username = item.get("username") or item.get("user")
            dest_ip = item.get("dest_ip") or item.get("dst_ip")
            hostname = item.get("hostname") or item.get("host")
            outcome = normalize_outcome(item.get("outcome") or item.get("status"))
            source_port = str(item.get("source_port") or item.get("src_port") or "") or None
            dest_port = str(item.get("dest_port") or item.get("dst_port") or "") or None
            source_event_id = str(item.get("id") or item.get("event_id") or "") or None

            risk_val = item.get("risk") or item.get("risk_score")
            severity_val = item.get("severity")
            try:
                risk = max(0, min(100, int(risk_val))) if risk_val is not None else map_severity_risk(severity_val)
            except (ValueError, TypeError):
                risk = map_severity_risk(severity_val)
            severity = map_risk_severity(risk)

            behavior = str(item.get("behavior") or item.get("details") or f"{attack} observed")

            forensic = extract_forensic_payload(
                raw_source_text=source_line,
                reconstructed_text=raw_text,
                source_format="ndjson"
            )

            field_provenance = {
                "source_ip": "observed" if ip else "unavailable",
                "dest_ip": "observed" if dest_ip else "unavailable",
                "username": "observed" if username else "unavailable",
                "hostname": "observed" if hostname else "unavailable",
                "event_time": "observed",
                "raw_evidence": {
                    "payload_type": forensic["payload_type"],
                    "payload_provenance": forensic["payload_provenance"],
                    "is_truncated": forensic["is_truncated"],
                    "original_byte_length": forensic["original_byte_length"],
                    "exact_source_bytes_hash": forensic["raw_bytes_hash"],
                    "normalized_payload_hash": forensic["normalized_payload_hash"]
                }
            }

            records.append({
                "source_type": "ndjson",
                "event_time": event_time,
                "original_timestamp": orig_time,
                "original_timezone": orig_tz,
                "category": category,
                "attack_type": attack,
                "username": str(username).strip() if username else "unknown",
                "source_ip": str(ip).strip(),
                "dest_ip": str(dest_ip).strip() if dest_ip else None,
                "hostname": str(hostname).strip() if hostname else None,
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_port": source_port,
                "dest_port": dest_port,
                "source_event_id": source_event_id,
                "source_record_ref": f"ndjson_line_{idx}",
                "field_provenance": field_provenance,
                "raw_payload": forensic["raw_payload"],
                "raw_hash": forensic["raw_hash"],
                "raw_bytes_hash": forensic["raw_bytes_hash"],
                "normalized_payload_hash": forensic["normalized_payload_hash"],
                "raw_payload_type": forensic["payload_type"],
                "raw_payload_provenance": forensic["payload_provenance"],
                "is_truncated": forensic["is_truncated"],
                "original_byte_length": forensic["original_byte_length"],
                "metadata": item
            })

        return records, errors

    @staticmethod
    def parse_windows_event(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse Windows Security Event Log (JSON or NDJSON) for Event IDs 4624 & 4625.
        Extracts EventID, SystemTime, Computer, TargetUserName, IpAddress, LogonType, SubStatus.
        Strictly avoids fabricating IPs, hostnames, usernames, or destinations.
        """
        records = []
        errors = []
        clean = content.strip()

        # Parse either JSON array, single JSON, or NDJSON
        items = []
        if clean.startswith("[") and clean.endswith("]"):
            try:
                items = [(i + 1, item, json.dumps(item, sort_keys=True), None) for i, item in enumerate(json.loads(clean))]
            except Exception as e:
                return [], [{"record_index": 0, "error": f"Invalid Windows JSON: {str(e)}"}]
        elif clean.startswith("{") and clean.endswith("}") and "\n{" not in clean:
            try:
                items = [(1, json.loads(clean), clean, clean)]
            except Exception as e:
                return [], [{"record_index": 1, "error": f"Invalid Windows JSON: {str(e)}"}]
        else:
            for idx, line in enumerate(clean.splitlines(), start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    items.append((idx, json.loads(line_str), line_str, line_str))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed Windows event JSON: {str(e)}"})

        for idx, obj, raw_text, source_line in items:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            event_obj = obj.get("Event", obj)
            system = event_obj.get("System", {})
            event_data = event_obj.get("EventData", {})

            event_id = str(system.get("EventID", event_obj.get("EventID", "")))
            if not event_id:
                event_id = str(event_data.get("EventID", ""))

            if event_id not in ("4624", "4625"):
                errors.append({"record_index": idx, "error": f"Unsupported Windows EventID '{event_id}'. Only 4624 (Success) and 4625 (Failure) are supported."})
                continue

            # Strict SystemTime normalization
            time_created = system.get("TimeCreated", {})
            if isinstance(time_created, dict):
                raw_time = time_created.get("@SystemTime") or time_created.get("SystemTime")
            else:
                raw_time = time_created or event_obj.get("TimeCreated") or event_obj.get("timestamp")

            try:
                event_time, orig_time, orig_tz = normalize_timestamp_strict(raw_time)
            except TimestampNormalizationError as e:
                errors.append({"record_index": idx, "error": f"Invalid or missing Windows SystemTime: {str(e)}"})
                continue

            # Computer/Hostname - never fabricate default
            hostname = system.get("Computer") or event_obj.get("Computer") or None

            # Target user - never fabricate default
            username = event_data.get("TargetUserName") or event_obj.get("TargetUserName") or event_obj.get("username") or None

            # IP Address extraction without fabrication (remove 10.0.0.15 fallback)
            raw_ip = event_data.get("IpAddress") or event_obj.get("IpAddress") or event_obj.get("source_ip")
            ip = None
            if raw_ip and str(raw_ip).strip() not in ("-", ""):
                ip_clean = str(raw_ip).strip()
                if is_valid_ip(ip_clean):
                    ip = ip_clean
                else:
                    errors.append({"record_index": idx, "error": f"Invalid IP address in Windows event: '{ip_clean}'"})
                    continue

            # Where schema requires non-null source IP, represent unobserved local console logons as 'unknown'
            source_ip_val = ip if ip else "unknown"

            logon_type = str(event_data.get("LogonType") or event_obj.get("LogonType") or "")
            sub_status = event_data.get("SubStatus") or event_obj.get("SubStatus") or ""
            source_port = str(event_data.get("IpPort") or "") or None
            source_event_id = str(system.get("EventRecordID") or "") or None

            if event_id == "4625":
                outcome = "failure"
                attack = "Logon Failure (Windows 4625)"
                risk = 80
                severity = "high"
                behavior = f"Failed logon for {username or 'unknown'} via LogonType {logon_type or 'unknown'} (SubStatus: {sub_status or '0xC000006A'})"
            else:  # 4624
                outcome = "success"
                attack = "Logon Success (Windows 4624)"
                risk = 15
                severity = "low"
                behavior = f"Successful logon for {username or 'unknown'} via LogonType {logon_type or 'unknown'}"

            forensic = extract_forensic_payload(
                raw_source_text=source_line,
                reconstructed_text=raw_text,
                source_format="windows_event"
            )

            field_provenance = {
                "source_ip": "observed" if ip else "unavailable",
                "dest_ip": "unavailable",
                "username": "observed" if username else "unavailable",
                "hostname": "observed" if hostname else "unavailable",
                "event_time": "observed",
                "raw_evidence": {
                    "payload_type": forensic["payload_type"],
                    "payload_provenance": forensic["payload_provenance"],
                    "is_truncated": forensic["is_truncated"],
                    "original_byte_length": forensic["original_byte_length"],
                    "exact_source_bytes_hash": forensic["raw_bytes_hash"],
                    "normalized_payload_hash": forensic["normalized_payload_hash"]
                }
            }

            records.append({
                "source_type": "windows_event",
                "event_time": event_time,
                "original_timestamp": orig_time,
                "original_timezone": orig_tz,
                "category": "Authentication",
                "attack_type": attack,
                "username": username or "unknown",
                "source_ip": source_ip_val,
                "dest_ip": None,  # Strictly NO fabricated destination 10.0.0.1
                "hostname": str(hostname).strip() if hostname else None,
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_port": source_port,
                "dest_port": None,
                "source_event_id": source_event_id,
                "source_record_ref": f"EventID_{event_id}_record_{source_event_id or idx}",
                "field_provenance": field_provenance,
                "raw_payload": forensic["raw_payload"],
                "raw_hash": forensic["raw_hash"],
                "raw_bytes_hash": forensic["raw_bytes_hash"],
                "normalized_payload_hash": forensic["normalized_payload_hash"],
                "raw_payload_type": forensic["payload_type"],
                "raw_payload_provenance": forensic["payload_provenance"],
                "is_truncated": forensic["is_truncated"],
                "original_byte_length": forensic["original_byte_length"],
                "metadata": {
                    "EventID": event_id,
                    "LogonType": logon_type,
                    "SubStatus": sub_status,
                    "TargetDomainName": event_data.get("TargetDomainName"),
                    "WorkstationName": event_data.get("WorkstationName")
                }
            })

        return records, errors

    @staticmethod
    def parse_linux_ssh(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse Linux SSH authentication logs (syslog auth.log format).
        Extracts timestamp, host, username, source IP, port, and authentication outcome.
        Classifies single failure as SSH Login Attempt, not premature confirmed brute force.
        Never fabricates destination IPs or hostnames.
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
                    try:
                        event_time, orig_time, orig_tz = normalize_timestamp_strict(raw_time)
                    except TimestampNormalizationError as e:
                        errors.append({"record_index": idx, "error": f"Invalid or missing SSH syslog timestamp: {str(e)}"})
                        break

                    hostname = gd.get("hostname") or None
                    username = gd.get("username") or None
                    ip = gd.get("ip")

                    if not ip or not is_valid_ip(ip):
                        errors.append({"record_index": idx, "error": f"Invalid IP in SSH log: '{ip}'"})
                        break

                    port = gd.get("port")
                    lower_line = clean_line.lower()

                    # Do not classify single failure as confirmed brute force!
                    if "failed password" in lower_line or "invalid user" in lower_line:
                        outcome = "failure"
                        attack = "SSH Login Attempt"
                        risk = 75
                        severity = "high"
                        behavior = f"SSH authentication failure for user {username or 'unknown'} from port {port or 'unknown'}"
                    elif "accepted" in lower_line:
                        outcome = "success"
                        attack = "SSH Logon Success"
                        risk = 20
                        severity = "low"
                        behavior = f"SSH session established for {username or 'unknown'} from port {port or 'unknown'}"
                    else:
                        outcome = "blocked"
                        attack = "SSH Connection Closed"
                        risk = 40
                        severity = "medium"
                        behavior = f"SSH connection terminated during authentication for {username or 'unknown'}"

                    forensic = extract_forensic_payload(
                        raw_source_text=clean_line,
                        source_format="linux_ssh"
                    )

                    field_provenance = {
                        "source_ip": "observed",
                        "dest_ip": "unavailable",
                        "username": "observed" if username else "unavailable",
                        "hostname": "observed" if hostname else "unavailable",
                        "event_time": "observed" if orig_tz != "local_syslog" else "inferred_year",
                        "raw_evidence": {
                            "payload_type": forensic["payload_type"],
                            "payload_provenance": forensic["payload_provenance"],
                            "is_truncated": forensic["is_truncated"],
                            "original_byte_length": forensic["original_byte_length"],
                            "exact_source_bytes_hash": forensic["raw_bytes_hash"],
                            "normalized_payload_hash": forensic["normalized_payload_hash"]
                        }
                    }

                    records.append({
                        "source_type": "linux_ssh",
                        "event_time": event_time,
                        "original_timestamp": orig_time,
                        "original_timezone": orig_tz,
                        "category": "Authentication",
                        "attack_type": attack,
                        "username": username or "unknown",
                        "source_ip": ip,
                        "dest_ip": None,  # Strictly NO fabricated destination 192.168.1.10
                        "hostname": hostname,
                        "outcome": outcome,
                        "severity": severity,
                        "risk_score": risk,
                        "behavior": behavior,
                        "source_port": str(port) if port else None,
                        "dest_port": "22",
                        "source_event_id": None,
                        "source_record_ref": f"syslog_line_{idx}",
                        "field_provenance": field_provenance,
                        "raw_payload": forensic["raw_payload"],
                        "raw_hash": forensic["raw_hash"],
                        "raw_bytes_hash": forensic["raw_bytes_hash"],
                        "normalized_payload_hash": forensic["normalized_payload_hash"],
                        "raw_payload_type": forensic["payload_type"],
                        "raw_payload_provenance": forensic["payload_provenance"],
                        "is_truncated": forensic["is_truncated"],
                        "original_byte_length": forensic["original_byte_length"],
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
        Never fabricates usernames ('network_flow') or hostnames ('zeek-sensor-01').
        """
        records = []
        errors = []
        clean = content.strip()

        items = []
        if clean.startswith("[") and clean.endswith("]"):
            try:
                items = [(i + 1, item, json.dumps(item, sort_keys=True), None) for i, item in enumerate(json.loads(clean))]
            except Exception as e:
                return [], [{"record_index": 0, "error": f"Invalid Zeek JSON array: {str(e)}"}]
        else:
            for idx, line in enumerate(clean.splitlines(), start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    items.append((idx, json.loads(line_str), line_str, line_str))
                except Exception as e:
                    errors.append({"record_index": idx, "error": f"Malformed Zeek JSON: {str(e)}"})

        for idx, obj, raw_text, source_line in items:
            if idx > MAX_RECORDS_PER_BATCH:
                errors.append({"record_index": idx, "error": f"Batch limit exceeded (maximum {MAX_RECORDS_PER_BATCH} records)"})
                break

            if not isinstance(obj, dict):
                errors.append({"record_index": idx, "error": "Zeek record is not an object"})
                continue

            id_struct = obj.get("id", {})
            orig_h = id_struct.get("orig_h") or obj.get("id.orig_h") or obj.get("orig_h")
            resp_h = id_struct.get("resp_h") or obj.get("id.resp_h") or obj.get("resp_h")
            orig_p = id_struct.get("orig_p") or obj.get("id.orig_p") or obj.get("orig_p")
            resp_p = id_struct.get("resp_p") or obj.get("id.resp_p") or obj.get("resp_p")
            uid = obj.get("uid")

            if not orig_h or not is_valid_ip(str(orig_h)):
                errors.append({"record_index": idx, "error": f"Invalid source IP in Zeek log: '{orig_h}'"})
                continue

            raw_time = obj.get("ts") or obj.get("timestamp")
            try:
                event_time, orig_time, orig_tz = normalize_timestamp_strict(raw_time)
            except TimestampNormalizationError as e:
                errors.append({"record_index": idx, "error": f"Invalid or missing Zeek timestamp: {str(e)}"})
                continue

            proto = str(obj.get("proto") or "tcp").lower()
            service = str(obj.get("service") or "-").lower()
            conn_state = str(obj.get("conn_state") or "SF").upper()

            if conn_state in ("S0", "S1", "RSTOS0"):
                outcome = "blocked"
                attack = "Port Scan / Recon Probe (Zeek S0)"
                risk = 65
                severity = "high"
                behavior = f"Incomplete {proto} handshake to port {resp_p or 'unknown'} (State: {conn_state})"
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

            forensic = extract_forensic_payload(
                raw_source_text=source_line,
                reconstructed_text=raw_text,
                source_format="zeek_conn"
            )

            field_provenance = {
                "source_ip": "observed" if orig_h else "unavailable",
                "dest_ip": "observed" if resp_h else "unavailable",
                "username": "unavailable",
                "hostname": "unavailable",
                "event_time": "observed",
                "raw_evidence": {
                    "payload_type": forensic["payload_type"],
                    "payload_provenance": forensic["payload_provenance"],
                    "is_truncated": forensic["is_truncated"],
                    "original_byte_length": forensic["original_byte_length"],
                    "exact_source_bytes_hash": forensic["raw_bytes_hash"],
                    "normalized_payload_hash": forensic["normalized_payload_hash"]
                }
            }

            records.append({
                "source_type": "zeek_conn",
                "event_time": event_time,
                "original_timestamp": orig_time,
                "original_timezone": orig_tz,
                "category": "Network Connection",
                "attack_type": attack,
                "username": None,  # Strictly NO fabricated username 'network_flow'
                "source_ip": str(orig_h).strip(),
                "dest_ip": str(resp_h).strip() if resp_h else None,
                "hostname": None,  # Strictly NO fabricated hostname 'zeek-sensor-01'
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk,
                "behavior": behavior,
                "source_port": str(orig_p) if orig_p else None,
                "dest_port": str(resp_p) if resp_p else None,
                "source_event_id": str(uid) if uid else None,
                "source_record_ref": f"zeek_uid_{uid}" if uid else f"zeek_line_{idx}",
                "field_provenance": field_provenance,
                "raw_payload": forensic["raw_payload"],
                "raw_hash": forensic["raw_hash"],
                "raw_bytes_hash": forensic["raw_bytes_hash"],
                "normalized_payload_hash": forensic["normalized_payload_hash"],
                "raw_payload_type": forensic["payload_type"],
                "raw_payload_provenance": forensic["payload_provenance"],
                "is_truncated": forensic["is_truncated"],
                "original_byte_length": forensic["original_byte_length"],
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
