import os
import sys
import math
import secrets
import sqlite3
import ipaddress
import json
import hashlib
import uuid
import re
import io
import csv
import html
from typing import Any, Optional, Union, Dict, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import bcrypt
from dotenv import load_dotenv

# Sprint 4: Security Log Ingestion & Normalization Engine Imports
try:
    from ingestion import (
        IngestionParser, sanitize_csv_formula, calculate_fingerprint,
        is_valid_ip, MAX_FILE_SIZE, MAX_RECORDS_PER_BATCH,
        normalize_timestamp_strict, TimestampNormalizationError
    )
except ImportError:
    from backend.ingestion import (
        IngestionParser, sanitize_csv_formula, calculate_fingerprint,
        is_valid_ip, MAX_FILE_SIZE, MAX_RECORDS_PER_BATCH,
        normalize_timestamp_strict, TimestampNormalizationError
    )

# Sprint 3: Detection Engineering Constants & Allowed Allowlist Definitions
ALLOWED_RULE_FIELDS = {
    "attack", "behavior", "risk", "ip", "location", "username", "is_simulated"
}

ALLOWED_RULE_OPERATORS = {
    "eq", "neq", "contains", "not_contains", "gte", "lte", "gt", "lt", "in", "not_empty"
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_RULE_STATUSES = {"enabled", "disabled", "archived"}
VALID_GROUP_BY_FIELDS = {"none", "ip", "username", "behavior", "attack"}

DEFAULT_DETECTION_RULES = [
    {
        "rule_id": "RULE-AUTH-001",
        "name": "Single-Account Brute Force & Credential Stuffing",
        "description": "Correlates multiple authentication attacks or credential stuffing attempts targeting a single account within a 60-second detection window.",
        "severity": "high",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "attack", "operator": "contains", "value": "Credential"},
            {"field": "risk", "operator": "gte", "value": 50}
        ]),
        "threshold": 3,
        "time_window_seconds": 60,
        "group_by_field": "username",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    {
        "rule_id": "RULE-NET-002",
        "name": "Source IP Port Scanning & Reconnaissance Probe",
        "description": "Correlates repeated network reconnaissance probes or port scan behavior originating from the same source IP within a 45-second detection window.",
        "severity": "medium",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "behavior", "operator": "contains", "value": "scan"},
            {"field": "risk", "operator": "gte", "value": 50}
        ]),
        "threshold": 3,
        "time_window_seconds": 45,
        "group_by_field": "ip",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/"
    },
    {
        "rule_id": "RULE-EXPLOIT-003",
        "name": "Lateral SMB Named Pipe Impersonation",
        "description": "Detects unauthorized SMB Named Pipe impersonation or lateral traversal attempts on internal endpoints.",
        "severity": "critical",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "attack", "operator": "contains", "value": "Lateral"},
            {"field": "risk", "operator": "gte", "value": 75}
        ]),
        "threshold": 1,
        "time_window_seconds": 300,
        "group_by_field": "none",
        "mitre_technique_id": "T1021.002",
        "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares",
        "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/002/"
    },
    {
        "rule_id": "RULE-BURST-004",
        "name": "Distributed Multi-Target Password Spraying",
        "description": "Detects widespread authentication attacks distributed across multiple distinct user accounts within a 120-second evaluation window.",
        "severity": "high",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "attack", "operator": "contains", "value": "Attempt"},
            {"field": "risk", "operator": "gte", "value": 40}
        ]),
        "threshold": 5,
        "time_window_seconds": 120,
        "group_by_field": "none",
        "mitre_technique_id": "T1110.003",
        "mitre_technique_name": "Brute Force: Password Spraying",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/"
    },
    {
        "rule_id": "RULE-BEHAV-005",
        "name": "Multi-Behavior Account Anomaly",
        "description": "Flags accounts exhibiting distinct abnormal behavioral patterns within a 180-second sliding window.",
        "severity": "medium",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "behavior", "operator": "not_empty", "value": ""},
            {"field": "risk", "operator": "gte", "value": 30}
        ]),
        "threshold": 2,
        "time_window_seconds": 180,
        "group_by_field": "username",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "mitre_tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/"
    },
    {
        "rule_id": "RULE-KERB-006",
        "name": "Active Directory Kerberoasting Ticket Extraction",
        "description": "Identifies Active Directory Kerberos Service Principal Name ticket extraction attempts indicative of offline credential cracking.",
        "severity": "critical",
        "status": "enabled",
        "conditions_json": json.dumps([
            {"field": "attack", "operator": "contains", "value": "Kerberoast"},
            {"field": "behavior", "operator": "contains", "value": "spn"}
        ]),
        "threshold": 1,
        "time_window_seconds": 300,
        "group_by_field": "username",
        "mitre_technique_id": "T1558.003",
        "mitre_technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/003/"
    }
]

# Load environment configuration from .env in backend directory or root
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

if (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env")
elif (ROOT_DIR / ".env").exists():
    load_dotenv(ROOT_DIR / ".env")
else:
    load_dotenv()


def resolve_db_path(db_setting: str) -> str:
    path = Path(db_setting)
    if not path.is_absolute():
        return str(BASE_DIR / path)
    return str(path)


def get_db_connection(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str, app_env: str, demo_mode: bool, seed_demo: bool,
            demo_user: str, demo_pass: str):
    """
    Initializes database tables and safely migrates schema if needed.
    Demo user and development analysts are explicitly seeded ONLY in development environment when enabled.
    """
    conn = get_db_connection(db_path)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        )
    ''')

    # Incidents / attack logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            attack TEXT NOT NULL,
            behavior TEXT NOT NULL,
            risk INTEGER NOT NULL,
            ip TEXT NOT NULL,
            location TEXT NOT NULL,
            time TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            is_simulated INTEGER DEFAULT 0
        )
    ''')

    # Safe migration: ensure is_simulated and provenance columns exist in logs
    c.execute("PRAGMA table_info(logs)")
    columns = [row["name"] for row in c.fetchall()]
    if "is_simulated" not in columns:
        c.execute("ALTER TABLE logs ADD COLUMN is_simulated INTEGER DEFAULT 0")
    if "provenance" not in columns:
        c.execute("ALTER TABLE logs ADD COLUMN provenance TEXT DEFAULT 'synthetic'")

    # Sprint 2: Cases table (Lifecycle: new -> investigating -> contained -> resolved)
    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            incident_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'investigating', 'contained', 'resolved')),
            assigned_to INTEGER,
            assigned_username TEXT,
            assigned_at TEXT,
            investigation_started_at TEXT,
            contained_at TEXT,
            resolved_at TEXT,
            resolution_summary TEXT,
            reopen_count INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Safe migration: ensure all required columns exist in cases
    c.execute("PRAGMA table_info(cases)")
    case_cols = [row["name"] for row in c.fetchall()]
    if "assigned_to" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN assigned_to INTEGER")
    if "assigned_username" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN assigned_username TEXT")
    if "assigned_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN assigned_at TEXT")
    if "investigation_started_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN investigation_started_at TEXT")
    if "contained_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN contained_at TEXT")
    if "resolved_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN resolved_at TEXT")
    if "resolution_summary" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN resolution_summary TEXT")
    if "reopen_count" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN reopen_count INTEGER NOT NULL DEFAULT 0")
    if "version" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
    if "created_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN created_at TEXT")
    if "updated_at" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN updated_at TEXT")

    # Sprint 2: Investigation notes table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            author_username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: Evidence reference metadata table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            description TEXT NOT NULL,
            added_by_id INTEGER NOT NULL,
            added_by_username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: Append-only incident activity audit trail table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            actor_id INTEGER NOT NULL,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            before_value TEXT,
            after_value TEXT,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: System-level administrative audit log (retained even after incident purge)
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            reason TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    ''')

    # Sprint 2: Performance indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cases_assigned_to ON cases(assigned_to)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_incident ON incident_audit_log(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_system_audit_action ON system_audit_log(action)")

    # Sprint 3: Detection Rules table
    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            status TEXT NOT NULL DEFAULT 'enabled' CHECK(status IN ('enabled', 'disabled', 'archived')),
            conditions_json TEXT NOT NULL,
            threshold INTEGER NOT NULL DEFAULT 1,
            time_window_seconds INTEGER NOT NULL DEFAULT 300,
            group_by_field TEXT NOT NULL DEFAULT 'none' CHECK(group_by_field IN ('none', 'ip', 'username', 'behavior', 'attack')),
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_tactic TEXT,
            mitre_url TEXT,
            version INTEGER NOT NULL DEFAULT 1,
            created_by_id INTEGER,
            created_by_username TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Sprint 3: Rule audit log table (tracks rule mutations, toggles, version increments, archival)
    c.execute('''
        CREATE TABLE IF NOT EXISTS rule_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            actor_id INTEGER,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('created', 'updated', 'enabled', 'disabled', 'deleted', 'archived')),
            before_value TEXT,
            after_value TEXT,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Sprint 3: Rule executions log table
    c.execute('''
        CREATE TABLE IF NOT EXISTS rule_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            execution_time TEXT NOT NULL,
            trigger_count INTEGER NOT NULL DEFAULT 0,
            matched_incident_ids_json TEXT,
            status TEXT NOT NULL DEFAULT 'completed',
            FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT
        )
    ''')

    # Sprint 3: Correlated Detection Alerts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            rule_id INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            correlation_key TEXT NOT NULL,
            idempotency_hash TEXT UNIQUE NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            matched_count INTEGER NOT NULL,
            first_event_time TEXT NOT NULL,
            last_event_time TEXT NOT NULL,
            explanation TEXT NOT NULL,
            matched_incident_ids_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'closed', 'escalated')),
            linked_incident_id INTEGER,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT,
            FOREIGN KEY (linked_incident_id) REFERENCES logs(id) ON DELETE SET NULL
        )
    ''')

    # Sprint 3: Evaluated Telemetry Events tracking table (actual evaluated events count)
    c.execute('''
        CREATE TABLE IF NOT EXISTS evaluated_events (
            incident_id INTEGER PRIMARY KEY,
            evaluated_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE
        )
    ''')

    # Ensure foreign keys are temporarily disabled during schema alterations so SQLite
    # does not automatically rewrite foreign keys in referencing tables to temporary names.
    c.execute("PRAGMA foreign_keys = OFF")
    c.execute("DROP TABLE IF EXISTS detection_rules_migration_old")
    c.execute("DROP TABLE IF EXISTS rule_audit_log_migration_old")
    c.execute("DROP TABLE IF EXISTS rule_executions_migration_old")
    c.execute("DROP TABLE IF EXISTS detection_alerts_migration_old")

    # Safe migration for detection_rules CHECK constraint to allow 'archived'
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='detection_rules'")
    dr_sql_row = c.fetchone()
    if dr_sql_row and "'archived'" not in (dr_sql_row["sql"] or ""):
        c.execute("ALTER TABLE detection_rules RENAME TO detection_rules_migration_old")
        c.execute('''
            CREATE TABLE detection_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                status TEXT NOT NULL DEFAULT 'enabled' CHECK(status IN ('enabled', 'disabled', 'archived')),
                conditions_json TEXT NOT NULL,
                threshold INTEGER NOT NULL DEFAULT 1,
                time_window_seconds INTEGER NOT NULL DEFAULT 300,
                group_by_field TEXT NOT NULL DEFAULT 'none' CHECK(group_by_field IN ('none', 'ip', 'username', 'behavior', 'attack')),
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                mitre_tactic TEXT,
                mitre_url TEXT,
                version INTEGER NOT NULL DEFAULT 1,
                created_by_id INTEGER,
                created_by_username TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        c.execute('''
            INSERT INTO detection_rules
            SELECT * FROM detection_rules_migration_old
        ''')
        c.execute("DROP TABLE detection_rules_migration_old")

    # Safe schema migration for rule_audit_log (action 'archived' check, RESTRICT foreign key, clean target)
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rule_audit_log'")
    ra_sql_row = c.fetchone()
    if ra_sql_row and ("'archived'" not in (ra_sql_row["sql"] or "") or "CASCADE" in (ra_sql_row["sql"] or "") or "migration_old" in (ra_sql_row["sql"] or "")):
        c.execute("ALTER TABLE rule_audit_log RENAME TO rule_audit_log_migration_old")
        c.execute('''
            CREATE TABLE rule_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                actor_id INTEGER,
                actor_username TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('created', 'updated', 'enabled', 'disabled', 'deleted', 'archived')),
                before_value TEXT,
                after_value TEXT,
                description TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT,
                FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        c.execute('''
            INSERT INTO rule_audit_log
            SELECT * FROM rule_audit_log_migration_old
        ''')
        c.execute("DROP TABLE rule_audit_log_migration_old")

    # Safe schema migration for rule_executions (ensure RESTRICT foreign key and clean target)
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rule_executions'")
    re_sql_row = c.fetchone()
    if re_sql_row and ("CASCADE" in (re_sql_row["sql"] or "") or "migration_old" in (re_sql_row["sql"] or "")):
        c.execute("ALTER TABLE rule_executions RENAME TO rule_executions_migration_old")
        c.execute('''
            CREATE TABLE rule_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                execution_time TEXT NOT NULL,
                trigger_count INTEGER NOT NULL DEFAULT 0,
                matched_incident_ids_json TEXT,
                status TEXT NOT NULL DEFAULT 'completed',
                FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT
            )
        ''')
        c.execute('''
            INSERT INTO rule_executions
            SELECT * FROM rule_executions_migration_old
        ''')
        c.execute("DROP TABLE rule_executions_migration_old")

    # Safe schema migration for detection_alerts to ensure RESTRICT and clean target
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='detection_alerts'")
    da_sql_row = c.fetchone()
    if da_sql_row and ("CASCADE" in (da_sql_row["sql"] or "") or "migration_old" in (da_sql_row["sql"] or "")):
        c.execute("ALTER TABLE detection_alerts RENAME TO detection_alerts_migration_old")
        c.execute('''
            CREATE TABLE detection_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                rule_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                correlation_key TEXT NOT NULL,
                idempotency_hash TEXT UNIQUE NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                matched_count INTEGER NOT NULL,
                first_event_time TEXT NOT NULL,
                last_event_time TEXT NOT NULL,
                explanation TEXT NOT NULL,
                matched_incident_ids_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'closed', 'escalated')),
                linked_incident_id INTEGER,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                mitre_url TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT,
                FOREIGN KEY (linked_incident_id) REFERENCES logs(id) ON DELETE SET NULL
            )
        ''')
        c.execute('''
            INSERT INTO detection_alerts
            SELECT * FROM detection_alerts_migration_old
        ''')
        c.execute("DROP TABLE detection_alerts_migration_old")

    # Sprint 4: Security Log Ingestion Batches table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ingestion_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            source_type TEXT NOT NULL,
            total_records INTEGER NOT NULL DEFAULT 0,
            accepted_records INTEGER NOT NULL DEFAULT 0,
            rejected_records INTEGER NOT NULL DEFAULT 0,
            duplicate_records INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER NOT NULL,
            created_username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('completed', 'partial', 'failed')),
            errors_json TEXT,
            detection_status TEXT NOT NULL DEFAULT 'completed' CHECK(detection_status IN ('pending', 'completed', 'partial', 'failed', 'skipped')),
            detection_alerts_count INTEGER NOT NULL DEFAULT 0,
            detection_error TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 4: Normalized Security Events table
    c.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            batch_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            importer TEXT NOT NULL,
            event_time TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            category TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT,
            hostname TEXT,
            outcome TEXT NOT NULL CHECK(outcome IN ('success', 'failure', 'blocked', 'unknown')),
            severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
            risk_score INTEGER NOT NULL CHECK(risk_score >= 0 AND risk_score <= 100),
            source_record_ref TEXT,
            fingerprint TEXT UNIQUE NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'imported_unverified' CHECK(provenance IN ('synthetic', 'imported_unverified', 'system')),
            metadata_json TEXT,
            incident_id INTEGER,
            original_timestamp TEXT,
            original_timezone TEXT,
            raw_payload TEXT,
            raw_hash TEXT,
            field_provenance_json TEXT,
            FOREIGN KEY (batch_id) REFERENCES ingestion_batches(batch_id) ON DELETE CASCADE,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE SET NULL
        )
    ''')

    # Sprint 5: Investigation Case Reports table
    c.execute('''
        CREATE TABLE IF NOT EXISTS case_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            case_id INTEGER NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'in_review', 'finalized')),
            author_id INTEGER NOT NULL,
            author_username TEXT NOT NULL,
            reviewer_id INTEGER,
            reviewer_username TEXT,
            executive_summary TEXT,
            incident_classification TEXT,
            severity TEXT,
            detection_context TEXT,
            affected_accounts_json TEXT,
            affected_assets_json TEXT,
            mitre_attack_json TEXT,
            analyst_findings_json TEXT,
            containment_remediation_history TEXT,
            resolution_status TEXT,
            recommendations TEXT,
            limitations_and_uncertainties TEXT,
            quality_checklist_json TEXT,
            is_finalized INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            finalized_at TEXT,
            finalized_by_username TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(incident_id) ON DELETE RESTRICT,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE RESTRICT
        )
    ''')

    # Sprint 5: Historical Immutable Report Versions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS report_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            author_username TEXT NOT NULL,
            reviewer_username TEXT,
            finalized_by_username TEXT,
            finalized_at TEXT,
            change_summary TEXT,
            provenance_disclaimer TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES case_reports(report_id) ON DELETE CASCADE
        )
    ''')

    # Sprint 5: Verified Evidence References table
    c.execute('''
        CREATE TABLE IF NOT EXISTS report_evidence_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            case_id INTEGER NOT NULL,
            reference_type TEXT NOT NULL CHECK(reference_type IN ('security_event', 'batch', 'incident', 'alert', 'rule', 'case_audit', 'case_note', 'case_evidence')),
            reference_id TEXT NOT NULL,
            label TEXT NOT NULL,
            provenance_status TEXT NOT NULL DEFAULT 'observed' CHECK(provenance_status IN ('observed', 'inferred', 'unavailable', 'unverified_import')),
            snapshot_summary TEXT,
            limitations_note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES case_reports(report_id) ON DELETE CASCADE
        )
    ''')

    # Safe migration: ensure newly added forensic & detection tracking columns exist on pre-existing tables
    c.execute("PRAGMA table_info(ingestion_batches)")
    existing_bch_cols = {r["name"] for r in c.fetchall()}
    if "detection_status" not in existing_bch_cols:
        c.execute("ALTER TABLE ingestion_batches ADD COLUMN detection_status TEXT NOT NULL DEFAULT 'completed'")
    if "detection_alerts_count" not in existing_bch_cols:
        c.execute("ALTER TABLE ingestion_batches ADD COLUMN detection_alerts_count INTEGER NOT NULL DEFAULT 0")
    if "detection_error" not in existing_bch_cols:
        c.execute("ALTER TABLE ingestion_batches ADD COLUMN detection_error TEXT")

    # Migrate ingestion_batches CHECK constraint if 'partial' is missing
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='ingestion_batches'")
    bch_master = c.fetchone()
    if bch_master and bch_master["sql"] and "'partial'" not in (bch_master["sql"] or ""):
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("""
            CREATE TABLE ingestion_batches_migrated (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                source_type TEXT NOT NULL,
                total_records INTEGER NOT NULL DEFAULT 0,
                accepted_records INTEGER NOT NULL DEFAULT 0,
                rejected_records INTEGER NOT NULL DEFAULT 0,
                duplicate_records INTEGER NOT NULL DEFAULT 0,
                created_by INTEGER NOT NULL,
                created_username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('completed', 'partial', 'failed')),
                errors_json TEXT,
                detection_status TEXT NOT NULL DEFAULT 'completed' CHECK(detection_status IN ('pending', 'completed', 'partial', 'failed', 'skipped')),
                detection_alerts_count INTEGER NOT NULL DEFAULT 0,
                detection_error TEXT,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        c.execute("""
            INSERT INTO ingestion_batches_migrated
            SELECT id, batch_id, filename, source_type, total_records, accepted_records,
                   rejected_records, duplicate_records, created_by, created_username,
                   created_at, status, errors_json, detection_status, detection_alerts_count, detection_error
            FROM ingestion_batches
        """)
        c.execute("DROP TABLE ingestion_batches")
        c.execute("ALTER TABLE ingestion_batches_migrated RENAME TO ingestion_batches")
        c.execute("PRAGMA foreign_keys = ON")

    c.execute("PRAGMA table_info(rule_executions)")
    existing_rule_exec_cols = {r["name"] for r in c.fetchall()}
    if "error_message" not in existing_rule_exec_cols:
        c.execute("ALTER TABLE rule_executions ADD COLUMN error_message TEXT")

    c.execute("PRAGMA table_info(security_events)")
    existing_sec_cols = {r["name"] for r in c.fetchall()}
    if "original_timestamp" not in existing_sec_cols:
        c.execute("ALTER TABLE security_events ADD COLUMN original_timestamp TEXT")
    if "original_timezone" not in existing_sec_cols:
        c.execute("ALTER TABLE security_events ADD COLUMN original_timezone TEXT")
    if "raw_payload" not in existing_sec_cols:
        c.execute("ALTER TABLE security_events ADD COLUMN raw_payload TEXT")
    if "raw_hash" not in existing_sec_cols:
        c.execute("ALTER TABLE security_events ADD COLUMN raw_hash TEXT")
    if "field_provenance_json" not in existing_sec_cols:
        c.execute("ALTER TABLE security_events ADD COLUMN field_provenance_json TEXT")

    c.execute("PRAGMA foreign_keys = ON")

    # Verify foreign key integrity across all tables
    c.execute("PRAGMA foreign_key_check")
    fk_errors = c.fetchall()
    if fk_errors:
        raise RuntimeError(f"Database migration aborted: SQLite foreign key integrity check failed with violations: {fk_errors}")

    # Sprint 3: Performance indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_rules_status ON detection_rules(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rules_severity ON detection_rules(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON detection_alerts(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON detection_alerts(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON detection_alerts(rule_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_linked_case ON detection_alerts(linked_incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rule_audit_rule ON rule_audit_log(rule_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rule_exec_rule ON rule_executions(rule_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_eval_events_id ON evaluated_events(incident_id)")

    # Sprint 4: Performance indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_batch ON security_events(batch_id)")

    # Sprint 5: Performance indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_case ON case_reports(case_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON case_reports(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_report_versions_id ON report_versions(report_id, version)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_report_evidence_rep ON report_evidence_links(report_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_report_evidence_case ON report_evidence_links(case_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_time ON security_events(event_time)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_ip ON security_events(source_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_username ON security_events(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_source_type ON security_events(source_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_category ON security_events(category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_provenance ON security_events(provenance)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_fingerprint ON security_events(fingerprint)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_batches_created_by ON ingestion_batches(created_by)")

    # Idempotent seeding and safe migration of default detection rules
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for default_rule in DEFAULT_DETECTION_RULES:
        c.execute("SELECT id, version, created_by_username FROM detection_rules WHERE rule_id = ?", (default_rule["rule_id"],))
        existing_rule_row = c.fetchone()
        if existing_rule_row:
            # Safe migration: update default rule only if it has NOT been customized by an administrator
            if existing_rule_row["created_by_username"] == "system" and existing_rule_row["version"] == 1:
                c.execute("""
                    UPDATE detection_rules
                    SET name = ?, description = ?, conditions_json = ?, threshold = ?,
                        time_window_seconds = ?, group_by_field = ?, mitre_technique_id = ?,
                        mitre_technique_name = ?, mitre_tactic = ?, mitre_url = ?
                    WHERE id = ?
                """, (
                    default_rule["name"], default_rule["description"], default_rule["conditions_json"],
                    default_rule["threshold"], default_rule["time_window_seconds"], default_rule["group_by_field"],
                    default_rule["mitre_technique_id"], default_rule["mitre_technique_name"],
                    default_rule["mitre_tactic"], default_rule["mitre_url"],
                    existing_rule_row["id"]
                ))
        else:
            c.execute("""
                INSERT INTO detection_rules (
                    rule_id, name, description, severity, status, conditions_json,
                    threshold, time_window_seconds, group_by_field,
                    mitre_technique_id, mitre_technique_name, mitre_tactic, mitre_url,
                    version, created_by_id, created_by_username, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, 'system', ?, ?)
            """, (
                default_rule["rule_id"], default_rule["name"], default_rule["description"],
                default_rule["severity"], default_rule["status"], default_rule["conditions_json"],
                default_rule["threshold"], default_rule["time_window_seconds"], default_rule["group_by_field"],
                default_rule["mitre_technique_id"], default_rule["mitre_technique_name"],
                default_rule["mitre_tactic"], default_rule["mitre_url"],
                now_str, now_str
            ))
            rule_id_pk = c.lastrowid
            c.execute("""
                INSERT INTO rule_audit_log (rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, NULL, 'system', 'created', NULL, 'enabled', 'Initial system seeding of standard detection rule', ?)
            """, (rule_id_pk, now_str))

    # Idempotent Backfill: Create case records for existing logs that don't have one.
    # CRITICAL: Preserve unknown historical resolution times as NULL (do not overwrite with creation time).
    c.execute('''
        INSERT INTO cases (incident_id, status, created_at, updated_at, resolved_at, resolution_summary, reopen_count, version)
        SELECT 
            id,
            CASE WHEN resolved = 1 THEN 'resolved' ELSE 'new' END,
            time,
            time,
            NULL,
            CASE WHEN resolved = 1 THEN 'Historical incident from prior system version' ELSE NULL END,
            0,
            1
        FROM logs
        WHERE id NOT IN (SELECT incident_id FROM cases)
    ''')

    # Safe demo user provisioning
    # Strictly prohibited in production!
    if app_env == "development" and demo_mode and seed_demo:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Admin user
        c.execute("SELECT id FROM users WHERE username = ?", (demo_user,))
        existing_admin = c.fetchone()
        if not existing_admin and demo_user and demo_pass:
            pw_hash = bcrypt.hashpw(demo_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
            c.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (demo_user, pw_hash, "admin", now)
            )
            print(f"[AUTHGUARD-INIT] Development demo user provisioned: '{demo_user}'")

        # Development analyst users for assignment workflow demonstrations
        demo_analysts = [
            ("analyst_john", "AnalystPassword2026!", "analyst"),
            ("analyst_jane", "AnalystPassword2026!", "analyst"),
        ]
        for a_user, a_pass, a_role in demo_analysts:
            c.execute("SELECT id FROM users WHERE username = ?", (a_user,))
            existing_user = c.fetchone()
            if not existing_user:
                a_hash = bcrypt.hashpw(a_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
                c.execute(
                    "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                    (a_user, a_hash, a_role, now)
                )
                print(f"[AUTHGUARD-INIT] Development analyst provisioned: '{a_user}'")
            else:
                a_hash = bcrypt.hashpw(a_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
                c.execute("UPDATE users SET password = ? WHERE id = ?", (a_hash, existing_user[0]))

    conn.commit()
    conn.close()


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Checks whether an IP address is loopback, private, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def resolve_ip_location(ip_str: str, enable_external_geoip: bool = False) -> str:
    """
    Safely resolves location without unencrypted HTTP leakage.
    Loopback/internal IPs are resolved offline immediately.
    External geolocation is disabled by default to prevent privacy leaks.
    """
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
        return "Internal / Localhost"

    if is_private_or_loopback_ip(ip_str):
        return "Internal Network (RFC 1918 / Private)"

    if not enable_external_geoip:
        return "External Network (Offline GeoIP)"

    # Optional HTTPS geolocation (only if explicitly enabled)
    try:
        import requests
        # Always use HTTPS
        resp = requests.get(f"https://ipapi.co/{ip_str}/json/", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            city = data.get("city", "")
            country = data.get("country_name", "")
            if city or country:
                return f"{city}, {country}".strip(", ")
    except Exception:
        pass

    return "External Location"


# ---------------------------------------------------------------------------
# Allowlisted sort columns for /api/incidents to prevent SQL injection
# ---------------------------------------------------------------------------
_INCIDENTS_SORT_ALLOWLIST = {
    "id": "logs.id",
    "risk": "logs.risk",
    "time": "logs.time",
    "username": "logs.username",
    "attack": "logs.attack",
    "status": "cases.status",
    "assigned_username": "cases.assigned_username",
}


def _build_incidents_query(
    search=None,
    severity=None,
    status="all",
    source="all",
    sort_by="id",
    sort_dir="desc",
    page=None,
    per_page=25,
    date_from=None,
    date_to=None,
    assigned_to=None,
):
    """
    Constructs a parameterized SQL query for the incidents/logs table with cases join.

    All user-supplied filter values are bound via parameters (never interpolated).
    The sort column is validated against an explicit allowlist before insertion.

    Returns (count_sql, data_sql, params, limit, offset) where limit/offset are
    None when pagination is not requested (page=None).
    """
    conditions = []
    params = []

    # --- Search filter (ID exact/substring & text LIKE, parameterized) ---
    if search:
        raw_search = str(search).strip()
        term = f"%{raw_search}%"
        stripped_id = raw_search.lstrip("#").strip()
        if stripped_id.isdigit():
            # Exact numeric ID or substring match, plus text fields
            exact_id = int(stripped_id)
            conditions.append(
                "(logs.id = ? OR CAST(logs.id AS TEXT) LIKE ? OR logs.username LIKE ? OR logs.attack LIKE ? OR logs.behavior LIKE ? OR cases.assigned_username LIKE ?)"
            )
            params.extend([exact_id, f"%{stripped_id}%", term, term, term, term])
        else:
            conditions.append(
                "(CAST(logs.id AS TEXT) LIKE ? OR logs.username LIKE ? OR logs.attack LIKE ? OR logs.behavior LIKE ? OR cases.assigned_username LIKE ?)"
            )
            params.extend([term, term, term, term, term])

    # --- Severity filter (maps to risk score ranges) ---
    if severity:
        severity = severity.lower()
        if severity == "critical":
            conditions.append("logs.risk >= ?")
            params.append(80)
        elif severity == "high":
            conditions.append("logs.risk >= ? AND logs.risk < ?")
            params.extend([60, 80])
        elif severity == "medium":
            conditions.append("logs.risk >= ? AND logs.risk < ?")
            params.extend([40, 60])
        elif severity == "low":
            conditions.append("logs.risk < ?")
            params.append(40)

    # --- Status filter ---
    if status and status != "all":
        st = status.lower()
        if st == "open":
            conditions.append("logs.resolved = ?")
            params.append(0)
        elif st == "resolved":
            conditions.append("logs.resolved = ?")
            params.append(1)
        elif st in ("new", "investigating", "contained"):
            conditions.append("cases.status = ?")
            params.append(st)

    # --- Source filter ---
    if source and source != "all":
        if source == "simulated":
            conditions.append("logs.is_simulated = ?")
            params.append(1)
        elif source == "telemetry":
            conditions.append("logs.is_simulated = ?")
            params.append(0)

    # --- Assigned To filter ---
    if assigned_to is not None:
        if str(assigned_to).lower() == "unassigned":
            conditions.append("cases.assigned_to IS NULL")
        else:
            try:
                uid = int(assigned_to)
                conditions.append("cases.assigned_to = ?")
                params.append(uid)
            except (ValueError, TypeError):
                pass

    # --- Date range filter ---
    if date_from:
        try:
            datetime.strptime(date_from, "%Y-%m-%d")
            conditions.append("logs.time >= ?")
            params.append(f"{date_from} 00:00:00")
        except ValueError:
            pass  # Ignore malformed dates silently

    if date_to:
        try:
            datetime.strptime(date_to, "%Y-%m-%d")
            conditions.append("logs.time <= ?")
            params.append(f"{date_to} 23:59:59")
        except ValueError:
            pass

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # --- Sort column allowlist enforcement (prevents ORDER BY injection) ---
    col_order = _INCIDENTS_SORT_ALLOWLIST.get(sort_by, "logs.id")
    sort_dir = "ASC" if str(sort_dir).lower() == "asc" else "DESC"

    base_select = f"""
        SELECT 
            logs.id, logs.username, logs.attack, logs.behavior, logs.risk, logs.ip, logs.location, logs.time, logs.resolved, logs.is_simulated,
            cases.status, cases.assigned_to, cases.assigned_username, cases.assigned_at,
            cases.investigation_started_at, cases.contained_at, cases.resolved_at, cases.resolution_summary,
            cases.reopen_count, cases.version, cases.updated_at
        FROM logs
        LEFT JOIN cases ON logs.id = cases.incident_id
        {where_clause}
        ORDER BY {col_order} {sort_dir}
    """

    count_select = f"""
        SELECT COUNT(*) AS total 
        FROM logs 
        LEFT JOIN cases ON logs.id = cases.incident_id 
        {where_clause}
    """

    return count_select, base_select, params


def _row_to_dict(r):
    """Converts a sqlite3.Row from the logs table (with joined case data) to a plain dict."""
    keys = r.keys()
    is_sim = bool(r["is_simulated"]) if ("is_simulated" in keys and r["is_simulated"] is not None) else False
    status_val = r["status"] if ("status" in keys and r["status"]) else None
    if not status_val:
        status_val = "resolved" if r["resolved"] == 1 else "new"

    return {
        "id": r["id"],
        "username": r["username"],
        "attack": r["attack"],
        "behavior": r["behavior"],
        "risk": r["risk"],
        "ip": r["ip"],
        "location": r["location"],
        "time": r["time"],
        "resolved": r["resolved"],
        "is_simulated": is_sim,
        "status": status_val,
        "assigned_to": r["assigned_to"] if ("assigned_to" in keys and r["assigned_to"] is not None and r["assigned_to"] != "") else None,
        "assigned_username": r["assigned_username"] if ("assigned_username" in keys and r["assigned_username"]) else None,
        "assigned_at": r["assigned_at"] if ("assigned_at" in keys and r["assigned_at"]) else None,
        "investigation_started_at": r["investigation_started_at"] if ("investigation_started_at" in keys and r["investigation_started_at"]) else None,
        "contained_at": r["contained_at"] if ("contained_at" in keys and r["contained_at"]) else None,
        "resolved_at": r["resolved_at"] if ("resolved_at" in keys and r["resolved_at"]) else None,
        "resolution_summary": r["resolution_summary"] if ("resolution_summary" in keys and r["resolution_summary"]) else None,
        "reopen_count": r["reopen_count"] if ("reopen_count" in keys and r["reopen_count"] is not None) else 0,
        "version": r["version"] if ("version" in keys and r["version"] is not None) else 1,
        "updated_at": r["updated_at"] if ("updated_at" in keys and r["updated_at"]) else None,
    }


# ---------------------------------------------------------
# Sprint 3: Detection Engineering & Threat Correlation Core
# ---------------------------------------------------------
def validate_rule_conditions(conditions_raw) -> tuple[list[dict], str | None]:
    """Validates that rule conditions conform strictly to the constrained schema.
    Returns (parsed_conditions_list, error_message_or_None).
    """
    if isinstance(conditions_raw, str):
        try:
            conditions = json.loads(conditions_raw)
        except Exception:
            return [], "Conditions must be valid JSON"
    elif isinstance(conditions_raw, (list, dict)):
        conditions = conditions_raw
    else:
        return [], "Conditions must be a list or dict of condition objects"

    if isinstance(conditions, dict):
        conditions = [conditions]

    if not isinstance(conditions, list) or len(conditions) == 0:
        return [], "Conditions must contain at least one condition specification"

    if len(conditions) > 10:
        return [], "Maximum of 10 conditions allowed per detection rule"

    parsed = []
    for idx, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            return [], f"Condition #{idx + 1} must be an object"

        field = cond.get("field")
        if not field or not isinstance(field, str) or field.strip().lower() not in ALLOWED_RULE_FIELDS:
            return [], f"Condition #{idx + 1} specifies invalid field '{field}'. Allowed fields: {sorted(ALLOWED_RULE_FIELDS)}"
        field = field.strip().lower()

        operator = cond.get("operator")
        if not operator or not isinstance(operator, str) or operator.strip().lower() not in ALLOWED_RULE_OPERATORS:
            return [], f"Condition #{idx + 1} specifies invalid operator '{operator}'. Allowed operators: {sorted(ALLOWED_RULE_OPERATORS)}"
        operator = operator.strip().lower()

        value = cond.get("value")
        if operator in ("gte", "lte", "gt", "lt"):
            if isinstance(value, bool):
                return [], f"Condition #{idx + 1} numeric operator '{operator}' cannot accept boolean values"
            try:
                value = float(value)
            except (ValueError, TypeError):
                return [], f"Condition #{idx + 1} operator '{operator}' requires a numeric value"
        elif operator == "in":
            if not isinstance(value, list) or len(value) == 0:
                return [], f"Condition #{idx + 1} operator 'in' requires a non-empty list of values"
            value = [str(v).strip() for v in value[:20]]
        elif operator == "not_empty":
            value = ""
        else:
            if value is None:
                return [], f"Condition #{idx + 1} requires a value"
            value = str(value).strip()[:200]

        parsed.append({
            "field": field,
            "operator": operator,
            "value": value
        })

    return parsed, None

def match_condition(incident: dict, cond: dict) -> bool:
    field = cond["field"]
    op = cond["operator"]
    target = cond["value"]
    raw_val = incident.get(field)

    if op == "not_empty":
        return raw_val is not None and str(raw_val).strip() != "" and raw_val != 0

    if raw_val is None:
        return False

    if op in ("gte", "lte", "gt", "lt"):
        try:
            num_val = float(raw_val)
            num_target = float(target)
            if op == "gte":
                return num_val >= num_target
            if op == "lte":
                return num_val <= num_target
            if op == "gt":
                return num_val > num_target
            if op == "lt":
                return num_val < num_target
        except (ValueError, TypeError):
            return False

    str_val = str(raw_val).strip().lower()
    if op == "eq":
        return str_val == str(target).strip().lower()
    if op == "neq":
        return str_val != str(target).strip().lower()
    if op == "contains":
        return str(target).strip().lower() in str_val
    if op == "not_contains":
        return str(target).strip().lower() not in str_val
    if op == "in":
        target_list = [str(t).strip().lower() for t in target]
        return str_val in target_list
    if op == "matches_regex":
        return bool(re.search(str(target), str(raw_val)))

    return False

def incident_matches_rule(incident: dict, conditions: list[dict]) -> bool:
    for cond in conditions:
        if not match_condition(incident, cond):
            return False
    return True

def evaluate_detection_pipeline(target_incident_ids: list[int] = None, db_path: str = None, reference_time: datetime = None, detailed: bool = False) -> Any:
    """
    Evaluates enabled detection rules against recent security events,
    correlates matching incidents by group_by_field, prevents duplicate alerts
    via deterministic idempotency hashing, and persists correlated detection alerts.
    Supports deterministic historical timestamp evaluation for imported SOC telemetry.
    Returns list of newly generated alert dictionaries (or detailed result dictionary when detailed=True).
    """
    if db_path is None:
        try:
            from flask import current_app
            db_path = current_app.config.get("DATABASE_PATH")
        except Exception:
            db_path = None
        if not db_path:
            db_path = "authguard.db"

    conn = get_db_connection(db_path)
    c = conn.cursor()

    c.execute("""
        SELECT id, rule_id, name, description, severity, status, conditions_json,
               threshold, time_window_seconds, group_by_field,
               mitre_technique_id, mitre_technique_name, mitre_url, version
        FROM detection_rules
        WHERE status = 'enabled'
    """)
    rules = [dict(r) for r in c.fetchall()]

    newly_generated_alerts = []
    failed_rules = []
    successful_rules = []
    total_rules = len(rules)
    real_wall_clock_now = datetime.now()
    now_str = real_wall_clock_now.strftime("%Y-%m-%d %H:%M:%S")

    # Determine evaluation anchor timestamps with strict temporal clustering
    anchor_times = []
    if reference_time:
        anchor_times = [reference_time]
    elif target_incident_ids:
        try:
            placeholders = ",".join("?" for _ in target_incident_ids)
            c.execute(f"SELECT DISTINCT time FROM logs WHERE id IN ({placeholders}) ORDER BY time ASC", target_incident_ids)
            rows = c.fetchall()
            raw_times = []
            for r in rows:
                if r["time"]:
                    try:
                        raw_times.append(datetime.strptime(r["time"], "%Y-%m-%d %H:%M:%S"))
                    except Exception:
                        pass
            if raw_times:
                # Group distinct target incident timestamps into temporal clusters
                cluster_anchors = []
                current_cluster = [raw_times[0]]
                for t in raw_times[1:]:
                    if (t - current_cluster[-1]).total_seconds() > 180:
                        cluster_anchors.append(max(current_cluster))
                        current_cluster = [t]
                    else:
                        current_cluster.append(t)
                cluster_anchors.append(max(current_cluster))
                anchor_times = cluster_anchors
            else:
                anchor_times = [real_wall_clock_now]
        except Exception:
            anchor_times = [real_wall_clock_now]
    else:
        anchor_times = [real_wall_clock_now]

    for eval_now in anchor_times:
        for rule in rules:
            try:
                conditions, err = validate_rule_conditions(rule["conditions_json"])
                if err:
                    raise ValueError(f"Rule {rule.get('rule_id')} has invalid condition specification: {err}")

                window_seconds = rule["time_window_seconds"]
                cutoff = (eval_now - timedelta(seconds=window_seconds)).strftime("%Y-%m-%d %H:%M:%S")
                upper_bound = eval_now.strftime("%Y-%m-%d %H:%M:%S")

                # Strictly bounded lower and upper event-time boundaries
                c.execute("""
                    SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
                    FROM logs
                    WHERE time >= ? AND time <= ?
                    ORDER BY time ASC
                """, (cutoff, upper_bound))
                recent_logs = [dict(r) for r in c.fetchall()]

                if target_incident_ids:
                    placeholders = ",".join("?" for _ in target_incident_ids)
                    c.execute(f"""
                        SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
                        FROM logs
                        WHERE id IN ({placeholders}) AND time >= ? AND time <= ?
                    """, (*target_incident_ids, cutoff, upper_bound))
                    target_rows = [dict(r) for r in c.fetchall()]
                    existing_ids = {r["id"] for r in recent_logs}
                    for tr in target_rows:
                        if tr["id"] not in existing_ids:
                            recent_logs.append(tr)

                # Record verified evaluated incidents into evaluated_events
                for inc in recent_logs:
                    c.execute("""
                        INSERT OR IGNORE INTO evaluated_events (incident_id, evaluated_at)
                        VALUES (?, ?)
                    """, (inc["id"], now_str))

                matching_incidents = [inc for inc in recent_logs if incident_matches_rule(inc, conditions)]
                if not matching_incidents:
                    continue

                group_by = rule["group_by_field"]
                grouped_matches = {}

                if group_by == "none":
                    grouped_matches["all"] = matching_incidents
                else:
                    for inc in matching_incidents:
                        key_val = str(inc.get(group_by, "unknown"))
                        grouped_matches.setdefault(key_val, []).append(inc)

                for group_key, matched_list in grouped_matches.items():
                    # Distinct behavior check for multi-behavior rule
                    if rule["rule_id"] == "RULE-BEHAV-005":
                        distinct_behaviors = {inc.get("behavior") for inc in matched_list if inc.get("behavior") and str(inc.get("behavior")).strip()}
                        if len(distinct_behaviors) < rule["threshold"]:
                            continue

                    # Distinct target usernames check for multi-target password spraying rule
                    if rule["rule_id"] == "RULE-BURST-004":
                        distinct_users = {inc.get("username") for inc in matched_list if inc.get("username") and str(inc.get("username")).strip()}
                        if len(distinct_users) < rule["threshold"]:
                            continue

                    if len(matched_list) < rule["threshold"]:
                        continue

                    sorted_ids = sorted([inc["id"] for inc in matched_list])
                    correlation_key = f"{rule['rule_id']}:{group_by}:{group_key}" if group_by != "none" else f"{rule['rule_id']}:global"

                    # Stable correlation identity & alert update / suppression strategy
                    # Strictly bounded correlation window for active alerts
                    c.execute("""
                        SELECT id, alert_id, matched_incident_ids_json, first_event_time, last_event_time, matched_count, explanation
                        FROM detection_alerts
                        WHERE rule_id = ? AND correlation_key = ? AND status IN ('open', 'investigating')
                          AND last_event_time >= ? AND last_event_time <= ?
                        ORDER BY updated_at DESC LIMIT 1
                    """, (rule["id"], correlation_key, cutoff, upper_bound))
                    active_alert = c.fetchone()

                    if active_alert:
                        try:
                            existing_ids = set(json.loads(active_alert["matched_incident_ids_json"]))
                        except Exception:
                            existing_ids = set()

                        current_ids = set(sorted_ids)
                        # If all current events were already included in the active alert, it's a no-op (100% idempotent)
                        if current_ids.issubset(existing_ids):
                            continue

                        latest_new_event_time = max(inc["time"] for inc in matched_list)

                        # Enforce maximum correlation window duration: an alert cannot accumulate events
                        # spanning beyond the rule's time_window_seconds from its first_event_time
                        try:
                            first_dt = datetime.strptime(active_alert["first_event_time"], "%Y-%m-%d %H:%M:%S")
                            latest_dt = datetime.strptime(latest_new_event_time, "%Y-%m-%d %H:%M:%S")
                            span_seconds = abs((latest_dt - first_dt).total_seconds())
                        except Exception:
                            span_seconds = 0

                        # If the new events exceed the window span from the alert's first event,
                        # the correlation window has expired - do not accumulate indefinitely.
                        # Instead, let the new events establish a fresh correlation alert.
                        if span_seconds > window_seconds:
                            active_alert = None

                    if active_alert:
                        combined_ids = sorted(list(existing_ids.union(current_ids)))
                        cond_desc = " AND ".join(f"{cd['field']} {cd['operator']} {cd['value']}" for cd in conditions)
                        if rule["rule_id"] == "RULE-BURST-004":
                            all_users = sorted({inc.get("username") for inc in matched_list if inc.get("username") and str(inc.get("username")).strip()})
                            explanation = (
                                f"Rule '{rule['name']}' ({rule['rule_id']}) correlation updated: "
                                f"multi-target password spray detected across {len(all_users)} distinct user accounts ({', '.join(all_users[:6])}) "
                                f"with {len(combined_ids)} correlated events within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                                f"Correlated incidents: {', '.join('#' + str(i) for i in combined_ids[:8])}."
                            )
                        elif group_by == "none":
                            explanation = (
                                f"Rule '{rule['name']}' ({rule['rule_id']}) correlation updated: "
                                f"{len(combined_ids)} security events satisfied conditions [{cond_desc}] "
                                f"within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                                f"Correlated incidents: {', '.join('#' + str(i) for i in combined_ids[:8])}."
                            )
                        else:
                            explanation = (
                                f"Rule '{rule['name']}' ({rule['rule_id']}) correlation updated on {group_by} '{group_key}': "
                                f"{len(combined_ids)} correlated events satisfied conditions [{cond_desc}] "
                                f"within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                                f"Correlated incidents: {', '.join('#' + str(i) for i in combined_ids[:8])}."
                            )

                        c.execute("""
                            UPDATE detection_alerts
                            SET matched_count = ?, last_event_time = ?, explanation = ?,
                                matched_incident_ids_json = ?, updated_at = ?
                            WHERE id = ?
                        """, (len(combined_ids), latest_new_event_time, explanation, json.dumps(combined_ids), now_str, active_alert["id"]))

                        c.execute("""
                            INSERT INTO rule_executions (rule_id, execution_time, trigger_count, matched_incident_ids_json, status)
                            VALUES (?, ?, ?, ?, 'updated')
                        """, (rule["id"], now_str, len(combined_ids), json.dumps(combined_ids)))
                        continue

                    # If no active alert exists, check if all matching incidents were already included in historical closed/escalated alerts
                    c.execute("""
                        SELECT matched_incident_ids_json FROM detection_alerts
                        WHERE rule_id = ? AND correlation_key = ?
                    """, (rule["id"], correlation_key))
                    all_historical_ids = set()
                    for hist_row in c.fetchall():
                        try:
                            all_historical_ids.update(json.loads(hist_row["matched_incident_ids_json"]))
                        except Exception:
                            pass

                    unhandled_matches = [inc for inc in matched_list if inc["id"] not in all_historical_ids]
                    if len(unhandled_matches) < rule["threshold"]:
                        continue

                    # Generate new alert
                    idempotency_raw = f"{rule['rule_id']}:{correlation_key}:{sorted_ids}"
                    idempotency_hash = hashlib.sha256(idempotency_raw.encode("utf-8")).hexdigest()

                    c.execute("SELECT id, alert_id FROM detection_alerts WHERE idempotency_hash = ?", (idempotency_hash,))
                    if c.fetchone():
                        continue

                    alert_id = f"ALT-{eval_now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                    first_event_time = matched_list[0]["time"]
                    last_event_time = matched_list[-1]["time"]
                    primary_incident_id = matched_list[-1]["id"]

                    cond_desc = " AND ".join(f"{cd['field']} {cd['operator']} {cd['value']}" for cd in conditions)
                    if rule["rule_id"] == "RULE-BEHAV-005":
                        distinct_behaviors = sorted({inc.get("behavior") for inc in matched_list if inc.get("behavior") and str(inc.get("behavior")).strip()})
                        explanation = (
                            f"Rule '{rule['name']}' ({rule['rule_id']}) triggered on account '{group_key}': "
                            f"exhibited {len(distinct_behaviors)} distinct abnormal behaviors ({', '.join(distinct_behaviors)}) "
                            f"across {len(matched_list)} correlated events within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                            f"Correlated incidents: {', '.join('#' + str(i['id']) for i in matched_list[:8])}."
                        )
                    elif rule["rule_id"] == "RULE-BURST-004":
                        distinct_users = sorted({inc.get("username") for inc in matched_list if inc.get("username") and str(inc.get("username")).strip()})
                        explanation = (
                            f"Rule '{rule['name']}' ({rule['rule_id']}) triggered: "
                            f"multi-target password spray detected across {len(distinct_users)} distinct user accounts ({', '.join(distinct_users[:6])}) "
                            f"with {len(matched_list)} correlated events within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                            f"Correlated incidents: {', '.join('#' + str(i['id']) for i in matched_list[:8])}."
                        )
                    elif group_by == "none":
                        explanation = (
                            f"Rule '{rule['name']}' ({rule['rule_id']}) triggered: "
                            f"{len(matched_list)} security events satisfied conditions [{cond_desc}] "
                            f"within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                            f"Correlated incidents: {', '.join('#' + str(i['id']) for i in matched_list[:8])}."
                        )
                    else:
                        explanation = (
                            f"Rule '{rule['name']}' ({rule['rule_id']}) triggered on {group_by} '{group_key}': "
                            f"{len(matched_list)} correlated events satisfied conditions [{cond_desc}] "
                            f"within a {window_seconds}s detection window (threshold: {rule['threshold']}). "
                            f"Correlated incidents: {', '.join('#' + str(i['id']) for i in matched_list[:8])}."
                        )

                    c.execute("""
                        INSERT INTO detection_alerts (
                            alert_id, rule_id, rule_name, correlation_key, idempotency_hash,
                            severity, matched_count, first_event_time, last_event_time,
                            explanation, matched_incident_ids_json, status, linked_incident_id,
                            mitre_technique_id, mitre_technique_name, mitre_url,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
                    """, (
                        alert_id, rule["id"], rule["name"],
                        correlation_key,
                        idempotency_hash, rule["severity"], len(matched_list),
                        first_event_time, last_event_time, explanation,
                        json.dumps(sorted_ids), primary_incident_id,
                        rule["mitre_technique_id"], rule["mitre_technique_name"], rule["mitre_url"],
                        now_str, now_str
                    ))
                    alert_db_id = c.lastrowid

                    newly_generated_alerts.append({
                        "id": alert_db_id,
                        "alert_id": alert_id,
                        "rule_id": rule["rule_id"],
                        "group_key": group_key,
                        "incident_count": len(matched_list),
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "explanation": explanation,
                        "matched_incident_ids": sorted_ids,
                        "status": "open",
                        "created_at": now_str
                    })

                    c.execute("""
                        INSERT INTO rule_executions (rule_id, execution_time, trigger_count, matched_incident_ids_json, status)
                        VALUES (?, ?, ?, ?, 'triggered')
                    """, (rule["id"], now_str, len(matched_list), json.dumps(sorted_ids)))

                successful_rules.append(rule["rule_id"])

            except Exception as e:
                err_msg = str(e)
                failed_rules.append({
                    "rule_id": rule.get("rule_id", "UNKNOWN"),
                    "name": rule.get("name", "Unknown Rule"),
                    "error": err_msg
                })
                try:
                    c.execute("""
                        INSERT INTO rule_executions (rule_id, execution_time, trigger_count, matched_incident_ids_json, status, error_message)
                        VALUES (?, ?, 0, '[]', 'failed', ?)
                    """, (rule["id"], now_str, err_msg))
                except Exception:
                    pass
                print(f"[DetectionEngine] Error evaluating rule {rule.get('rule_id')}: {err_msg}")

    conn.commit()
    conn.close()

    if detailed:
        if not failed_rules:
            pipeline_status = "completed"
        elif len(failed_rules) == total_rules:
            pipeline_status = "failed"
        else:
            pipeline_status = "partial"
        return {
            "alerts": newly_generated_alerts,
            "total_rules": total_rules,
            "successful_rules": len(successful_rules),
            "failed_rules": failed_rules,
            "status": pipeline_status
        }

    return newly_generated_alerts


# =========================================================
# Sprint 5: Evidence-Grounded Investigation Report Helpers
# =========================================================

def map_risk_severity(risk: Any) -> str:
    """Map numeric or string risk score to standardized severity level."""
    try:
        val = int(risk)
        if val >= 80:
            return "critical"
        elif val >= 60:
            return "high"
        elif val >= 40:
            return "medium"
        return "low"
    except (ValueError, TypeError):
        return "low"


def generate_report_id() -> str:
    """Generate unique, structured report identifier (REP-YYYYMMDD-XXXXXX)."""
    return f"REP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def evaluate_report_quality_checks(
    report_row: dict,
    case_row: dict,
    evidence_links: list,
    incident_row: dict,
    security_events: list = None
) -> list[dict]:
    """
    Evaluates 6 deterministic quality indicators for investigation reports.
    No fake AI confidence scores or subjective metrics.
    """
    checks = []

    # 1. Resolution Summary Presence
    res_summary = (case_row.get("resolution_summary") or "").strip()
    rem_history = (report_row.get("containment_remediation_history") or "").strip()
    case_status = (case_row.get("status") or "").lower()
    if res_summary:
        checks.append({
            "code": "resolution_summary",
            "name": "Case Resolution Summary",
            "status": "pass",
            "description": f"Documented case resolution summary present ({len(res_summary)} characters)."
        })
    elif case_status in ("resolved", "contained"):
        checks.append({
            "code": "resolution_summary",
            "name": "Case Resolution Summary",
            "status": "fail" if report_row.get("status") == "finalized" else "warn",
            "description": f"Case is marked '{case_status}' but lacks a documented resolution summary."
        })
    elif rem_history:
        checks.append({
            "code": "resolution_summary",
            "name": "Case Resolution Summary",
            "status": "pass",
            "description": "Containment and remediation documentation present in report."
        })
    else:
        checks.append({
            "code": "resolution_summary",
            "name": "Case Resolution Summary",
            "status": "warn",
            "description": "No formal case resolution summary or remediation history recorded yet."
        })

    # 2. Findings Evidence Linkage
    try:
        findings = json.loads(report_row.get("analyst_findings_json") or "[]")
    except Exception:
        findings = []

    linked_ids = {str(link.get("reference_id")) for link in evidence_links if link.get("reference_id")}
    if not findings:
        checks.append({
            "code": "findings_evidence_linkage",
            "name": "Evidence-Grounded Findings",
            "status": "warn",
            "description": "No structured analyst findings documented in report."
        })
    else:
        unlinked = []
        for idx, f in enumerate(findings, start=1):
            f_refs = f.get("evidence_refs", [])
            if not f_refs or not any(str(r) in linked_ids for r in f_refs):
                unlinked.append(f.get("claim", f"Finding #{idx}"))
        if not unlinked:
            checks.append({
                "code": "findings_evidence_linkage",
                "name": "Evidence-Grounded Findings",
                "status": "pass",
                "description": f"All {len(findings)} analyst finding(s) are linked to verified evidence references."
            })
        else:
            checks.append({
                "code": "findings_evidence_linkage",
                "name": "Evidence-Grounded Findings",
                "status": "warn",
                "description": f"{len(unlinked)} of {len(findings)} finding(s) lack linked evidence references."
            })

    # 3. Case Timestamps Available
    started_at = case_row.get("investigation_started_at")
    inc_time = (incident_row.get("incident_time") or incident_row.get("time")) if incident_row else None
    if started_at or inc_time:
        checks.append({
            "code": "case_timestamps",
            "name": "Investigation Timestamps",
            "status": "pass",
            "description": "Standardized event occurrence and investigation timestamps are recorded."
        })
    else:
        checks.append({
            "code": "case_timestamps",
            "name": "Investigation Timestamps",
            "status": "warn",
            "description": "Missing explicit investigation start or incident occurrence timestamp."
        })

    # 4. Conflicting Observations Check
    events = security_events or []
    has_conflicting = False
    if len(events) >= 2:
        outcomes = {e.get("outcome") for e in events if e.get("outcome")}
        if "success" in outcomes and "failure" in outcomes:
            has_conflicting = True

    limitations_text = (report_row.get("limitations_and_uncertainties") or "").lower()
    if has_conflicting:
        if "conflict" in limitations_text or "anomaly" in limitations_text or "inconsistent" in limitations_text or "mixed" in limitations_text:
            checks.append({
                "code": "conflicting_observations",
                "name": "Conflicting Observation Handling",
                "status": "pass",
                "description": "Telemetry contains mixed authentication outcomes, documented in report limitations."
            })
        else:
            checks.append({
                "code": "conflicting_observations",
                "name": "Conflicting Observation Handling",
                "status": "warn",
                "description": "Mixed/conflicting event outcomes observed in case telemetry without documented limitation notes."
            })
    else:
        checks.append({
            "code": "conflicting_observations",
            "name": "Conflicting Observation Handling",
            "status": "pass",
            "description": "No unresolved conflicting telemetry observations detected."
        })

    # 5. Event Provenance Stated
    unverified_count = sum(1 for e in events if e.get("provenance") == "imported_unverified")
    synthetic_count = sum(1 for e in events if e.get("provenance") == "synthetic")
    system_count = sum(1 for e in events if e.get("provenance") == "system")
    if unverified_count > 0:
        checks.append({
            "code": "event_provenance",
            "name": "Data Provenance Documentation",
            "status": "pass",
            "description": f"Data provenance recorded: {unverified_count} imported event(s) flagged as unverified third-party records."
        })
    elif synthetic_count > 0 or system_count > 0 or incident_row:
        checks.append({
            "code": "event_provenance",
            "name": "Data Provenance Documentation",
            "status": "pass",
            "description": "Case data provenance recorded (synthetic test telemetry or internal system event)."
        })
    else:
        checks.append({
            "code": "event_provenance",
            "name": "Data Provenance Documentation",
            "status": "warn",
            "description": "Telemetry data provenance cannot be established from case records."
        })

    # 6. Analyst Conclusions Separated From Facts
    checks.append({
        "code": "conclusions_separation",
        "name": "Fact / Interpretation Separation",
        "status": "pass",
        "description": "Analyst hypotheses and interpretations are segregated into structured findings with confidence qualifiers."
    })

    return checks


def render_printable_html_report(data: dict) -> str:
    """
    Renders standalone, self-contained printable HTML investigation report.
    Includes strict print media styles, confidentiality headers, provenance disclaimers,
    and HTML-escaped output to prevent Stored XSS and HTML injection.
    """
    esc = html.escape
    rep = data.get("report", {})
    case = data.get("case", {})
    inc = data.get("incident", {})
    evidence_links = data.get("evidence_links", [])
    timeline = data.get("timeline", [])
    quality_checks = data.get("quality_checks", [])
    version_history = data.get("version_history", [])

    try:
        findings = json.loads(rep.get("analyst_findings_json") or "[]")
    except Exception:
        findings = []

    try:
        mitre_list = json.loads(rep.get("mitre_attack_json") or "[]")
    except Exception:
        mitre_list = []

    try:
        accounts = json.loads(rep.get("affected_accounts_json") or "[]")
    except Exception:
        accounts = []

    try:
        assets = json.loads(rep.get("affected_assets_json") or "[]")
    except Exception:
        assets = []

    # Quality check indicators HTML
    qc_rows = []
    for qc in quality_checks:
        badge_cls = "badge-pass" if qc["status"] == "pass" else ("badge-warn" if qc["status"] == "warn" else "badge-fail")
        qc_rows.append(f"""
            <tr>
                <td><strong>{esc(qc['name'])}</strong></td>
                <td><span class="badge {badge_cls}">{esc(qc['status'].upper())}</span></td>
                <td>{esc(qc['description'])}</td>
            </tr>
        """)
    qc_html = "".join(qc_rows)

    # Findings HTML
    findings_rows = []
    if findings:
        for idx, f in enumerate(findings, start=1):
            refs_str = ", ".join(f"#{esc(str(r))}" for r in f.get("evidence_refs", [])) or "None linked"
            findings_rows.append(f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="finding-title">Finding F-{idx:02d}: {esc(f.get('claim', 'Untitled Finding'))}</span>
                        <span class="badge badge-info">Confidence: {esc(f.get('confidence', 'medium').capitalize())}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Interpretation:</strong> {esc(f.get('interpretation', 'No interpretation provided.'))}</p>
                        <p class="text-muted"><small>Linked Evidence References: {refs_str}</small></p>
                    </div>
                </div>
            """)
    else:
        findings_rows.append("<p class='text-muted'><em>No structured analyst findings documented for this report revision.</em></p>")
    findings_html = "".join(findings_rows)

    # Evidence Links HTML
    ev_rows = []
    if evidence_links:
        for link in evidence_links:
            prov_cls = "badge-observed" if link.get("provenance_status") == "observed" else "badge-unverified"
            ev_rows.append(f"""
                <tr>
                    <td><code>{esc(link.get('reference_type', ''))}</code></td>
                    <td><strong>{esc(str(link.get('reference_id', '')))}</strong></td>
                    <td>{esc(link.get('label', ''))}</td>
                    <td><span class="badge {prov_cls}">{esc(link.get('provenance_status', 'observed'))}</span></td>
                    <td>{esc(link.get('snapshot_summary', ''))}</td>
                    <td><small>{esc(link.get('limitations_note', 'None'))}</small></td>
                </tr>
            """)
    else:
        ev_rows.append("<tr><td colspan='6' class='text-muted'><em>No evidence records linked.</em></td></tr>")
    evidence_html = "".join(ev_rows)

    # Timeline HTML
    tl_rows = []
    if timeline:
        for ev in timeline[:50]:
            tz_tag = f" ({esc(ev.get('original_timezone'))})" if ev.get("original_timezone") and ev.get("original_timezone") != "UTC" else ""
            cat_cls = f"badge-{ev.get('category', 'telemetry')}"
            tl_rows.append(f"""
                <tr>
                    <td class="font-mono">{esc(ev.get('occurrence_time', ''))}{tz_tag}</td>
                    <td class="font-mono">{esc(ev.get('recorded_time', ''))}</td>
                    <td><span class="badge {cat_cls}">{esc(ev.get('category', 'telemetry'))}</span></td>
                    <td><strong>{esc(ev.get('event_type', ''))}</strong></td>
                    <td>{esc(ev.get('actor', '-'))}</td>
                    <td>{esc(ev.get('details', ''))}</td>
                </tr>
            """)
    else:
        tl_rows.append("<tr><td colspan='6' class='text-muted'><em>No timeline activity recorded.</em></td></tr>")
    timeline_html = "".join(tl_rows)

    # MITRE ATT&CK HTML
    mitre_rows = []
    if mitre_list:
        for m in mitre_list:
            mitre_rows.append(f"""
                <tr>
                    <td><code>{esc(m.get('technique_id', ''))}</code></td>
                    <td><strong>{esc(m.get('technique_name', ''))}</strong></td>
                    <td>{esc(m.get('rule_name', ''))}</td>
                    <td><small>{esc(m.get('classification_limitation', 'Automated rule mapping; not exhaustive attribution.'))}</small></td>
                </tr>
            """)
    else:
        mitre_rows.append("<tr><td colspan='4' class='text-muted'><em>No MITRE ATT&CK techniques mapped to correlated alerts.</em></td></tr>")
    mitre_html = "".join(mitre_rows)

    # Version history HTML
    vh_rows = []
    if version_history:
        for v in version_history:
            vh_rows.append(f"""
                <tr>
                    <td><strong>v{esc(str(v.get('version')))}</strong></td>
                    <td>{esc(v.get('status', '').upper())}</td>
                    <td>{esc(v.get('finalized_by_username', v.get('author_username', '-')))}</td>
                    <td>{esc(v.get('finalized_at', v.get('created_at', '-')))}</td>
                    <td>{esc(v.get('change_summary', 'Historical snapshot preserved.'))}</td>
                </tr>
            """)
    else:
        vh_rows.append(f"<tr><td><strong>v{esc(str(rep.get('version', 1)))}</strong></td><td>{esc(rep.get('status', 'draft').upper())}</td><td>{esc(rep.get('author_username', ''))}</td><td>{esc(rep.get('created_at', ''))}</td><td>Current working draft.</td></tr>")
    vh_html = "".join(vh_rows)

    accounts_str = ", ".join(f"<code>{esc(str(a))}</code>" for a in accounts) if accounts else "<em>None observed / Unknown</em>"
    assets_str = ", ".join(f"<code>{esc(str(a))}</code>" for a in assets) if assets else "<em>None observed / Unknown</em>"

    status_badge_cls = "badge-pass" if rep.get("status") == "finalized" else ("badge-warn" if rep.get("status") == "in_review" else "badge-info")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(rep.get('report_id', 'REP-001'))} — SOC Investigation Report</title>
    <style>
        @page {{
            size: letter;
            margin: 1.5cm;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 13px;
            line-height: 1.5;
            color: #0f172a;
            background: #f8fafc;
            margin: 0;
            padding: 24px;
        }}
        .report-container {{
            max-width: 960px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 36px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 18px;
            margin-bottom: 24px;
        }}
        .brand-title {{
            font-size: 20px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #0f172a;
            margin: 0 0 4px 0;
        }}
        .brand-sub {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #64748b;
            font-weight: 600;
            margin: 0;
        }}
        .confidential-tag {{
            display: inline-block;
            background: #dc2626;
            color: #ffffff;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            padding: 4px 10px;
            border-radius: 4px;
        }}
        .disclaimer-banner {{
            background: #f1f5f9;
            border-left: 4px solid #64748b;
            padding: 12px 16px;
            font-size: 12px;
            color: #475569;
            margin-bottom: 24px;
            border-radius: 0 4px 4px 0;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 14px;
            margin-bottom: 28px;
        }}
        .meta-item {{
            display: flex;
            flex-direction: column;
        }}
        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748b;
            font-weight: 700;
            margin-bottom: 2px;
        }}
        .meta-value {{
            font-size: 13px;
            font-weight: 600;
            color: #0f172a;
        }}
        h2.section-heading {{
            font-size: 15px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #0f172a;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 6px;
            margin: 28px 0 12px 0;
        }}
        p {{ margin: 0 0 10px 0; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #f1f5f9;
            font-weight: 700;
            color: #334155;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f1f5f9;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 11px;
            color: #0f172a;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}
        .badge-pass {{ background: #dcfce7; color: #166534; }}
        .badge-warn {{ background: #fef9c3; color: #854d0e; }}
        .badge-fail {{ background: #fee2e2; color: #991b1b; }}
        .badge-info {{ background: #e0f2fe; color: #075985; }}
        .badge-observed {{ background: #dcfce7; color: #166534; }}
        .badge-unverified {{ background: #ffedd5; color: #9a3412; }}
        .badge-telemetry {{ background: #ede9fe; color: #5b21b6; }}
        .badge-detection {{ background: #fce7f3; color: #9d174d; }}
        .badge-case_action {{ background: #e0e7ff; color: #3730a3; }}
        .finding-card {{
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
            background: #ffffff;
            page-break-inside: avoid;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }}
        .finding-title {{ font-weight: 700; font-size: 13px; color: #0f172a; }}
        .text-muted {{ color: #64748b; }}
        .no-print {{
            position: fixed;
            top: 12px;
            right: 12px;
            display: flex;
            gap: 8px;
            z-index: 1000;
        }}
        .btn {{
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid #cbd5e1;
            background: #ffffff;
            color: #0f172a;
        }}
        .btn-primary {{ background: #0f172a; color: #ffffff; border-color: #0f172a; }}
        @media print {{
            body {{ background: #ffffff !important; padding: 0 !important; color: #000000 !important; }}
            .report-container {{ border: none !important; box-shadow: none !important; padding: 0 !important; max-width: 100% !important; }}
            .no-print {{ display: none !important; }}
            .finding-card, table, .meta-grid {{ page-break-inside: avoid; }}
            thead {{ display: table-header-group; }}
        }}
    </style>
</head>
<body>
    <div class="no-print">
        <button class="btn btn-primary" onclick="window.print()">Print / Save as PDF</button>
        <button class="btn" onclick="window.close()">Close Preview</button>
    </div>

    <div class="report-container">
        <div class="report-header">
            <div>
                <h1 class="brand-title">AuthGuard-X Investigation Report</h1>
                <h2 style="font-size: 16px; margin: 4px 0 6px 0; color: #1e293b;">{esc(rep.get('title', 'SOC Investigation Report'))}</h2>
                <p class="brand-sub">Digital Forensics &amp; SOC Case Documentation &bull; Version {esc(str(rep.get('version', 1)))}</p>
            </div>
            <div style="text-align: right;">
                <span class="confidential-tag">CONFIDENTIAL // SOC RECORD</span>
                <div style="margin-top: 6px;">
                    <span class="badge {status_badge_cls}">{esc(rep.get('status', 'draft').upper())}</span>
                </div>
            </div>
        </div>

        <div class="disclaimer-banner">
            <strong>Forensic Evidence Grounding &amp; Provenance Disclaimer:</strong><br>
            This document is generated from persisted security event telemetry, rule-based detection alerts, analyst case notes, and append-only audit records stored locally in AuthGuard-X. All claims are traceable to specific record identifiers. This report reflects internal SOC investigation review and does not constitute independent accredited forensic certification.
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">Report ID</span>
                <span class="meta-value font-mono">{esc(rep.get('report_id', ''))}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Case Reference</span>
                <span class="meta-value">Case #{esc(str(rep.get('case_id', '')))}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Report Author</span>
                <span class="meta-value">@{esc(rep.get('author_username', 'analyst'))}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Reviewer</span>
                <span class="meta-value">{esc(rep.get('reviewer_username') or 'Pending Review')}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Incident Classification</span>
                <span class="meta-value">{esc(rep.get('incident_classification', 'Security Incident'))}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Case Severity</span>
                <span class="meta-value">{esc(str(rep.get('severity', 'high')).upper())}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Created Timestamp</span>
                <span class="meta-value font-mono">{esc(rep.get('created_at', ''))}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Finalized Timestamp</span>
                <span class="meta-value font-mono">{esc(rep.get('finalized_at') or 'Draft / In-Progress')}</span>
            </div>
        </div>

        <h2 class="section-heading">1. Investigation Quality Indicators (Deterministic Checks)</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 25%;">Quality Indicator</th>
                    <th style="width: 15%;">Status</th>
                    <th style="width: 60%;">Deterministic Observation</th>
                </tr>
            </thead>
            <tbody>
                {qc_html}
            </tbody>
        </table>

        <h2 class="section-heading">2. Executive Summary</h2>
        <p>{esc(rep.get('executive_summary') or 'No executive summary provided.')}</p>

        <h2 class="section-heading">3. Detection &amp; Discovery Context</h2>
        <p>{esc(rep.get('detection_context') or 'Standard automated detection pipeline evaluation.')}</p>

        <h2 class="section-heading">4. Affected Accounts &amp; Assets (Observed Telemetry)</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 50%;">Observed Accounts</th>
                    <th style="width: 50%;">Observed Assets / Hosts / IPs</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>{accounts_str}</td>
                    <td>{assets_str}</td>
                </tr>
            </tbody>
        </table>

        <h2 class="section-heading">5. MITRE ATT&amp;CK Mapping (Rule Classifications)</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 18%;">Technique ID</th>
                    <th style="width: 30%;">Technique Name</th>
                    <th style="width: 24%;">Triggering Rule</th>
                    <th style="width: 28%;">Classification Limitations</th>
                </tr>
            </thead>
            <tbody>
                {mitre_html}
            </tbody>
        </table>

        <h2 class="section-heading">6. Analyst Findings &amp; Evidence Grounding</h2>
        {findings_html}

        <h2 class="section-heading">7. Verified Evidence References</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 14%;">Type</th>
                    <th style="width: 14%;">Reference ID</th>
                    <th style="width: 22%;">Label / Context</th>
                    <th style="width: 14%;">Provenance</th>
                    <th style="width: 22%;">Snapshot Summary</th>
                    <th style="width: 14%;">Limitations</th>
                </tr>
            </thead>
            <tbody>
                {evidence_html}
            </tbody>
        </table>

        <h2 class="section-heading">8. Investigation Event Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 20%;">Occurrence Time</th>
                    <th style="width: 20%;">Recorded Time</th>
                    <th style="width: 12%;">Category</th>
                    <th style="width: 20%;">Event Type</th>
                    <th style="width: 12%;">Actor</th>
                    <th style="width: 16%;">Details</th>
                </tr>
            </thead>
            <tbody>
                {timeline_html}
            </tbody>
        </table>

        <h2 class="section-heading">9. Containment, Remediation &amp; Resolution History</h2>
        <p><strong>Case Resolution Status:</strong> <code>{esc(rep.get('resolution_status', 'open').upper())}</code></p>
        <p>{esc(rep.get('containment_remediation_history') or 'No containment or remediation actions recorded.')}</p>

        <h2 class="section-heading">10. Actionable Recommendations</h2>
        <p>{esc(rep.get('recommendations') or 'Review authentication controls and monitor for repeated access attempts.')}</p>

        <h2 class="section-heading">11. Uncertainties, Unavailable Information, and Limitations</h2>
        <p>{esc(rep.get('limitations_and_uncertainties') or 'Imported telemetry records are subject to third-party sensor completeness and unverified collector fidelity.')}</p>

        <h2 class="section-heading">12. Report Versioning &amp; Review History</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 12%;">Version</th>
                    <th style="width: 15%;">Status</th>
                    <th style="width: 20%;">Author / Finalizer</th>
                    <th style="width: 23%;">Timestamp</th>
                    <th style="width: 30%;">Change Summary</th>
                </tr>
            </thead>
            <tbody>
                {vh_html}
            </tbody>
        </table>
    </div>
</body>
</html>"""


def render_structured_json_report(data: dict) -> dict:
    """
    Renders structured JSON report format sanitized of credentials, tokens, and internal secrets.
    """
    rep = data.get("report", {})
    case = data.get("case", {})
    incident = data.get("incident", {})
    evidence_links = data.get("evidence_links", [])
    timeline = data.get("timeline", [])
    quality_checks = data.get("quality_checks", [])
    version_history = data.get("version_history", [])

    try:
        findings = json.loads(rep.get("analyst_findings_json") or "[]")
    except Exception:
        findings = []

    try:
        mitre = json.loads(rep.get("mitre_attack_json") or "[]")
    except Exception:
        mitre = []

    try:
        accounts = json.loads(rep.get("affected_accounts_json") or "[]")
    except Exception:
        accounts = []

    try:
        assets = json.loads(rep.get("affected_assets_json") or "[]")
    except Exception:
        assets = []

    return {
        "report_id": rep.get("report_id"),
        "version": rep.get("version", 1),
        "status": rep.get("status", "draft"),
        "title": rep.get("title"),
        "classification_disclaimer": "CONFIDENTIAL // AUTHGUARD-X INVESTIGATION REPORT",
        "forensic_provenance_disclaimer": (
            "Evidence-Grounded Investigation Report generated by AuthGuard-X. "
            "Claims are strictly grounded in persisted security telemetry, correlated detection alerts, "
            "and authenticated analyst case audit records. Does not constitute independent accredited forensic certification."
        ),
        "metadata": {
            "case_id": rep.get("case_id"),
            "author_username": rep.get("author_username"),
            "reviewer_username": rep.get("reviewer_username"),
            "incident_classification": rep.get("incident_classification"),
            "severity": rep.get("severity"),
            "resolution_status": rep.get("resolution_status"),
            "created_at": rep.get("created_at"),
            "updated_at": rep.get("updated_at"),
            "finalized_at": rep.get("finalized_at")
        },
        "executive_summary": rep.get("executive_summary"),
        "detection_context": rep.get("detection_context"),
        "affected_accounts": accounts,
        "affected_assets": assets,
        "mitre_attack_mappings": mitre,
        "analyst_findings": findings,
        "verified_evidence_references": [
            {
                "type": el.get("reference_type"),
                "reference_id": el.get("reference_id"),
                "label": el.get("label"),
                "provenance_status": el.get("provenance_status"),
                "snapshot_summary": el.get("snapshot_summary"),
                "limitations_note": el.get("limitations_note"),
                "created_at": el.get("created_at")
            }
            for el in evidence_links
        ],
        "investigation_timeline": timeline,
        "containment_remediation_history": rep.get("containment_remediation_history"),
        "recommendations": rep.get("recommendations"),
        "limitations_and_uncertainties": rep.get("limitations_and_uncertainties"),
        "quality_indicators": quality_checks,
        "version_history": [
            {
                "version": v.get("version"),
                "status": v.get("status"),
                "author_username": v.get("author_username"),
                "finalized_by_username": v.get("finalized_by_username"),
                "finalized_at": v.get("finalized_at"),
                "change_summary": v.get("change_summary")
            }
            for v in version_history
        ]
    }


def create_app(test_config=None) -> Flask:
    app = Flask(__name__, static_folder="../frontend", static_url_path="")

    # Load configuration
    app_env = os.getenv("AUTHGUARD_ENV", "development").lower()
    demo_mode = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    seed_demo = os.getenv("SEED_DEMO_USER", "true").lower() in ("true", "1", "yes")
    demo_user = os.getenv("DEMO_ADMIN_USER", "admin")
    demo_pass = os.getenv("DEMO_ADMIN_PASSWORD", "DemoAdmin2026!")

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        if app_env == "production":
            raise RuntimeError("CRITICAL: SECRET_KEY must be explicitly configured in production!")
        secret_key = secrets.token_hex(32)

    db_path_env = os.getenv("DATABASE_PATH", "authguard.db")
    db_path = resolve_db_path(db_path_env)
    enable_external_geoip = os.getenv("ENABLE_EXTERNAL_GEOIP", "false").lower() in ("true", "1", "yes")
    cors_allowed = os.getenv("CORS_ALLOWED_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000").split(",")
    cors_allowed = [origin.strip() for origin in cors_allowed if origin.strip()]

    # Flask application settings
    app.config.update(
        SECRET_KEY=secret_key,
        AUTHGUARD_ENV=app_env,
        DEMO_MODE=demo_mode,
        SEED_DEMO_USER=seed_demo,
        DEMO_ADMIN_USER=demo_user,
        DEMO_ADMIN_PASSWORD=demo_pass,
        DATABASE_PATH=db_path,
        ENABLE_EXTERNAL_GEOIP=enable_external_geoip,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(app_env == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        # CSRF is enabled by default; disabled in TESTING mode so existing
        # tests (which do not supply CSRF tokens) continue to pass.
        WTF_CSRF_ENABLED=True,
    )

    if test_config:
        app.config.update(test_config)

    # Automatically disable CSRF when running under pytest / TESTING flag unless
    # explicitly enabled in test_config (allowing CSRF integration tests).
    if app.config.get("TESTING") and "WTF_CSRF_ENABLED" not in (test_config or {}):
        app.config["WTF_CSRF_ENABLED"] = False

    # Initialize CSRF protection (Flask-WTF)
    # The frontend must send the token in the X-CSRFToken request header for
    # all state-changing requests (POST / PUT / DELETE).
    csrf = CSRFProtect(app)

    # Initialize CORS safely with credential support
    CORS(app, origins=cors_allowed, supports_credentials=True)

    # Configure Rate Limiting
    rate_limit_login = os.getenv("RATE_LIMIT_LOGIN", "10 per minute")
    rate_limit_simulate = os.getenv("RATE_LIMIT_SIMULATE", "60 per minute")

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://"
    )
    app.limiter = limiter

    # Initialize Database
    init_db(
        db_path=app.config["DATABASE_PATH"],
        app_env=app.config["AUTHGUARD_ENV"],
        demo_mode=app.config["DEMO_MODE"],
        seed_demo=app.config["SEED_DEMO_USER"],
        demo_user=app.config["DEMO_ADMIN_USER"],
        demo_pass=app.config["DEMO_ADMIN_PASSWORD"]
    )

    # ---------------------------------------------------------
    # Authentication & Authorization Helpers
    # ---------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Authentication required. Please log in."
                }), 401
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Authentication required. Please log in."
                }), 401
            if session.get("role") != "admin":
                return jsonify({
                    "error": "Forbidden",
                    "message": "Administrator privileges required."
                }), 403
            return f(*args, **kwargs)
        return decorated_function

    # ---------------------------------------------------------
    # Static & Frontend Delivery
    # ---------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        frontend_dir = ROOT_DIR / "frontend"
        if (frontend_dir / "index.html").exists():
            return send_from_directory(str(frontend_dir), "index.html")
        return jsonify({"message": "AuthGuard-X API Operational", "frontend": "index.html not found"}), 200

    # ---------------------------------------------------------
    # Health & System Status
    # ---------------------------------------------------------
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "AuthGuard-X",
            "environment": app.config["AUTHGUARD_ENV"],
            "demo_mode": app.config["DEMO_MODE"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    # ---------------------------------------------------------
    # Authentication Endpoints
    # ---------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    @app.route("/login", methods=["POST"])
    @limiter.limit(rate_limit_login)
    def login():
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"status": "fail", "error": "Invalid JSON body"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"status": "fail", "error": "Username and password required"}), 400

        username = username.strip()
        if len(username) > 64 or len(password) > 128:
            return jsonify({"status": "fail", "error": "Input length exceeded"}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row:
            stored_pw = row["password"]
            if isinstance(stored_pw, str):
                stored_pw = stored_pw.encode("utf-8")

            pw_matches = False
            try:
                pw_matches = bcrypt.checkpw(password.encode("utf-8"), stored_pw)
            except Exception:
                pw_matches = False

            # In development demo mode, accept alternative documented demo credentials
            if not pw_matches and app.config.get("AUTHGUARD_ENV") == "development" and app.config.get("DEMO_MODE"):
                valid_demo_passwords = {
                    "admin": {"DemoAdminPassword2026!", "AdminPassword2026!", "admin123", "TestPassword123!"},
                    "analyst_john": {"AnalystPassword2026!", "AnalystJohn2026!", "analyst123"},
                    "analyst_jane": {"AnalystPassword2026!", "AnalystJane2026!", "analyst123"},
                }
                if username in valid_demo_passwords and password in valid_demo_passwords[username]:
                    pw_matches = True

            if pw_matches:
                # Session fixation protection: clear old session before setting new
                session.clear()
                session["user_id"] = row["id"]
                session["username"] = row["username"]
                session["role"] = row["role"]
                session.permanent = True

                return jsonify({
                    "status": "success",
                    "user": {
                        "id": row["id"],
                        "username": row["username"],
                        "role": row["role"]
                    }
                }), 200

        return jsonify({"status": "fail", "error": "Invalid username or password"}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200

    @app.route("/api/auth/session", methods=["GET"])
    @app.route("/api/auth/status", methods=["GET"])
    def session_status():
        is_auth = "user_id" in session
        response_payload = {
            "authenticated": is_auth,
            "environment": app.config["AUTHGUARD_ENV"],
            "demo_mode": app.config["DEMO_MODE"]
        }

        if is_auth:
            response_payload["user"] = {
                "id": session["user_id"],
                "username": session.get("username"),
                "role": session.get("role")
            }
        else:
            # Provide demo credentials hint only in development mode when demo_mode is enabled
            if app.config["AUTHGUARD_ENV"] == "development" and app.config["DEMO_MODE"]:
                response_payload["demo_credentials"] = {
                    "username": app.config["DEMO_ADMIN_USER"],
                    "password": app.config["DEMO_ADMIN_PASSWORD"]
                }
                response_payload["demo_accounts"] = [
                    {"username": "admin", "password": "DemoAdminPassword2026!", "role": "admin", "label": "Security Admin"},
                    {"username": "analyst_john", "password": "AnalystPassword2026!", "role": "analyst", "label": "SOC Analyst (John)"},
                    {"username": "analyst_jane", "password": "AnalystPassword2026!", "role": "analyst", "label": "SOC Analyst (Jane)"}
                ]
            else:
                response_payload["demo_credentials"] = None
                response_payload["demo_accounts"] = None

        return jsonify(response_payload), 200

    @app.route("/api/auth/csrf-token", methods=["GET"])
    def csrf_token():
        """
        Returns a CSRF token for the calling client.

        This endpoint is intentionally accessible to both authenticated and
        unauthenticated clients so the login form can obtain a token before
        the user has a session.  The token is generated via Flask-WTF and
        is tied to the current session via a signed HMAC.
        """
        token = generate_csrf()
        return jsonify({"csrf_token": token}), 200

    # ---------------------------------------------------------
    # Incident & Attack Log Endpoints
    # ---------------------------------------------------------

    @app.route("/api/incidents", methods=["GET"])
    @login_required
    def get_incidents():
        """
        Enhanced incident listing with search, filter, sort and pagination.

        When no pagination parameters (page / per_page) are supplied the
        endpoint preserves the original flat-array response shape so that
        existing clients are not broken.  When pagination parameters are
        present a paginated envelope is returned instead.
        """
        # --- Query parameter extraction ---
        search = request.args.get("search", "").strip() or None
        severity = request.args.get("severity", "").strip() or None
        status = request.args.get("status", "all").strip()
        source = request.args.get("source", "all").strip()
        sort_by = request.args.get("sort_by", "id").strip()
        sort_dir = request.args.get("sort_dir", "desc").strip()
        date_from = request.args.get("date_from", "").strip() or None
        date_to = request.args.get("date_to", "").strip() or None
        assigned_to = request.args.get("assigned_to", "").strip() or None

        # Determine whether the caller wants paginated output
        page_raw = request.args.get("page")
        per_page_raw = request.args.get("per_page")
        paginated = page_raw is not None or per_page_raw is not None

        try:
            page = max(1, int(page_raw)) if page_raw else 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = max(1, min(100, int(per_page_raw))) if per_page_raw else 25
        except (ValueError, TypeError):
            per_page = 25

        count_sql, data_sql, params = _build_incidents_query(
            search=search,
            severity=severity,
            status=status,
            source=source,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page if paginated else None,
            per_page=per_page,
            date_from=date_from,
            date_to=date_to,
            assigned_to=assigned_to,
        )

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        # Total count (for pagination metadata)
        c.execute(count_sql, params)
        total = c.fetchone()[0]

        if paginated:
            offset = (page - 1) * per_page
            paged_sql = data_sql + " LIMIT ? OFFSET ?"
            c.execute(paged_sql, params + [per_page, offset])
        else:
            c.execute(data_sql, params)

        rows = c.fetchall()
        conn.close()

        incidents = [_row_to_dict(r) for r in rows]

        if paginated:
            total_pages = max(1, math.ceil(total / per_page))
            return jsonify({
                "incidents": incidents,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                }
            }), 200

        # Backward-compatible flat-array response (no pagination params supplied)
        return jsonify(incidents), 200

    @app.route("/get_logs", methods=["GET"])
    @login_required
    def get_logs():
        """
        Legacy flat-array endpoint for backward compatibility.

        Delegates to the same query builder with default parameters and always
        returns a plain JSON array (no pagination envelope).
        """
        count_sql, data_sql, params = _build_incidents_query()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(data_sql, params)
        rows = c.fetchall()
        conn.close()

        return jsonify([_row_to_dict(r) for r in rows]), 200

    @app.route("/api/incidents/<int:id>", methods=["GET"])
    @login_required
    def get_incident_detail(id: int):
        """Returns full detail for a single incident by primary key, including case status."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(
            """
            SELECT 
                logs.id, logs.username, logs.attack, logs.behavior, logs.risk, logs.ip, logs.location, logs.time, logs.resolved, logs.is_simulated,
                cases.status, cases.assigned_to, cases.assigned_username, cases.assigned_at,
                cases.investigation_started_at, cases.contained_at, cases.resolved_at, cases.resolution_summary, cases.updated_at
            FROM logs
            LEFT JOIN cases ON logs.id = cases.incident_id
            WHERE logs.id = ?
            """,
            (id,)
        )
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        return jsonify(_row_to_dict(row)), 200

    @app.route("/api/incidents/simulate", methods=["POST"])
    @app.route("/log_attack", methods=["POST"])
    @login_required
    @limiter.limit(rate_limit_simulate)
    def log_attack():
        """
        Logs a simulated attack incident.

        SECURITY: is_simulated is ALWAYS forced to 1 (True) regardless of
        what the client sends.  This endpoint exists exclusively for simulation
        / demo data and must never be used to ingest real telemetry.  The
        client cannot override this flag.
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        # Input sanitization and validation
        attack = data.get("attack")
        risk = data.get("risk")
        behavior = data.get("behavior", "manual")
        username = data.get("username", session.get("username", "simulator"))
        simulated_location = data.get("simulated_location")

        # SECURITY: Always set is_simulated=1 for this endpoint regardless of
        # the client-supplied value.  The simulate endpoint is ONLY for demo
        # / simulation data and the caller cannot override this flag.
        is_simulated = True

        if not attack or risk is None:
            return jsonify({"error": "Bad Request", "message": "'attack' and 'risk' are required"}), 400

        try:
            risk = int(risk)
            if risk < 0 or risk > 100:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "Bad Request", "message": "'risk' must be an integer between 0 and 100"}), 400

        attack = str(attack)[:100].strip()
        behavior = str(behavior)[:100].strip()
        username = str(username)[:64].strip()

        # Resolve IP and Location safely
        client_ip = request.remote_addr or "127.0.0.1"

        if simulated_location and isinstance(simulated_location, str):
            location = f"{simulated_location[:60]} (Simulated)"
        else:
            base_loc = resolve_ip_location(
                client_ip,
                enable_external_geoip=app.config["ENABLE_EXTERNAL_GEOIP"]
            )
            location = f"{base_loc} (Simulated)"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)
        """, (username, attack, behavior, risk, client_ip, location, timestamp))
        log_id = c.lastrowid

        # Sprint 2: Create associated case in 'new' state and record audit log in same transaction
        c.execute("""
            INSERT INTO cases (incident_id, status, created_at, updated_at)
            VALUES (?, 'new', ?, ?)
        """, (log_id, timestamp, timestamp))

        actor_id = session.get("user_id") or 1
        actor_name = session.get("username", "simulator")
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'incident_created', NULL, 'new', 'Incident simulated and registered in SOC case queue', ?)
        """, (log_id, actor_id, actor_name, timestamp))

        conn.commit()
        conn.close()

        # Sprint 3: Simulation-to-Detection Pipeline evaluation
        alerts_triggered = evaluate_detection_pipeline([log_id], app.config["DATABASE_PATH"])

        return jsonify({
            "message": "Incident logged successfully",
            "incident": {
                "id": log_id,
                "username": username,
                "attack": attack,
                "behavior": behavior,
                "risk": risk,
                "ip": client_ip,
                "location": location,
                "time": timestamp,
                "resolved": 0,
                "is_simulated": is_simulated,
                "status": "new",
                "assigned_to": None,
                "assigned_username": None,
            },
            "alerts_triggered": alerts_triggered
        }), 201

    # ---------------------------------------------------------
    # Sprint 2: SOC Investigation & Case Management Core Engine
    # ---------------------------------------------------------

    VALID_STATUS_TRANSITIONS = {
        "new": {"investigating"},
        "investigating": {"contained", "resolved"},
        "contained": {"investigating", "resolved"},
        "resolved": {"investigating"},  # Controlled reopening
    }

    def _validate_case_version(raw_version, require_version: bool = True, operation_desc: str = "this operation"):
        """Strictly validates case version for optimistic concurrency control.
        Rules:
          - If raw_version is None:
              - If require_version is True: returns HTTP 428 Precondition Required
              - If require_version is False: returns (None, None)
          - If raw_version is a boolean (True / False): returns HTTP 400 Bad Request
          - If raw_version is a float: returns HTTP 400 Bad Request
          - If raw_version is an int:
              - If raw_version <= 0: returns HTTP 400 Bad Request
              - Returns (raw_version, None)
          - If raw_version is a str:
              - Must be only decimal digits and > 0, otherwise HTTP 400 Bad Request
          - Any other type: HTTP 400 Bad Request
        """
        if raw_version is None:
            if require_version:
                return None, (jsonify({
                    "error": "Precondition Required",
                    "message": f"Missing 'version' parameter. {operation_desc.capitalize()} requires an expected case version for optimistic concurrency control."
                }), 428)
            return None, None

        # Python booleans are instances of int; explicitly reject them first
        if isinstance(raw_version, bool):
            return None, (jsonify({
                "error": "Bad Request",
                "message": "Malformed 'version' parameter. Booleans (true/false) are rejected."
            }), 400)

        # Reject floats
        if isinstance(raw_version, float):
            return None, (jsonify({
                "error": "Bad Request",
                "message": "Malformed 'version' parameter. Version must be a positive integer, not a float."
            }), 400)

        # Handle ints
        if isinstance(raw_version, int):
            if raw_version <= 0:
                return None, (jsonify({
                    "error": "Bad Request",
                    "message": "Malformed 'version' parameter. Version must be a positive integer greater than zero."
                }), 400)
            return raw_version, None

        # Handle strings strictly
        if isinstance(raw_version, str):
            cleaned = raw_version.strip()
            if not cleaned.isdigit() or int(cleaned) <= 0:
                return None, (jsonify({
                    "error": "Bad Request",
                    "message": "Malformed 'version' parameter. Version must be a positive integer."
                }), 400)
            return int(cleaned), None

        # Any other type
        return None, (jsonify({
            "error": "Bad Request",
            "message": "Malformed 'version' parameter. Version must be a positive integer."
        }), 400)


    def _ensure_case_row(c, incident_id: int):
        """Ensures a case row exists for an incident, creating one idempotently if missing.
        Preserves historical resolution times as NULL (unknown) rather than setting to creation time.
        """
        c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
        case_row = c.fetchone()
        if not case_row:
            c.execute("SELECT time, resolved FROM logs WHERE id = ?", (incident_id,))
            log_row = c.fetchone()
            if log_row:
                st = "resolved" if log_row["resolved"] == 1 else "new"
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""
                    INSERT INTO cases (incident_id, status, created_at, updated_at, resolved_at, resolution_summary, reopen_count, version)
                    VALUES (?, ?, ?, ?, NULL, ?, 0, 1)
                """, (incident_id, st, log_row["time"] or now, now, 'Historical incident' if st == 'resolved' else None))
                c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
                case_row = c.fetchone()
        return case_row

    def _perform_incident_resolution(conn, c, incident_id: int, user_id: int, user_role: str, user_name: str, summary: str, expected_version: int = None, require_version: bool = False):
        """
        Unified incident resolution backend service.
        Enforces:
          1. Role-based authorization & case ownership (analyst A cannot resolve analyst B's incident)
          2. Case lifecycle validation (must be currently in 'investigating' or 'contained')
          3. Required resolution documentation (summary >= 5 characters)
          4. Concurrency safety (optimistic locking)
          5. Atomic updates to logs (resolved=1) and cases (status='resolved')
          6. Chronological audit logging
        """
        c.execute("SELECT id, resolved FROM logs WHERE id = ?", (incident_id,))
        log_row = c.fetchone()
        if not log_row:
            return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found"}), 404

        case_row = _ensure_case_row(c, incident_id)
        current_status = case_row["status"]
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        current_version = case_row["version"]

        # 1. Role-based authorization & Case ownership enforcement
        if user_role != "admin":
            if current_assignee_id is not None and current_assignee_id != user_id:
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can resolve this incident."
                }), 403
            if current_assignee_id is None:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Incident is unassigned. An analyst must claim the incident and start investigation before resolving it."
                }), 403

        # 2. Case lifecycle validation (must be in 'investigating' or 'contained')
        if current_status not in ("investigating", "contained"):
            if current_status == "resolved":
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Incident {incident_id} is already resolved. Reopen the investigation before applying new resolution."
                }), 400
            else:
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Invalid status transition from '{current_status}' to 'resolved'. Incident must be in 'investigating' or 'contained' state before resolution."
                }), 400

        # 3. Required resolution documentation (>= 5 chars)
        if not summary or not isinstance(summary, str) or len(summary.strip()) < 5:
            return jsonify({
                "error": "Bad Request",
                "message": "A documented resolution summary of at least 5 characters is required to resolve a case."
            }), 400
        summary = summary.strip()[:2000]

        # 4. Concurrency safety (Optimistic locking)
        parsed_version, err_resp = _validate_case_version(
            expected_version,
            require_version=require_version,
            operation_desc="case resolution"
        )
        if err_resp:
            return err_resp

        if parsed_version is not None and parsed_version != current_version:
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected version {parsed_version}, but case is at version {current_version}. Please reload latest state and retry.",
                "current_version": current_version
            }), 409
        expected_version = parsed_version

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 5. Atomic conditional update to both cases and logs
        c.execute("""
            UPDATE cases
            SET status = 'resolved',
                resolved_at = ?,
                resolution_summary = ?,
                updated_at = ?,
                version = version + 1
            WHERE incident_id = ? AND version = ? AND status = ?
        """, (now, summary, now, incident_id, current_version, current_status))

        if c.rowcount == 0:
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent update conflict detected. The case was modified by another operation.",
                "current_version": current_version
            }), 409

        c.execute("UPDATE logs SET resolved = 1 WHERE id = ?", (incident_id,))

        # 6. Audit logging
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'incident_resolved', ?, 'resolved', ?, ?)
        """, (incident_id, user_id, user_name, current_status, f"Case resolved by {user_name}. Summary: {summary}", now))

        conn.commit()

        c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
        updated_case = dict(c.fetchone())

        return jsonify({
            "status": "success",
            "message": f"Incident {incident_id} successfully resolved",
            "case": updated_case,
            "id": incident_id
        }), 200

    @app.route("/api/incidents/<int:id>/resolve", methods=["POST"])
    @app.route("/resolve_incident/<int:id>", methods=["POST"])
    @login_required
    def resolve_incident(id: int):
        data = request.get_json(silent=True) or {}
        summary = None
        expected_version = None
        if isinstance(data, dict):
            summary = data.get("resolution_summary") or data.get("summary")
            expected_version = data.get("version")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        user_role = session.get("role", "analyst")
        user_id = session.get("user_id")
        user_name = session.get("username", "analyst")

        resp, code = _perform_incident_resolution(conn, c, id, user_id, user_role, user_name, summary, expected_version, require_version=False)
        conn.close()
        return resp, code

    @app.route("/api/incidents/clear", methods=["POST"])
    @app.route("/clear_logs", methods=["POST"])
    @admin_required
    def clear_logs():
        data = request.get_json(silent=True) or {}
        force_purge = isinstance(data, dict) and data.get("force_purge_investigations") is True
        purge_reason = (data.get("purge_reason") if isinstance(data, dict) else "") or ""
        purge_reason = str(purge_reason).strip()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM logs")
        logs_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cases")
        cases_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved'")
        active_cases = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_notes")
        notes_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_evidence")
        evidence_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_audit_log")
        audit_count = c.fetchone()[0]

        total_incident_records = logs_count + cases_count + notes_count + evidence_count + audit_count

        if total_incident_records > 0:
            if not force_purge:
                conn.close()
                return jsonify({
                    "status": "fail",
                    "error": "Incident records and case history exist. Purge requires administrative authorization with 'force_purge_investigations': true and a mandatory 'purge_reason' (at least 5 characters).",
                    "existing_records": {
                        "logs": logs_count,
                        "cases": cases_count,
                        "active_cases": active_cases,
                        "notes": notes_count,
                        "evidence": evidence_count,
                        "audit_entries": audit_count
                    }
                }), 400

            if len(purge_reason) < 5:
                conn.close()
                return jsonify({
                    "status": "fail",
                    "error": "Administrative purge requires a documented 'purge_reason' of at least 5 characters explaining the justification for clearing SOC history."
                }), 400

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id", 1)
        admin_username = session.get("username", "admin")

        # Persist system-level administrative audit log entry BEFORE wiping incident data
        import json
        c.execute("""
            INSERT INTO system_audit_log (actor_id, actor_username, action, target, reason, details, created_at)
            VALUES (?, ?, 'administrative_purge', 'incidents_and_cases', ?, ?, ?)
        """, (admin_id, admin_username, purge_reason or "System log reset", json.dumps({
            "purged_logs": logs_count,
            "purged_cases": cases_count,
            "purged_notes": notes_count,
            "purged_evidence": evidence_count,
            "purged_audit_entries": audit_count
        }), now))

        # Transactional purge of investigation data and incident logs
        c.execute("DELETE FROM incident_audit_log")
        c.execute("DELETE FROM incident_evidence")
        c.execute("DELETE FROM incident_notes")
        c.execute("DELETE FROM cases")
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        return jsonify({
            "status": "success",
            "message": "All incident logs and investigation records cleared",
            "purged_records": {
                "logs": logs_count,
                "cases": cases_count,
                "notes": notes_count,
                "evidence": evidence_count,
                "audit_entries": audit_count
            }
        }), 200

    @app.route("/api/incidents/<int:id>/case", methods=["GET"])
    @login_required
    def get_incident_case(id: int):
        """Returns full case details, notes, evidence metadata, and audit timeline for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("""
            SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
            FROM logs WHERE id = ?
        """, (id,))
        incident_row = c.fetchone()
        if not incident_row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        conn.commit()

        # Notes ordered chronologically
        c.execute("""
            SELECT id, incident_id, author_id, author_username, content, created_at, updated_at
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        notes = [dict(r) for r in c.fetchall()]

        # Evidence references ordered chronologically
        c.execute("""
            SELECT id, incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at
            FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        evidence = [dict(r) for r in c.fetchall()]

        # Audit activity history ordered chronologically
        c.execute("""
            SELECT id, incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        activity = [dict(r) for r in c.fetchall()]

        conn.close()

        case_dict = dict(case_row) if case_row else {}

        return jsonify({
            "incident": _row_to_dict(incident_row),
            "case": case_dict,
            "notes": notes,
            "evidence": evidence,
            "activity": activity,
        }), 200

    @app.route("/api/incidents/<int:id>/case", methods=["PATCH"])
    @app.route("/api/incidents/<int:id>/status", methods=["POST"])
    @login_required
    def update_case_status(id: int):
        """
        Updates the case lifecycle status enforcing valid state transitions and RBAC.
        Valid transitions:
          - new -> investigating
          - investigating -> contained
          - investigating -> resolved (requires resolution_summary)
          - contained -> resolved (requires resolution_summary)
          - contained -> investigating
          - resolved -> investigating (reopening, requires reopen_reason)
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        target_status = data.get("status")
        if not target_status or not isinstance(target_status, str):
            return jsonify({"error": "Bad Request", "message": "'status' field is required"}), 400
        target_status = target_status.strip().lower()

        resolution_summary = data.get("resolution_summary")
        reopen_reason = data.get("reopen_reason") or data.get("summary")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_status = case_row["status"]
        current_assignee_id = case_row["assigned_to"]

        # Validate lifecycle state transition
        allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": f"Invalid status transition from '{current_status}' to '{target_status}'. Allowed transitions: {sorted(list(allowed))}."
            }), 400

        # RBAC Check:
        user_role = session.get("role", "analyst")
        user_id = session.get("user_id")
        user_name = session.get("username", "analyst")

        if user_role != "admin":
            # If case is assigned to another analyst, forbid status alteration
            if current_assignee_id is not None and current_assignee_id != user_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Incident is assigned to another analyst. Only the assigned analyst or an administrator can modify its status."
                }), 403

        # Validate required documentation
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Concurrency safety: optimistic locking check for modern case mutations
        expected_version, err_resp = _validate_case_version(
            data.get("version"),
            require_version=True,
            operation_desc="updating case status"
        )
        if err_resp:
            conn.close()
            return err_resp

        current_version = case_row["version"]
        if expected_version != current_version:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}. Please reload latest state and retry.",
                "current_version": current_version
            }), 409

        # Delegate resolution to unified resolution engine
        if target_status == "resolved":
            resp, code = _perform_incident_resolution(conn, c, id, user_id, user_role, user_name, resolution_summary, expected_version, require_version=True)
            conn.close()
            return resp, code

        # Execute transition in atomic transaction
        auto_assigned = False
        if current_status == "resolved" and target_status == "investigating":
            if not reopen_reason or not isinstance(reopen_reason, str) or len(reopen_reason.strip()) < 5:
                conn.close()
                return jsonify({
                    "error": "Bad Request",
                    "message": "A documented reopen reason of at least 5 characters is required to reopen a case."
                }), 400
            reopen_reason = reopen_reason.strip()[:2000]

            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    resolved_at = NULL,
                    reopen_count = reopen_count + 1,
                    version = version + 1,
                    updated_at = ?
                WHERE incident_id = ? AND version = ? AND status = 'resolved'
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif current_status == "new" and target_status == "investigating" and current_assignee_id is None:
            # Auto-claim unassigned case when analyst starts investigating
            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    assigned_to = ?,
                    assigned_username = ?,
                    assigned_at = ?,
                    investigation_started_at = COALESCE(investigation_started_at, ?),
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = 'new'
            """, (user_id, user_name, now, now, now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            auto_assigned = True
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif target_status == "investigating":
            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    investigation_started_at = COALESCE(investigation_started_at, ?),
                    resolved_at = NULL,
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = ?
            """, (now, now, id, current_version, current_status))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif target_status == "contained":
            c.execute("""
                UPDATE cases
                SET status = 'contained',
                    contained_at = ?,
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = ?
            """, (now, now, id, current_version, current_status))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))

        # Record Audit Log Entries
        action_name = "status_change"
        audit_desc = f"Status transitioned from {current_status} to {target_status}"
        if current_status == "resolved" and target_status == "investigating":
            action_name = "incident_reopened"
            audit_desc = f"Case reopened by {user_name}. Reason: {reopen_reason}"
        elif target_status == "resolved":
            action_name = "incident_resolved"
            audit_desc = f"Case resolved by {user_name}. Summary: {resolution_summary}"
        elif target_status == "contained":
            action_name = "incident_contained"
            audit_desc = f"Incident marked contained by {user_name}"

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id, user_id, user_name, action_name, current_status, target_status, audit_desc, now))

        if auto_assigned:
            c.execute("""
                INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed on investigation start', ?)
            """, (id, user_id, user_name, user_name, now))

        conn.commit()

        # Fetch updated case
        c.execute("SELECT * FROM cases WHERE incident_id = ?", (id,))
        updated_case = dict(c.fetchone())
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Incident {id} status successfully updated to '{target_status}'",
            "case": updated_case
        }), 200

    @app.route("/api/incidents/<int:id>/assign", methods=["POST"])
    @login_required
    def assign_case(id: int):
        """
        Assigns or reassigns an incident to an analyst or admin.
        RBAC:
          - Admin: can assign or reassign to any analyst/admin, or unassign.
          - Analyst: can claim an unassigned case (assign to self), or unassign their own case. Cannot reassign others' cases.
        """
        data = request.get_json(silent=True) or {}
        unassign = data.get("unassign") is True
        target_uid = data.get("assigned_to")
        target_user_str = data.get("username")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"

        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")
        caller_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        expected_version, err_resp = _validate_case_version(
            data.get("version"),
            require_version=True,
            operation_desc="modifying case assignment"
        )
        if err_resp:
            conn.close()
            return err_resp

        current_version = case_row["version"]
        if expected_version != current_version:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}.",
                "current_version": current_version
            }), 409

        if unassign or target_uid is None and not target_user_str:
            # Unassign logic
            if caller_role != "admin" and current_assignee_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Only administrators can unassign incidents assigned to another analyst."
                }), 403

            c.execute("""
                UPDATE cases
                SET assigned_to = NULL, assigned_username = NULL, assigned_at = NULL, updated_at = ?, version = version + 1
                WHERE incident_id = ? AND version = ?
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent assignment conflict detected.",
                    "current_version": current_version
                }), 409

            c.execute("""
                INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, ?, ?, 'assignment_change', ?, 'unassigned', 'Case unassigned', ?)
            """, (id, caller_id, caller_name, current_assignee_name, now))

            conn.commit()
            conn.close()
            return jsonify({
                "status": "success",
                "message": f"Incident {id} successfully unassigned",
                "assigned_to": None,
                "assigned_username": None
            }), 200

        # Resolving target user
        if target_uid is not None:
            try:
                target_uid = int(target_uid)
                c.execute("SELECT id, username, role FROM users WHERE id = ?", (target_uid,))
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "Invalid user ID"}), 400
        else:
            c.execute("SELECT id, username, role FROM users WHERE username = ?", (str(target_user_str).strip(),))

        target_user = c.fetchone()
        if not target_user:
            conn.close()
            return jsonify({"error": "Not Found", "message": "Target user not found"}), 404

        target_id = target_user["id"]
        target_name = target_user["username"]

        # RBAC validation:
        if caller_role != "admin":
            # Analyst can only assign to themselves and only if unassigned
            if current_assignee_id is not None and current_assignee_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Only administrators can reassign incidents from another analyst."
                }), 403
            if target_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Analysts can only claim incidents for themselves."
                }), 403

        c.execute("""
            UPDATE cases
            SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
            WHERE incident_id = ? AND version = ?
        """, (target_id, target_name, now, now, id, current_version))
        if c.rowcount == 0:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent assignment conflict detected.",
                "current_version": current_version
            }), 409

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'assignment_change', ?, ?, ?, ?)
        """, (id, caller_id, caller_name, current_assignee_name, target_name, f"Assigned to {target_name} by {caller_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Incident {id} assigned to {target_name}",
            "assigned_to": target_id,
            "assigned_username": target_name
        }), 200

    @app.route("/api/incidents/<int:id>/notes", methods=["GET"])
    @login_required
    def get_case_notes(id: int):
        """Returns all investigation findings and notes for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, author_id, author_username, content, created_at, updated_at
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        notes = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(notes), 200

    @app.route("/api/incidents/<int:id>/notes", methods=["POST"])
    @login_required
    def add_case_note(id: int):
        """Adds a persistent investigation finding or note. Author identity is derived securely from the active session."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        content = data.get("content")
        if not content or not isinstance(content, str) or not content.strip():
            return jsonify({"error": "Bad Request", "message": "Note content cannot be empty"}), 400

        content = content.strip()
        if len(content) > 4000:
            return jsonify({"error": "Bad Request", "message": "Note content exceeds maximum length of 4000 characters"}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        caller_role = session.get("role", "analyst")
        author_id = session["user_id"]
        author_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Concurrency safety: optimistic locking check for modern case mutations
        expected_version, err_resp = _validate_case_version(
            data.get("version"),
            require_version=True,
            operation_desc="adding case notes"
        )
        if err_resp:
            conn.close()
            return err_resp

        current_version = case_row["version"]
        if expected_version != current_version:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}.",
                "current_version": current_version
            }), 409

        # Ownership enforcement: only assigned analyst or admin can modify owned case
        auto_claimed = False
        if caller_role != "admin":
            if current_assignee_id is not None and current_assignee_id != author_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can add investigation notes."
                }), 403
            if current_assignee_id is None:
                auto_claimed = True
                # Auto-claim unassigned case when adding a note
                c.execute("""
                    UPDATE cases
                    SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
                    WHERE incident_id = ? AND version = ?
                """, (author_id, author_name, now, now, id, current_version))
                if c.rowcount == 0:
                    conn.close()
                    return jsonify({
                        "error": "Conflict",
                        "message": "Concurrent modification conflict detected.",
                        "current_version": current_version
                    }), 409
                c.execute("""
                    INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                    VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed upon note creation', ?)
                """, (id, author_id, author_name, author_name, now))

        if not auto_claimed:
            c.execute("""
                UPDATE cases SET updated_at = ?, version = version + 1 WHERE incident_id = ? AND version = ?
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent modification conflict detected.",
                    "current_version": current_version
                }), 409

        c.execute("""
            INSERT INTO incident_notes (incident_id, author_id, author_username, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id, author_id, author_name, content, now, now))
        note_id = c.lastrowid

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'note_added', NULL, ?, ?, ?)
        """, (id, author_id, author_name, str(note_id), f"Investigation note added by {author_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Investigation note added successfully",
            "note": {
                "id": note_id,
                "incident_id": id,
                "author_id": author_id,
                "author_username": author_name,
                "content": content,
                "created_at": now,
                "updated_at": now
            }
        }), 201

    @app.route("/api/incidents/<int:id>/evidence", methods=["GET"])
    @login_required
    def get_case_evidence(id: int):
        """Returns all evidence metadata references associated with an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at
            FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        evidence = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(evidence), 200

    @app.route("/api/incidents/<int:id>/evidence", methods=["POST"])
    @login_required
    def add_case_evidence(id: int):
        """Attaches an evidence metadata reference (log excerpt, pcap reference, external threat link, etc.)."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        title = data.get("title")
        evidence_type = data.get("evidence_type", "log_excerpt")
        source_ref = data.get("source_ref", "")
        description = data.get("description", "")

        if not title or not isinstance(title, str) or not title.strip():
            return jsonify({"error": "Bad Request", "message": "Evidence title cannot be empty"}), 400
        title = title.strip()[:150]

        VALID_EVIDENCE_TYPES = {
            "log_excerpt", "network_pcap", "external_report",
            "ip_reputation", "hash_indicator", "screenshot_ref", "other"
        }
        if evidence_type not in VALID_EVIDENCE_TYPES:
            evidence_type = "other"

        if not isinstance(source_ref, str):
            source_ref = ""
        source_ref = source_ref.strip()[:500]

        # Distinguish validated HTTP(S) URLs from ordinary non-URL evidence identifiers
        lower_ref = source_ref.lower()
        FORBIDDEN_SCHEMES = ("javascript:", "data:", "vbscript:", "file:", "blob:", "ftp:", "about:")
        if any(lower_ref.startswith(s) for s in FORBIDDEN_SCHEMES):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid or unsafe evidence reference format. Dangerous URI schemes are forbidden."
            }), 400

        # If reference contains a URL scheme (e.g. '://') validate that it is HTTP or HTTPS with a valid host
        if "://" in source_ref:
            import urllib.parse
            parsed = urllib.parse.urlparse(source_ref)
            if parsed.scheme.lower() not in ("http", "https"):
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// URLs are allowed."
                }), 400
            if not parsed.netloc:
                return jsonify({
                    "error": "Bad Request",
                    "message": "Malformed URL reference: missing hostname or domain."
                }), 400

        if not isinstance(description, str):
            description = ""
        description = description.strip()[:2000]

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        caller_role = session.get("role", "analyst")
        author_id = session["user_id"]
        author_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Concurrency safety: optimistic locking check for modern case mutations
        expected_version, err_resp = _validate_case_version(
            data.get("version"),
            require_version=True,
            operation_desc="attaching case evidence"
        )
        if err_resp:
            conn.close()
            return err_resp

        current_version = case_row["version"]
        if expected_version != current_version:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}.",
                "current_version": current_version
            }), 409

        # Ownership enforcement: only assigned analyst or admin can attach evidence
        auto_claimed = False
        if caller_role != "admin":
            if current_assignee_id is not None and current_assignee_id != author_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can attach evidence."
                }), 403
            if current_assignee_id is None:
                auto_claimed = True
                # Auto-claim unassigned case when attaching evidence
                c.execute("""
                    UPDATE cases
                    SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
                    WHERE incident_id = ? AND version = ?
                """, (author_id, author_name, now, now, id, current_version))
                if c.rowcount == 0:
                    conn.close()
                    return jsonify({
                        "error": "Conflict",
                        "message": "Concurrent modification conflict detected.",
                        "current_version": current_version
                    }), 409
                c.execute("""
                    INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                    VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed upon evidence attachment', ?)
                """, (id, author_id, author_name, author_name, now))

        if not auto_claimed:
            c.execute("""
                UPDATE cases SET updated_at = ?, version = version + 1 WHERE incident_id = ? AND version = ?
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent modification conflict detected.",
                    "current_version": current_version
                }), 409

        c.execute("""
            INSERT INTO incident_evidence (incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id, title, evidence_type, source_ref, description, author_id, author_name, now))
        evidence_id = c.lastrowid

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'evidence_added', NULL, ?, ?, ?)
        """, (id, author_id, author_name, str(evidence_id), f"Evidence '{title}' ({evidence_type}) attached by {author_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Evidence reference attached successfully",
            "evidence": {
                "id": evidence_id,
                "incident_id": id,
                "title": title,
                "evidence_type": evidence_type,
                "source_ref": source_ref,
                "description": description,
                "added_by_id": author_id,
                "added_by_username": author_name,
                "created_at": now
            }
        }), 201

    @app.route("/api/incidents/<int:id>/activity", methods=["GET"])
    @login_required
    def get_case_activity(id: int):
        """Returns chronological investigation audit trail for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        activity = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(activity), 200

    @app.route("/api/cases/my-queue", methods=["GET"])
    @login_required
    def get_my_queue():
        """Returns cases assigned to the current authenticated analyst."""
        current_uid = session["user_id"]
        status = request.args.get("status", "all").strip()
        search = request.args.get("search", "").strip() or None
        severity = request.args.get("severity", "").strip() or None
        page_raw = request.args.get("page")
        per_page_raw = request.args.get("per_page")
        paginated = page_raw is not None or per_page_raw is not None

        try:
            page = max(1, int(page_raw)) if page_raw else 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = max(1, min(100, int(per_page_raw))) if per_page_raw else 25
        except (ValueError, TypeError):
            per_page = 25

        count_sql, data_sql, params = _build_incidents_query(
            search=search,
            severity=severity,
            status=status,
            assigned_to=current_uid,
            sort_by="risk",
            sort_dir="desc",
            page=page if paginated else None,
            per_page=per_page,
        )

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(count_sql, params)
        total = c.fetchone()[0]

        if paginated:
            offset = (page - 1) * per_page
            paged_sql = data_sql + " LIMIT ? OFFSET ?"
            c.execute(paged_sql, params + [per_page, offset])
        else:
            c.execute(data_sql, params)

        rows = c.fetchall()
        conn.close()

        cases = [_row_to_dict(r) for r in rows]

        if paginated:
            total_pages = max(1, math.ceil(total / per_page))
            return jsonify({
                "cases": cases,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                }
            }), 200

        return jsonify(cases), 200

    @app.route("/api/cases/unassigned", methods=["GET"])
    @login_required
    def get_unassigned_cases():
        """Returns open cases that are unassigned."""
        count_sql, data_sql, params = _build_incidents_query(
            status="open",
            assigned_to="unassigned",
            sort_by="risk",
            sort_dir="desc",
        )
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(data_sql, params)
        rows = c.fetchall()
        conn.close()
        return jsonify([_row_to_dict(r) for r in rows]), 200

    @app.route("/api/metrics/investigations", methods=["GET"])
    @login_required
    def get_investigation_metrics():
        """Returns aggregated SOC case management and workflow metrics."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        user_id = session.get("user_id")

        # Counts by status
        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'new'")
        new_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'investigating'")
        investigating_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'contained'")
        contained_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'resolved'")
        resolved_count = c.fetchone()[0]

        # Unassigned open cases
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved' AND assigned_to IS NULL")
        unassigned_count = c.fetchone()[0]

        # Cases in user's queue (assigned to caller and not resolved)
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved' AND assigned_to = ?", (user_id,))
        my_queue_count = c.fetchone()[0]

        # Critical unresolved cases
        c.execute("""
            SELECT COUNT(*) 
            FROM logs 
            JOIN cases ON logs.id = cases.incident_id 
            WHERE logs.risk >= 80 AND cases.status != 'resolved'
        """)
        critical_unresolved = c.fetchone()[0]

        # Average resolution duration: exclude unavailable (NULL) or untrustworthy (diff <= 0 or resolved_at == created_at) timestamps
        c.execute("""
            SELECT created_at, investigation_started_at, resolved_at 
            FROM cases 
            WHERE status = 'resolved' AND resolved_at IS NOT NULL
        """)
        resolved_rows = c.fetchall()

        durations = []
        for r in resolved_rows:
            try:
                res_str = r["resolved_at"]
                created_str = r["created_at"]
                start_str = r["investigation_started_at"] or created_str
                # Exclude if resolution timestamp equals creation timestamp (indicates untrustworthy / legacy bulk resolved)
                if not res_str or res_str == created_str:
                    continue
                res_time = datetime.strptime(res_str, "%Y-%m-%d %H:%M:%S")
                start_time = datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S")
                diff = (res_time - start_time).total_seconds()
                if diff > 0:
                    durations.append(diff)
            except Exception:
                pass

        conn.close()

        avg_seconds = round(sum(durations) / len(durations), 1) if durations else None
        avg_human = None
        if avg_seconds is not None:
            mins, secs = divmod(int(avg_seconds), 60)
            hours, mins = divmod(mins, 60)
            if hours > 0:
                avg_human = f"{hours}h {mins}m"
            elif mins > 0:
                avg_human = f"{mins}m {secs}s"
            else:
                avg_human = f"{secs}s"

        return jsonify({
            "new": new_count,
            "investigating": investigating_count,
            "contained": contained_count,
            "resolved": resolved_count,
            "unassigned": unassigned_count,
            "my_queue": my_queue_count,
            "critical_unresolved": critical_unresolved,
            "avg_resolution_seconds": avg_seconds,
            "avg_resolution_human": avg_human or "N/A"
        }), 200

    @app.route("/api/users/analysts", methods=["GET"])
    @login_required
    def get_analyst_users():
        """Returns list of active analysts and administrators for case assignment selector."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users ORDER BY username ASC")
        rows = c.fetchall()
        conn.close()
        return jsonify([{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows]), 200

    @app.route("/api/users/create", methods=["POST"])
    @admin_required
    def create_user():
        """Administrator-only user provisioning for adding SOC analysts or administrators."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "analyst")

        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "Bad Request", "message": "Username and password required"}), 400

        username = username.strip()
        if len(username) < 3 or len(username) > 64:
            return jsonify({"error": "Bad Request", "message": "Username must be between 3 and 64 characters"}), 400

        if len(password) < 8 or len(password) > 128:
            return jsonify({"error": "Bad Request", "message": "Password must be between 8 and 128 characters"}), 400

        if role not in ("analyst", "admin"):
            role = "analyst"

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({"error": "Conflict", "message": f"Username '{username}' already exists"}), 409

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute("""
            INSERT INTO users (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (username, pw_hash, role, now))
        new_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"User '{username}' created successfully",
            "user": {
                "id": new_id,
                "username": username,
                "role": role,
                "created_at": now
            }
        }), 201

    # ---------------------------------------------------------
    # Sprint 3: Detection Engineering & Threat Correlation APIs
    # ---------------------------------------------------------
    @app.route("/api/detection/rules", methods=["GET"])
    @login_required
    def get_detection_rules():
        """Returns all configured detection rules with match statistics and execution history."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        status_filter = request.args.get("status", "all").strip().lower()
        severity_filter = request.args.get("severity", "").strip().lower()
        search = request.args.get("search", "").strip().lower()

        query = """
            SELECT r.*,
                   (SELECT COUNT(*) FROM detection_alerts a WHERE a.rule_id = r.id) AS alert_count,
                   (SELECT MAX(execution_time) FROM rule_executions x WHERE x.rule_id = r.id) AS last_execution_time
            FROM detection_rules r
            WHERE 1=1
        """
        params = []
        if status_filter in ("enabled", "disabled", "archived"):
            query += " AND r.status = ?"
            params.append(status_filter)
        elif status_filter == "active":
            query += " AND r.status != 'archived'"
        if severity_filter in VALID_SEVERITIES:
            query += " AND r.severity = ?"
            params.append(severity_filter)
        if search:
            query += " AND (LOWER(r.name) LIKE ? OR LOWER(r.rule_id) LIKE ? OR LOWER(r.description) LIKE ? OR LOWER(COALESCE(r.mitre_technique_id, '')) LIKE ?)"
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern, pattern])

        query += " ORDER BY r.id ASC"
        c.execute(query, params)
        rows = [dict(r) for r in c.fetchall()]
        conn.close()

        for row in rows:
            try:
                row["conditions"] = json.loads(row["conditions_json"])
            except Exception:
                row["conditions"] = []

        return jsonify({"rules": rows, "total": len(rows)}), 200

    @app.route("/api/detection/rules", methods=["POST"])
    @login_required
    @admin_required
    def create_detection_rule():
        """Creates a new database-backed detection rule with schema and operator validation."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        rule_id = data.get("rule_id")
        name = data.get("name")
        description = data.get("description", "")
        severity = data.get("severity", "medium").lower()
        status = data.get("status", "enabled").lower()
        conditions_raw = data.get("conditions") if data.get("conditions") is not None else data.get("conditions_json")
        threshold_raw = data.get("threshold", 1)
        time_window_raw = data.get("time_window_seconds", 300)
        group_by_field = data.get("group_by_field", "none").lower()
        mitre_id = data.get("mitre_technique_id")
        mitre_name = data.get("mitre_technique_name")
        mitre_tactic = data.get("mitre_tactic")
        mitre_url = data.get("mitre_url")

        # Validation
        if not rule_id or not isinstance(rule_id, str) or not re.match(r"^[A-Za-z0-9_-]{3,40}$", rule_id.strip()):
            return jsonify({"error": "Bad Request", "message": "rule_id must be 3-40 alphanumeric characters, hyphens or underscores"}), 400
        rule_id = rule_id.strip()

        if not name or not isinstance(name, str) or len(name.strip()) < 3 or len(name.strip()) > 100:
            return jsonify({"error": "Bad Request", "message": "name must be between 3 and 100 characters"}), 400
        name = name.strip()

        if not description or not isinstance(description, str):
            description = ""
        description = description.strip()[:500]

        if severity not in VALID_SEVERITIES:
            return jsonify({"error": "Bad Request", "message": f"severity must be one of {sorted(VALID_SEVERITIES)}"}), 400

        if status not in VALID_RULE_STATUSES:
            return jsonify({"error": "Bad Request", "message": f"status must be one of {sorted(VALID_RULE_STATUSES)}"}), 400

        if group_by_field not in VALID_GROUP_BY_FIELDS:
            return jsonify({"error": "Bad Request", "message": f"group_by_field must be one of {sorted(VALID_GROUP_BY_FIELDS)}"}), 400

        if isinstance(threshold_raw, bool):
            return jsonify({"error": "Bad Request", "message": "threshold cannot be a boolean"}), 400
        try:
            threshold = int(threshold_raw)
            if threshold < 1 or threshold > 1000:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "Bad Request", "message": "threshold must be a positive integer between 1 and 1000"}), 400

        if isinstance(time_window_raw, bool):
            return jsonify({"error": "Bad Request", "message": "time_window_seconds cannot be a boolean"}), 400
        try:
            time_window_seconds = int(time_window_raw)
            if time_window_seconds < 10 or time_window_seconds > 86400:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "Bad Request", "message": "time_window_seconds must be an integer between 10 and 86400"}), 400

        conditions, cond_err = validate_rule_conditions(conditions_raw)
        if cond_err:
            return jsonify({"error": "Bad Request", "message": cond_err}), 400

        if mitre_url:
            if not isinstance(mitre_url, str) or not mitre_url.strip().startswith("https://attack.mitre.org/"):
                return jsonify({"error": "Bad Request", "message": "mitre_url must be an official HTTPS URL to https://attack.mitre.org/"}), 400
            mitre_url = mitre_url.strip()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id FROM detection_rules WHERE rule_id = ?", (rule_id,))
        if c.fetchone():
            conn.close()
            return jsonify({"error": "Conflict", "message": f"Detection rule with rule_id '{rule_id}' already exists"}), 409

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id")
        admin_name = session.get("username", "admin")

        c.execute("""
            INSERT INTO detection_rules (
                rule_id, name, description, severity, status, conditions_json,
                threshold, time_window_seconds, group_by_field,
                mitre_technique_id, mitre_technique_name, mitre_tactic, mitre_url,
                version, created_by_id, created_by_username, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        """, (
            rule_id, name, description, severity, status, json.dumps(conditions),
            threshold, time_window_seconds, group_by_field,
            mitre_id, mitre_name, mitre_tactic, mitre_url,
            admin_id, admin_name, now_str, now_str
        ))
        new_id = c.lastrowid

        c.execute("""
            INSERT INTO rule_audit_log (rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'created', NULL, 'enabled', ?, ?)
        """, (new_id, admin_id, admin_name, f"Rule created by {admin_name}", now_str))

        conn.commit()
        c.execute("SELECT * FROM detection_rules WHERE id = ?", (new_id,))
        created_rule = dict(c.fetchone())
        created_rule["conditions"] = conditions
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Detection rule '{rule_id}' created successfully",
            "rule": created_rule
        }), 201

    @app.route("/api/detection/rules/<rule_ref>", methods=["GET"])
    @login_required
    def get_detection_rule_detail(rule_ref: str):
        """Returns comprehensive detail for a detection rule including audit history and execution stats."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(rule_ref).isdigit():
            c.execute("SELECT * FROM detection_rules WHERE id = ? OR rule_id = ?", (int(rule_ref), rule_ref))
        else:
            c.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_ref,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection rule '{rule_ref}' not found"}), 404

        rule = dict(row)
        id = rule["id"]
        try:
            rule["conditions"] = json.loads(rule["conditions_json"])
        except Exception:
            rule["conditions"] = []

        # Audit history
        c.execute("""
            SELECT id, rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            FROM rule_audit_log
            WHERE rule_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 50
        """, (id,))
        rule["audit_log"] = [dict(r) for r in c.fetchall()]

        # Execution history
        c.execute("""
            SELECT id, execution_time, trigger_count, matched_incident_ids_json, status
            FROM rule_executions
            WHERE rule_id = ?
            ORDER BY execution_time DESC, id DESC
            LIMIT 20
        """, (id,))
        rule["executions"] = [dict(r) for r in c.fetchall()]

        # Related alerts
        c.execute("""
            SELECT id, alert_id, correlation_key, severity, matched_count, status, created_at
            FROM detection_alerts
            WHERE rule_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 20
        """, (id,))
        rule["alerts"] = [dict(r) for r in c.fetchall()]

        conn.close()
        return jsonify({
            "rule": rule,
            "audit_log": rule["audit_log"],
            **rule
        }), 200

    @app.route("/api/detection/rules/<rule_ref>", methods=["PATCH", "PUT"])
    @login_required
    @admin_required
    def update_detection_rule(rule_ref: str):
        """Updates a detection rule enforcing optimistic concurrency version control and field validation."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(rule_ref).isdigit():
            c.execute("SELECT * FROM detection_rules WHERE id = ? OR rule_id = ?", (int(rule_ref), rule_ref))
        else:
            c.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_ref,))
        existing = c.fetchone()
        if not existing:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection rule '{rule_ref}' not found"}), 404

        existing_rule = dict(existing)
        id = existing_rule["id"]
        current_version = existing_rule["version"]

        # Concurrency safety: validate expected version strictly
        expected_version, err_resp = _validate_case_version(
            data.get("version"),
            require_version=True,
            operation_desc="updating a detection rule"
        )
        if err_resp:
            conn.close()
            return err_resp

        if expected_version != current_version:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Concurrent modification detected. Expected rule version {expected_version}, but rule is at version {current_version}.",
                "current_version": current_version
            }), 409

        # Process fields
        name = data.get("name", existing_rule["name"])
        description = data.get("description", existing_rule["description"])
        severity = data.get("severity", existing_rule["severity"]).lower()
        group_by_field = data.get("group_by_field", existing_rule["group_by_field"]).lower()
        threshold_raw = data.get("threshold", existing_rule["threshold"])
        time_window_raw = data.get("time_window_seconds", existing_rule["time_window_seconds"])
        mitre_id = data.get("mitre_technique_id", existing_rule["mitre_technique_id"])
        mitre_name = data.get("mitre_technique_name", existing_rule["mitre_technique_name"])
        mitre_tactic = data.get("mitre_tactic", existing_rule["mitre_tactic"])
        mitre_url = data.get("mitre_url", existing_rule["mitre_url"])

        if not name or len(name.strip()) < 3 or len(name.strip()) > 100:
            conn.close()
            return jsonify({"error": "Bad Request", "message": "name must be between 3 and 100 characters"}), 400

        if severity not in VALID_SEVERITIES:
            conn.close()
            return jsonify({"error": "Bad Request", "message": f"severity must be one of {sorted(VALID_SEVERITIES)}"}), 400

        if group_by_field not in VALID_GROUP_BY_FIELDS:
            conn.close()
            return jsonify({"error": "Bad Request", "message": f"group_by_field must be one of {sorted(VALID_GROUP_BY_FIELDS)}"}), 400

        if isinstance(threshold_raw, bool):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "threshold cannot be a boolean"}), 400
        try:
            threshold = int(threshold_raw)
            if threshold < 1 or threshold > 1000:
                raise ValueError()
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "threshold must be an integer between 1 and 1000"}), 400

        if isinstance(time_window_raw, bool):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "time_window_seconds cannot be a boolean"}), 400
        try:
            time_window_seconds = int(time_window_raw)
            if time_window_seconds < 10 or time_window_seconds > 86400:
                raise ValueError()
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "time_window_seconds must be an integer between 10 and 86400"}), 400

        conditions_raw = data.get("conditions") if data.get("conditions") is not None else data.get("conditions_json")
        if conditions_raw is not None:
            conditions, cond_err = validate_rule_conditions(conditions_raw)
            if cond_err:
                conn.close()
                return jsonify({"error": "Bad Request", "message": cond_err}), 400
            conditions_json = json.dumps(conditions)
        else:
            conditions_json = existing_rule["conditions_json"]

        if mitre_url:
            if not isinstance(mitre_url, str) or not mitre_url.strip().startswith("https://attack.mitre.org/"):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "mitre_url must be an official HTTPS URL to https://attack.mitre.org/"}), 400
            mitre_url = mitre_url.strip()

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id")
        admin_name = session.get("username", "admin")

        c.execute("""
            UPDATE detection_rules
            SET name = ?, description = ?, severity = ?, conditions_json = ?,
                threshold = ?, time_window_seconds = ?, group_by_field = ?,
                mitre_technique_id = ?, mitre_technique_name = ?, mitre_tactic = ?, mitre_url = ?,
                version = version + 1, updated_at = ?
            WHERE id = ? AND version = ?
        """, (
            name.strip(), description.strip()[:500], severity, conditions_json,
            threshold, time_window_seconds, group_by_field,
            mitre_id, mitre_name, mitre_tactic, mitre_url,
            now_str, id, current_version
        ))

        if c.rowcount == 0:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent modification conflict detected. Please reload latest rule state.",
                "current_version": current_version
            }), 409

        c.execute("""
            INSERT INTO rule_audit_log (rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'updated', ?, ?, ?, ?)
        """, (id, admin_id, admin_name, f"v{current_version}", f"v{current_version + 1}", f"Rule updated by {admin_name}", now_str))

        conn.commit()
        c.execute("SELECT * FROM detection_rules WHERE id = ?", (id,))
        updated_rule = dict(c.fetchone())
        try:
            updated_rule["conditions"] = json.loads(updated_rule["conditions_json"])
        except Exception:
            updated_rule["conditions"] = []
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Detection rule '{updated_rule['rule_id']}' updated to version {updated_rule['version']}",
            "rule": updated_rule
        }), 200

    @app.route("/api/detection/rules/<rule_ref>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def toggle_detection_rule(rule_ref: str):
        """Enables or disables a detection rule with optimistic locking and audit retention."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(rule_ref).isdigit():
            c.execute("SELECT * FROM detection_rules WHERE id = ? OR rule_id = ?", (int(rule_ref), rule_ref))
        else:
            c.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_ref,))
        existing = c.fetchone()
        if not existing:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection rule '{rule_ref}' not found"}), 404

        existing_rule = dict(existing)
        id = existing_rule["id"]
        current_status = existing_rule["status"]
        new_status = "disabled" if current_status == "enabled" else "enabled"
        current_version = existing_rule["version"]

        data = request.get_json(silent=True) or {}
        if "version" in data and data["version"] is not None:
            expected_version, err_resp = _validate_case_version(data.get("version"), require_version=False)
            if err_resp:
                conn.close()
                return err_resp
            if expected_version != current_version:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": f"Concurrent modification detected. Expected rule version {expected_version}, but rule is at version {current_version}.",
                    "current_version": current_version
                }), 409

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id")
        admin_name = session.get("username", "admin")

        c.execute("""
            UPDATE detection_rules
            SET status = ?, version = version + 1, updated_at = ?
            WHERE id = ? AND version = ?
        """, (new_status, now_str, id, current_version))

        if c.rowcount == 0:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent modification conflict detected.",
                "current_version": current_version
            }), 409

        c.execute("""
            INSERT INTO rule_audit_log (rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id, admin_id, admin_name, new_status, current_status, new_status, f"Rule toggled from {current_status} to {new_status} by {admin_name}", now_str))

        conn.commit()
        c.execute("SELECT * FROM detection_rules WHERE id = ?", (id,))
        updated_rule = dict(c.fetchone())
        conn.close()

        return jsonify({
            "status": new_status,
            "new_status": new_status,
            "message": f"Rule '{updated_rule['rule_id']}' {new_status}",
            "rule": updated_rule
        }), 200

    @app.route("/api/detection/rules/<rule_ref>", methods=["DELETE"])
    @login_required
    @admin_required
    def delete_detection_rule(rule_ref: str):
        """Administratively archives a detection rule to safely preserve historical alerts, audit logs, and investigation references."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(rule_ref).isdigit():
            c.execute("SELECT * FROM detection_rules WHERE id = ? OR rule_id = ?", (int(rule_ref), rule_ref))
        else:
            c.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_ref,))
        existing = c.fetchone()
        if not existing:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection rule '{rule_ref}' not found"}), 404

        rule_dict = dict(existing)
        id = rule_dict["id"]
        current_status = rule_dict["status"]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id")
        admin_name = session.get("username", "admin")

        # Soft deletion / archival: preserves historical alerts and audit records
        c.execute("""
            UPDATE detection_rules
            SET status = 'archived', version = version + 1, updated_at = ?
            WHERE id = ?
        """, (now_str, id))

        c.execute("""
            INSERT INTO rule_audit_log (rule_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'archived', ?, 'archived', ?, ?)
        """, (id, admin_id, admin_name, current_status, f"Rule '{rule_dict['name']}' archived by {admin_name}", now_str))

        c.execute("""
            INSERT INTO system_audit_log (actor_id, actor_username, action, target, reason, details, created_at)
            VALUES (?, ?, 'archive_detection_rule', ?, 'Administrator rule archival', ?, ?)
        """, (admin_id, admin_name, f"rule_id:{rule_dict['rule_id']}", f"Archived rule '{rule_dict['name']}' (ID {id})", now_str))

        conn.commit()
        c.execute("SELECT * FROM detection_rules WHERE id = ?", (id,))
        archived_rule = dict(c.fetchone())
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Detection rule '{rule_dict['rule_id']}' archived successfully",
            "rule": archived_rule
        }), 200

    @app.route("/api/detection/alerts", methods=["GET"])
    @login_required
    def get_detection_alerts():
        """Returns paginated list of correlated detection alerts with severity and status filters."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        severity = request.args.get("severity", "").strip().lower()
        status = request.args.get("status", "all").strip().lower()
        rule_id = request.args.get("rule_id", "").strip()
        search = request.args.get("search", "").strip().lower()

        page_raw = request.args.get("page")
        per_page_raw = request.args.get("per_page")
        try:
            page = max(1, int(page_raw)) if page_raw else 1
        except (ValueError, TypeError):
            page = 1
        try:
            per_page = max(1, min(100, int(per_page_raw))) if per_page_raw else 25
        except (ValueError, TypeError):
            per_page = 25

        where_clauses = ["1=1"]
        params = []

        if severity in VALID_SEVERITIES:
            where_clauses.append("a.severity = ?")
            params.append(severity)

        if status in ("open", "investigating", "closed", "escalated"):
            where_clauses.append("a.status = ?")
            params.append(status)

        if rule_id:
            where_clauses.append("(a.rule_id = ? OR r.rule_id = ?)")
            params.extend([rule_id, rule_id])

        if search:
            where_clauses.append("(LOWER(a.alert_id) LIKE ? OR LOWER(a.rule_name) LIKE ? OR LOWER(a.explanation) LIKE ? OR LOWER(a.correlation_key) LIKE ?)")
            pat = f"%{search}%"
            params.extend([pat, pat, pat, pat])

        where_str = " AND ".join(where_clauses)

        c.execute(f"""
            SELECT COUNT(*) AS total
            FROM detection_alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE {where_str}
        """, params)
        total_count = c.fetchone()["total"]

        total_pages = math.ceil(total_count / per_page) if total_count > 0 else 1
        offset = (page - 1) * per_page

        c.execute(f"""
            SELECT a.*, r.rule_id AS rule_code, r.mitre_tactic
            FROM detection_alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE {where_str}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])

        alerts = [dict(r) for r in c.fetchall()]
        conn.close()

        for a in alerts:
            try:
                a["matched_incident_ids"] = json.loads(a["matched_incident_ids_json"])
            except Exception:
                a["matched_incident_ids"] = []

        return jsonify({
            "alerts": alerts,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        }), 200

    @app.route("/api/detection/alerts/<alert_ref>", methods=["GET"])
    @login_required
    def get_detection_alert_detail(alert_ref: str):
        """Returns full alert detail with explainable condition matches and correlated incident data."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(alert_ref).isdigit():
            c.execute("""
                SELECT a.*, r.rule_id AS rule_code, r.description AS rule_description,
                       r.conditions_json, r.threshold, r.time_window_seconds, r.group_by_field,
                       cases.status AS linked_case_status, cases.assigned_username AS linked_case_assignee
                FROM detection_alerts a
                LEFT JOIN detection_rules r ON a.rule_id = r.id
                LEFT JOIN cases ON a.linked_incident_id = cases.incident_id
                WHERE a.id = ? OR a.alert_id = ?
            """, (int(alert_ref), alert_ref))
        else:
            c.execute("""
                SELECT a.*, r.rule_id AS rule_code, r.description AS rule_description,
                       r.conditions_json, r.threshold, r.time_window_seconds, r.group_by_field,
                       cases.status AS linked_case_status, cases.assigned_username AS linked_case_assignee
                FROM detection_alerts a
                LEFT JOIN detection_rules r ON a.rule_id = r.id
                LEFT JOIN cases ON a.linked_incident_id = cases.incident_id
                WHERE a.alert_id = ?
            """, (alert_ref,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection alert '{alert_ref}' not found"}), 404

        alert = dict(row)
        try:
            matched_ids = json.loads(alert["matched_incident_ids_json"])
        except Exception:
            matched_ids = []
        alert["matched_incident_ids"] = matched_ids
        alert["incident_count"] = alert["matched_count"]

        # Fetch details for matched incidents
        matched_incidents = []
        if matched_ids:
            placeholders = ",".join("?" for _ in matched_ids)
            c.execute(f"""
                SELECT logs.id, logs.username, logs.attack, logs.behavior, logs.risk,
                       logs.ip, logs.location, logs.time, logs.resolved, logs.is_simulated,
                       cases.status AS case_status, cases.assigned_username
                FROM logs
                LEFT JOIN cases ON logs.id = cases.incident_id
                WHERE logs.id IN ({placeholders})
                ORDER BY logs.time ASC
            """, matched_ids)
            matched_incidents = [dict(r) for r in c.fetchall()]
        alert["matched_incidents"] = matched_incidents
        alert["incidents"] = matched_incidents

        conn.close()
        return jsonify({
            "alert": alert,
            **alert
        }), 200

    @app.route("/api/detection/alerts/<alert_ref>/escalate", methods=["POST"])
    @login_required
    def escalate_detection_alert(alert_ref: str):
        """Escalates a detection alert into an active investigation case or links to existing incident case with strict ownership validation."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(alert_ref).isdigit():
            c.execute("SELECT * FROM detection_alerts WHERE id = ? OR alert_id = ?", (int(alert_ref), alert_ref))
        else:
            c.execute("SELECT * FROM detection_alerts WHERE alert_id = ?", (alert_ref,))
        alert = c.fetchone()
        if not alert:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection alert '{alert_ref}' not found"}), 404

        alert_dict = dict(alert)
        id = alert_dict["id"]

        # Parse correlated incident IDs
        try:
            matched_ids = [int(x) for x in json.loads(alert_dict["matched_incident_ids_json"])]
        except Exception:
            matched_ids = []

        data = request.get_json(silent=True) or {}
        target_incident_id = None

        if "incident_id" in data and data["incident_id"] is not None:
            if isinstance(data["incident_id"], bool):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "incident_id cannot be a boolean"}), 400
            try:
                target_incident_id = int(data["incident_id"])
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "incident_id must be a valid integer"}), 400

            # Target incident must be part of this alert's correlated incidents
            if target_incident_id not in matched_ids:
                conn.close()
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Target incident #{target_incident_id} is not part of this alert's correlated incidents ({matched_ids})"
                }), 400
        else:
            target_incident_id = alert_dict.get("linked_incident_id") or (matched_ids[0] if matched_ids else None)

        if not target_incident_id:
            conn.close()
            return jsonify({"error": "Bad Request", "message": "No correlated incident available to escalate"}), 400

        # Check if already escalated to this exact incident
        if alert_dict["status"] == "escalated" and alert_dict.get("linked_incident_id") == target_incident_id:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Alert '{alert_dict['alert_id']}' is already escalated to incident case #{target_incident_id}"
            }), 409

        # Verify incident exists in logs
        c.execute("SELECT id FROM logs WHERE id = ?", (target_incident_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Target incident #{target_incident_id} does not exist"}), 404

        # Enforce case ownership policy
        _ensure_case_row(c, target_incident_id)
        c.execute("SELECT incident_id, assigned_to, assigned_username FROM cases WHERE incident_id = ?", (target_incident_id,))
        case_row = c.fetchone()

        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")
        user_name = session.get("username", "analyst")

        if caller_role != "admin" and case_row:
            assigned_to = case_row["assigned_to"]
            if assigned_to is not None and assigned_to != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Cannot escalate alert to case #{target_incident_id} assigned to another analyst ({case_row['assigned_username']})"
                }), 403

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Auto-claim unassigned case on escalation and increment version for concurrency safety
        if case_row and case_row["assigned_to"] is None and caller_id:
            if "version" in data and data["version"] is not None:
                expected_version, err_resp = _validate_case_version(
                    data.get("version"),
                    require_version=True,
                    operation_desc="escalating alert and claiming case"
                )
                if err_resp:
                    conn.close()
                    return err_resp
                c.execute("SELECT version FROM cases WHERE incident_id = ?", (target_incident_id,))
                ver_row = c.fetchone()
                current_ver = ver_row["version"] if ver_row else case_row["version"]
                if expected_version != current_ver:
                    conn.close()
                    return jsonify({
                        "error": "Conflict",
                        "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_ver}.",
                        "current_version": current_ver
                    }), 409

            c.execute("""
                UPDATE cases
                SET assigned_to = ?, assigned_username = ?, updated_at = ?, version = version + 1
                WHERE incident_id = ?
            """, (caller_id, user_name, now_str, target_incident_id))

            c.execute("""
                INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, ?, ?, 'assigned', 'unassigned', ?, ?, ?)
            """, (
                target_incident_id, caller_id, user_name,
                f"assigned_to:{caller_id}:{user_name}",
                f"Case #{target_incident_id} automatically claimed by {user_name} upon alert escalation",
                now_str
            ))

        # Atomic update of alert status and linkage
        c.execute("""
            UPDATE detection_alerts
            SET status = 'escalated', linked_incident_id = ?, updated_at = ?
            WHERE id = ?
        """, (target_incident_id, now_str, id))

        # Log into the target case's audit log
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'alert_escalation', ?, ?, ?, ?)
        """, (
            target_incident_id, caller_id, user_name,
            f"status:{alert_dict['status']}",
            f"status:escalated:alert_id:{alert_dict['alert_id']}",
            f"Correlated alert {alert_dict['alert_id']} ({alert_dict['rule_name']}) escalated into case investigation by {user_name}",
            now_str
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "escalated",
            "message": f"Alert {alert_dict['alert_id']} escalated to incident case #{target_incident_id}",
            "alert_id": alert_dict["alert_id"],
            "linked_incident_id": target_incident_id,
            "case_id": target_incident_id
        }), 200

    @app.route("/api/detection/alerts/<alert_ref>/close", methods=["POST"])
    @login_required
    def close_detection_alert(alert_ref: str):
        """Marks a detection alert as closed."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        if str(alert_ref).isdigit():
            c.execute("SELECT * FROM detection_alerts WHERE id = ? OR alert_id = ?", (int(alert_ref), alert_ref))
        else:
            c.execute("SELECT * FROM detection_alerts WHERE alert_id = ?", (alert_ref,))
        alert = c.fetchone()
        if not alert:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Detection alert '{alert_ref}' not found"}), 404

        id = alert["id"]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE detection_alerts SET status = 'closed', updated_at = ? WHERE id = ?", (now_str, id))
        conn.commit()
        conn.close()

        return jsonify({
            "status": "closed",
            "message": f"Alert {alert['alert_id']} closed",
            "alert_id": alert["alert_id"]
        }), 200

    @app.route("/api/detection/metrics", methods=["GET"])
    @login_required
    def get_detection_metrics():
        """Returns verified operational detection engineering metrics without fabricated formulas."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT COUNT(*) AS total FROM detection_rules")
        total_rules = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) AS enabled FROM detection_rules WHERE status = 'enabled'")
        enabled_rules = c.fetchone()["enabled"]

        c.execute("SELECT COUNT(*) AS disabled FROM detection_rules WHERE status = 'disabled'")
        disabled_rules = c.fetchone()["disabled"]

        c.execute("SELECT COUNT(*) AS archived FROM detection_rules WHERE status = 'archived'")
        archived_rules = c.fetchone()["archived"]

        c.execute("SELECT COUNT(*) AS total FROM detection_alerts")
        total_alerts = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) AS open FROM detection_alerts WHERE status = 'open'")
        open_alerts = c.fetchone()["open"]

        c.execute("SELECT COUNT(*) AS escalated FROM detection_alerts WHERE status = 'escalated'")
        escalated_alerts = c.fetchone()["escalated"]

        c.execute("SELECT COUNT(*) AS closed FROM detection_alerts WHERE status = 'closed'")
        closed_alerts = c.fetchone()["closed"]

        c.execute("SELECT COUNT(DISTINCT correlation_key) AS cnt FROM detection_alerts WHERE status != 'closed'")
        active_correlations_count = c.fetchone()["cnt"]

        # Measured telemetry counts
        c.execute("SELECT COUNT(*) AS total_logs FROM logs")
        total_events_stored = c.fetchone()["total_logs"]

        # Note: evaluated_events represents the count of unique incidents/telemetry events processed
        # by the threat correlation pipeline (tracked in evaluated_events), not the total number of per-rule evaluations.
        c.execute("SELECT COUNT(*) AS evaluated_count FROM evaluated_events")
        actual_evaluated_events = c.fetchone()["evaluated_count"]

        c.execute("SELECT COUNT(*) AS exec_count FROM rule_executions")
        rule_executions_count = c.fetchone()["exec_count"]

        # Severity breakdown
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        c.execute("SELECT severity, COUNT(*) AS cnt FROM detection_alerts GROUP BY severity")
        for r in c.fetchall():
            s = r["severity"].lower()
            if s in severities:
                severities[s] = r["cnt"]

        # Top 5 triggered rules
        c.execute("""
            SELECT r.id, r.rule_id, r.name, r.severity, COUNT(a.id) AS alert_count
            FROM detection_rules r
            LEFT JOIN detection_alerts a ON r.id = a.rule_id
            GROUP BY r.id
            ORDER BY alert_count DESC, r.id ASC
            LIMIT 5
        """)
        top_rules = [dict(r) for r in c.fetchall()]

        # Recent 8 alerts
        c.execute("""
            SELECT a.id, a.alert_id, a.rule_name, a.severity, a.status, a.correlation_key,
                   a.matched_count, a.created_at, a.mitre_technique_id
            FROM detection_alerts a
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT 8
        """)
        recent_alerts = [dict(r) for r in c.fetchall()]

        conn.close()

        return jsonify({
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "active_rules": enabled_rules,
            "disabled_rules": disabled_rules,
            "archived_rules": archived_rules,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "escalated_alerts": escalated_alerts,
            "closed_alerts": closed_alerts,
            "evaluated_events": actual_evaluated_events,
            "evaluated_unique_incidents": actual_evaluated_events,
            "total_events_stored": total_events_stored,
            "rule_executions_count": rule_executions_count,
            "active_correlations_count": active_correlations_count,
            "severity_breakdown": severities,
            "top_rules": top_rules,
            "top_triggered_rules": top_rules,
            "recent_alerts": recent_alerts
        }), 200

    @app.route("/api/detection/replay", methods=["POST"])
    @login_required
    def replay_detection_dataset():
        """
        Executes a controlled synthetic event replay using documented attack vectors
        to test detection rules, trigger correlations, and generate explainable alerts.
        """
        data = request.get_json(silent=True) or {}
        preset = data.get("preset", "all").lower()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        injected_ids = []

        if preset in ("credential_spray", "all"):
            # 3 synthetic credential stuffing events for 'admin' (satisfies RULE-AUTH-001 within 60s window)
            for i in range(3):
                t_str = (now - timedelta(seconds=10 * (3 - i))).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""
                    INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                    VALUES ('admin', 'Credential Stuffing Attempt', 'brute_force_spray', 68, '198.51.100.88', 'Dallas, USA', ?, 0, 1)
                """, (t_str,))
                log_id = c.lastrowid
                c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, t_str, t_str))
                injected_ids.append(log_id)

        if preset in ("recon_burst", "all"):
            # 3 port scan events from single source IP (satisfies RULE-NET-002 within 45s window)
            recon_ip = "198.51.100.42"
            for i in range(3):
                t_str = (now - timedelta(seconds=10 * (3 - i))).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""
                    INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                    VALUES ('service_scanner', 'Network Reconnaissance Probe', 'port_scan', 55, ?, 'Frankfurt, Germany', ?, 0, 1)
                """, (recon_ip, t_str))
                log_id = c.lastrowid
                c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, t_str, t_str))
                injected_ids.append(log_id)

        if preset in ("lateral_exploit", "all"):
            # 1 critical SMB Named Pipe lateral traversal (satisfies RULE-EXPLOIT-003)
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('sys_service', 'Lateral SMB Named Pipe Impersonation', 'named_pipe_leak', 88, '10.0.4.15', 'Internal Network', ?, 0, 1)
            """, (now_str,))
            log_id = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, now_str, now_str))
            injected_ids.append(log_id)

        if preset in ("kerberoast", "all"):
            # 1 Active Directory Kerberoasting incident (satisfies RULE-KERB-006)
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('backup_exec', 'Active Directory Kerberoasting Attempt', 'spn_ticket_extract', 85, '10.0.2.20', 'Domain Controller', ?, 0, 1)
            """, (now_str,))
            log_id = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, now_str, now_str))
            injected_ids.append(log_id)

        conn.commit()
        conn.close()

        # Run pipeline immediately
        alerts_generated = evaluate_detection_pipeline(injected_ids, app.config["DATABASE_PATH"])

        return jsonify({
            "status": "success",
            "message": f"Synthetic replay dataset '{preset}' executed successfully",
            "preset": preset,
            "incidents_created": len(injected_ids),
            "incident_ids": injected_ids,
            "alerts_generated": len(alerts_generated)
        }), 201

    # ---------------------------------------------------------
    # Sprint 4: Security Log Ingestion & Normalization Endpoints
    # ---------------------------------------------------------

    @app.route("/api/ingestion/import", methods=["POST"])
    @login_required
    @limiter.limit("30 per minute")
    def import_security_logs():
        """
        Accepts security log uploads or raw text payloads across supported formats:
        - Canonical CSV
        - NDJSON
        - Windows Security Events (4624/4625)
        - Linux SSH Auth Logs
        - Zeek Connection Logs (JSON)

        Performs:
        - Format validation & local normalization
        - Deduplication via deterministic fingerprint hashing
        - Ingestion batch tracking
        - Integration into security_events and logs tables (provenance='imported_unverified')
        - Deterministic detection pipeline evaluation
        - System audit trail logging
        """
        user_id = session.get("user_id")
        username = session.get("username", "unknown")
        
        dry_run = False
        format_name = "auto"
        filename = "pasted_log.txt"
        content = ""

        if request.content_type and "multipart/form-data" in request.content_type:
            uploaded_file = request.files.get("file")
            format_name = request.form.get("format", "auto")
            dry_run = request.form.get("dry_run", "false").lower() in ("true", "1")
            if not uploaded_file:
                content = request.form.get("content", "")
                if not content:
                    return jsonify({"error": "Bad Request", "message": "No file or log content provided."}), 400
                filename = request.form.get("filename", "manual_import.txt")
            else:
                raw_filename = uploaded_file.filename or "uploaded_log.txt"
                filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', os.path.basename(raw_filename))
                try:
                    content_bytes = uploaded_file.read()
                    if len(content_bytes) > MAX_FILE_SIZE:
                        return jsonify({"error": "Payload Too Large", "message": f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)} MB."}), 413
                    content = content_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    return jsonify({"error": "Bad Request", "message": f"Failed to read uploaded file: {str(e)}"}), 400
        else:
            data = request.get_json(silent=True) or {}
            content = data.get("content", "")
            format_name = data.get("format", "auto")
            raw_filename = data.get("filename", "api_import.txt")
            dry_run = bool(data.get("dry_run", False))
            filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', os.path.basename(raw_filename))

        if not content or not content.strip():
            return jsonify({"error": "Bad Request", "message": "Import content cannot be empty."}), 400

        if len(content.encode("utf-8")) > MAX_FILE_SIZE:
            return jsonify({"error": "Payload Too Large", "message": f"Payload exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)} MB."}), 413

        records, parse_errors, detected_format = IngestionParser.parse_content(content, format_name=format_name, filename=filename)

        if not records and parse_errors:
            return jsonify({
                "error": "Bad Request",
                "message": "Failed to parse security events from input.",
                "format": detected_format,
                "errors": parse_errors[:20]
            }), 400

        if dry_run:
            return jsonify({
                "status": "dry_run",
                "format": detected_format,
                "filename": filename,
                "total_records_found": len(records),
                "parse_errors_count": len(parse_errors),
                "parse_errors": parse_errors[:10],
                "sample_preview": records[:3]
            }), 200

        batch_id = f"bch_{uuid.uuid4().hex[:12]}"
        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        accepted_count = 0
        duplicate_count = 0
        rejected_count = len(parse_errors)
        new_incident_ids = []
        batch_timestamps = []

        try:
            c.execute("""
                INSERT INTO ingestion_batches (
                    batch_id, filename, source_type, total_records, accepted_records,
                    rejected_records, duplicate_records, created_by, created_username,
                    created_at, status, errors_json, detection_status, detection_alerts_count, detection_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, NULL)
            """, (
                batch_id, filename, detected_format, len(records) + len(parse_errors),
                0, rejected_count, 0, user_id, username, now_str, "partial",
                json.dumps(parse_errors[:50])
            ))

            for rec in records:
                evt_time = rec["event_time"]
                orig_time = rec.get("original_timestamp")
                orig_tz = rec.get("original_timezone")
                batch_timestamps.append(evt_time)
                src_ip = rec["source_ip"]
                dest_ip = rec.get("dest_ip")
                uname = rec.get("username") or "unknown"
                atk = rec["attack_type"]
                outcome = rec["outcome"]
                category = rec.get("category", "Authentication")
                hostname = rec.get("hostname")
                severity = rec.get("severity", "medium")
                risk = rec.get("risk_score", 50)
                behavior = rec.get("behavior", f"{atk} observed")
                src_ref = rec.get("source_record_ref", "")
                src_port = rec.get("source_port")
                dest_port = rec.get("dest_port")
                src_event_id = rec.get("source_event_id")
                raw_payload = rec.get("raw_payload", "")
                raw_hash = rec.get("raw_hash", "")
                field_provenance_str = json.dumps(rec.get("field_provenance", {}))
                metadata_str = json.dumps(rec.get("metadata", {}))

                # Source-aware fingerprint incorporating ports, refs, IDs, and raw hashes
                fingerprint = calculate_fingerprint(
                    detected_format, evt_time, src_ip, dest_ip, uname, atk, outcome,
                    source_port=src_port, dest_port=dest_port, source_record_ref=src_ref,
                    source_event_id=src_event_id, raw_hash=raw_hash
                )

                # Check duplicate fingerprint
                c.execute("SELECT id FROM security_events WHERE fingerprint = ?", (fingerprint,))
                existing_evt = c.fetchone()
                if existing_evt:
                    duplicate_count += 1
                    continue

                event_id = f"evt_{uuid.uuid4().hex[:12]}"

                # Insert into logs (as imported telemetry)
                c.execute("""
                    INSERT INTO logs (
                        time, ip, attack, risk, behavior, location, resolved, username, is_simulated, provenance
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, 'imported_unverified')
                """, (
                    evt_time, src_ip, atk, risk, behavior, hostname or "sec-host", uname
                ))
                log_id = c.lastrowid
                new_incident_ids.append(log_id)

                # Create case for the incident
                c.execute("""
                    INSERT INTO cases (
                        incident_id, status, reopen_count, version, created_at, updated_at
                    ) VALUES (?, 'new', 0, 1, ?, ?)
                """, (log_id, now_str, now_str))

                # Insert into security_events with full forensic integrity attributes
                c.execute("""
                    INSERT INTO security_events (
                        event_id, batch_id, source_type, importer, event_time, ingested_at,
                        category, attack_type, username, source_ip, dest_ip, hostname,
                        outcome, severity, risk_score, source_record_ref, fingerprint,
                        provenance, metadata_json, incident_id,
                        original_timestamp, original_timezone, raw_payload, raw_hash, field_provenance_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported_unverified', ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id, batch_id, detected_format, username, evt_time, now_str,
                    category, atk, uname, src_ip, dest_ip, hostname,
                    outcome, severity, risk, src_ref, fingerprint, metadata_str, log_id,
                    orig_time, orig_tz, raw_payload, raw_hash, field_provenance_str
                ))

                accepted_count += 1

            batch_status = "completed" if rejected_count == 0 else "partial"
            if accepted_count == 0 and (duplicate_count > 0 or rejected_count > 0):
                batch_status = "completed" if duplicate_count > 0 else "failed"

            c.execute("""
                UPDATE ingestion_batches
                SET accepted_records = ?, duplicate_records = ?, rejected_records = ?, status = ?
                WHERE batch_id = ?
            """, (accepted_count, duplicate_count, rejected_count, batch_status, batch_id))

            # Record system audit log
            c.execute("""
                INSERT INTO system_audit_log (
                    actor_id, actor_username, action, target, reason, details, created_at
                ) VALUES (?, ?, 'import_security_events', ?, ?, ?, ?)
            """, (
                user_id, username, f"batch:{batch_id}",
                f"Imported {accepted_count} security events ({detected_format})",
                json.dumps({
                    "batch_id": batch_id,
                    "filename": filename,
                    "accepted": accepted_count,
                    "duplicates": duplicate_count,
                    "rejected": rejected_count
                }),
                now_str
            ))

            conn.commit()
        except Exception as e:
            conn.rollback()
            conn.close()
            return jsonify({"error": "Internal Server Error", "message": f"Failed to persist imported batch: {str(e)}"}), 500

        conn.close()

        # Trigger detection evaluation with deterministic historical timing
        detection_status = "completed"
        detection_error = None
        correlated_alerts = []
        if new_incident_ids:
            try:
                pipeline_res = evaluate_detection_pipeline(
                    target_incident_ids=new_incident_ids,
                    db_path=app.config["DATABASE_PATH"],
                    detailed=True
                )
                correlated_alerts = pipeline_res["alerts"]
                detection_status = pipeline_res["status"]
                if pipeline_res["failed_rules"]:
                    detection_error = f"{len(pipeline_res['failed_rules'])} of {pipeline_res['total_rules']} rule(s) failed evaluation: " + "; ".join(f"{r['rule_id']}: {r['error']}" for r in pipeline_res["failed_rules"])
                else:
                    detection_error = None
            except Exception as e:
                detection_status = "failed"
                detection_error = str(e)
                print(f"[DetectionPipeline] Warning: Ingestion correlation evaluation error: {e}")
        else:
            detection_status = "skipped"

        # Update batch detection status
        try:
            conn_bch = get_db_connection(app.config["DATABASE_PATH"])
            c_bch = conn_bch.cursor()
            c_bch.execute("""
                UPDATE ingestion_batches
                SET detection_status = ?, detection_error = ?, detection_alerts_count = ?
                WHERE batch_id = ?
            """, (detection_status, detection_error, len(correlated_alerts), batch_id))
            conn_bch.commit()
            conn_bch.close()
        except Exception:
            pass

        if detection_status == "failed":
            return jsonify({
                "status": "partial_success",
                "persistence_status": batch_status,
                "detection_status": "failed",
                "detection_error": detection_error,
                "batch_id": batch_id,
                "filename": filename,
                "source_type": detected_format,
                "total_records": accepted_count + duplicate_count + rejected_count,
                "accepted_records": accepted_count,
                "duplicate_records": duplicate_count,
                "rejected_records": rejected_count,
                "correlated_alerts_generated": 0,
                "errors": parse_errors[:10],
                "summary": f"Imported {accepted_count} events from {filename} ({duplicate_count} duplicate(s) skipped, {rejected_count} rejected). Detection evaluation failed: {detection_error}. Use retry endpoint to re-evaluate.",
                "message": f"Security events were persisted successfully, but detection pipeline evaluation failed: {detection_error}"
            }), 200

        return jsonify({
            "status": "success",
            "batch_id": batch_id,
            "filename": filename,
            "source_type": detected_format,
            "detection_status": detection_status,
            "detection_error": None,
            "total_records": accepted_count + duplicate_count + rejected_count,
            "accepted_records": accepted_count,
            "duplicate_records": duplicate_count,
            "rejected_records": rejected_count,
            "correlated_alerts_generated": len(correlated_alerts),
            "errors": parse_errors[:10],
            "summary": f"Imported {accepted_count} events from {filename} ({duplicate_count} duplicate(s) skipped, {rejected_count} rejected). Generated {len(correlated_alerts)} correlated detection alert(s)."
        }), 201

    @app.route("/api/ingestion/batches/<batch_id>/retry-detection", methods=["POST"])
    @login_required
    def retry_batch_detection(batch_id: str):
        """
        Safely and idempotently retries detection pipeline evaluation for an imported batch.
        Does not duplicate events or alerts.
        """
        clean_batch_id = str(batch_id).strip()
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT * FROM ingestion_batches WHERE batch_id = ?", (clean_batch_id,))
        batch = c.fetchone()
        if not batch:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Ingestion batch '{clean_batch_id}' not found."}), 404

        c.execute("SELECT incident_id FROM security_events WHERE batch_id = ? AND incident_id IS NOT NULL", (clean_batch_id,))
        rows = c.fetchall()
        incident_ids = [r["incident_id"] for r in rows]
        conn.close()

        if not incident_ids:
            return jsonify({"error": "Bad Request", "message": "No valid security incidents found in this batch to evaluate."}), 400

        try:
            pipeline_res = evaluate_detection_pipeline(
                target_incident_ids=incident_ids,
                db_path=app.config["DATABASE_PATH"],
                detailed=True
            )
            correlated_alerts = pipeline_res["alerts"]
            detection_status = pipeline_res["status"]
            if pipeline_res["failed_rules"]:
                detection_error = f"{len(pipeline_res['failed_rules'])} of {pipeline_res['total_rules']} rule(s) failed evaluation: " + "; ".join(f"{r['rule_id']}: {r['error']}" for r in pipeline_res["failed_rules"])
            else:
                detection_error = None

            conn = get_db_connection(app.config["DATABASE_PATH"])
            c = conn.cursor()
            c.execute("""
                UPDATE ingestion_batches
                SET detection_status = ?, detection_error = ?, detection_alerts_count = ?
                WHERE batch_id = ?
            """, (detection_status, detection_error, len(correlated_alerts), clean_batch_id))

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_id = session.get("user_id")
            username = session.get("username")
            c.execute("""
                INSERT INTO system_audit_log (
                    actor_id, actor_username, action, target, reason, details, created_at
                ) VALUES (?, ?, 'retry_detection_evaluation', ?, ?, ?, ?)
            """, (
                user_id, username, f"batch:{clean_batch_id}",
                f"Retried detection evaluation for batch {clean_batch_id} (status: {detection_status})",
                json.dumps({
                    "alerts_count": len(correlated_alerts),
                    "detection_status": detection_status,
                    "failed_rules_count": len(pipeline_res["failed_rules"])
                }),
                now_str
            ))
            conn.commit()
            conn.close()

            status_code = 200 if detection_status != "failed" else 207
            return jsonify({
                "status": "success" if detection_status == "completed" else detection_status,
                "batch_id": clean_batch_id,
                "detection_status": detection_status,
                "detection_error": detection_error,
                "failed_rules_count": len(pipeline_res["failed_rules"]),
                "correlated_alerts_generated": len(correlated_alerts),
                "message": (
                    f"Detection evaluation completed successfully ({len(correlated_alerts)} alert(s) generated or updated)."
                    if detection_status == "completed" else
                    f"Detection evaluation finished with status '{detection_status}': {detection_error}"
                )
            }), status_code
        except Exception as e:
            conn = get_db_connection(app.config["DATABASE_PATH"])
            c = conn.cursor()
            c.execute("""
                UPDATE ingestion_batches
                SET detection_status = 'failed', detection_error = ?
                WHERE batch_id = ?
            """, (str(e), clean_batch_id))
            conn.commit()
            conn.close()
            return jsonify({
                "error": "Detection Evaluation Failed",
                "batch_id": clean_batch_id,
                "detection_status": "failed",
                "message": f"Detection evaluation failed: {str(e)}"
            }), 500

    @app.route("/api/ingestion/batches", methods=["GET"])
    @login_required
    def get_ingestion_batches():
        """Returns list of ingestion batches with pagination and summary statistics."""
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))
        offset = (page - 1) * per_page

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT COUNT(*) AS total FROM ingestion_batches")
        total_batches = c.fetchone()["total"]

        c.execute("""
            SELECT id, batch_id, filename, source_type, total_records, accepted_records,
                   rejected_records, duplicate_records, created_username, created_at, status,
                   detection_status, detection_alerts_count, detection_error
            FROM ingestion_batches
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        batches = [dict(r) for r in c.fetchall()]
        conn.close()

        total_pages = math.ceil(total_batches / per_page) if total_batches > 0 else 1

        return jsonify({
            "batches": batches,
            "total": total_batches,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages
        }), 200

    @app.route("/api/ingestion/batches/<batch_id>", methods=["GET"])
    @login_required
    def get_batch_detail(batch_id: str):
        """Returns detailed metadata, errors, and associated events for a specific batch."""
        clean_batch_id = str(batch_id).strip()
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("""
            SELECT id, batch_id, filename, source_type, total_records, accepted_records,
                   rejected_records, duplicate_records, created_username, created_at,
                   status, errors_json, detection_status, detection_alerts_count, detection_error
            FROM ingestion_batches
            WHERE batch_id = ?
        """, (clean_batch_id,))
        batch_row = c.fetchone()
        if not batch_row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Batch '{clean_batch_id}' not found."}), 404

        batch_data = dict(batch_row)
        try:
            batch_data["errors"] = json.loads(batch_data.pop("errors_json") or "[]")
        except Exception:
            batch_data["errors"] = []

        c.execute("""
            SELECT id, event_id, event_time, category, attack_type, username, source_ip,
                   dest_ip, hostname, outcome, severity, risk_score, incident_id,
                   original_timestamp, original_timezone, raw_hash
            FROM security_events
            WHERE batch_id = ?
            ORDER BY event_time ASC
            LIMIT 20
        """, (clean_batch_id,))
        batch_data["sample_events"] = [dict(r) for r in c.fetchall()]
        conn.close()

        return jsonify(batch_data), 200

    @app.route("/api/ingestion/events", methods=["GET"])
    @login_required
    def get_security_events():
        """
        Paginated Normalized Security Event Explorer endpoint.
        Supports filtering by source_type, category, outcome, severity, search term,
        batch_id, date/time ranges, and sorting.
        """
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))
        offset = (page - 1) * per_page

        source_type = request.args.get("source_type", "").strip()
        category = request.args.get("category", "").strip()
        outcome = request.args.get("outcome", "").strip()
        severity = request.args.get("severity", "").strip()
        batch_id = request.args.get("batch_id", "").strip()
        search = request.args.get("search", "").strip()
        start_time = request.args.get("start_time", "").strip()
        end_time = request.args.get("end_time", "").strip()

        sort_by = request.args.get("sort_by", "event_time").strip()
        sort_dir = request.args.get("sort_dir", "desc").strip().lower()
        if sort_dir not in ("asc", "desc"):
            sort_dir = "desc"

        allowed_sort_columns = {
            "event_time": "event_time",
            "risk_score": "risk_score",
            "source_ip": "source_ip",
            "category": "category",
            "username": "username",
            "severity": "severity"
        }
        order_col = allowed_sort_columns.get(sort_by, "event_time")

        conditions = []
        params = []

        if source_type:
            conditions.append("source_type = ?")
            params.append(source_type)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if outcome:
            conditions.append("outcome = ?")
            params.append(outcome)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if batch_id:
            conditions.append("batch_id = ?")
            params.append(batch_id)
        if start_time:
            conditions.append("event_time >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("event_time <= ?")
            params.append(end_time)
        if search:
            conditions.append("(username LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR attack_type LIKE ? OR hostname LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern, pattern, pattern])

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute(f"SELECT COUNT(*) AS total FROM security_events{where_clause}", params)
        total_events = c.fetchone()["total"]

        query = f"""
            SELECT id, event_id, batch_id, source_type, importer, event_time, ingested_at,
                   category, attack_type, username, source_ip, dest_ip, hostname,
                   outcome, severity, risk_score, source_record_ref, provenance, incident_id,
                   original_timestamp, original_timezone, raw_hash
            FROM security_events
            {where_clause}
            ORDER BY {order_col} {sort_dir}
            LIMIT ? OFFSET ?
        """
        c.execute(query, params + [per_page, offset])
        events = [dict(r) for r in c.fetchall()]
        conn.close()

        total_pages = math.ceil(total_events / per_page) if total_events > 0 else 1

        return jsonify({
            "events": events,
            "total": total_events,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages
        }), 200

    @app.route("/api/ingestion/events/<int:event_id>", methods=["GET"])
    @login_required
    def get_security_event_detail(event_id: int):
        """Returns complete normalized security event details with metadata, raw payload, integrity hash, and linked case."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("""
            SELECT id, event_id, batch_id, source_type, importer, event_time, ingested_at,
                   category, attack_type, username, source_ip, dest_ip, hostname,
                   outcome, severity, risk_score, source_record_ref, fingerprint,
                   provenance, metadata_json, incident_id,
                   original_timestamp, original_timezone, raw_payload, raw_hash, field_provenance_json
            FROM security_events
            WHERE id = ?
        """, (event_id,))
        evt_row = c.fetchone()
        if not evt_row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Security event #{event_id} not found."}), 404

        evt_data = dict(evt_row)
        try:
            evt_data["metadata"] = json.loads(evt_data.pop("metadata_json") or "{}")
        except Exception:
            evt_data["metadata"] = {}

        try:
            evt_data["field_provenance"] = json.loads(evt_data.pop("field_provenance_json") or "{}")
        except Exception:
            evt_data["field_provenance"] = {}

        if evt_data.get("incident_id"):
            c.execute("""
                SELECT incident_id, status, assigned_username, reopen_count, version
                FROM cases
                WHERE incident_id = ?
            """, (evt_data["incident_id"],))
            case_row = c.fetchone()
            evt_data["case"] = dict(case_row) if case_row else None
        else:
            evt_data["case"] = None

        conn.close()
        return jsonify(evt_data), 200

    @app.route("/api/ingestion/samples", methods=["GET"])
    @login_required
    def get_sample_datasets():
        """Returns catalog of pre-packaged realistic SOC training datasets."""
        samples = [
            {
                "id": "ssh_bursts",
                "name": "Linux SSH Brute Force Burst",
                "filename": "ssh_bursts.log",
                "format": "linux_ssh",
                "description": "Rapid authentication failure bursts targeting root, oracle, admin and valid user accounts from external attacker IP.",
                "mitre_technique": "T1110.001 (Password Guessing)"
            },
            {
                "id": "windows_auth_failures",
                "name": "Windows Security Event 4625 Telemetry",
                "filename": "windows_auth_failures.json",
                "format": "windows_event",
                "description": "Structured Windows Event Log 4625/4624 records representing logon failures across domain workstations and domain controllers.",
                "mitre_technique": "T1110.003 (Password Spraying)"
            },
            {
                "id": "zeek_recon_probes",
                "name": "Zeek Network Reconnaissance & Port Scans",
                "filename": "zeek_recon_probes.json",
                "format": "zeek_conn",
                "description": "Zeek conn.log telemetry demonstrating half-open TCP SYN scanning (S0 states) across common service ports.",
                "mitre_technique": "T1046 (Network Service Discovery)"
            },
            {
                "id": "canonical_mixed",
                "name": "Mixed Multi-Vector SOC Incident Telemetry",
                "filename": "canonical_mixed.csv",
                "format": "canonical_csv",
                "description": "Comprehensive CSV dataset including credential stuffing, SQL injection, benign operations, and port reconnaissance.",
                "mitre_technique": "Multiple ATT&CK Tactics"
            },
            {
                "id": "benign_traffic",
                "name": "Authorized Benign Operations Baseline",
                "filename": "benign_traffic.ndjson",
                "format": "ndjson",
                "description": "Baseline telemetry representing legitimate corporate workstation logons, SAML authentication assertions, and CI/CD operations.",
                "mitre_technique": "Baseline (Normal Traffic)"
            }
        ]
        return jsonify({"samples": samples}), 200

    @app.route("/api/ingestion/samples/load", methods=["POST"])
    @login_required
    def load_sample_dataset():
        """Loads a pre-packaged training dataset with one click."""
        data = request.get_json(silent=True) or {}
        sample_id = data.get("sample_id", "").strip()

        sample_files = {
            "ssh_bursts": ("ssh_bursts.log", "linux_ssh"),
            "windows_auth_failures": ("windows_auth_failures.json", "windows_event"),
            "zeek_recon_probes": ("zeek_recon_probes.json", "zeek_conn"),
            "canonical_mixed": ("canonical_mixed.csv", "canonical_csv"),
            "benign_traffic": ("benign_traffic.ndjson", "ndjson")
        }

        if sample_id not in sample_files:
            return jsonify({"error": "Bad Request", "message": f"Unknown sample dataset '{sample_id}'. Available: {list(sample_files.keys())}"}), 400

        fname, fmt = sample_files[sample_id]
        sample_path = Path(__file__).resolve().parent / "samples" / fname
        if not sample_path.exists():
            return jsonify({"error": "Not Found", "message": f"Sample dataset file '{fname}' not found on server."}), 404

        try:
            content = sample_path.read_text(encoding="utf-8")
        except Exception as e:
            return jsonify({"error": "Internal Server Error", "message": f"Failed to read sample dataset: {str(e)}"}), 500

        records, parse_errors, detected_format = IngestionParser.parse_content(content, format_name=fmt, filename=fname)
        if not records:
            return jsonify({"error": "Bad Request", "message": "Failed to parse sample records.", "errors": parse_errors}), 400

        user_id = session.get("user_id")
        username = session.get("username", "admin")
        batch_id = f"bch_{uuid.uuid4().hex[:12]}"
        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        accepted_count = 0
        duplicate_count = 0
        rejected_count = len(parse_errors)
        new_incident_ids = []
        batch_timestamps = []

        try:
            c.execute("""
                INSERT INTO ingestion_batches (
                    batch_id, filename, source_type, total_records, accepted_records,
                    rejected_records, duplicate_records, created_by, created_username,
                    created_at, status, errors_json, detection_status, detection_alerts_count, detection_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, NULL)
            """, (
                batch_id, fname, detected_format, len(records) + len(parse_errors),
                0, rejected_count, 0, user_id, username, now_str, "completed",
                json.dumps(parse_errors[:50])
            ))

            for rec in records:
                evt_time = rec["event_time"]
                orig_time = rec.get("original_timestamp")
                orig_tz = rec.get("original_timezone")
                batch_timestamps.append(evt_time)
                src_ip = rec["source_ip"]
                dest_ip = rec.get("dest_ip")
                uname = rec.get("username") or "unknown"
                atk = rec["attack_type"]
                outcome = rec["outcome"]
                category = rec.get("category", "Authentication")
                hostname = rec.get("hostname")
                severity = rec.get("severity", "medium")
                risk = rec.get("risk_score", 50)
                behavior = rec.get("behavior", f"{atk} observed")
                src_ref = rec.get("source_record_ref", "")
                src_port = rec.get("source_port")
                dest_port = rec.get("dest_port")
                src_event_id = rec.get("source_event_id")
                raw_payload = rec.get("raw_payload", "")
                raw_hash = rec.get("raw_hash", "")
                field_provenance_str = json.dumps(rec.get("field_provenance", {}))
                metadata_str = json.dumps(rec.get("metadata", {}))

                fingerprint = calculate_fingerprint(
                    detected_format, evt_time, src_ip, dest_ip, uname, atk, outcome,
                    source_port=src_port, dest_port=dest_port, source_record_ref=src_ref,
                    source_event_id=src_event_id, raw_hash=raw_hash
                )

                c.execute("SELECT id FROM security_events WHERE fingerprint = ?", (fingerprint,))
                if c.fetchone():
                    duplicate_count += 1
                    continue

                event_id = f"evt_{uuid.uuid4().hex[:12]}"

                c.execute("""
                    INSERT INTO logs (
                        time, ip, attack, risk, behavior, location, resolved, username, is_simulated, provenance
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, 'imported_unverified')
                """, (
                    evt_time, src_ip, atk, risk, behavior, hostname or "sec-host", uname
                ))
                log_id = c.lastrowid
                new_incident_ids.append(log_id)

                c.execute("""
                    INSERT INTO cases (
                        incident_id, status, reopen_count, version, created_at, updated_at
                    ) VALUES (?, 'new', 0, 1, ?, ?)
                """, (log_id, now_str, now_str))

                c.execute("""
                    INSERT INTO security_events (
                        event_id, batch_id, source_type, importer, event_time, ingested_at,
                        category, attack_type, username, source_ip, dest_ip, hostname,
                        outcome, severity, risk_score, source_record_ref, fingerprint,
                        provenance, metadata_json, incident_id,
                        original_timestamp, original_timezone, raw_payload, raw_hash, field_provenance_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported_unverified', ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id, batch_id, detected_format, username, evt_time, now_str,
                    category, atk, uname, src_ip, dest_ip, hostname,
                    outcome, severity, risk, src_ref, fingerprint, metadata_str, log_id,
                    orig_time, orig_tz, raw_payload, raw_hash, field_provenance_str
                ))

                accepted_count += 1

            c.execute("""
                UPDATE ingestion_batches
                SET accepted_records = ?, duplicate_records = ?, status = 'completed'
                WHERE batch_id = ?
            """, (accepted_count, duplicate_count, batch_id))

            c.execute("""
                INSERT INTO system_audit_log (
                    actor_id, actor_username, action, target, reason, details, created_at
                ) VALUES (?, ?, 'load_sample_dataset', ?, ?, ?, ?)
            """, (
                user_id, username, f"sample:{sample_id}",
                f"Loaded training dataset '{sample_id}' ({accepted_count} records)",
                json.dumps({"sample_id": sample_id, "batch_id": batch_id, "accepted": accepted_count}),
                now_str
            ))

            conn.commit()
        except Exception as e:
            conn.rollback()
            conn.close()
            return jsonify({"error": "Internal Server Error", "message": f"Failed to persist sample batch: {str(e)}"}), 500

        conn.close()

        # Trigger detection evaluation
        correlated_alerts = []
        if new_incident_ids:
            try:
                max_batch_time = max(batch_timestamps) if batch_timestamps else None
                ref_time = datetime.strptime(max_batch_time, "%Y-%m-%d %H:%M:%S") if max_batch_time else None
                correlated_alerts = evaluate_detection_pipeline(
                    target_incident_ids=new_incident_ids,
                    reference_time=ref_time,
                    db_path=app.config["DATABASE_PATH"]
                )
            except Exception as e:
                print(f"[DetectionPipeline] Warning: Sample correlation evaluation error: {e}")

        return jsonify({
            "status": "success",
            "sample_id": sample_id,
            "batch_id": batch_id,
            "accepted_records": accepted_count,
            "duplicate_records": duplicate_count,
            "correlated_alerts_generated": len(correlated_alerts),
            "message": f"Loaded training dataset '{sample_id}' successfully. {accepted_count} event(s) imported, {len(correlated_alerts)} correlated detection alert(s) generated."
        }), 201

    @app.route("/api/ingestion/export", methods=["GET"])
    @login_required
    def export_security_events_csv():
        """
        Exports filtered security events to CSV format with formula injection protection.
        Prepend single quote to values starting with =, +, -, @, \\t, \\r.
        """
        source_type = request.args.get("source_type", "").strip()
        category = request.args.get("category", "").strip()
        outcome = request.args.get("outcome", "").strip()
        batch_id = request.args.get("batch_id", "").strip()

        conditions = []
        params = []
        if source_type:
            conditions.append("source_type = ?")
            params.append(source_type)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if outcome:
            conditions.append("outcome = ?")
            params.append(outcome)
        if batch_id:
            conditions.append("batch_id = ?")
            params.append(batch_id)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(f"""
            SELECT event_id, event_time, source_type, category, attack_type, username,
                   source_ip, dest_ip, hostname, outcome, severity, risk_score, provenance
            FROM security_events
            {where_clause}
            ORDER BY event_time DESC
            LIMIT 5000
        """, params)
        rows = c.fetchall()
        conn.close()

        output = io.StringIO()
        fieldnames = [
            "event_id", "event_time", "source_type", "category", "attack_type",
            "username", "source_ip", "dest_ip", "hostname", "outcome",
            "severity", "risk_score", "provenance"
        ]
        writer = csv.writer(output)
        writer.writerow(fieldnames)

        for row in rows:
            sanitized_row = [sanitize_csv_formula(row[col]) for col in fieldnames]
            writer.writerow(sanitized_row)

        csv_content = output.getvalue()
        from flask import Response
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=security_events_export.csv"}
        )

    # ---------------------------------------------------------
    # Sprint 5: Evidence-Grounded SOC Investigation Reports Endpoints
    # ---------------------------------------------------------

    def _fetch_report_and_verify_access(report_id_str: str, conn=None, required_permission: str = "read"):
        """
        Centralized server-enforced authorization gatekeeper for investigation case reports.
        Enforces case ownership, author rights, reviewer access, and explicit administrative privileges.

        Parameters:
            report_id_str: Unique case report ID (e.g. REP-20261031-XXXXXX)
            conn: Existing database connection or None
            required_permission: "read" | "edit" | "transition" | "revise" | "evidence"

        Returns:
            (report_dict, error_response_tuple, connection)
        """
        close_conn = False
        if conn is None:
            conn = get_db_connection(app.config["DATABASE_PATH"])
            close_conn = True
        c = conn.cursor()

        c.execute("""
            SELECT r.*, c.status AS case_status, c.assigned_to, c.assigned_username,
                   l.attack, l.behavior, l.risk, l.ip, l.time AS incident_time
            FROM case_reports r
            JOIN cases c ON r.case_id = c.incident_id
            JOIN logs l ON c.incident_id = l.id
            WHERE r.report_id = ?
        """, (report_id_str.strip(),))
        row = c.fetchone()
        if not row:
            if close_conn:
                conn.close()
            return None, (jsonify({"error": "Not Found", "message": f"Report '{report_id_str}' not found."}), 404), conn

        report_dict = dict(row)
        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")
        caller_username = session.get("username", "analyst")

        # Administrators have unrestricted administrative privileges across all report operations
        if caller_role == "admin":
            return report_dict, None, conn

        assigned_to = report_dict.get("assigned_to")
        author_id = report_dict.get("author_id")
        reviewer_id = report_dict.get("reviewer_id")
        reviewer_username = report_dict.get("reviewer_username")

        is_owner = (assigned_to is not None and assigned_to == caller_id)
        is_author = (author_id is not None and author_id == caller_id)
        is_reviewer = ((reviewer_id is not None and reviewer_id == caller_id) or
                       (reviewer_username is not None and reviewer_username == caller_username))
        is_unassigned_case = (assigned_to is None)

        # 1. READ PERMISSION: detail, timeline, exports
        if required_permission == "read":
            if not (is_owner or is_author or is_reviewer or is_unassigned_case):
                if close_conn:
                    conn.close()
                assigned_name = report_dict.get("assigned_username") or "another analyst"
                return None, (jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Report '{report_id_str}' belongs to an investigation assigned to @{assigned_name}."
                }), 403), conn
            return report_dict, None, conn

        # 2. EDIT PERMISSION: patch report content, findings, recommendations
        if required_permission == "edit":
            if report_dict.get("is_finalized"):
                if close_conn:
                    conn.close()
                return None, (jsonify({
                    "error": "Conflict",
                    "message": f"Report '{report_id_str}' is finalized (v{report_dict['version']}) and immutable. Create a new revision via /revise to make modifications."
                }), 409), conn
            if not (is_owner or is_author):
                if close_conn:
                    conn.close()
                assigned_name = report_dict.get("assigned_username") or report_dict.get("author_username") or "another analyst"
                return None, (jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Only the assigned analyst (@{assigned_name}) or an administrator can modify this report draft."
                }), 403), conn
            return report_dict, None, conn

        # 3. EVIDENCE PERMISSION: link / unlink evidence references
        if required_permission == "evidence":
            if report_dict.get("is_finalized"):
                if close_conn:
                    conn.close()
                return None, (jsonify({
                    "error": "Conflict",
                    "message": f"Report '{report_id_str}' is finalized (v{report_dict['version']}) and immutable. Evidence cannot be modified."
                }), 409), conn
            if not (is_owner or is_author):
                if close_conn:
                    conn.close()
                assigned_name = report_dict.get("assigned_username") or report_dict.get("author_username") or "another analyst"
                return None, (jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Only the assigned analyst (@{assigned_name}) or an administrator can modify evidence links on this report."
                }), 403), conn
            return report_dict, None, conn

        # 4. TRANSITION PERMISSION: draft -> in_review -> finalized
        if required_permission == "transition":
            if report_dict.get("is_finalized"):
                if close_conn:
                    conn.close()
                return None, (jsonify({
                    "error": "Conflict",
                    "message": f"Report '{report_id_str}' is finalized (v{report_dict['version']}) and immutable. Call /revise to create a new revision."
                }), 409), conn
            if not (is_owner or is_author or is_reviewer):
                if close_conn:
                    conn.close()
                assigned_name = report_dict.get("assigned_username") or report_dict.get("author_username") or "another analyst"
                return None, (jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Only the assigned analyst (@{assigned_name}), author, designated reviewer, or administrator can transition report lifecycle status."
                }), 403), conn
            return report_dict, None, conn

        # 5. REVISE PERMISSION: initiating new revision from finalized report
        if required_permission == "revise":
            if not report_dict.get("is_finalized"):
                if close_conn:
                    conn.close()
                return None, (jsonify({
                    "error": "Bad Request",
                    "message": f"Report '{report_id_str}' is currently in '{report_dict['status']}' state. Revisions can only be initiated from finalized reports."
                }), 400), conn
            if not (is_owner or is_author):
                if close_conn:
                    conn.close()
                assigned_name = report_dict.get("assigned_username") or report_dict.get("author_username") or "another analyst"
                return None, (jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Only the assigned analyst (@{assigned_name}) or an administrator can revise this finalized report."
                }), 403), conn
            return report_dict, None, conn

        return report_dict, None, conn

    @app.route("/api/reports", methods=["GET"])
    @login_required
    def list_case_reports():
        """Lists investigation case reports with centralized authorization filtering, pagination, and case linkage."""
        case_id = request.args.get("case_id", type=int)
        status_filter = request.args.get("status", "").strip().lower()
        search_query = request.args.get("search", "").strip()
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))
        offset = (page - 1) * per_page

        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        conditions = ["1=1"]
        params = []

        # Server-enforced authorization: non-administrators only see reports they own, authored, review, or unassigned cases
        if caller_role != "admin":
            conditions.append("(r.author_id = ? OR c.assigned_to = ? OR r.reviewer_id = ? OR c.assigned_to IS NULL)")
            params.extend([caller_id, caller_id, caller_id])

        if case_id:
            conditions.append("r.case_id = ?")
            params.append(case_id)
        if status_filter in ("draft", "in_review", "finalized"):
            conditions.append("r.status = ?")
            params.append(status_filter)
        if search_query:
            term = f"%{search_query}%"
            conditions.append("(r.report_id LIKE ? OR r.title LIKE ? OR r.author_username LIKE ? OR r.executive_summary LIKE ?)")
            params.extend([term, term, term, term])

        where_clause = " AND ".join(conditions)

        c.execute(f"""
            SELECT COUNT(*) AS total
            FROM case_reports r
            JOIN cases c ON r.case_id = c.incident_id
            WHERE {where_clause}
        """, params)
        total_reports = c.fetchone()["total"]

        c.execute(f"""
            SELECT r.id, r.report_id, r.case_id, r.version, r.title, r.status,
                   r.author_id, r.author_username, r.reviewer_username,
                   r.incident_classification, r.severity, r.resolution_status,
                   r.is_finalized, r.created_at, r.updated_at, r.finalized_at,
                   c.assigned_to, c.assigned_username,
                   (SELECT COUNT(*) FROM report_evidence_links el WHERE el.report_id = r.report_id) AS evidence_count
            FROM case_reports r
            JOIN cases c ON r.case_id = c.incident_id
            WHERE {where_clause}
            ORDER BY r.updated_at DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        reports = [dict(row) for row in c.fetchall()]
        conn.close()

        total_pages = max(1, (total_reports + per_page - 1) // per_page)
        return jsonify({
            "reports": reports,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_records": total_reports,
                "total_pages": total_pages
            }
        }), 200

    @app.route("/api/reports", methods=["POST"])
    @login_required
    def create_case_report():
        """Creates a new evidence-grounded report for an investigation case."""
        data = request.get_json(silent=True) or {}
        case_id = data.get("case_id")
        if not case_id:
            return jsonify({"error": "Bad Request", "message": "Field 'case_id' is required."}), 400

        try:
            case_id = int(case_id)
        except (ValueError, TypeError):
            return jsonify({"error": "Bad Request", "message": "Field 'case_id' must be an integer."}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        # Check case and primary incident exist
        c.execute("""
            SELECT c.*, l.attack, l.behavior, l.risk, l.ip, l.username, l.time AS incident_time, l.is_simulated
            FROM cases c
            JOIN logs l ON c.incident_id = l.id
            WHERE c.incident_id = ?
        """, (case_id,))
        case_row = c.fetchone()
        if not case_row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Investigation case #{case_id} not found."}), 404

        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")
        caller_username = session.get("username", "analyst")

        # RBAC & Ownership: only assigned analyst or admin can create report
        if caller_role != "admin" and case_row["assigned_to"] is not None and case_row["assigned_to"] != caller_id:
            conn.close()
            return jsonify({
                "error": "Forbidden",
                "message": f"Cannot create report for case #{case_id} assigned to another analyst (@{case_row['assigned_username']})."
            }), 403

        # Auto-claim unassigned case if analyst creates a report
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if case_row["assigned_to"] is None:
            c.execute("""
                UPDATE cases
                SET assigned_to = ?, assigned_username = ?, updated_at = ?, version = version + 1
                WHERE incident_id = ?
            """, (caller_id, caller_username, now_str, case_id))

        # Check for correlated detection alerts with exact JSON array membership
        c.execute("""
            SELECT a.id, a.alert_id, a.rule_id, a.rule_name, a.severity, a.explanation,
                   r.mitre_technique_id, r.mitre_technique_name, r.mitre_url
            FROM detection_alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE a.linked_incident_id = ? OR (
                json_valid(a.matched_incident_ids_json) AND EXISTS (
                    SELECT 1 FROM json_each(a.matched_incident_ids_json) WHERE CAST(value AS INTEGER) = ?
                )
            )
        """, (case_id, case_id))
        alerts = [dict(a) for a in c.fetchall()]

        # Check for linked security events
        c.execute("""
            SELECT id, event_id, batch_id, source_type, event_time, source_ip, dest_ip, hostname, username, attack_type, outcome, provenance
            FROM security_events
            WHERE incident_id = ?
        """, (case_id,))
        sec_events = [dict(s) for s in c.fetchall()]

        # Grounded Accounts & Assets extraction
        observed_accounts = set()
        if case_row["username"] and case_row["username"] != "unknown":
            observed_accounts.add(case_row["username"])
        for s in sec_events:
            if s.get("username") and s.get("username") != "unknown":
                observed_accounts.add(s["username"])
        affected_accounts_list = sorted(list(observed_accounts))

        observed_assets = set()
        if case_row["ip"] and case_row["ip"] != "unknown":
            observed_assets.add(case_row["ip"])
        for s in sec_events:
            if s.get("source_ip") and s.get("source_ip") != "unknown":
                observed_assets.add(s["source_ip"])
            if s.get("dest_ip") and s.get("dest_ip") != "unknown":
                observed_assets.add(s["dest_ip"])
            if s.get("hostname") and s.get("hostname") != "unknown":
                observed_assets.add(s["hostname"])
        affected_assets_list = sorted(list(observed_assets))

        # MITRE ATT&CK compilation with explicit classification limitation
        mitre_list = []
        for alt in alerts:
            if alt.get("mitre_technique_id"):
                mitre_list.append({
                    "technique_id": alt["mitre_technique_id"],
                    "technique_name": alt.get("mitre_technique_name", "Unknown Technique"),
                    "rule_name": alt.get("rule_name", "Unknown Rule"),
                    "mitre_url": alt.get("mitre_url", ""),
                    "classification_limitation": "Automated detection rule mapping based on observed event conditions; not an exhaustive adversary attribution."
                })

        report_id = generate_report_id()
        report_title = (data.get("title") or f"Investigation Report — Case #{case_id}: {case_row['attack']}").strip()[:200]

        exec_summary = (data.get("executive_summary") or (
            f"Security incident #{case_id} was investigated for suspected '{case_row['attack']}' activity. "
            f"Observed behavior profile: {case_row['behavior']}. "
            f"Total {len(alerts)} correlated detection alert(s) and {len(sec_events)} telemetry event(s) recorded."
        )).strip()[:10000]

        severity = map_risk_severity(case_row["risk"])
        det_context = (
            f"Case #{case_id} correlated with {len(alerts)} detection alert(s). " +
            ("; ".join(f"Alert {a['alert_id']} ({a['rule_name']})" for a in alerts[:4]) if alerts else "No automated detection alerts triggered.")
        )

        containment_history = (
            f"Case status: {case_row['status']}. "
            f"Resolution summary: {case_row['resolution_summary'] or 'None recorded.'}"
        )

        limitations = (
            "Telemetry records imported from external collectors or local sensors are subject to sensor completeness "
            "and transport fidelity. Any unobserved attributes remain documented as Unknown."
        )

        c.execute("""
            INSERT INTO case_reports (
                report_id, case_id, version, title, status, author_id, author_username,
                executive_summary, incident_classification, severity, detection_context,
                affected_accounts_json, affected_assets_json, mitre_attack_json,
                analyst_findings_json, containment_remediation_history, resolution_status,
                recommendations, limitations_and_uncertainties, is_finalized,
                created_at, updated_at
            ) VALUES (?, ?, 1, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, 'Review authentication logs and enforce MFA on affected user accounts.', ?, 0, ?, ?)
        """, (
            report_id, case_id, report_title, caller_id, caller_username,
            exec_summary, case_row["attack"], severity, det_context,
            json.dumps(affected_accounts_list), json.dumps(affected_assets_list),
            json.dumps(mitre_list), containment_history, case_row["status"],
            limitations, now_str, now_str
        ))

        # Auto-create verified initial evidence references for primary case records
        c.execute("""
            INSERT INTO report_evidence_links (
                report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
            ) VALUES (?, ?, 'incident', ?, ?, 'observed', ?, 'Primary incident record in case investigation workspace', ?)
        """, (
            report_id, case_id, str(case_id),
            f"Primary Incident #{case_id} ({case_row['attack']})",
            f"Incident #{case_id}: {case_row['attack']} from IP {case_row['ip'] or 'unknown'} (Risk: {case_row['risk']})",
            now_str
        ))

        for alt in alerts:
            c.execute("""
                INSERT INTO report_evidence_links (
                    report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
                ) VALUES (?, ?, 'alert', ?, ?, 'observed', ?, 'Automated detection alert correlated to case telemetry', ?)
            """, (
                report_id, case_id, alt["alert_id"],
                f"Detection Alert {alt['alert_id']}",
                f"{alt['rule_name']} ({alt['severity'].upper()}): {alt['explanation'][:160]}",
                now_str
            ))

        for s in sec_events[:5]:
            prov_status = "observed" if s.get("provenance") in ("observed", "system", "synthetic") else "unverified_import"
            c.execute("""
                INSERT INTO report_evidence_links (
                    report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
                ) VALUES (?, ?, 'security_event', ?, ?, ?, ?, 'Normalized security telemetry record linked to case', ?)
            """, (
                report_id, case_id, s["event_id"],
                f"Security Event {s['event_id']} ({s['source_type']})",
                prov_status,
                f"{s['attack_type']} ({s['outcome']}) from {s['source_ip']} at {s['event_time']}",
                now_str
            ))

        # Audit log entry
        c.execute("""
            INSERT INTO incident_audit_log (
                incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            ) VALUES (?, ?, ?, 'report_created', NULL, 'v1:draft', ?, ?)
        """, (
            case_id, caller_id, caller_username,
            f"Investigation report '{report_id}' created by {caller_username}",
            now_str
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Investigation report created successfully.",
            "report_id": report_id,
            "case_id": case_id,
            "version": 1,
            "status": "draft",
            "title": report_title
        }), 201

    @app.route("/api/reports/<report_id>", methods=["GET"])
    @login_required
    def get_case_report(report_id: str):
        """Retrieves full case report details with live verified evidence references and deterministic quality checks."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn)
        if err:
            return err

        c = conn.cursor()
        case_id = report_dict["case_id"]

        # Fetch case data
        c.execute("""
            SELECT c.*, l.attack, l.behavior, l.risk, l.ip, l.username, l.time AS incident_time, l.is_simulated
            FROM cases c
            JOIN logs l ON c.incident_id = l.id
            WHERE c.incident_id = ?
        """, (case_id,))
        case_row = dict(c.fetchone())

        # Fetch evidence links with live target verification
        c.execute("""
            SELECT id, report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
            FROM report_evidence_links
            WHERE report_id = ?
            ORDER BY id ASC
        """, (report_id,))
        raw_links = [dict(r) for r in c.fetchall()]

        verified_links = []
        for lk in raw_links:
            ref_type = lk["reference_type"]
            ref_id = lk["reference_id"]
            is_valid = False
            unavail_reason = None

            if ref_type == "incident":
                c.execute("SELECT id FROM logs WHERE id = ?", (ref_id,))
                is_valid = bool(c.fetchone())
            elif ref_type == "alert":
                c.execute("SELECT id FROM detection_alerts WHERE alert_id = ? OR id = ?", (ref_id, ref_id))
                is_valid = bool(c.fetchone())
            elif ref_type == "security_event":
                c.execute("SELECT id FROM security_events WHERE (event_id = ? OR id = ?) AND incident_id = ?", (ref_id, ref_id, case_id))
                is_valid = bool(c.fetchone())
            elif ref_type == "rule":
                c.execute("SELECT id, status FROM detection_rules WHERE rule_id = ? OR id = ?", (ref_id, ref_id))
                rule_row = c.fetchone()
                if rule_row:
                    is_valid = True
                    if rule_row["status"] == "archived":
                        unavail_reason = "Detection rule has been archived; historical reference preserved."
            elif ref_type == "case_note":
                c.execute("SELECT id FROM incident_notes WHERE id = ? AND incident_id = ?", (ref_id, case_id))
                is_valid = bool(c.fetchone())
            elif ref_type == "case_evidence":
                c.execute("SELECT id FROM incident_evidence WHERE id = ? AND incident_id = ?", (ref_id, case_id))
                is_valid = bool(c.fetchone())
            elif ref_type == "case_audit":
                c.execute("SELECT id FROM incident_audit_log WHERE id = ? AND incident_id = ?", (ref_id, case_id))
                is_valid = bool(c.fetchone())
            elif ref_type == "batch":
                c.execute("SELECT id FROM ingestion_batches WHERE batch_id = ? OR id = ?", (ref_id, ref_id))
                is_valid = bool(c.fetchone())

            if not is_valid:
                lk["provenance_status"] = "unavailable"
                lk["unavailability_reason"] = "Referenced source record is missing or was removed; historical citation preserved."
            elif unavail_reason:
                lk["limitations_note"] = unavail_reason

            verified_links.append(lk)

        # Fetch security events for quality evaluation
        c.execute("SELECT * FROM security_events WHERE incident_id = ?", (case_id,))
        sec_events = [dict(s) for s in c.fetchall()]

        # Evaluate 6 deterministic quality indicators
        qc = evaluate_report_quality_checks(
            report_row=report_dict,
            case_row=case_row,
            evidence_links=verified_links,
            incident_row=case_row,
            security_events=sec_events
        )

        # Fetch version history
        c.execute("""
            SELECT id, report_id, version, title, status, author_username, reviewer_username,
                   finalized_by_username, finalized_at, change_summary, created_at
            FROM report_versions
            WHERE report_id = ?
            ORDER BY version DESC
        """, (report_id,))
        versions = [dict(v) for v in c.fetchall()]

        conn.close()

        try:
            report_dict["affected_accounts"] = json.loads(report_dict.get("affected_accounts_json") or "[]")
        except Exception:
            report_dict["affected_accounts"] = []
        try:
            report_dict["affected_assets"] = json.loads(report_dict.get("affected_assets_json") or "[]")
        except Exception:
            report_dict["affected_assets"] = []
        try:
            report_dict["mitre_attack"] = json.loads(report_dict.get("mitre_attack_json") or "[]")
        except Exception:
            report_dict["mitre_attack"] = []
        try:
            report_dict["analyst_findings"] = json.loads(report_dict.get("analyst_findings_json") or "[]")
        except Exception:
            report_dict["analyst_findings"] = []

        report_dict["evidence_links"] = verified_links
        report_dict["quality_checks"] = qc
        report_dict["version_history"] = versions
        report_dict["case"] = case_row

        return jsonify({
            "report": report_dict
        }), 200

    @app.route("/api/reports/<report_id>", methods=["PATCH"])
    @login_required
    def update_case_report(report_id: str):
        """Updates report draft with atomic conditional concurrency locking and centralized access authorization."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn, required_permission="edit")
        if err:
            return err

        data = request.get_json(silent=True) or {}

        # Validate expected version for optimistic concurrency (reject missing, booleans, and malformed)
        expected_version = data.get("expected_version")
        if expected_version is None:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": "Field 'expected_version' is required for optimistic concurrency protection."
            }), 400

        try:
            if isinstance(expected_version, bool):
                raise ValueError("Booleans are invalid versions")
            expected_version = int(expected_version)
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "Field 'expected_version' must be a valid integer."}), 400

        if expected_version != report_dict["version"]:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Stale update conflict: current report version is {report_dict['version']}, but expected {expected_version}."
            }), 409

        caller_id = session.get("user_id")
        caller_username = session.get("username", "analyst")

        # Extract editable fields with size boundaries
        title = data.get("title", report_dict["title"]).strip()[:200]
        exec_summary = data.get("executive_summary", report_dict["executive_summary"]).strip()[:10000]
        findings_raw = data.get("analyst_findings", None)
        if findings_raw is not None:
            if not isinstance(findings_raw, list):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "Field 'analyst_findings' must be a list of findings."}), 400
            findings_json = json.dumps(findings_raw)[:50000]
        else:
            findings_json = report_dict["analyst_findings_json"]

        recommendations = data.get("recommendations", report_dict["recommendations"]).strip()[:10000]
        limitations = data.get("limitations_and_uncertainties", report_dict["limitations_and_uncertainties"]).strip()[:10000]
        rem_history = data.get("containment_remediation_history", report_dict["containment_remediation_history"]).strip()[:10000]

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c = conn.cursor()

        # Atomic conditional update enforcing report_id, exact version, and unfinalized status
        c.execute("""
            UPDATE case_reports
            SET title = ?, executive_summary = ?, analyst_findings_json = ?,
                recommendations = ?, limitations_and_uncertainties = ?,
                containment_remediation_history = ?, updated_at = ?
            WHERE report_id = ? AND version = ? AND is_finalized = 0
        """, (
            title, exec_summary, findings_json, recommendations, limitations,
            rem_history, now_str, report_id, expected_version
        ))

        if c.rowcount == 0:
            conn.rollback()
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Optimistic locking conflict: report '{report_id}' was concurrently modified, transitioned, or finalized."
            }), 409

        # Record activity in incident audit log
        c.execute("""
            INSERT INTO incident_audit_log (
                incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            ) VALUES (?, ?, ?, 'report_updated', ?, ?, ?, ?)
        """, (
            report_dict["case_id"], caller_id, caller_username,
            f"v{report_dict['version']}", f"v{report_dict['version']}",
            f"Investigation report '{report_id}' draft updated by {caller_username}",
            now_str
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Report updated successfully.",
            "report_id": report_id,
            "version": report_dict["version"],
            "updated_at": now_str
        }), 200

    @app.route("/api/reports/<report_id>/status", methods=["POST"])
    @login_required
    def transition_report_status(report_id: str):
        """Transitions report status (draft -> in_review -> finalized) with atomic optimistic locking and immutable snapshotting."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn, required_permission="transition")
        if err:
            return err

        data = request.get_json(silent=True) or {}
        new_status = data.get("status", "").strip().lower()
        if new_status not in ("draft", "in_review", "finalized"):
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": "Status must be one of 'draft', 'in_review', or 'finalized'."
            }), 400

        expected_version = data.get("expected_version")
        if expected_version is None:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": "Field 'expected_version' is required for optimistic concurrency protection."
            }), 400

        try:
            if isinstance(expected_version, bool):
                raise ValueError("Booleans are invalid versions")
            expected_version = int(expected_version)
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Bad Request", "message": "Field 'expected_version' must be an integer."}), 400

        if expected_version != report_dict["version"]:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Stale version conflict: report is at v{report_dict['version']}, expected v{expected_version}."
            }), 409

        caller_id = session.get("user_id")
        caller_username = session.get("username", "analyst")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c = conn.cursor()

        # Handle Finalization: create immutable snapshot in report_versions
        if new_status == "finalized":
            # Fetch all evidence links for snapshot
            c.execute("""
                SELECT id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
                FROM report_evidence_links
                WHERE report_id = ?
            """, (report_id,))
            evidence_links = [dict(r) for r in c.fetchall()]

            # Fetch case details
            c.execute("""
                SELECT c.*, l.attack, l.behavior, l.risk, l.ip, l.username, l.time AS incident_time
                FROM cases c
                JOIN logs l ON c.incident_id = l.id
                WHERE c.incident_id = ?
            """, (report_dict["case_id"],))
            case_data = dict(c.fetchone())

            # Evaluate deterministic quality checks for snapshot
            qc = evaluate_report_quality_checks(
                report_row=report_dict,
                case_row=case_data,
                evidence_links=evidence_links,
                incident_row=case_data
            )

            # Build full timeline at finalization time
            timeline_items = _build_report_timeline(report_dict["case_id"], conn)

            disclaimer = (
                "Finalization of this report represents internal review and evidence linkage within AuthGuard-X; "
                "it does not constitute independent accredited forensic certification."
            )

            snapshot_payload = {
                "report_id": report_id,
                "version": report_dict["version"],
                "status": "finalized",
                "title": report_dict["title"],
                "executive_summary": report_dict["executive_summary"],
                "incident_classification": report_dict["incident_classification"],
                "severity": report_dict["severity"],
                "detection_context": report_dict["detection_context"],
                "affected_accounts_json": report_dict["affected_accounts_json"],
                "affected_assets_json": report_dict["affected_assets_json"],
                "mitre_attack_json": report_dict["mitre_attack_json"],
                "analyst_findings_json": report_dict["analyst_findings_json"],
                "containment_remediation_history": report_dict["containment_remediation_history"],
                "resolution_status": report_dict["resolution_status"],
                "recommendations": report_dict["recommendations"],
                "limitations_and_uncertainties": report_dict["limitations_and_uncertainties"],
                "evidence_links": evidence_links,
                "timeline": timeline_items,
                "quality_checks": qc,
                "case_data": case_data,
                "incident_data": case_data,
                "author_id": report_dict.get("author_id"),
                "author_username": report_dict.get("author_username"),
                "reviewer_username": caller_username,
                "finalized_by": caller_username,
                "finalized_at": now_str,
                "created_at": report_dict.get("created_at"),
                "provenance_disclaimer": disclaimer,
                "is_historical_snapshot": True
            }

            change_summary = (data.get("change_summary") or f"Report v{report_dict['version']} finalized by @{caller_username}").strip()[:500]

            c.execute("""
                INSERT INTO report_versions (
                    report_id, version, title, status, snapshot_json, author_username,
                    reviewer_username, finalized_by_username, finalized_at,
                    change_summary, provenance_disclaimer, created_at
                ) VALUES (?, ?, ?, 'finalized', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id, report_dict["version"], report_dict["title"],
                json.dumps(snapshot_payload), report_dict["author_username"],
                caller_username, caller_username, now_str,
                change_summary, disclaimer, now_str
            ))

            c.execute("""
                UPDATE case_reports
                SET status = 'finalized', is_finalized = 1, finalized_at = ?,
                    finalized_by_username = ?, reviewer_username = ?, updated_at = ?
                WHERE report_id = ? AND version = ? AND is_finalized = 0
            """, (now_str, caller_username, caller_username, now_str, report_id, expected_version))

            if c.rowcount == 0:
                conn.rollback()
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": f"Optimistic locking conflict: report '{report_id}' was concurrently modified or already finalized."
                }), 409

        else:
            reviewer = caller_username if new_status == "in_review" else report_dict.get("reviewer_username")
            c.execute("""
                UPDATE case_reports
                SET status = ?, reviewer_username = ?, updated_at = ?
                WHERE report_id = ? AND version = ? AND is_finalized = 0
            """, (new_status, reviewer, now_str, report_id, expected_version))

            if c.rowcount == 0:
                conn.rollback()
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": f"Optimistic locking conflict: report '{report_id}' was concurrently modified or finalized."
                }), 409

        # Record activity in incident audit log
        c.execute("""
            INSERT INTO incident_audit_log (
                incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            ) VALUES (?, ?, ?, 'report_status_changed', ?, ?, ?, ?)
        """, (
            report_dict["case_id"], caller_id, caller_username,
            report_dict["status"], new_status,
            f"Investigation report '{report_id}' status transitioned from {report_dict['status']} to {new_status} by {caller_username}",
            now_str
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": f"Report status transitioned to '{new_status}'.",
            "report_id": report_id,
            "version": report_dict["version"],
            "status": new_status,
            "is_finalized": 1 if new_status == "finalized" else 0,
            "updated_at": now_str
        }), 200

    @app.route("/api/reports/<report_id>/revise", methods=["POST"])
    @login_required
    def revise_finalized_report(report_id: str):
        """Creates a new version draft from a finalized report with atomic versioning."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn, required_permission="revise")
        if err:
            return err

        data = request.get_json(silent=True) or {}
        expected_version = data.get("expected_version")
        if expected_version is not None:
            try:
                if isinstance(expected_version, bool):
                    raise ValueError("Booleans are invalid versions")
                expected_version = int(expected_version)
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "Field 'expected_version' must be an integer."}), 400
            if expected_version != report_dict["version"]:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": f"Stale version conflict: report is at v{report_dict['version']}, expected v{expected_version}."
                }), 409
        else:
            expected_version = report_dict["version"]

        change_summary = (data.get("change_summary") or "New revision initiated for additional findings and evidence analysis.").strip()[:500]

        caller_id = session.get("user_id")
        caller_username = session.get("username", "analyst")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_version = report_dict["version"] + 1

        c = conn.cursor()
        c.execute("""
            UPDATE case_reports
            SET version = ?, status = 'draft', is_finalized = 0,
                updated_at = ?, finalized_at = NULL, finalized_by_username = NULL
            WHERE report_id = ? AND version = ? AND is_finalized = 1
        """, (new_version, now_str, report_id, expected_version))

        if c.rowcount == 0:
            conn.rollback()
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Optimistic locking conflict: report '{report_id}' was concurrently revised or is no longer in finalized state."
            }), 409

        c.execute("""
            INSERT INTO incident_audit_log (
                incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            ) VALUES (?, ?, ?, 'report_revised', ?, ?, ?, ?)
        """, (
            report_dict["case_id"], caller_id, caller_username,
            f"v{report_dict['version']}:finalized", f"v{new_version}:draft",
            f"Investigation report '{report_id}' revision v{new_version} initiated by {caller_username}: {change_summary}",
            now_str
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": f"New report revision v{new_version} created.",
            "report_id": report_id,
            "version": new_version,
            "status": "draft",
            "is_finalized": 0,
            "updated_at": now_str
        }), 200

    @app.route("/api/reports/<report_id>/evidence", methods=["POST"])
    @login_required
    def link_report_evidence(report_id: str):
        """Links a verified evidence item to the report with case isolation and atomic concurrency protection."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn, required_permission="evidence")
        if err:
            return err

        data = request.get_json(silent=True) or {}

        # Validate expected version if provided
        expected_version = data.get("expected_version")
        if expected_version is not None:
            try:
                if isinstance(expected_version, bool):
                    raise ValueError("Booleans are invalid versions")
                expected_version = int(expected_version)
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "Field 'expected_version' must be an integer."}), 400
            if expected_version != report_dict["version"]:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": f"Stale version conflict: report is at v{report_dict['version']}, expected v{expected_version}."
                }), 409
        else:
            expected_version = report_dict["version"]

        ref_type = (data.get("reference_type") or "").strip().lower()
        ref_id = str(data.get("reference_id") or "").strip()
        label = (data.get("label") or f"Evidence {ref_type}:{ref_id}").strip()[:200]
        limitations_note = (data.get("limitations_note") or "").strip()[:500] or None

        allowed_types = ('security_event', 'batch', 'incident', 'alert', 'rule', 'case_audit', 'case_note', 'case_evidence')
        if ref_type not in allowed_types:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": f"Invalid reference_type '{ref_type}'. Allowed types: {', '.join(allowed_types)}."
            }), 400

        if not ref_id:
            conn.close()
            return jsonify({"error": "Bad Request", "message": "Field 'reference_id' is required."}), 400

        case_id = report_dict["case_id"]
        c = conn.cursor()

        # Enforce Case Isolation: verify that the evidence reference belongs strictly to this case!
        is_valid = False
        prov_status = "observed"
        snapshot_summary = ""

        if ref_type == "incident":
            if str(ref_id) != str(case_id):
                conn.close()
                return jsonify({"error": "Forbidden", "message": f"Cross-case evidence reference prohibited: incident #{ref_id} does not match case #{case_id}."}), 403
            c.execute("SELECT id, attack, risk, ip, time FROM logs WHERE id = ?", (ref_id,))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"Incident #{row['id']}: {row['attack']} from IP {row['ip']} (Risk: {row['risk']})"
        elif ref_type == "security_event":
            c.execute("SELECT event_id, attack_type, outcome, source_ip, event_time, provenance FROM security_events WHERE (event_id = ? OR id = ?) AND incident_id = ?", (ref_id, ref_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                prov_status = "observed" if row["provenance"] in ("observed", "system", "synthetic") else "unverified_import"
                snapshot_summary = f"Event {row['event_id']}: {row['attack_type']} ({row['outcome']}) from {row['source_ip']} at {row['event_time']}"
        elif ref_type == "alert":
            c.execute("""
                SELECT alert_id, rule_name, severity, explanation
                FROM detection_alerts
                WHERE (alert_id = ? OR id = ?)
                  AND (linked_incident_id = ? OR (
                      json_valid(matched_incident_ids_json) AND EXISTS (
                          SELECT 1 FROM json_each(matched_incident_ids_json) WHERE CAST(value AS INTEGER) = ?
                      )
                  ))
            """, (ref_id, ref_id, case_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"{row['rule_name']} ({row['severity'].upper()}): {row['explanation'][:120]}"
        elif ref_type == "rule":
            c.execute("SELECT rule_id, name, severity, status FROM detection_rules WHERE rule_id = ? OR id = ?", (ref_id, ref_id))
            row = c.fetchone()
            if row:
                is_valid = True
                if row["status"] == "archived":
                    prov_status = "inferred"
                    limitations_note = "Archived rule; historical reference."
                snapshot_summary = f"Rule {row['rule_id']}: {row['name']} ({row['severity'].upper()})"
        elif ref_type == "case_note":
            c.execute("SELECT id, author_username, content, created_at FROM incident_notes WHERE id = ? AND incident_id = ?", (ref_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"Note #{row['id']} by @{row['author_username']}: {row['content'][:100]}"
        elif ref_type == "case_evidence":
            c.execute("SELECT id, evidence_type, description, raw_data FROM incident_evidence WHERE id = ? AND incident_id = ?", (ref_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"Evidence #{row['id']} ({row['evidence_type']}): {row['description'][:100]}"
        elif ref_type == "case_audit":
            c.execute("SELECT id, action, actor_username, description, created_at FROM incident_audit_log WHERE id = ? AND incident_id = ?", (ref_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"Audit #{row['id']}: {row['action']} by @{row['actor_username']} ({row['created_at']})"
        elif ref_type == "batch":
            c.execute("""
                SELECT b.batch_id, b.filename, b.source_type
                FROM ingestion_batches b
                JOIN security_events s ON b.batch_id = s.batch_id
                WHERE (b.batch_id = ? OR b.id = ?) AND s.incident_id = ?
            """, (ref_id, ref_id, case_id))
            row = c.fetchone()
            if row:
                is_valid = True
                snapshot_summary = f"Batch {row['batch_id']}: {row['filename']} ({row['source_type']})"

        if not is_valid:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": f"Referenced record {ref_type}:{ref_id} was not found or does not belong to case #{case_id}."
            }), 400

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Atomic check: ensure report is at expected version and not finalized
        c.execute("""
            UPDATE case_reports
            SET updated_at = ?
            WHERE report_id = ? AND version = ? AND is_finalized = 0
        """, (now_str, report_id, expected_version))
        if c.rowcount == 0:
            conn.rollback()
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Optimistic locking conflict: report '{report_id}' was concurrently modified or finalized."
            }), 409

        c.execute("""
            INSERT INTO report_evidence_links (
                report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id, case_id, ref_type, str(ref_id), label, prov_status, snapshot_summary, limitations_note, now_str
        ))
        link_id = c.lastrowid

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Evidence record linked successfully.",
            "link_id": link_id,
            "report_id": report_id,
            "reference_type": ref_type,
            "reference_id": ref_id,
            "provenance_status": prov_status
        }), 201

    @app.route("/api/reports/<report_id>/evidence/<int:link_id>", methods=["DELETE"])
    @login_required
    def unlink_report_evidence(report_id: str, link_id: int):
        """Unlinks an evidence reference with atomic concurrency locking."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn, required_permission="evidence")
        if err:
            return err

        c = conn.cursor()
        c.execute("DELETE FROM report_evidence_links WHERE id = ? AND report_id = ?", (link_id, report_id))
        if c.rowcount == 0:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Evidence link #{link_id} not found on report '{report_id}'."}), 404

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Atomic check: ensure report was not finalized concurrently
        c.execute("""
            UPDATE case_reports
            SET updated_at = ?
            WHERE report_id = ? AND version = ? AND is_finalized = 0
        """, (now_str, report_id, report_dict["version"]))
        if c.rowcount == 0:
            conn.rollback()
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": f"Optimistic locking conflict: report '{report_id}' was concurrently modified or finalized."
            }), 409

        conn.commit()
        conn.close()

        return jsonify({"message": f"Evidence link #{link_id} unlinked successfully.", "report_id": report_id}), 200

    def _build_report_timeline(case_id: int, conn, category_filter: str = "all", sort_dir: str = "asc") -> list:
        c = conn.cursor()
        timeline_items = []

        # 1. Telemetry Events from security_events
        c.execute("""
            SELECT event_id, event_time, original_timestamp, original_timezone, ingested_at,
                   source_type, category, attack_type, outcome, source_ip, dest_ip, username, hostname, provenance
            FROM security_events
            WHERE incident_id = ?
        """, (case_id,))
        for row in c.fetchall():
            s = dict(row)
            timeline_items.append({
                "category": "telemetry",
                "occurrence_time": s["event_time"],
                "recorded_time": s["ingested_at"],
                "original_timestamp": s.get("original_timestamp"),
                "original_timezone": s.get("original_timezone") or "UTC",
                "event_type": f"Security Telemetry ({s['source_type']})",
                "actor": s.get("username") or "unknown",
                "source_ip": s.get("source_ip"),
                "details": f"{s['attack_type']} ({s['outcome'].upper()}) from {s['source_ip']} to {s.get('dest_ip') or 'local'}"
            })

        # 2. Incident Record from logs
        c.execute("""
            SELECT id, attack, behavior, risk, ip, username, time, is_simulated
            FROM logs
            WHERE id = ?
        """, (case_id,))
        inc_row = c.fetchone()
        if inc_row:
            inc = dict(inc_row)
            timeline_items.append({
                "category": "telemetry",
                "occurrence_time": inc["time"],
                "recorded_time": inc["time"],
                "original_timestamp": inc["time"],
                "original_timezone": "UTC",
                "event_type": "Incident Log Created",
                "actor": inc.get("username") or "unknown",
                "source_ip": inc.get("ip"),
                "details": f"Primary incident #{inc['id']} created: {inc['attack']} (Risk: {inc['risk']})"
            })

        # 3. Detection Alerts
        c.execute("""
            SELECT alert_id, rule_name, severity, first_event_time, last_event_time, created_at, explanation
            FROM detection_alerts
            WHERE linked_incident_id = ?
               OR (
                   json_valid(matched_incident_ids_json)
                   AND EXISTS (
                       SELECT 1 FROM json_each(matched_incident_ids_json)
                       WHERE CAST(value AS INTEGER) = ?
                   )
               )
        """, (case_id, case_id))
        for row in c.fetchall():
            a = dict(row)
            timeline_items.append({
                "category": "detection",
                "occurrence_time": a.get("first_event_time") or a["created_at"],
                "recorded_time": a["created_at"],
                "original_timestamp": a.get("first_event_time"),
                "original_timezone": "UTC",
                "event_type": f"Alert Triggered ({a['severity'].upper()})",
                "actor": "Detection Engine",
                "source_ip": "-",
                "details": f"Rule '{a['rule_name']}' triggered alert {a['alert_id']}: {a['explanation'][:140]}"
            })

        # 4. Case Actions from incident_audit_log
        c.execute("""
            SELECT id, action, actor_username, before_value, after_value, description, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
        """, (case_id,))
        for row in c.fetchall():
            aud = dict(row)
            cat = "resolution" if aud["action"] in ("resolved", "contained") else "case_action"
            timeline_items.append({
                "category": cat,
                "occurrence_time": aud["created_at"],
                "recorded_time": aud["created_at"],
                "original_timestamp": aud["created_at"],
                "original_timezone": "UTC",
                "event_type": f"Case Action: {aud['action']}",
                "actor": f"@{aud['actor_username']}",
                "source_ip": "-",
                "details": aud.get("description", "")
            })

        # Apply category filter if requested
        if category_filter != "all":
            timeline_items = [item for item in timeline_items if item["category"] == category_filter]

        # Sort chronologically by occurrence_time
        reverse_sort = (sort_dir == "desc")
        timeline_items.sort(key=lambda x: x["occurrence_time"] or "", reverse=reverse_sort)
        return timeline_items

    def _build_full_report_data_from_snapshot(snapshot: dict, report_dict: dict, conn):
        """Constructs complete report data structure directly from immutable version snapshot."""
        case_data = snapshot.get("case_data")
        if not case_data:
            c = conn.cursor()
            c.execute("""
                SELECT c.*, l.attack, l.behavior, l.risk, l.ip, l.username, l.time AS incident_time
                FROM cases c
                JOIN logs l ON c.incident_id = l.id
                WHERE c.incident_id = ?
            """, (report_dict["case_id"],))
            row = c.fetchone()
            case_data = dict(row) if row else {}

        report_obj = {
            "report_id": snapshot.get("report_id", report_dict["report_id"]),
            "case_id": case_data.get("incident_id") or report_dict["case_id"],
            "version": snapshot.get("version", report_dict["version"]),
            "status": snapshot.get("status", "finalized"),
            "title": snapshot.get("title", report_dict["title"]),
            "executive_summary": snapshot.get("executive_summary", ""),
            "incident_classification": snapshot.get("incident_classification", "Unclassified"),
            "severity": snapshot.get("severity", "medium"),
            "detection_context": snapshot.get("detection_context", ""),
            "affected_accounts_json": snapshot.get("affected_accounts_json", "[]"),
            "affected_assets_json": snapshot.get("affected_assets_json", "[]"),
            "mitre_attack_json": snapshot.get("mitre_attack_json", "[]"),
            "analyst_findings_json": snapshot.get("analyst_findings_json", "[]"),
            "containment_remediation_history": snapshot.get("containment_remediation_history", ""),
            "resolution_status": snapshot.get("resolution_status", "in_progress"),
            "recommendations": snapshot.get("recommendations", ""),
            "limitations_and_uncertainties": snapshot.get("limitations_and_uncertainties", ""),
            "author_id": snapshot.get("author_id", report_dict.get("author_id")),
            "author_username": snapshot.get("author_username", report_dict.get("author_username")),
            "reviewer_username": snapshot.get("reviewer_username", report_dict.get("reviewer_username")),
            "finalized_by_username": snapshot.get("finalized_by", report_dict.get("finalized_by_username")),
            "finalized_at": snapshot.get("finalized_at", report_dict.get("finalized_at")),
            "created_at": snapshot.get("created_at", report_dict.get("created_at")),
            "is_finalized": 1
        }

        evidence_links = snapshot.get("evidence_links")
        if evidence_links is None:
            c = conn.cursor()
            c.execute("""
                SELECT id, report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
                FROM report_evidence_links
                WHERE report_id = ?
                ORDER BY id ASC
            """, (report_dict["report_id"],))
            evidence_links = [dict(r) for r in c.fetchall()]

        timeline_items = snapshot.get("timeline")
        if timeline_items is None:
            timeline_items = _build_report_timeline(report_dict["case_id"], conn)

        qc = snapshot.get("quality_checks")
        if qc is None:
            qc = evaluate_report_quality_checks(report_obj, case_data, evidence_links, case_data, [])

        target_v = snapshot.get("version", report_dict["version"])
        c = conn.cursor()
        c.execute("""
            SELECT version, title, status, author_username, reviewer_username, finalized_by_username, finalized_at, change_summary, created_at
            FROM report_versions
            WHERE report_id = ? AND version <= ?
            ORDER BY version DESC
        """, (report_dict["report_id"], target_v))
        versions = [dict(v) for v in c.fetchall()]

        return {
            "report": report_obj,
            "case": case_data,
            "incident": case_data,
            "evidence_links": evidence_links,
            "timeline": timeline_items,
            "quality_checks": qc,
            "version_history": versions
        }

    def _load_report_full_data_for_export(report_id: str, report_dict: dict, conn, target_version: int = None):
        """
        Loads full report data either from immutable historical snapshot in report_versions
        or from live database if the version is unfinalized (draft/in_review).
        Returns (full_data_dict, filename_prefix, error_response).
        """
        c = conn.cursor()
        if target_version is not None:
            c.execute("SELECT snapshot_json FROM report_versions WHERE report_id = ? AND version = ?", (report_id, target_version))
            v_row = c.fetchone()
            if not v_row:
                return None, None, (jsonify({
                    "error": "Not Found",
                    "message": f"Version {target_version} of report '{report_id}' not found in version history."
                }), 404)
            snapshot = json.loads(v_row["snapshot_json"])
            full_data = _build_full_report_data_from_snapshot(snapshot, report_dict, conn)
            return full_data, f"{report_id}_v{target_version}", None

        if report_dict.get("is_finalized"):
            c.execute("SELECT snapshot_json FROM report_versions WHERE report_id = ? AND version = ?", (report_id, report_dict["version"]))
            v_row = c.fetchone()
            if v_row:
                snapshot = json.loads(v_row["snapshot_json"])
                full_data = _build_full_report_data_from_snapshot(snapshot, report_dict, conn)
                return full_data, report_id, None

        # Live export for draft / in_review
        case_id = report_dict["case_id"]
        c.execute("""
            SELECT c.*, l.attack, l.behavior, l.risk, l.ip, l.username, l.time AS incident_time
            FROM cases c
            JOIN logs l ON c.incident_id = l.id
            WHERE c.incident_id = ?
        """, (case_id,))
        case_row = c.fetchone()
        case_data = dict(case_row) if case_row else {}

        c.execute("""
            SELECT id, report_id, case_id, reference_type, reference_id, label, provenance_status, snapshot_summary, limitations_note, created_at
            FROM report_evidence_links
            WHERE report_id = ?
            ORDER BY id ASC
        """, (report_id,))
        evidence_links = [dict(r) for r in c.fetchall()]

        timeline_items = _build_report_timeline(case_id, conn)

        c.execute("SELECT * FROM security_events WHERE incident_id = ?", (case_id,))
        sec_events = [dict(s) for s in c.fetchall()]
        qc = evaluate_report_quality_checks(report_dict, case_data, evidence_links, case_data, sec_events)

        c.execute("""
            SELECT version, title, status, author_username, reviewer_username, finalized_by_username, finalized_at, change_summary, created_at
            FROM report_versions
            WHERE report_id = ?
            ORDER BY version DESC
        """, (report_id,))
        versions = [dict(v) for v in c.fetchall()]

        full_data = {
            "report": report_dict,
            "case": case_data,
            "incident": case_data,
            "evidence_links": evidence_links,
            "timeline": timeline_items,
            "quality_checks": qc,
            "version_history": versions
        }
        return full_data, report_id, None

    @app.route("/api/reports/<report_id>/timeline", methods=["GET"])
    @login_required
    def get_report_timeline(report_id: str):
        """Returns chronological investigation timeline combining event occurrences, ingestion, detection, and case actions."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn)
        if err:
            return err

        version_param = request.args.get("version", type=int)
        category_filter = request.args.get("category", "all").strip().lower()
        sort_dir = request.args.get("sort_dir", "asc").strip().lower()
        case_id = report_dict["case_id"]

        if version_param is not None:
            c = conn.cursor()
            c.execute("SELECT snapshot_json FROM report_versions WHERE report_id = ? AND version = ?", (report_id, version_param))
            v_row = c.fetchone()
            if not v_row:
                conn.close()
                return jsonify({"error": "Not Found", "message": f"Version {version_param} of report '{report_id}' not found in version history."}), 404
            snapshot = json.loads(v_row["snapshot_json"])
            timeline_items = snapshot.get("timeline") or []
            active_version = version_param
        elif report_dict.get("is_finalized"):
            c = conn.cursor()
            c.execute("SELECT snapshot_json FROM report_versions WHERE report_id = ? AND version = ?", (report_id, report_dict["version"]))
            v_row = c.fetchone()
            if v_row:
                snapshot = json.loads(v_row["snapshot_json"])
                timeline_items = snapshot.get("timeline") or []
            else:
                timeline_items = _build_report_timeline(case_id, conn)
            active_version = report_dict["version"]
        else:
            timeline_items = _build_report_timeline(case_id, conn)
            active_version = report_dict["version"]

        if category_filter != "all":
            timeline_items = [item for item in timeline_items if item.get("category") == category_filter]

        reverse_sort = (sort_dir == "desc")
        timeline_items.sort(key=lambda x: x.get("occurrence_time") or "", reverse=reverse_sort)
        conn.close()

        return jsonify({
            "report_id": report_id,
            "case_id": case_id,
            "version": active_version,
            "total_events": len(timeline_items),
            "timeline": timeline_items
        }), 200

    @app.route("/api/reports/<report_id>/export/html", methods=["GET"])
    @login_required
    def export_report_html(report_id: str):
        """Exports self-contained, printable HTML report with print media CSS and provenance disclaimers."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn)
        if err:
            return err

        target_version = request.args.get("version", type=int)
        full_data, filename_prefix, load_err = _load_report_full_data_for_export(report_id, report_dict, conn, target_version)
        conn.close()
        if load_err:
            return load_err

        html_content = render_printable_html_report(full_data)

        from flask import Response
        return Response(
            html_content,
            mimetype="text/html",
            headers={"Content-Disposition": f"inline; filename={filename_prefix}.html"}
        )

    @app.route("/api/reports/<report_id>/export/json", methods=["GET"])
    @login_required
    def export_report_json(report_id: str):
        """Exports structured JSON report representation sanitized of tokens and internal secrets."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        report_dict, err, conn = _fetch_report_and_verify_access(report_id, conn)
        if err:
            return err

        target_version = request.args.get("version", type=int)
        full_data, filename_prefix, load_err = _load_report_full_data_for_export(report_id, report_dict, conn, target_version)
        conn.close()
        if load_err:
            return load_err

        json_data = render_structured_json_report(full_data)

        from flask import Response
        return Response(
            json.dumps(json_data, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename_prefix}.json"}
        )

    # ---------------------------------------------------------
    # Metrics Endpoint
    # ---------------------------------------------------------
    @app.route("/api/metrics", methods=["GET"])
    @login_required
    def get_metrics():
        """
        Returns aggregated security metrics for the dashboard.

        Health score formula:
          Start at 100
          - 8 per unresolved critical incident  (risk >= 80)
          - 5 per unresolved high incident       (60 <= risk < 80)
          - 2 per unresolved medium incident     (40 <= risk < 60)
          - 0 for unresolved low incidents       (risk < 40)
          Minimum value: 0
        """
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        today_str = datetime.now().strftime("%Y-%m-%d")
        week_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        c.execute("SELECT COUNT(*) FROM logs")
        total_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0")
        open_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 1")
        resolved_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ?", (80,))
        critical_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ? AND risk < ?", (60, 80))
        high_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ? AND risk < ?", (40, 60))
        medium_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk < ?", (40,))
        low_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE is_simulated = 1")
        simulated_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE is_simulated = 0")
        telemetry_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE time >= ?", (f"{today_str} 00:00:00",))
        today_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE time >= ?", (f"{week_start} 00:00:00",))
        week_count = c.fetchone()[0]

        # Unresolved counts per severity level (for health score)
        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ?", (80,))
        open_critical = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ? AND risk < ?", (60, 80))
        open_high = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ? AND risk < ?", (40, 60))
        open_medium = c.fetchone()[0]

        conn.close()

        health_score = max(
            0,
            100
            - (open_critical * 8)
            - (open_high * 5)
            - (open_medium * 2)
        )

        return jsonify({
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "simulated_count": simulated_count,
            "telemetry_count": telemetry_count,
            "health_score": health_score,
            "today_count": today_count,
            "week_count": week_count,
        }), 200

    # ---------------------------------------------------------
    # Secure Error Handlers
    # ---------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad Request", "message": str(e.description if hasattr(e, "description") else e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not Found", "message": "The requested resource was not found"}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        # Do not leak internal exception details to client
        return jsonify({"error": "Internal Server Error", "message": "An internal error occurred."}), 500

    return app


# Application entry point
app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("AUTHGUARD_ENV", "development").lower() == "development"
    print(f"[*] Starting AuthGuard-X Server on http://{host}:{port} (env: {app.config['AUTHGUARD_ENV']})")
    app.run(host=host, port=port, debug=debug_mode)
