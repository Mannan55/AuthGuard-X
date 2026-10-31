# AuthGuard-X — Project Presentation Outline (8–10 Slides)

This outline is structured for academic project defenses, capstone presentations, and cybersecurity engineering technical interviews.

---

## Slide 1: Title & Overview
- **Project Title:** AuthGuard-X: Security Operations Center Simulation & Incident Investigation Platform
- **Presenter:** Autonomous Release Engineering & Cyber Defense
- **Core Mission:** Bridging the gap between raw security log ingestion, sliding-window detection engineering, structured case investigations, and evidence-grounded reporting.
- **Key Tenet:** Local-first, privacy-preserving, zero external cloud LLM dependencies, deterministic forensic chain-of-custody.

---

## Slide 2: The Problem Space in Modern SOC Workflows
- **Alert Fatigue & Noise:** Tier-1 analysts are flooded with disconnected log alerts that lack contextual correlation.
- **Disconnected Triage Tools:** Telemetry parsing, rule authoring, case tracking, and executive reporting are often scattered across siloed tools.
- **Lack of Hands-On Training Environments:** Junior analysts rarely experience realistic, multi-stage attack scenarios without complex cloud SIEM licensing.
- **Reporting Hallucinations & Evidence Drift:** Traditional manual reporting often loses track of exact source records, timestamps, and containment timelines.

---

## Slide 3: System Architecture & Workflow Pipeline
- **End-to-End Pipeline:**
  $$\text{Log Ingestion} \longrightarrow \text{Event Normalization} \longrightarrow \text{Detection Rules} \longrightarrow \text{Sliding-Window Correlation} \longrightarrow \text{Case Management} \longrightarrow \text{Immutable Reporting}$$
- **Modular Monolith Design:** Clean Flask backend, SQLite 3 with WAL mode, modular vanilla JavaScript (ES6+), custom CSS design tokens (8px grid).
- **Zero Insecure Dynamic Code:** Custom AST condition evaluator replaces dangerous `eval()` mechanisms.

---

## Slide 4: Structured Security Event Ingestion & Normalization
- **Multi-Format Parsers:** Native support for Windows Event ID 4625, Linux `/var/log/auth.log`, RFC 5424 Syslog, Palo Alto Firewalls, and JSON.
- **Forensic Provenance & Source Hashing:** Every ingested batch and raw log line receives a deterministic SHA-256 hash (`exact_source_bytes`).
- **Strict Timestamp Normalization:** Timezone offsets (e.g., UTC+05:30, UTC−05:00, Unix epoch milliseconds) are normalized to ISO-8601 UTC with original timezone metadata preserved.

---

## Slide 5: Detection Engineering & Threat Correlation Engine
- **Enterprise Rule Catalog:** Schema-constrained rules with configurable severity, operators (`equals`, `contains`, `greater_than`, `in`, `regex_safe`), and time thresholds.
- **Sliding-Window Aggregation:** Evaluates temporal relationships (e.g., 5 failures within 60 seconds) without cross-window event leakage.
- **Distinct Target Enforcement:** Rules like multi-target password spraying require strictly distinct usernames, eliminating false-positive single-target bursts.
- **Idempotency Hashing:** Generates deterministic correlation hashes, preventing duplicate alert generation during active bursts.

---

## Slide 6: MITRE ATT&CK Framework Alignment
- **Tactical Mapping:** Direct alignment of detection rules and alerts to official MITRE tactics and techniques:
  - **T1110.001:** Password Spraying (Credential Access)
  - **T1046:** Network Service Discovery (Discovery)
  - **T1190:** Exploit Public-Facing Application (Initial Access)
  - **T1078:** Valid Accounts (Defense Evasion / Persistence)
- **Explainability Notes:** Dynamic narrative summaries translate raw correlation counts into human-readable investigative leads.

---

## Slide 7: Case Management & 4-Stage Lifecycle State Machine
- **Structured Investigation Progression:**
  $$\text{New} \longrightarrow \text{Investigating} \longrightarrow \text{Contained} \longrightarrow \text{Resolved}$$
- **Queue Isolation & Assignment:** Personal work queues, analyst claiming, and role-based access control (Admin vs. Analyst).
- **Safe Evidence References:** Pointers to PCAP captures and external intel are validated against URL scheme whitelists (`http://`, `https://`).
- **Optimistic Concurrency Control:** Version-checking on mutating requests rejects concurrent edits with HTTP `409 Conflict`.

---

## Slide 8: Evidence-Grounded SOC Reporting & Quality Indicators
- **Strict Data Grounding:** Reports are synthesized purely from stored event telemetry, alerts, and audit logs—zero artificial or fabricated facts.
- **Deterministic Quality Checks (6 Quality Indicators):**
  1. Incident Classification Alignment
  2. Occurrence vs Recorded Latency
  3. Correlated Detection Rule Coverage
  4. Analyst Hypothesis & Finding Documentation
  5. Evidence Reference Traceability
  6. Containment Milestone Validation
- **Immutable Version Snapshots:** Frozen historical versions (`v1`, `v2`) with reproducible export generation (`?version=N`).

---

## Slide 9: Defensive Hardening & DevSecOps Validation
- **Security Foundations:** Bcrypt password hashing (12 rounds), Flask-WTF CSRF tokens, signed `HttpOnly`/`SameSite` cookies, strict input bounds, and context-aware XSS escaping.
- **Automated Test Coverage:**
  - **161 Automated Pytest Unit & Integration Tests** covering authentication, ingestion, parsing, detection, state transitions, locking, and reporting.
  - **34 Real-Browser Chromium CDP Verification Assertions** across mobile (390px), tablet (768px), desktop (1440px), and widescreen (1920px).
  - **6-Matrix GitHub Actions CI** executing on Python 3.11, 3.12, 3.13 on Ubuntu and Windows.

---

## Slide 10: Conclusion, Project Impact & Future Vision
- **Demonstrated Competencies:** Full-stack cybersecurity engineering, digital forensics chain-of-custody, detection engineering, DevSecOps pipeline automation.
- **Educational Impact:** A turnkey, local-first training lab for universities, bootcamps, and SOC hiring evaluations.
- **Future Enhancements:** Native SIGMA rule translation, STIX/TAXII threat feed ingestion, and Dockerized multi-node clustering.
- **Project Repository:** [https://github.com/Mannan55/AuthGuard-X](https://github.com/Mannan55/AuthGuard-X)
