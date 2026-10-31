# AuthGuard-X v3.0.0 Release Notes

**Release Date:** October 31, 2026  
**Baseline Git Tag:** `v3.0.0` / `v3`  
**Previous Baseline:** `v2.0.0` / `v2` (Sprint 5 Final Completion)  
**Original Baseline:** `v1.0.0` / `v1` (`e59ffb0` Initial Project Baseline)

---

## Executive Summary

AuthGuard-X v3.0 marks a major milestone in the evolution of the local-first Security Operations Center (SOC) demonstration, training, and threat simulation platform. Building upon the foundational investigation and reporting architecture established in previous releases, v3.0 introduces a real-time geospatial Threat Map simulation engine, repairs multi-analyst authentication workflows, streamlines project documentation, and completes end-to-end verification across both unit and full-browser test suites.

---

## Major Enhancements in v3.0

### 1. Global Threat Map & Real-Time Trajectory Simulation Engine
- **Local-First Geospatial Asset**: Integrated an offline-capable, self-contained SVG world map (`frontend/assets/world_map.svg`) eliminating third-party external CDN latency and potential CORS/CSP blocking.
- **Geospatial Origin Coordinate Matrix**: Mapped 17 global adversary origin hotspots (Frankfurt, London, Tokyo, Singapore, Sydney, Sao Paulo, San Jose, Amsterdam, Seoul, Mumbai, Stockholm, Toronto, Johannesburg, Dubai, Hong Kong, Paris, Warsaw) with precise viewport coordinate scaling.
- **Animated SVG Trajectory Layer**: Dynamic quadratic bezier curve laser/arc rendering from origin coordinates to the enterprise target authentication gateway (`AUTH-GATEWAY-01`), accompanied by concentric expanding origin radar ripples and transient city labels.
- **Interactive Simulation Controls**:
  - Live Stream Toggle (`[Pause Stream]` / `[Resume Stream]`) with real-time status indicators.
  - Manual vector injection (`[Inject Threat Vector]`).
  - Simulation frequency speed selector (`Fast 1.5s`, `Normal 2.5s`, `Slow 5.0s`).
  - Scenario category filtering (`Credential Attacks`, `Recon & Probes`, `Critical Severities`, `All Scenarios`).
  - Database sync toggle (`Sync to Incidents`) allowing visual-only telemetry streaming or live persistence to `/api/incidents/simulate`.
- **Live Intercept Feed & Origin Breakdown**: Real-time rolling ticker of synthetic telemetry intercepts alongside a top-origin frequency distribution bar chart.

### 2. SOC Analyst Authentication & Role Autofill Alignment
- **Credential Synchronization**: Standardized bcrypt (12 rounds) credential hashes for demo analyst accounts (`analyst_john` and `analyst_jane`) to match published documentation (`AnalystPassword2026!` and `analyst123`).
- **One-Click Role Autofill**: Enhanced the development login interface with 1-click autofill buttons for Admin (`admin`), Analyst John (`analyst_john`), and Analyst Jane (`analyst_jane`), facilitating rapid role-switching and permission review.
- **Multi-Alias Development Tolerance**: Configured development authentication helpers to seamlessly accept documented development passwords without compromising production security enforcement.

### 3. Documentation & Screenshot Streamlining
- **Streamlined Visual Overview**: Replaced verbose screenshot tables in `README.md` with 4 core, high-impact workspace showcases (SOC Overview, Investigation Lifecycle, Threat Detection Alerts, and Report Builder) plus a clean collapsible drawer for secondary views.
- **Fresh Evidence Capture**: Regenerated all 34 real-browser screenshots across mobile (390px), tablet (768px), desktop (1440px), and widescreen (1920px) viewports via the automated headless CDP runner.

---

## Verification & Test Results

| Test Category | Scope | Passing Assertions | Execution Time |
| :--- | :--- | :--- | :--- |
| **Backend Unit & API Suite** | Pytest (`tests/`) | **161 / 161 (100%)** | ~2 min 28s |
| **End-to-End Real-Browser Suite** | Chromium CDP (`scripts/capture_evidence.py`) | **34 / 34 (100%)** | ~1 min 45s |
| **Geospatial Trajectory Rendering** | Threat Map Overlay (`frontend/js/threat-map.js`) | Verified | Real-time |
| **Role-Based Access Control** | Admin vs Analyst Separation | Verified | Real-time |

---

## Versioning Taxonomy

- **v1.0.0 / v1**: Original legacy repository baseline (`e59ffb0`) prior to SOC modernization sprints.
- **v2.0.0 / v2**: Multi-sprint hardening baseline (`d5c0161`) incorporating Sprints 1–5 (SOC UI, Case Investigation, Detection Engineering, Log Ingestion, and Grounded Reporting).
- **v3.0.0 / v3**: Current release incorporating the live threat map simulation engine, analyst authentication fix, streamlined visual documentation, and comprehensive verification.
