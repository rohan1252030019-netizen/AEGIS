# Ram Antivirus Project Factsheet

## Project Identification
- **Project Title:** Development of Threat Detection and Response System, EDR & MDR using Open Source
- **Project Name:** Ram Antivirus (Autonomous Endpoint Guard and Intelligence System)
- **Codebase Version:** 1.6.4.9 / 1.6.5.1
- **Academic Context:** Engineering Final Year / IND Capstone Project (2025–2026)
- **License:** GNU Affero General Public License v3.0 (AGPL-3.0)

---

## Executive Summary
Ram Antivirus is an open-source, self-hosted autonomous cybersecurity platform designed to provide Endpoint Detection and Response (EDR) and centralized Security Operations Center (MDR-style) capabilities without relying on recurring commercial licenses or external cloud AI dependencies. It integrates deterministic rule evaluation, behavioral machine learning, automated response playbooks (SOAR), and privacy-preserving local large language models.

---

## Problem Statement
Small-to-medium enterprises, academic institutions, and homelab environments are disproportionately exposed to advanced cyber attacks (particularly modern ransomware and credential abuse). Existing enterprise EDR/MDR solutions impose high recurring per-seat costs, mandate continuous transmission of sensitive telemetry to third-party cloud infrastructure, and present significant operational complexity. Conversely, conventional open-source tools (SIEMs, log parsers) require manual rule composition and lack tightly integrated, automated containment and remediation mechanisms.

---

## Measurable Project Objectives
1. **O1 (Telemetry Collection):** Implement a dual-tier telemetry collection framework featuring a lightweight Python user-space agent (`psutil`, `watchdog`) and a high-performance native Rust prototype agent (`sysinfo`, `notify`).
2. **O2 (Deterministic Threat Correlation):** Develop an in-memory Sigma-style correlation engine executing 168+ built-in rules across 15 MITRE ATT&CK categories with sub-millisecond in-memory rule evaluation latency.
3. **O3 (Behavioral Anomaly Detection):** Deploy an unsupervised machine learning model (Isolation Forest) tracking 8 baseline host metrics over a rolling 7-day window to identify stealthy, signature-evasive activity.
4. **O4 (Ransomware Defense):** Establish a dedicated ransomware kill-chain detection and containment pipeline spanning 12 attack stages, sentinel canary files, entropy spike analysis, and active process termination.
5. **O5 (Privacy-Preserving AI Triage):** Integrate local LLM inference (via Ollama) for autonomous incident triage, root-cause explanation, and playbook recommendation, supported by a deterministic offline fallback mode.
6. **O6 (Automated SOAR & Containment):** Build automated response playbooks providing safe IP-guarded permanent and provisional firewall blocking (auto-expiring to limit false positives).
7. **O7 (Centralized Operations Management):** Construct a reactive, multi-tenant administrative dashboard (Next.js 14) communicating with the backend over real-time WebSockets and authenticated REST endpoints.

---

## Technology Stack

| Layer | Technologies / Frameworks |
|---|---|
| **Backend Core** | Python 3.12, FastAPI, Starlette, Pydantic v2, asyncio |
| **Database & ORM** | PostgreSQL 16 (production) / MySQL 8.0 (verified compatibility), SQLAlchemy 2.0 (async), aiomysql, asyncpg |
| **In-Memory & Messaging**| Python Collections (deque), In-Memory EventBus, Redis Streams (optional scale-out) |
| **Machine Learning & Math**| scikit-learn (Isolation Forest), NumPy, SciPy (Rényi entropy) |
| **Local AI Framework** | Ollama (Llama-3), OpenRouter (optional fallback), Jinja2 (deterministic fallback) |
| **Native Endpoint Agent** | Rust (Edition 2021), tokio, notify, sysinfo, reqwest, serde, nix, windows-sys |
| **User-Space Python Agent**| Python 3.10+, psutil, watchdog, win32evtlog, requests |
| **Frontend Dashboard** | Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, shadcn/ui, Recharts |
| **Deployment & Ops** | Docker, Docker Compose, PM2 process manager, Linux pfctl/iptables |

---

## Key Core Modules

1. **Correlation Engine (`correlation_engine.py`):**
   - 10,000-event in-memory sliding window (`collections.deque`).
   - O(1) type-indexed rule candidate lookup dictionary.
   - Evaluates 168+ Sigma-style rules and 6 multi-step attack chain rules.
   - Measures evaluation loop via `time.perf_counter_ns()`.
   - Incorporates dynamic confidence factor multipliers (Tor exit, scanner UA, known attacker).

2. **Behavioral ML Engine (`behavioral_ml.py`):**
   - Implements `sklearn.ensemble.IsolationForest` (`contamination=0.05`).
   - Tracks 8 specific vector dimensions per asset: `connection_count`, `unique_ips`, `request_rate`, `error_rate`, `new_ports`, `data_volume`, `auth_failures`, `unique_user_agents`.
   - Requires 24 hours minimum baseline training; updates on 7-day rolling history.

3. **Ransomware Defense Subsystem (`agent-rust/src/ransomware/` & `raas_intel.py`):**
   - Multi-indicator coverage: shadow-copy deletion (`vssadmin`), LOLBin abuse (`certutil`), mass extension rename, sentinel canary trip, ransom note drop.
   - Rust `killer.rs` terminates process trees via native OS process APIs.
   - Live RaaS threat intelligence feed refreshed every 6 hours (RansomLook + CISA).

4. **Edge Defense & DoS Shield (`dos_shield.py`, `attack_detector.py`):**
   - Layer 7 request inspection using pre-compiled mega-regex with double URL-decoding.
   - Rate-limiting (per-IP, per-subnet, global) and Slowloris mitigation.
   - Immediate 403 blocking of high-severity web payloads.

5. **Quantum Security Analytics (`modules/quantum/`):**
   - Multi-order Rényi entropy calculations ($\alpha \in \{0.5, 1.0, 2.0, \infty\}$) for C2 beacon profile matching.
   - Mathematical modeling of Grover's and Shor's algorithms estimating symmetric/asymmetric cryptographic longevity under hypothetical quantum hardware.

---

## Key Measurable Contributions
- **Zero-Licensing Cost:** Complete EDR/MDR capability under the AGPL-3.0 license.
- **In-Memory Rule Performance:** Sub-millisecond rule evaluation latency ($<1$ ms) under local benchmark conditions for events already buffered in memory.
- **Privacy-Preserving Triage:** Full security incident summarization without external data exfiltration via local Ollama integration.
- **Provisional Block Innovation:** Self-reversing automated firewall blocks (default 6-hour TTL) that mitigate catastrophic network lockouts caused by false positives.
- **Multi-Tenant Architecture:** Complete data partitioning at the database layer utilizing tenant-scoped foreign keys and API keys.

---

## Verified Codebase Limitations
1. **Reactive Ransomware Interception:** Ram Antivirus does not implement a synchronous Windows kernel minifilter driver; fast ransomware can encrypt a limited batch of files prior to canary tripping and process termination.
2. **User-Space Telemetry Boundary:** The Python agent relies on polling APIs (`psutil`), which can be bypassed by kernel rootkits or ephemeral processes executing entirely between 10-second polling intervals.
3. **Absence of True ETW / eBPF:** Kernel event tracing (Windows ETW via `ferrisetw` or Linux eBPF via `aya`) is documented as a target architecture but is not yet compiled into the agent binaries.
4. **Snapshot Recovery Platform Dependencies:** Snapshot restoration is functional on macOS (`tmutil`) and Linux (`btrfs`/`zfs`) when `AEGIS_REAL_RECOVERY=1` is explicitly asserted; Windows VSS recovery remains a stub.
5. **Absence of Labeled Benchmark Evaluation:** Formal statistical evaluation against public datasets (e.g., CIC-IDS-2017) was outside the implementation scope; ML validation is currently conducted via synthetic anomaly injection test fixtures.
6. **MDR Semantic Scope:** The platform provides an *MDR-style technical architecture* (centralized logging, automated correlation, playbooks), but does not provide a 24/7 human-operated Managed Security Operations Center.

---

## Future Roadmap
- **Kernel Telemetry Integration:** Implement Windows ETW provider sessions and Linux eBPF syscall tracing (`sched_process_exec`, `sys_enter_openat`).
- **Synchronous Minifilter Driver:** Author a Windows File System Minifilter driver for pre-write file interception.
- **Dataset Benchmarking:** Execute formal detection accuracy studies against the CIC-IDS-2018 and UNSW-NB15 corpora.
- **YARA Binary Integration:** Direct linkage of the native `yara` library for static executable inspection.
- **STIX/TAXII Federation:** Automate standardized threat intelligence ingestion and export.
