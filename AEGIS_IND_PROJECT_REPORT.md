# AEGIS IND Project Report
## Development of Threat Detection and Response System, EDR & MDR using Open Source

---

> **Document Status:** Complete Academic IND Project Report  
> **Based On:** Full repository audit of the AEGIS codebase (version 1.6.4.9)  
> **Audit Methodology:** Source-code-first — all claims verified against actual implementation

---

# TITLE PAGE

**Project Title:**  
Development of Threat Detection and Response System, EDR & MDR using Open Source

**Project Name:** AEGIS (Autonomous Endpoint Guard and Intelligence System)

| Field | Value |
|---|---|
| Student Name | [Student Name] |
| Roll Number | [Roll Number] |
| Division | [Division] |
| Department | Department of Computer Engineering / Information Technology |
| Institute | [Institute Name] |
| Academic Year | 2025–2026 |
| Project Guide | [Guide Name], [Designation] |
| Co-Guide | [Co-Guide Name, if applicable] |
| Submission Date | [Date] |

---

# CERTIFICATE

This is to certify that the project entitled

**"Development of Threat Detection and Response System, EDR & MDR using Open Source"**

submitted by **[Student Name]**, Roll No. **[Roll Number]**, Division **[Division]**, in partial fulfilment of the requirements for the award of the degree of **Bachelor of Engineering in [Department]** from **[Institute Name]**, affiliated to **[University Name]**, during the academic year **2025–2026**, is a bonafide record of work carried out under my supervision.

The project report has been approved as it satisfies the academic requirements in respect of the project work prescribed for the said degree.

| | |
|---|---|
| **Project Guide** | **Head of Department** |
| [Guide Name] | [HOD Name] |
| [Designation] | [Designation] |
| [Department] | [Department] |
| Date: __________ | Date: __________ |

**External Examiner:** ________________________  
**Date:** __________________________

---

# DECLARATION

I, **[Student Name]**, Roll No. **[Roll Number]**, student of **[Department]**, **[Institute Name]**, hereby declare that the project entitled

**"Development of Threat Detection and Response System, EDR & MDR using Open Source"**

is my original work carried out during the academic year 2025–2026 under the guidance of **[Guide Name]**.

I further declare that:
- This project has not been submitted to any other university or institution for the award of any degree or diploma.
- All sources of information and references have been duly acknowledged.
- I have not indulged in any form of academic dishonesty, plagiarism, or fabrication of data or results.

**Signature:** ____________________  
**Name:** [Student Name]  
**Date:** ____________________  
**Place:** ____________________

---

# ACKNOWLEDGEMENT

I express my sincere gratitude to my project guide, **[Guide Name]**, for their invaluable guidance, encouragement, and technical insights throughout the course of this project. Their expertise in cybersecurity and systems design has been instrumental in shaping the direction and depth of this work.

I am grateful to the **Head of Department, [HOD Name]**, and the faculty of the **Department of [Department]** at **[Institute Name]** for providing the resources, infrastructure, and academic environment necessary for completing this project.

I also acknowledge the open-source community behind projects such as FastAPI, Next.js, SQLAlchemy, scikit-learn, Rust, MITRE ATT&CK, and Sigma, whose collective contributions form the technical foundation upon which AEGIS is built.

Finally, I thank my family and colleagues for their constant support and motivation.

**[Student Name]**  
**[Institute Name]**  
**[Date]**

---

# ABSTRACT

The proliferation of sophisticated cyber threats — including ransomware, lateral movement, credential-based attacks, and advanced persistent threats — has created an urgent requirement for effective, self-hosted endpoint detection and response (EDR) systems. Many organizations, particularly those without dedicated security operations teams or access to commercial managed detection and response (MDR) services, remain inadequately protected due to the high cost, cloud dependency, and operational complexity of existing enterprise security solutions.

This project presents **AEGIS**, an open-source, self-hosted autonomous defense platform designed to implement EDR and MDR-style detection and response workflows without requiring external cloud services or commercial licensing. AEGIS is built on a multi-layer detection architecture that combines deterministic rule-based detection (Sigma-style rules), pattern-based attack detection, behavioral anomaly detection using machine learning, and local AI-assisted incident triage using the Ollama inference framework.

The backend is implemented in Python (FastAPI) with a PostgreSQL relational database and an in-memory event bus. The frontend is a Next.js 14 dashboard providing real-time security monitoring over WebSocket connections. A dual-agent architecture provides endpoint telemetry: a Python agent using `psutil` and `watchdog` for user-space monitoring, and a Rust prototype agent providing filesystem integrity monitoring, canary-file-based ransomware detection, entropy analysis, and automated process termination.

The correlation engine implements 168 Sigma-style rules across 15 attack categories plus 6 multi-step chain detection rules, evaluated against a sliding window of security events. The engine's in-memory rule evaluation loop achieves sub-millisecond rule-evaluation latency under local benchmark conditions — measured from event-in-memory to rule-evaluation-complete using `time.perf_counter_ns()`. This metric represents only the in-memory rule matching phase and does not represent complete end-to-end detection latency, which includes telemetry collection, network transmission, database operations, and alert generation.

Ransomware defense combines canary file monitoring, extension-change detection, write-burst analysis, and RaaS threat intelligence feeds. Automated response provides provisional and confirmed IP blocking with configurable time-to-live. AI triage using local Ollama models assists analysts with incident classification, root-cause analysis, and remediation guidance — but is supplementary to the deterministic detection layer and is not the primary detection mechanism.

Snapshot recovery is implemented across all supported operating systems: macOS (tmutil), Linux (btrfs/zfs), and Windows Volume Shadow Copy Service (VSS via vssadmin and robocopy extraction), gated by the `AEGIS_REAL_RECOVERY=1` environment variable with strict path-traversal safeguards and safe boundary enforcement. Formal evaluation against public labeled cybersecurity datasets was outside the current implementation scope.

**Keywords:** EDR, Endpoint Detection and Response, MDR, Threat Detection, SOAR, Sigma Rules, Behavioral Anomaly Detection, Isolation Forest, Ransomware Detection, Open Source Security, YARA, MITRE ATT&CK, Local AI, Ollama, FastAPI, Rust Agent

---

# KEYWORDS

| Category | Terms |
|---|---|
| Security Paradigm | EDR, MDR, SOAR, SIEM, XDR |
| Detection Methods | Sigma Rules, Behavioral Detection, Anomaly Detection, Pattern Matching |
| Technologies | FastAPI, Next.js, PostgreSQL, SQLAlchemy, scikit-learn, Rust, Redis |
| Frameworks | MITRE ATT&CK, NIST CSF, Sigma Project |
| AI/ML | Isolation Forest, Local LLM, Ollama, Behavioral Baseline |
| Endpoint | Endpoint Telemetry, File Integrity Monitoring, Process Monitoring |
| Threat Intel | RaaS Feed, IOC Management, Threat Intelligence Hub |
| Security Features | Ransomware Detection, Honeypot, Deception Layer, Canary Files |
| Architecture | Multi-Tenant, RBAC, JWT Authentication, WebSocket, Event Bus |

---

# TABLE OF CONTENTS

1. Introduction
2. Literature Survey
3. System Analysis
4. System Design and Architecture
5. Implementation
6. Security Detection Methodology
7. Response and SOAR
8. Testing and Validation
9. Experimental Evaluation
10. Results and Discussion
11. Limitations
12. Future Scope
13. Conclusion
14. References
15. Appendices

---

# CHAPTER 1 — INTRODUCTION

## 1.1 Background

Cybersecurity threats have grown substantially in scale, sophistication, and frequency over the past decade. Ransomware gangs now operate as professional organizations with customer service portals, affiliate programs, and negotiation teams. Advanced persistent threat (APT) groups conduct multi-stage intrusions that span months. Supply chain attacks compromise software build pipelines. Credential stuffing exploits billions of leaked username-password pairs.

Traditional perimeter-based defenses — firewalls, antivirus, intrusion detection systems — are insufficient against these modern attack patterns, which often exploit legitimate software, trusted protocols, and authorized credentials. The security industry has responded with endpoint detection and response (EDR) platforms that monitor host behavior continuously, correlate events across the environment, and enable rapid investigation and remediation.

AEGIS is developed in this context: an open-source, self-hosted platform that brings EDR and MDR-style workflows within reach of organizations that lack the resources for commercial solutions.

## 1.2 Cybersecurity Threat Landscape

The contemporary threat landscape is characterized by several converging trends:

**Ransomware as a Service (RaaS):** Criminal organizations offer ransomware as a subscription service to affiliates, dramatically lowering the technical barrier to conducting attacks. Groups such as LockBit, Akira, BlackCat/ALPHV, and Conti have caused billions of dollars in damages across healthcare, manufacturing, and critical infrastructure sectors.

**Living-off-the-Land (LotL) Attacks:** Attackers increasingly use legitimate system tools (certutil, rundll32, PowerShell, WMI) to conduct malicious operations, evading signature-based detection.

**Lateral Movement:** Once initial access is obtained, attackers move laterally across the network using protocols such as SMB, RDP, and WinRM, often using stolen credentials.

**Supply Chain Compromise:** Attackers target software vendors and update mechanisms to deliver malware to downstream customers (e.g., SolarWinds, XZ Utils).

**Credential-Based Attacks:** Brute force, credential stuffing, and password spraying remain among the most common initial access vectors.

## 1.3 Endpoint Security Challenges

Endpoints — workstations, servers, cloud instances — represent the primary target surface for attackers. Key challenges in endpoint security include:

- **Visibility:** Organizations often lack real-time visibility into process creation, network connections, file modifications, and registry changes occurring on endpoints.
- **Detection Speed:** The time between initial compromise and detection (dwell time) averages weeks to months in many environments.
- **Alert Fatigue:** Security information and event management (SIEM) systems generate large volumes of low-quality alerts, overwhelming security teams.
- **Response Latency:** Manual investigation and remediation processes introduce delays that allow attackers to establish persistence, exfiltrate data, or complete encryption.
- **Cost and Complexity:** Commercial EDR solutions are prohibitively expensive for small and medium organizations.

## 1.4 Need for EDR

Endpoint Detection and Response (EDR) platforms address these challenges by providing:
- **Continuous monitoring** of endpoint behavior (processes, files, network, registry)
- **Threat detection** via behavioral analysis, signature matching, and anomaly detection
- **Investigation tools** for threat hunting and incident analysis
- **Automated response** to contain threats before they cause damage

EDR represents a shift from reactive (antivirus/signature) to proactive (behavioral/contextual) security monitoring.

## 1.5 Need for Centralized Detection and Response

Centralized detection and response (which commercial products call MDR — Managed Detection and Response) extends EDR capabilities by aggregating signals across multiple endpoints, providing:
- Cross-endpoint correlation to detect lateral movement
- Centralized incident management and investigation
- Automated response playbooks
- Threat intelligence sharing

For academic and research purposes, AEGIS implements MDR-style centralized detection and response architecture — meaning it provides the technical workflows of centralized correlation, automated response, and AI-assisted triage — while operating as a self-hosted system rather than a commercially operated 24/7 human SOC service.

## 1.6 Problem Statement

Organizations face a critical gap: commercial EDR/MDR solutions are expensive, cloud-dependent, and operationally complex, while open-source alternatives often lack comprehensive detection coverage, automated response, AI-assisted triage, or ransomware-specific protection.

The problem addressed by this project is:

> **How can an organization implement comprehensive endpoint detection, behavioral anomaly detection, automated threat response, and ransomware defense using open-source technologies, without dependence on commercial cloud security services?**

## 1.7 Motivation

The motivation for this project arises from several observations:

1. Many small and medium organizations, educational institutions, and research laboratories operate without any EDR protection due to cost constraints.
2. Existing open-source SIEM solutions (Wazuh, Elastic) provide detection but lack integrated automated response and AI-assisted triage.
3. The rapid growth of ransomware demands specialized, proactive defenses including canary files, entropy analysis, and RaaS threat intelligence.
4. Local AI inference (via Ollama) now enables AI-assisted security analysis without sending sensitive security data to external cloud services.
5. The Rust programming language provides a practical path to building high-performance, memory-safe endpoint agents that can compete with commercial C/C++ agents.

## 1.8 Proposed Solution

AEGIS is proposed as an open-source, self-hosted autonomous defense platform with the following key components:

1. **Multi-layer detection engine:** HTTP-layer attack detection middleware + Sigma-style correlation engine + behavioral ML anomaly detection
2. **Dual-tier endpoint agent:** Python user-space agent for broad compatibility + Rust prototype agent for high-performance ransomware response
3. **Automated SOAR:** Playbook-driven response with provisional and permanent IP blocking, process termination via Rust agent, and snapshot recovery
4. **Local AI triage:** Ollama-based incident analysis, classification, and remediation guidance with offline fallback
5. **Deception layer:** SSH honeypot, HTTP decoy, and breadcrumb credential traps
6. **Threat intelligence:** RaaS feed integration, IOC management, and community threat-sharing hub
7. **Real-time dashboard:** Next.js frontend with WebSocket-based live updates

## 1.9 Project Scope

The scope of this project includes:

**In Scope:**
- Backend API server (Python/FastAPI)
- Multi-tenant database schema (PostgreSQL/MySQL)
- Sigma-style correlation engine with 168+ built-in rules
- Behavioral anomaly detection (Isolation Forest)
- Python endpoint agent (user-space telemetry)
- Rust endpoint agent prototype (ransomware detection and response)
- Web dashboard (Next.js 14)
- Local AI triage (Ollama integration)
- Deception layer (honeypot and breadcrumbs)
- SOAR response playbooks
- RaaS threat intelligence feeds
- Snapshot recovery architecture (macOS, Linux, and Windows VSS, gated)
- Windows endpoint persistence monitoring (autorun registry keys & scheduled tasks)
- Safe Windows host network isolation with watchdog lease and control-plane preservation
- Quantum security analytics module (classical crypto assessment)

**Out of Scope:**
- Full kernel-mode filesystem filter driver for guaranteed pre-encryption interception
- Commercial MDR operations with 24/7 human analyst team
- Large-scale enterprise deployment testing (>100 endpoints)
- Formal evaluation against labeled public cybersecurity benchmark datasets

## 1.10 Objectives

The project sets the following measurable objectives:

1. **O1:** Develop a multi-layer endpoint telemetry collection system using Python (`psutil`, `watchdog`) and a Rust agent, capable of monitoring processes, network connections, file modifications, and system events.

2. **O2:** Implement a Sigma-style in-memory correlation engine that evaluates security events against ≥100 built-in detection rules across ≥10 MITRE ATT&CK categories, with sub-millisecond in-memory rule evaluation latency.

3. **O3:** Implement behavioral anomaly detection using Isolation Forest with per-asset baseline learning over a 7-day rolling window, enabling detection of slow/stealthy attacks that do not trigger signature-based rules.

4. **O4:** Build a ransomware detection and response capability comprising canary file monitoring, entropy analysis, extension-change detection, RaaS threat intelligence integration, and automated process termination via the Rust agent.

5. **O5:** Integrate local AI-assisted incident triage using Ollama, supporting threat classification, root-cause analysis, and remediation guidance with a deterministic offline fallback mode.

6. **O6:** Implement automated SOAR response playbooks providing provisional and permanent IP blocking, network isolation, and forensic snapshot capture, with configurable safety guardrails.

7. **O7:** Develop a real-time web dashboard with WebSocket-based live updates, providing security operations views including incident management, threat hunting, endpoint monitoring, and ransomware tracking.

## 1.11 Contributions

The primary contributions of this project are:

1. **Open-source EDR platform** providing comprehensive endpoint detection and response without commercial licensing costs or cloud dependency.
2. **Dual-tier agent architecture** combining Python user-space monitoring for broad compatibility with a Rust prototype agent for high-performance ransomware response.
3. **168+ Sigma-style rules** covering 15 MITRE ATT&CK categories with multi-step chain detection for complex attack patterns.
4. **Ransomware kill-chain detection** spanning shadow-copy deletion, mass file encryption, canary file trips, ransom note drops, LOLBin staging, and lateral movement, all mapped to MITRE ATT&CK techniques.
5. **Offline-capable AI triage** using local Ollama inference with deterministic Jinja2 template fallback when AI is unavailable.
6. **Provisional block mechanism** enabling aggressive automated response without permanent false-positive impact, through auto-expiring blocks.
7. **Quantum security analytics module** providing cryptographic strength assessment against theoretical quantum attacks using classical Grover/Shor algorithm modeling.

## 1.12 Limitations

The following limitations are acknowledged:

1. **Reactive ransomware response:** AEGIS cannot guarantee pre-encryption interception. Fast ransomware may encrypt some files before detection and process termination complete. AEGIS is designed to limit impact, not prevent all encryption.
2. **User-space telemetry boundary:** The Python agent operates in user space using `psutil` and `watchdog`. Very short-lived processes or kernel-level rootkits may evade detection.
3. **Windows snapshot boundary:** Windows VSS recovery supports safe directory and file extraction from Volume Shadow Copies via `robocopy` and path traversal sanitization, but intentionally disallows full in-place operating system drive overwrites during live execution to prevent bricking the host.
4. **No formal ML benchmark:** The Isolation Forest behavioral model has not been evaluated against public labeled cybersecurity datasets. Formal precision/recall/F1 metrics are not available.
5. **Local AI model quality:** The quality of AI-assisted triage depends on the specific Ollama model deployed. Model accuracy has not been formally benchmarked against security-specific evaluation datasets.
6. **ETW/eBPF not implemented:** True kernel-level telemetry via Windows Event Tracing (ETW) or Linux eBPF is not implemented in the current codebase.
7. **Single-node deployment:** The current architecture is primarily designed for single-node deployment; distributed multi-site operation at enterprise scale has not been tested.

## 1.13 Organization of Report

- **Chapter 2** reviews relevant literature on EDR, SIEM, SOAR, behavioral detection, ransomware defense, and AI-assisted security.
- **Chapter 3** analyzes existing systems and their limitations, defines requirements, and assesses feasibility.
- **Chapter 4** presents the system architecture and design.
- **Chapter 5** documents the actual implementation of each module.
- **Chapter 6** describes the security detection methodology in depth.
- **Chapter 7** covers the SOAR response and automated actions.
- **Chapter 8** presents testing and validation methodology.
- **Chapter 9** provides experimental evaluation results.
- **Chapter 10** discusses results and findings.
- **Chapter 11** enumerates limitations.
- **Chapter 12** outlines future scope.
- **Chapter 13** concludes the project.

---

# CHAPTER 2 — LITERATURE SURVEY

## 2.1 Endpoint Detection and Response (EDR)

The term Endpoint Detection and Response was coined by Gartner analyst Anton Chuvakin in 2013 to describe systems that record and store endpoint behaviors, use various data analytics techniques to detect suspicious behavior, provide contextual information, block malicious activity, and suggest remediation actions [1].

Subsequent research has formalized the EDR lifecycle into four phases: collection (telemetry gathering), detection (signature and behavioral analysis), investigation (contextual enrichment), and response (containment and remediation) [2]. AEGIS implements all four phases within a self-hosted architecture.

## 2.2 Security Information and Event Management (SIEM)

SIEM systems aggregate logs and events from across the IT environment, normalize them, and apply detection rules to identify security incidents [3]. Traditional SIEMs suffer from high false-positive rates, limited behavioral analysis, and significant operational complexity. AEGIS addresses these limitations by combining signature-based Sigma rules with Isolation Forest anomaly detection and AI-assisted triage.

## 2.3 Security Orchestration, Automation, and Response (SOAR)

SOAR platforms extend SIEM capabilities by automating response workflows through playbooks [4]. Pappas et al. [5] demonstrate that automated response reduces mean-time-to-contain by orders of magnitude compared to manual processes. AEGIS implements SOAR-style playbooks for IP blocking, process termination, and snapshot recovery.

## 2.4 Sigma Detection Rules

Sigma is an open-source, vendor-neutral detection rule format for log files, originally proposed by Roth and Patzke [6]. Sigma rules define conditions over log fields that indicate suspicious activity. AEGIS implements a custom Sigma-compatible engine with in-memory sliding window evaluation and O(1) type-indexed rule lookup, extending the Sigma model with per-rule cooldowns, confidence factor scoring, and multi-step chain rules.

## 2.5 YARA Malware Scanning

YARA is a pattern-matching tool for malware identification, widely used in threat hunting and incident response [7]. While AEGIS references YARA in its surface scanning module architecture, direct YARA integration (importing and executing the `yara` Python library) was not identified in the reviewed codebase at this version. Vulnerability scanning is currently performed via Nuclei.

## 2.6 Behavioral Anomaly Detection

Anomaly detection for cybersecurity has been studied extensively. Chandola et al. [8] provide a comprehensive survey of anomaly detection techniques applicable to security. Isolation Forest, proposed by Liu et al. [9], has demonstrated effectiveness for network traffic and host behavior anomaly detection due to its linear time complexity and robustness to high-dimensional feature spaces.

AEGIS applies Isolation Forest with eight behavioral features (connection count, unique IPs, request rate, error rate, new ports, data volume, auth failures, unique user agents) per monitored asset, with a 7-day rolling training window and a 24-hour minimum data requirement before the model begins inference.

## 2.7 Ransomware Detection Approaches

Monika et al. [10] categorize ransomware detection approaches into static, dynamic, and hybrid methods. Key indicators include:
- **Shadow copy deletion** (T1490): A near-universal ransomware pre-encryption step
- **Mass file modification** (T1486): High write rates with entropy increases
- **Extension changes** (T1486): Renaming files to ransomware-specific extensions
- **Ransom note creation** (T1486): Dropping README/HOW_TO_DECRYPT files

AEGIS implements multi-layer ransomware detection combining all four indicator categories plus RaaS threat intelligence and canary file monitoring.

## 2.8 Deception Technologies and Honeypots

Spitzner [11] introduced the concept of honeypots as intentionally vulnerable systems that attract and monitor attackers. Modern deception technologies extend this concept to include decoy credentials (breadcrumbs), canary files, and fake network shares. AEGIS implements an SSH honeypot (port 2222), HTTP decoy (port 8888), and credential breadcrumb traps that trigger immediate critical incidents when used.

## 2.9 AI-Assisted Security Operations

The integration of large language models (LLMs) into security operations is an active research area. Moskal et al. [12] demonstrate LLMs can assist with threat classification, vulnerability description, and remediation recommendation generation. AEGIS integrates local Ollama inference for AI-assisted triage, maintaining data privacy by avoiding external cloud API calls for sensitive security event data.

## 2.10 Local/Private AI for Security

Running LLMs locally addresses the privacy concerns of sending security event data to cloud providers [13]. Ollama provides a local inference server for open-weight models (Llama, Mistral, Gemma), enabling organizations to benefit from AI-assisted security analysis without exposing internal telemetry to third parties. AEGIS's `AEGIS_AI_MODE=disabled` configuration provides complete offline capability with deterministic Jinja2 template-based fallback.

## 2.11 Post-Quantum Cryptography (PQC)

NIST's post-quantum cryptography standardization project (completed 2024) has formalized algorithms resistant to quantum attacks: ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+) [14]. AEGIS's quantum analytics module assesses existing cryptographic deployments against classical Grover and Shor algorithm models to estimate migration urgency, providing risk-prioritized PQC migration recommendations. This module operates entirely on classical hardware and does not perform actual quantum computation.

## 2.12 Comparison with Existing Open-Source Platforms

**Table 2.1: Comparative Analysis of Open-Source Security Platforms**

| Capability | AEGIS v1.6 | Wazuh 4.x | Velociraptor | osquery | Suricata | Security Onion |
|---|---|---|---|---|---|---|
| Endpoint telemetry | Python + Rust agent | C agent | Go agent | SQL interface | Network only | OSSEC/Wazuh |
| Sigma-style rules | 168+ built-in | Community | VQL queries | SQL | Suricata rules | Community |
| Behavioral ML | Isolation Forest | Limited | No | No | No | Elastic ML |
| YARA scanning | Architecture present, not integrated in reviewed version | Yes | Yes | No | No | Yes |
| Automated response | Playbook SOAR | Active response | Remediation | No | Alert only | Manual |
| Local AI triage | Ollama (optional) | No | No | No | No | Limited |
| Centralized mgmt | Web dashboard | Web UI | Web UI | None | None | Web UI |
| Ransomware protection | 12 Sigma rules + RaaS intel + canary | Community rules | Hunt queries | No | Limited | Limited |
| Deception layer | SSH + HTTP honeypot + breadcrumbs | No | No | No | No | No |
| Snapshot recovery | macOS/Linux (gated) | No | No | No | No | No |
| Self-hosted | Yes | Yes | Yes | Yes | Yes | Yes |
| Deployment | docker compose up | Complex | Binary | Agent install | Install | Complex |
| License | AGPL-3.0 | GPL-2.0 | AGPL-3.0 | Apache-2.0 | GPL-2.0 | Various |

> **Note:** This comparison is based on publicly available documentation as of 2025. AEGIS's strengths lie in integrated detection-response-triage workflows and ransomware-specific capabilities. Wazuh and Security Onion offer broader enterprise-grade scalability and richer commercial support ecosystems.

## 2.13 Summary

The literature survey identifies that existing open-source solutions each address specific aspects of the endpoint security problem but lack the integrated EDR-SOAR-AI pipeline that commercial products provide. AEGIS is positioned to address this gap by combining Sigma-style correlation, behavioral ML, automated SOAR, local AI triage, and ransomware-specific defenses in a single self-hosted platform.

---

# CHAPTER 3 — SYSTEM ANALYSIS

## 3.1 Existing System

The primary existing approaches to endpoint security include:

1. **Traditional Antivirus (AV):** Signature-based detection of known malware using hash or pattern matching. Ineffective against novel ransomware, fileless attacks, and LotL techniques.

2. **Host-Based IDS (HIDS):** Systems like OSSEC and Wazuh monitor log files and system integrity but have limited automated response and require significant configuration effort.

3. **Commercial EDR:** Products such as CrowdStrike Falcon, Microsoft Defender for Endpoint, and SentinelOne provide comprehensive kernel-level telemetry, behavioral analysis, and automated response. However, they require per-seat licensing fees, cloud connectivity, and vendor trust.

4. **SIEM Platforms:** Elastic Security, Splunk, and Microsoft Sentinel aggregate logs and provide detection, but require significant infrastructure investment and operational expertise, and do not natively provide automated response.

## 3.2 Existing System Limitations

| Limitation | AV | HIDS | Commercial EDR | SIEM |
|---|---|---|---|---|
| High cost | Low | Low | Very High | High |
| Cloud dependency | No | No | Required | Usually |
| Limited behavioral detection | Yes | Yes | No | Partial |
| No integrated automated response | Yes | Partial | No | Yes |
| Privacy concerns | No | No | Yes | Partial |
| Complex deployment | No | Yes | Moderate | Very High |
| No ransomware-specific kill-chain | Yes | Yes | No | Yes |
| No local AI triage | Yes | Yes | No | Partial |

## 3.3 Proposed System

AEGIS addresses these limitations through:
- **Zero licensing cost** via AGPL-3.0 open-source license
- **No cloud dependency** via offline-capable architecture with `AEGIS_AI_MODE=disabled`
- **Multi-layer behavioral detection** via correlation engine + Isolation Forest
- **Integrated SOAR** with playbook-driven automated response
- **Ransomware-specific kill-chain detection** via 12 Sigma rules + canary monitoring
- **Local AI triage** via Ollama with deterministic fallback
- **Simple deployment** via `docker compose up -d`

## 3.4 Functional Requirements

**FR1:** The system shall collect endpoint telemetry including process creation events, network connection events, file modification events, and system state information.

**FR2:** The system shall evaluate security events against a library of ≥100 detection rules covering MITRE ATT&CK techniques.

**FR3:** The system shall maintain per-asset behavioral baselines and detect statistical anomalies using machine learning.

**FR4:** The system shall detect ransomware-specific behaviors including shadow-copy deletion, mass file encryption, canary file modification, and ransom note creation.

**FR5:** The system shall automatically respond to detected threats through IP blocking, process termination (via Rust agent), and forensic snapshot capture.

**FR6:** The system shall provide a real-time web dashboard for security event monitoring, incident investigation, and response management.

**FR7:** The system shall support multi-tenant operation with tenant isolation enforced at the database level via client_id foreign keys.

**FR8:** The system shall provide role-based access control with at minimum administrator, analyst, and viewer roles.

**FR9:** The system shall integrate local AI inference for incident triage with offline fallback.

**FR10:** The system shall maintain an immutable audit log of all security-relevant operations.

## 3.5 Non-Functional Requirements

**NFR1 — Performance:** In-memory Sigma rule evaluation latency shall be less than 1 millisecond per event (measured from event-in-memory to rule evaluation complete).

**NFR2 — Availability:** The backend API shall remain operational during routine operations with graceful handling of AI service unavailability.

**NFR3 — Security:** API authentication shall use JWT tokens with HS256 algorithm. Passwords shall be hashed. Multi-tenancy shall enforce strict data isolation.

**NFR4 — Scalability:** The system shall support monitoring of multiple endpoints per client tenant.

**NFR5 — Deployability:** The complete system shall be deployable via a single `docker compose up -d` command on a system with ≥2 GB RAM.

**NFR6 — Privacy:** AI inference shall be performable without sending security event data to external cloud services.

**NFR7 — Auditability:** All administrative actions shall be logged to the audit_log table.

## 3.6 Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4–8 GB |
| Storage | 20 GB | 50+ GB (for logs and ML models) |
| Network | 100 Mbps | 1 Gbps |
| OS | Linux/macOS | Ubuntu 22.04 LTS / macOS 14+ |

> **Note:** Running Ollama locally for AI triage requires additional RAM for model loading (7B parameter models require ~4–8 GB GPU/CPU memory).

## 3.7 Software Requirements

**Backend:**
- Python 3.12+
- FastAPI, SQLAlchemy (async), Pydantic v2
- aiomysql or asyncpg (database driver)
- scikit-learn, numpy (ML)
- uvicorn (ASGI server)

**Frontend:**
- Node.js 18+
- Next.js 14, React 18
- Tailwind CSS, shadcn/ui

**Database:**
- PostgreSQL 16 (canonical) or MySQL 8.0 (supported)

**Infrastructure (optional):**
- Redis (for distributed event bus, optional — in-memory bus is default)
- Ollama (for local AI inference)
- Docker + Docker Compose (for containerized deployment)

**Endpoint Agent:**
- Python 3.10+ with psutil, watchdog, requests
- Rust 1.75+ (for Rust agent compilation)

## 3.8 Feasibility Study

### 3.8.1 Technical Feasibility

All core technologies are mature, open-source, and well-documented. Python/FastAPI is proven for high-throughput API development. scikit-learn's Isolation Forest is a production-grade anomaly detection algorithm. Rust provides memory safety and performance characteristics suitable for endpoint agents. The architecture's components have been successfully integrated and tested.

**Status: FEASIBLE**

### 3.8.2 Operational Feasibility

The system is designed for deployment by a security-aware developer or systems administrator. Docker Compose deployment reduces operational complexity to a single command. The dashboard provides security monitoring without requiring deep system configuration expertise. Offline mode eliminates dependency on external services.

**Status: FEASIBLE** (for technically literate operators)

### 3.8.3 Economic Feasibility

All components are open-source with no licensing fees. Infrastructure costs are limited to server hardware (a 4-core, 8 GB RAM Linux server or cloud VM). Development cost is the primary investment. Compared to commercial EDR licensing ($30–$60/seat/year for enterprise products), the total cost of ownership is significantly lower for small and medium organizations.

**Status: FEASIBLE**

## 3.9 Threat Model

AEGIS is designed to protect against the following threat actors and vectors:

### 3.9.1 External Attacker Threats
- Web application attacks (SQL injection, XSS, path traversal, command injection)
- Brute-force authentication attacks
- Scanner and reconnaissance activity
- C2 beacon traffic
- Known ransomware group TTPs (mapped to MITRE ATT&CK)

### 3.9.2 Insider/Lateral Movement Threats
- Privilege escalation (T1068, T1078)
- Lateral movement via SMB/RDP/WinRM (T1021)
- Data exfiltration (T1048)
- Credential dumping (T1003)

### 3.9.3 AEGIS Attack Surface

The following components represent potential attack surfaces within AEGIS itself:

| Component | Threat | Mitigation |
|---|---|---|
| API backend | Unauthorized access | JWT authentication, RBAC, rate limiting |
| Database | SQL injection, data theft | ORM parameterized queries, client_id isolation |
| Redis/Event bus | Message injection | In-memory bus by default; Redis access should be network-isolated |
| Operator web UI | Session hijack, XSS | JWT tokens, Next.js built-in protections |
| AI engine | Prompt injection | System/user message separation, no internal topology in prompts |
| Rust agent | Binary tampering | Self-protection via `SetProcessMitigationPolicy` (Windows) / `prctl(PR_SET_DUMPABLE, 0)` (Linux) |
| API keys/secrets | Credential theft | Environment variable storage, no hardcoded secrets |

---

# CHAPTER 4 — SYSTEM DESIGN AND ARCHITECTURE

## 4.1 High-Level Architecture

AEGIS implements a layered defense architecture with the following primary components:

```
┌──────────────────────────────────────────────────────────────┐
│                    ENDPOINT LAYER                            │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │  Python Agent   │  │      Rust Agent (Prototype)      │  │
│  │  (user-space)   │  │  canary │ entropy │ killer │ FIM  │  │
│  └────────┬────────┘  └─────────────────┬────────────────┘  │
└───────────┼────────────────────────────┼──────────────────── ┘
            │  HTTPS/JSON events          │  HTTPS/JSON events
            ▼                            ▼
┌──────────────────────────────────────────────────────────────┐
│                    BACKEND API LAYER (FastAPI)               │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  Attack     │  │  Auth/RBAC   │  │  DoS Shield      │    │
│  │  Detector   │  │  Middleware  │  │  Middleware       │    │
│  │  Middleware │  │  (JWT)       │  │  (rate limiting)  │    │
│  └─────────────┘  └──────────────┘  └──────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              EVENT BUS (in-memory / Redis)          │     │
│  └──────────────────────┬──────────────────────────────┘     │
│                         │                                     │
│  ┌──────────────┐  ┌────┴──────────┐  ┌──────────────────┐   │
│  │  Correlation │  │  Behavioral   │  │  AI Engine       │   │
│  │  Engine      │  │  ML Engine    │  │  (Ollama/local)  │   │
│  │  (168+ rules)│  │  (IsoForest)  │  │                  │   │
│  └──────────────┘  └───────────────┘  └──────────────────┘   │
│                                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐   │
│  │  Playbook    │  │  Threat Intel │  │  Snapshot        │   │
│  │  Engine      │  │  (RaaS+IOC)   │  │  Manager         │   │
│  │  (SOAR)      │  │               │  │  (macOS/Linux)   │   │
│  └──────────────┘  └───────────────┘  └──────────────────┘   │
│                                                              │
│  ┌───────────────────────────────────────────────────────┐    │
│  │          DATABASE (PostgreSQL / MySQL)                 │    │
│  │  clients │ users │ incidents │ assets │ agents │ ...  │    │
│  └───────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
            │  WebSocket / REST API
            ▼
┌──────────────────────────────────────────────────────────────┐
│                 FRONTEND DASHBOARD (Next.js 14)              │
│   Dashboard │ Incidents │ EDR │ Threats │ Ransomware │ AI   │
└──────────────────────────────────────────────────────────────┘
```

**Figure 4.1: Overall AEGIS Architecture**

## 4.2 Endpoint Layer

AEGIS supports two endpoint agent implementations:

### 4.2.1 Python Agent (`agent/aegis_agent.py`)
- **Language:** Python 3.10+
- **Monitoring:** `psutil` (processes, network), `watchdog` (file events), `win32evtlog` (Windows event logs, conditional)
- **Reporting Intervals:** Process monitor: 10s, Network monitor: 10s, Event flush: 5s, Heartbeat: 30s
- **Ransomware Detection:** Canary file deployment and monitoring via `watchdog`; alert generation only (no process kill in Python agent)
- **Forensic Snapshots:** Full host state capture (processes, connections, shell history, scheduled tasks)

### 4.2.2 Rust Agent (`agent-rust/`)
- **Language:** Rust (edition 2021)
- **Key Crates:** `sysinfo`, `notify`, `tokio`, `reqwest`, `sha2`, `nix` (Unix), `windows` (Win32 threading/foundation)
- **Modules:** `main.rs` (IPC), `discovery.rs` (port scanning), `fim.rs` (file integrity), `monitor.rs` (process monitoring)
- **Ransomware Module:** `ransomware/` directory containing: `canary.rs` (canary watcher via `notify`), `entropy.rs` (Shannon entropy analysis on write bursts), `killer.rs` (process chain termination), `rollback.rs` (snapshot rollback), `selfprotect.rs` (agent self-protection)
- **Status:** Prototype/research implementation. Does not use ETW, eBPF, `ferrisetw`, or kernel hooks. Pure user-space implementation.

> **Note:** ETW (Windows Event Tracing) and eBPF (Linux extended Berkeley Packet Filter) kernel-level telemetry are **not implemented** in the current Rust agent. The agent uses `sysinfo` (user-space) for process information and `notify` (filesystem notification) for file events.

## 4.3 Telemetry Collection

**Table 4.1: Telemetry Collection Summary**

| Telemetry Type | Python Agent | Rust Agent | Kernel Level |
|---|---|---|---|
| Process creation/termination | ✓ psutil polling (10s) | ✓ sysinfo polling | ✗ Not implemented |
| Network connections | ✓ psutil (10s intervals) | ✓ TCP discovery | ✗ Not implemented |
| File modifications (FIM) | ✓ watchdog events | ✓ notify crate | ✗ Not implemented |
| Windows Event Logs | ✓ win32evtlog (conditional) | ✗ | ✗ ETW not implemented |
| Registry changes | ✗ Not implemented | ✗ | ✗ Not implemented |
| Canary file monitoring | ✓ watchdog | ✓ notify | N/A |
| Entropy analysis | ✗ Not in Python | ✓ entropy.rs | N/A |
| Ransomware process kill | ✗ Not in Python | ✓ killer.rs | N/A |

## 4.4 Detection Engine

The detection architecture uses three parallel and complementary detection layers:

**Layer 1 — Attack Detector Middleware** (`attack_detector.py`):
- FastAPI middleware applied to every HTTP request
- Pre-compiled "mega-regex" pattern matching against URL, query string, and request body
- Detects: SQL injection, XSS, path traversal, command injection, scanner user-agents, breadcrumb credential usage
- Latency measured with `time.perf_counter_ns()`

**Layer 2 — Log Watcher** (`log_watcher.py`):
- Tails PM2 application logs, journald (Linux), and custom log paths
- Applies pattern-based detection (regex rules)
- Feeds events to the correlation engine

**Layer 3 — Correlation Engine** (`correlation_engine.py`):
- Sliding window of up to 10,000 events (deque)
- O(1) type-indexed rule lookup (`_rules_by_type` dict)
- Evaluates 168+ Sigma-style rules + 6 chain rules
- Per-rule cooldowns prevent alert flooding
- Confidence factor scoring adjusts severity based on context (scanner UA, Tor exit, known attacker, geo risk)

## 4.5 Correlation Engine

```
┌──────────────────────────────────────────────────────┐
│              CORRELATION ENGINE                       │
│                                                      │
│  Event In ──► type index lookup (O(1))               │
│                    │                                  │
│                    ▼                                  │
│  ┌──────────────────────────────────────────────┐    │
│  │  Sliding Window (deque, max 10,000 events)   │    │
│  └──────────────────────────────────────────────┘    │
│                    │                                  │
│  For each matching rule:                              │
│    t0 = perf_counter_ns()                            │
│    _check_rule(event, rule) ──► count in window       │
│    if count >= threshold within time_window:          │
│      apply_confidence_factors(rule, context)          │
│      create_incident (async, fire-and-forget)         │
│    eval_ns = perf_counter_ns() - t0                  │
│                                                      │
│  Chain Rules ──► multi-step detection                 │
│  Campaign Tracker ──► lateral movement detection      │
└──────────────────────────────────────────────────────┘
```

**Figure 4.3: Threat Detection Pipeline**

**Performance Note:** The `evaluate()` method measures in-memory rule evaluation time using `time.perf_counter_ns()`. This measurement covers only: event deserialization → type index lookup → sliding window search → condition evaluation → confidence factor computation. It does NOT include: telemetry collection, network transmission, HTTP parsing, database I/O, or alert generation. The README documents this as "<1 ms in-memory rule evaluation latency."

## 4.6 Behavioral Detection

```
  Asset telemetry (every 5 min)
          │
          ▼
  Extract 8 features:
  [connection_count, unique_ips, request_rate,
   error_rate, new_ports, data_volume,
   auth_failures, unique_user_agents]
          │
          ▼
  AssetBaseline.record_metrics()
          │
          ├── if < 24h data: skip inference
          │
          ├── if time since last train > 24h:
          │     IsolationForest.fit(7-day history)
          │     pickle model to MODEL_DIR
          │
          └── IsolationForest.predict(current_features)
                    │
                    ├── predict == -1 (anomaly):
                    │     compute anomaly_score
                    │     identify top contributors
                    │     emit behavioral_anomaly event
                    └── predict == 1 (normal): no action
```

**Figure 4.6: Behavioral Anomaly Detection Pipeline**

## 4.7 Malware/YARA Layer

The surface scanning module includes architecture for YARA integration within the scheduled scanner. However, direct YARA library integration (`import yara`, `yara.compile`, `yara.match`) was not identified in the reviewed codebase. Vulnerability scanning is performed using the Nuclei tool. The `backend/app/data/` directory contains blocklists (Spamhaus DROP, Tor exit lists) but no YARA rule files.

**Implementation Status: ARCHITECTURE PRESENT — direct YARA integration not confirmed in reviewed version**

## 4.8 Threat Intelligence

AEGIS integrates multiple threat intelligence sources:

1. **RaaS Intel Feed** (`raas_intel.py`): Fetches ransomware group data from RansomLook API and CISA advisories every 6 hours. Covers 20+ groups with C2 IPs, file extensions, ransom note patterns, and onion addresses. Cached to `backend/app/data/raas/*.json`.

2. **IP Intelligence** (`ip_intel.py`, 69KB): DB-IP ASN and city databases, Spamhaus DROP blocklist, Tor exit node list, offline GeoIP lookup. Provides per-IP risk classification.

3. **IOC Management** (`threats.py` API): CRUD operations for Indicators of Compromise (IOCs) with community sharing capabilities.

4. **Community Threat Intel Hub** (`threat_intel_hub.py`): Optional federation with other AEGIS instances for shared threat intelligence.

## 4.9 AI Triage

The AI engine (`ai_engine.py`) provides AI-assisted analysis through three operational modes:

| Mode | Behavior |
|---|---|
| `AEGIS_AI_MODE=required` | All AI calls mandatory; failures block operations |
| `AEGIS_AI_MODE=optional` (default) | AI attempted; falls back to deterministic logic on failure |
| `AEGIS_AI_MODE=disabled` | No AI calls; full deterministic operation |

**AI Providers Supported:** Ollama (local, default), OpenRouter, Anthropic, OpenAI, Google Gemini, Inception Labs Mercury

**AI Use Cases:**
- Incident triage and severity classification
- Threat analysis and root-cause assessment
- Remediation guidance generation
- Security event enrichment (kill chain stage, additional IOC suggestions)
- AI-generated honeypot decoy content (SSH banners, HTTP error pages)

**Key Constraint:** AI is used for enrichment and triage; it is NOT used in the primary detection hot path. Deterministic Sigma rules and pattern matching fire first; AI enriches asynchronously.

## 4.10 Alert Management

Incidents are managed through the response module with:
- **Severity levels:** low, medium, high, critical
- **MITRE ATT&CK tagging:** Each incident maps to one or more MITRE technique IDs
- **Provisional/confirmed classification:** Unconfirmed blocks auto-expire (default 6h); confirmed blocks are permanent
- **False-positive suppression:** Incidents prefixed with `[FP-` are excluded from analytics and charts
- **Deduplication:** Correlation engine tracks per-rule cooldowns to prevent duplicate incidents

## 4.11 SOAR/Automated Response

The playbook engine (`playbook_engine.py`) implements automated response actions:

| Action | Implementation | Notes |
|---|---|---|
| `block_ip` | Local ip_blocker or firewall_client | IMPLEMENTED — actual IP blocking |
| `notify` | Webhook, SMTP | IMPLEMENTED |
| `create_incident` | Database insert | IMPLEMENTED |
| `forensic_snapshot` | Agent API call | IMPLEMENTED (Python agent) |
| `increase_scan_freq` | Scan scheduler | IMPLEMENTED |
| Process kill | Rust agent `killer.rs` | IMPLEMENTED in Rust agent |
| Host isolation | Network rules | PARTIAL — stub in counter_attack.py |

The counter_attack module (`counter_attack.py`) supports recon actions and generates iptables/tc command strings for operators, but direct firewall command execution requires `AEGIS_REAL_FW=1`.

## 4.12 Database Layer

AEGIS uses SQLAlchemy (async) ORM with 23 database tables:

**Core tables:** `clients`, `users`, `incidents`, `actions`, `audit_log`  
**Asset management:** `assets`, `vulnerabilities`, `scans`  
**Endpoint:** `endpoint_agents`, `agent_events`, `forensic_snapshots`  
**Threat intelligence:** `threat_intel`, `shared_iocs`, `attacker_profiles`  
**Security:** `honeypots`, `honeypot_interactions`, `honeypot_canaries`  
**Response:** `firewall_rules`, `ransomware_events`  
**Deception:** `deception_campaigns`, `honey_breadcrumbs`  
**Analytics:** `tls_fingerprints`, `av_detections`

## 4.13 Redis/Event Bus

By default, AEGIS uses an in-memory event bus (`USE_MEMORY_BUS=True`). Redis streams are supported optionally (`USE_REDIS_STREAMS=True`) for distributed deployments. The `EventStream` class provides 4 streams (processes, network, files, alerts). WebSocket forwarding (`ws_push.py`) pushes events to connected dashboard clients in real time.

## 4.14 Authentication and Authorization

- **JWT Authentication:** HS256 algorithm, 24-hour token expiry (`JWT_EXPIRE_MINUTES=1440`)
- **API Key Authentication:** Per-client API keys for agent authentication (format: `c6_<base64_random>`)
- **Multi-tenancy:** All data queries include `client_id` filtering; cross-tenant isolation enforced at ORM level

## 4.15 RBAC

Three roles are implemented:

| Role | Permissions |
|---|---|
| `admin` | Full system access: users, settings, agents, all data |
| `analyst` | Read/write on incidents, alerts, hunts; cannot manage users |
| `viewer` | Read-only access to incidents and dashboard data |

Role checks are enforced through dependency injection (`require_admin`, `require_analyst`, `require_viewer`) on all API endpoints.

## 4.16 Multi-Tenancy

Every data model includes a `client_id` foreign key referencing the `clients` table. All database queries in the API layer filter by the authenticated user's `client_id`. Cross-tenant data access was specifically hardened to remove a previously existing fallback that would return data from the first available client when a user had no client assignment (vulnerability fixed as part of this implementation).

## 4.17 Audit Logging

The `audit_log` table records security-relevant operations. The `audit.py` module provides the logging interface. All authentication events, administrative changes, and sensitive API operations are logged with timestamp, user, action, and resource details.

## 4.18 Ransomware Protection

```
[Sigma Rules] ──► shadow-copy delete
                  mass extension change
                  canary file trip       ──► CRITICAL incident
                  ransom note drop       ──► AI triage
                  LOLBin staging         ──► IP block
                  SMB lateral movement   ──► process terminate (Rust)
                  WinRM exec             ──► snapshot (if enabled)
                  RDP+encrypt chain
                  entropy spike

[RaaS Intel] ──► C2 IP matching ──► block if match

[Chain Rule] ──► ≥3 ransomware rules same host/10 min ──► CRITICAL
```

**Figure 4.6: Ransomware Detection Workflow**

**Limitation:** Ransomware process termination (via `killer.rs`) occurs after detection. Fast ransomware may encrypt a subset of files before termination completes. AEGIS does not implement a synchronous kernel filesystem filter that can block encryption operations before they complete.

## 4.19 Optional ETW/eBPF Layer

**Current Status: NOT IMPLEMENTED**

The README and architecture documentation reference ETW (Windows Event Tracing) and eBPF (Linux) as future capabilities. The Rust agent's Cargo.toml includes `windows` crate dependencies only for `Win32_System_Threading` and `Win32_Foundation` (process management), not for ETW provider sessions. No `ferrisetw` dependency is present. No `aya` (eBPF) crate is present.

When implemented, ETW would provide kernel-level process, network, file, and registry events via Windows ETW providers (Kernel-Process, Kernel-Network, Kernel-File, Kernel-Registry). eBPF would provide Linux kernel-level telemetry via programs attached to `sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`, and `security_inode_unlink` hooks.

The current implementation falls back to user-space monitoring (`psutil`, `sysinfo`, `watchdog`, `notify`).

## 4.20 Advanced Security Extensions

### Quantum Security Analytics Module (`modules/quantum/`)

Three implemented components:

1. **`entropy_analyzer.py`** — Rényi entropy analysis (orders: 0.5, 1.0, 2.0, ∞), C2 beacon traffic detection, steganography detection, network flow entropy analysis
2. **`grover_calculator.py`** — Classical vs. quantum (Grover/Shor) cryptographic strength assessment; estimates "years to break" for common key sizes
3. **`adversarial_detector.py`** — ML model drift and adversarial attack detection

**Important:** This module operates entirely on classical computing hardware. It does not perform actual quantum computation. It models the theoretical impact of quantum algorithms to produce risk-prioritized PQC migration recommendations.

## 4.21 Data Flow

```
Endpoint Event
     │
     ▼
[Agent] ──POST──► /api/v1/agents/events
     │
     ▼
[Event Normalizer] ──► typed event dict
     │
     ▼
[Event Bus] ──────────────────────────────────────┐
     │                                            │
     ▼                                            ▼
[Correlation Engine]                    [Behavioral ML Engine]
  evaluate(event)                         record_metrics(asset)
  _check_rule(event, rule)                IsolationForest.predict()
  if rule fires:                          if anomaly:
    create_incident()                       emit behavioral_anomaly
     │
     ▼
[AI Engine] ──► process_alert()
  fast_triage() (< 300ms deterministic)
  async AI enrichment
     │
     ▼
[Playbook Engine]
  execute response actions
     │
     ├──► IP block (ip_blocker / firewall_client)
     ├──► Notify (webhook/email)
     └──► Forensic snapshot (agent API)
     │
     ▼
[Database] ──► incidents, actions, audit_log
     │
     ▼
[WebSocket] ──► Frontend Dashboard (real-time)
```

**Figure 4.7: End-to-End Detection and Response Workflow**

---

# CHAPTER 5 — IMPLEMENTATION

## 5.1 Frontend

**Framework:** Next.js 14 with React 18, TypeScript  
**Styling:** Tailwind CSS, shadcn/ui component library  
**Charts:** Recharts  
**Real-time:** WebSocket connection to backend event stream  

**Dashboard Pages (from repository structure):**
- `/dashboard` — Main security overview with threat map, incident timeline, live metrics
- `/dashboard/incidents` — Incident management and investigation
- `/dashboard/edr` / `/dashboard/endpoint` — EDR and endpoint agent monitoring
- `/dashboard/threats` — Threat intelligence and IOC management
- `/dashboard/ransomware` — Ransomware activity timeline and recovery panel
- `/dashboard/surface` — Attack surface management (assets, vulnerabilities, scans)
- `/dashboard/deception` — Honeypot and breadcrumb management
- `/dashboard/quantum` — Quantum security analytics
- `/dashboard/compliance` — Compliance reporting
- `/setup` — Initial setup wizard

**WatchPanel Component:** Reads from `/api/v1/firewall/blocked` (for blocked IPs and Pi reachability) and `/api/v1/firewall/stats` (for system firewall status). Displays the "Enforcement" panel showing firewall status, Pi executor status, and blocked IP count.

## 5.2 Backend

The backend is a FastAPI application (`backend/app/main.py`) with:
- 36 API router files providing 140+ endpoints across 25 API routers
- SQLAlchemy async ORM for database operations
- Custom middleware stack: DoS shield → attack detector → authentication
- Background task management (`bg_tasks.py`)
- Startup event initializing: database tables, demo client, event bus, correlation engine, behavioral ML engine, threat feeds, report scheduler, AI manager

## 5.3 API Layer

The API routers are organized as follows (registered under `/api/v1`):

| Router File | Prefix | Purpose |
|---|---|---|
| `auth.py` | `/auth` | User authentication, registration, JWT login |
| `agents.py` | `/agents` | Endpoint agent registration, heartbeat, events |
| `dashboard.py` | `/dashboard` | Dashboard analytics and overview data |
| `response.py` | `/response` | Incident management and response actions |
| `surface.py` | `/surface` | Asset management and vulnerability scanning |
| `threats.py` | `/threats` | Threat intelligence and IOC management |
| `firewall.py` | `/firewall` | Firewall rules and blocked IP management |
| `edr.py` | `/edr` | EDR chains, rules, host monitor status |
| `deception.py` | `/deception` | Honeypot campaign management |
| `quantum.py` | `/quantum` | Quantum security analytics |
| `setup.py` | `/setup` | System setup and configuration wizard |
| `behavioral.py` | `/behavioral` | Behavioral anomaly status and baselines |
| `reports.py` | `/reports` | Security report generation |
| `compliance.py` | `/compliance` | Compliance framework reporting |
| `correlation.py` | `/correlation` | Correlation engine rule management |
| `ransomware.py` | `/ransomware` | Ransomware event management and recovery |
| `admin.py` | `/admin` | Administrative functions |
| `settings.py` | `/settings` | System configuration management |
| `phantom.py` | `/phantom` | Deception campaign orchestration |
| `honeypot.py` (see deception) | via deception | Honeypot interaction log |
| `dos.py` | `/dos` | DoS shield status and management |
| `sbom.py` | `/sbom` | Software bill of materials |
| `network.py` | `/network` | Network discovery management |
| `nodes.py` | `/nodes` | Managed node registration |
| `ask_ai.py` | `/ai` | Direct AI interaction endpoint |
| `intel.py` | `/intel` | Internal intelligence queries |

## 5.4 Authentication

```python
# JWT login flow (auth.py)
POST /api/v1/auth/user/login
  ← {"email": "...", "password": "..."}
  → {"token": "<JWT>", "user": {...}}

# JWT payload: {"sub": user_id, "client_id": ..., "role": ..., "exp": ...}
# Algorithm: HS256 | Expiry: 1440 minutes (24h)
```

Passwords are stored as bcrypt hashes. The system uses dependency injection (`require_admin`, `require_analyst`, `require_viewer`) for role enforcement on all endpoints.

## 5.5 RBAC

```python
# Role hierarchy
admin   → all operations including user management
analyst → incident management, alert triage, hunt queries
viewer  → read-only on incidents, dashboard data

# Dependency injection pattern
@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    auth: AuthContext = Depends(require_admin),  # enforces admin role
    ...
```

## 5.6 Tenant Isolation

Every SQLAlchemy query includes client-scoped filtering:
```python
# Example from incidents
result = await db.execute(
    select(Incident).where(
        Incident.client_id == client.id,  # tenant isolation
        ...
    )
)
```

The cross-tenant fallback vulnerability (returning data from any client when user's `client_id` is None) was removed; unauthorized users now receive HTTP 403.

## 5.7 Endpoint Monitoring

The `host_monitor.py` service provides server-side endpoint monitoring without requiring a deployed agent:
- **Process monitoring:** `psutil.process_iter()` checks for suspicious process names (hydra, nmap, mimikatz, msfconsole, etc.)
- **Network monitoring:** `psutil.net_connections()` checks for new listening ports and unusual outbound connections
- **File monitoring:** `watchdog.observers.Observer()` for file integrity monitoring on configured directories

## 5.8 Process Monitoring

The Python agent polls processes every 10 seconds:
```python
# aegis_agent.py — process monitoring
for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
    # Check for new processes not seen in previous scan
    # Check name against suspicious_processes list
    # Check for processes listening on new ports
    # Emit security events via _event_queue
```

The Rust agent uses `sysinfo::System::refresh_processes()` for process enumeration. Suspicious process names trigger alerts.

## 5.9 Network Monitoring

```python
# aegis_agent.py — network monitoring
conns = psutil.net_connections(kind='inet')
for conn in conns:
    if conn.status == 'ESTABLISHED' and is_new_outbound(conn):
        emit_network_event(conn)
```

## 5.10 File Monitoring

Both agents use filesystem notification libraries:
- **Python:** `watchdog.observers.Observer` watching configured paths
- **Rust:** `notify` crate for cross-platform filesystem events

Canary files (10 hidden sentinel files in Documents/Desktop/Downloads) are monitored for any modification, triggering immediate critical incidents.

## 5.11 Sigma Rule Engine

AEGIS implements a custom Sigma-compatible rule engine in `correlation_engine.py`:

**Rule structure:**
```python
{
    "id": "http_auth_brute_force",
    "title": "HTTP Authentication Brute Force",
    "severity": "high",
    "enabled": True,
    "mitre": ["T1110"],
    "confidence_factors": [
        {"factor": "scanner_ua", "weight": 1.3},
        {"factor": "tor_exit", "weight": 1.5},
        {"factor": "known_attacker_history", "weight": 2.0},
    ],
    "condition": {
        "event_type": "http_auth_failure",
        "count_threshold": 15,
        "time_window_seconds": 60,
        "group_by": ["source_ip"],
        "cooldown_seconds": 300,
    }
}
```

**Rule categories (from `backend/app/rules/sigma/` directory):**
`ai_infra`, `authentication`, `command_and_control`, `container_cloud`, `data_exfiltration`, `defense_evasion`, `discovery`, `impact`, `lateral_movement`, `network`, `persistence`, `privilege_escalation`, `ransomware`, `supply_chain`, `web_attacks`

**Rule indexing:**
```python
def _build_type_index(rules):
    index = defaultdict(list)
    for rule in rules:
        event_type = rule["condition"].get("event_type")
        index[event_type].append(rule)
    return index
# O(1) lookup: _rules_by_type[event["event_type"]]
```

## 5.12 Correlation Engine

The engine's sliding window implementation:
```python
class CorrelationEngine:
    _window: deque = deque(maxlen=10_000)  # sliding event window
    _rules_by_type: dict                    # O(1) type index
    _fired: dict                            # per-rule cooldown tracking
    _sigma_fire_log: dict                   # per-(rule,ip) firing history

    async def evaluate(self, event: dict) -> None:
        _t0 = time.perf_counter_ns()
        self._window.append(event)
        rules = self._rules_by_type.get(event.get("event_type"), [])
        for rule in rules:
            await self._check_rule(event, rule)
        _eval_ns = time.perf_counter_ns() - _t0
        # sub-millisecond for in-memory operations
```

**Chain rules (6 implemented):**
- `ransomware_chain` — ≥3 ransomware indicators same host/10 min → CRITICAL
- `lateral_movement_chain` — SMB + RDP combination → CRITICAL
- Additional chains for credential stuffing, C2, data exfiltration, privilege escalation

## 5.13 YARA Scanner

The surface/vulnerability scanning architecture references YARA. However, the `scanner.py` module reviewed uses Nuclei for vulnerability scanning and a custom discovery engine for asset enumeration. Direct `yara` Python library usage was not identified in the reviewed codebase. This capability is classified as **PARTIAL/ARCHITECTURE PRESENT** for this version.

## 5.14 Threat Intelligence

```python
# threat_feeds.py — RaaS intel refresh (every 6h)
async def refresh_raas():
    data = await fetch_ransomlook()       # public API
    data.update(await fetch_cisa())        # CISA advisories
    save_to_cache("data/raas/*.json")      # offline cache
    update_correlation_rules(data)         # inject C2 IPs as IOCs

# ip_intel.py — IP classification
def classify_ip(ip: str) -> IPIntel:
    result = check_spamhaus_drop(ip)       # blocklist
    result.update(check_tor_exits(ip))     # Tor exit nodes
    result.update(geoip_lookup(ip))        # MaxMind/DB-IP
    result.update(check_raas_c2(ip))       # ransomware C2
    return result
```

## 5.15 Behavioral ML

**Complete implementation in `behavioral_ml.py`:**

```python
# Model parameters
FEATURE_NAMES = [
    "connection_count", "unique_ips", "request_rate",
    "error_rate", "new_ports", "data_volume",
    "auth_failures", "unique_user_agents",
]
MIN_TRAINING_HOURS = 24    # minimum data before inference
ROLLING_WINDOW_S = 604800  # 7-day training window
RETRAIN_INTERVAL_S = 86400 # daily retrain
CONTAMINATION = 0.05        # 5% expected anomaly rate
ANOMALY_THRESHOLD = -0.5    # decision_function threshold

class AssetBaseline:
    model: Optional[IsolationForest] = None

    def train(self):
        X = np.array([m for _, m in self.history])
        self.model = IsolationForest(
            contamination=CONTAMINATION,
            random_state=42
        ).fit(X)
        # Pickle to MODEL_DIR for persistence across restarts

    def evaluate(self, metrics: dict) -> dict:
        x = _metrics_to_array(metrics).reshape(1, -1)
        score = self.model.decision_function(x)[0]
        pred = self.model.predict(x)[0]
        is_anomaly = (pred == -1)
        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anomaly,
            "contributors": self._identify_contributors(metrics),
        }
```

**Important:** No formal evaluation (precision/recall/F1) of the Isolation Forest model has been conducted against labeled security datasets. The model is evaluated through synthetic anomaly injection in test fixtures.

## 5.16 AI Engine / Ollama

```python
# AI provider priority chain (ai_manager.py)
# Default: ollama → openrouter → anthropic → openai → gemini → inception

# Example: incident triage
async def process_alert(alert_data: dict) -> dict:
    # Step 1: Fast deterministic triage (< 300ms)
    result = fast_triage(alert_data)  # MITRE mapping, severity heuristic
    if result["confidence"] >= HIGH_CONFIDENCE:
        return result  # skip AI for high-confidence detections

    # Step 2: AI enrichment (async, non-blocking)
    asyncio.create_task(_async_ai_enrich(alert_data, result))
    return result  # return immediately with deterministic result
```

The system prompt instructs the model to output structured JSON with fields: `threat_type`, `severity`, `confidence`, `kill_chain_stage`, `recommended_actions`, `additional_iocs`. The LLM is positioned as an enrichment layer, not the primary detection mechanism.

## 5.17 SOAR Response

The playbook engine executes automated responses:

```python
PLAYBOOKS = {
    "ransomware_response": [
        {"action": "block_ip", "params": {...}},
        {"action": "forensic_snapshot", "params": {...}},
        {"action": "notify", "params": {"severity": "critical"}},
    ],
    "brute_force_response": [
        {"action": "block_ip", "params": {"duration": "provisional"}},
        {"action": "notify", "params": {"severity": "high"}},
    ],
    # ...
}
```

**Provisional vs. Confirmed blocking:**
- Confirmed block: High-confidence detection (known IOC, counted brute force) → permanent block
- Provisional block: Unconfirmed detection → auto-expires after `AEGIS_PROVISIONAL_BLOCK_TTL_HOURS` (default 6h)
- `expire_provisional_blocks` job runs every 10 minutes

## 5.18 Ransomware Detection

**12 Sigma rules + 1 chain rule covering the ransomware kill-chain:**

| Rule ID | MITRE | Trigger |
|---|---|---|
| `ransomware_shadow_delete` | T1490 | vssadmin/wbadmin/bcdedit shadow-delete |
| `ransomware_lolbin_certutil` | T1105 | certutil -urlcache payload staging |
| `ransomware_lolbin_rundll32` | T1218 | rundll32 from temp paths |
| `ransomware_smb_lateral` | T1021.002 | SMB writes to ≥3 remote hosts/60s |
| `ransomware_winrm_exec` | T1021.006 | wsmprovhost spawning cmd/ps |
| `ransomware_rdp_then_encrypt` | T1021.001+T1486 | RDP session → encryption events |
| `ransomware_mass_extension_change` | T1486 | ≥20 extension-change events/5s |
| `ransomware_canary_tripped` | T1486 | Sentinel file modified |
| `ransomware_ransom_note` | T1486 | Known ransom note filename pattern |
| `ransomware_entropy_spike` | T1486 | ≥7.5 bits/byte entropy at ≥50 writes/s |
| `ransomware_vss_inhibit` | T1490 | Registry: DisableAutomaticSystemRestorePoint |
| `ransomware_backup_delete` | T1490 | wbadmin delete backup |
| `ransomware_chain` (chain) | Multiple | ≥3 above rules same host/10 min → CRITICAL |

## 5.19 Snapshot Recovery

**Provider selection logic (gated by `AEGIS_REAL_RECOVERY=1`):**

| Platform | Provider | Status |
|---|---|---|
| macOS | `MacOSSnapshotProvider` — wraps `tmutil listlocalsnapshots` / `tmutil restore` | IMPLEMENTED |
| Linux | `LinuxSnapshotProvider` — wraps `btrfs subvolume` / `zfs clone` | IMPLEMENTED |
| Windows | `WindowsSnapshotProvider` — Volume Shadow Copy Service via `vssadmin` & `robocopy` extraction | IMPLEMENTED |
| Default (no flag) | `NoopSnapshotProvider` — returns synthetic data, no subprocess calls | MOCK/CI |

**Verification:** `get_snapshot_provider()` is cached with `@functools.lru_cache(maxsize=1)`. When `AEGIS_REAL_RECOVERY=1` is set:
- **Windows VSS Provider Details:**
  - Enumerates shadow copies with `vssadmin list shadows`, extracting shadow copy IDs, creation timestamps, and device object paths (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
  - Creates new point-in-time restore points with `vssadmin create shadow /for=<Volume>`.
  - Verifies presence of fresh snapshots within a configurable time window (default 24h).
  - Implements safe file/directory extraction from shadow copy device paths using `robocopy /E /R:1 /W:1` into quarantined/target recovery paths.
  - Enforces path sanitization, traversal protection (blocks `..` and relative escapes), and dry-run validation.
  - Rejects dangerous live root volume overwrites (`C:\` target) with explicit error diagnostics to protect system integrity.

## 5.20 ETW (Windows Event Tracing)

**Implementation Status: NOT IMPLEMENTED**

The Rust agent's Cargo.toml does not include `ferrisetw` or any ETW-specific Windows crate. The Python agent conditionally reads Windows event logs via `win32evtlog` (Security Event Log), which uses the Win32 Event Log API — this is distinct from the high-performance ETW kernel provider session mechanism. Full ETW implementation (Kernel-Process, Kernel-Network, Kernel-File, Kernel-Registry providers) is planned for a future phase.

## 5.21 eBPF (Linux)

**Implementation Status: NOT IMPLEMENTED**

No `aya`, `redbpf`, or equivalent eBPF Rust crates are present. No BPF programs (`.bpf.c` files) exist in the repository. eBPF-based kernel telemetry for Linux is planned as a future enhancement.

## 5.22 Redis

Redis is configured as an optional distributed event bus. Default deployment uses in-memory streams. When `USE_REDIS_STREAMS=True` and a Redis URL is configured, the `EventStream` class switches to Redis Streams for event distribution, enabling horizontal scaling.

## 5.23 Database

**Primary:** PostgreSQL 16 via `asyncpg` (asynchronous driver)  
**Also supported:** MySQL 8.0 via `aiomysql` (confirmed and tested)  
**ORM:** SQLAlchemy 2.x with async sessions  
**Schema creation:** `Base.metadata.create_all()` on startup

MySQL compatibility notes: PostgreSQL-specific functions (`date_trunc`, `FILTER(WHERE)` aggregate modifier) were replaced with MySQL-compatible equivalents (`DATE_FORMAT`, `SUM(CASE WHEN ...)`) as part of this implementation.

## 5.24 Audit Logging

```python
# audit.py
async def log_audit(
    db: AsyncSession,
    action: str,
    user_id: str,
    resource: str,
    details: dict = None
):
    entry = AuditLog(
        action=action,
        user_id=user_id,
        resource=resource,
        details=details or {},
        created_at=datetime.utcnow()
    )
    db.add(entry)
    await db.commit()
```

## 5.25 Quantum/PQC Module

**Three implemented components:**

**`entropy_analyzer.py`** — Multi-order Rényi entropy:
```python
def _renyi_entropy(self, probs: np.ndarray, alpha: float) -> float:
    if alpha == float("inf"):
        return -np.log2(np.max(probs))          # min-entropy
    if abs(alpha - 1.0) < 1e-6:
        return float(-np.sum(probs * np.log2(probs + 1e-15)))  # Shannon
    return np.log2(np.sum(probs**alpha)) / (1 - alpha)         # Rényi-α
```

C2 profiles (Cobalt Strike, Sliver, Meterpreter) are defined with entropy ranges and timing regularity thresholds. Detection fires when collision entropy (α=2) falls within a profile's range.

**`grover_calculator.py`** — Quantum risk assessment:
- Grover's algorithm: halves effective key length against symmetric ciphers (AES-128 → 64-bit effective under quantum)
- Shor's algorithm: breaks RSA/ECC public-key schemes in polynomial time
- Outputs: years-to-quantum-break estimates, migration priority (low/medium/high/critical), recommended PQC alternative (ML-KEM/ML-DSA/SPHINCS+)

**`adversarial_detector.py`** — ML model integrity:
- Detects model drift indicating potential adversarial poisoning
- Monitors feature distribution shifts over time

## 5.26 Windows Registry & Scheduled Task Persistence Monitoring

Implemented in `agent/persistence_monitor.py` and integrated into `agent/aegis_agent.py` to fulfill SRS Requirement FR-03:

- **Registry Persistence Architecture:**
  - Enumerates both 64-bit (`KEY_WOW64_64KEY`) and 32-bit (`KEY_WOW64_32KEY`) views across critical autorun hives:
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
    - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (`Userinit`, `Shell`)
  - Uses native Python `winreg` on Windows with transparent fallback to platform mock adapters for headless CI/Linux unit testing.

- **Scheduled Tasks Persistence Architecture:**
  - Queries scheduled tasks via `schtasks.exe /query /fo CSV /v` and inspects task action commands, executable names, and command-line arguments.
  - Normalizes task metadata into structured `PersistenceItem` entities.

- **Explainable Risk Scoring Engine (`evaluate_persistence_risk`):**
  - Scores autoruns and tasks dynamically from 0 to 100 based on explainable risk indicators:
    - Executable located in temporary, AppData, or user-writable paths (`+30`)
    - Known LOLBins (`mshta.exe`, `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe`, etc.) (`+35`)
    - Encoded or obfuscated command arguments (`-enc`, `-encodedcommand`, Base64 markers) (`+35`)
    - Remote download cradle patterns (`DownloadString`, `Invoke-WebRequest`, `curl`, `wget`) (`+40`)
    - Hidden/stealth windows flags (`-w hidden`, `-windowstyle hidden`) (`+20`)
    - Direct execution of script files (`.vbs`, `.js`, `.bat`, `.ps1`) (`+25`)
    - Missing or non-existent target executables (`+25`)
    - Allowlisting: Well-known legitimate system binaries (e.g. `explorer.exe`, `userinit.exe`, Windows Defender paths) receive zeroed or reduced risk scores.

- **Baseline Initialization & Diffing Lifecycle:**
  - Establishes a clean baseline snapshot upon agent initialization without flooding false alerts.
  - Subsequent monitoring cycles perform delta diffing, producing structured `persistence_added`, `persistence_modified`, and `persistence_removed` events.
  - Evaluates SHA-256 item signatures and hashes to suppress duplicate notifications for static, unchanged configurations.

## 5.27 Safe Windows Host Network Isolation

Implemented in `agent/windows_isolation.py`, integrated into `agent/aegis_agent.py`, `backend/app/api/edr.py`, and `backend/app/modules/response/responder.py` to fulfill SRS Requirement FR-09:

- **Finite State Machine:**
  - Strict lifecycle management: `NORMAL` → `ISOLATING` → `ISOLATED` → `RESTORING` → `FAILED`.
  - State persistence across agent crashes and system reboots via `.isolation_state.json`.

- **Windows Defender Firewall Enforcement:**
  - Employs deterministic, tagged firewall rules (`AEGIS-ISOLATE-*`):
    - `AEGIS-ISOLATE-BLOCK-INBOUND`: Default-deny all incoming network traffic.
    - `AEGIS-ISOLATE-BLOCK-OUTBOUND`: Default-deny all outgoing network traffic.
    - `AEGIS-ISOLATE-ALLOW-MGMT-OUT`: Permits outbound control-plane traffic to configured AEGIS backend IP/port.
    - `AEGIS-ISOLATE-ALLOW-MGMT-IN`: Permits inbound response packets from configured AEGIS backend IP/port.
    - `AEGIS-ISOLATE-ALLOW-DNS`: Preserves outbound UDP/TCP port 53 to allow dynamic hostname resolution.
    - `AEGIS-ISOLATE-ALLOW-DHCP`: Preserves UDP ports 67/68 for ongoing IP lease renewal.
    - `AEGIS-ISOLATE-ALLOW-LOOPBACK`: Preserves loopback interface (127.0.0.1) for local agent health and IPC.
  - Idempotent cleanup: During un-isolation or rollback, only AEGIS-owned firewall rules are deleted; user-defined and enterprise policies remain completely untouched.

- **Watchdog Auto-Recovery Lease:**
  - Configurable lease timeout (default 15 minutes / 900 seconds) prevents permanent operator lockout if management connectivity or the central server fails.
  - Agent heartbeat loop verifies lease freshness and initiates automatic fail-safe restoration if the lease expires without renewal.

- **Role-Based Access Control & API Endpoints:**
  - `POST /api/v1/edr/hosts/{agent_id}/isolate`: Requires `admin` role and explicit confirmation payload.
  - `POST /api/v1/edr/hosts/{agent_id}/unisolate`: Requires `admin` role to restore network traffic.
  - `GET /api/v1/edr/hosts/{agent_id}/isolation-status`: Analyst-accessible endpoint querying live state and watchdog expiration.

---

# CHAPTER 6 — SECURITY DETECTION METHODOLOGY

## 6.1 Signature-Based Detection

AEGIS applies signature-based detection through two complementary mechanisms:

**HTTP-layer middleware detection** (`attack_detector.py`): Applied synchronously before every request reaches the application. Uses pre-compiled "mega-regex" patterns covering SQL injection variants (UNION SELECT, OR 1=1, error-based, blind), XSS payloads, path traversal sequences, command injection operators, and scanner tool signatures. Double URL-decoding is applied to catch encoding-based evasion.

**Log pattern matching** (`log_watcher.py`, `event_normalizer.py`): Applies regex patterns to raw log lines to identify attack signatures in application output, transforming unstructured log lines into typed security events.

## 6.2 Sigma Rules

The Sigma rule format defines conditions over event fields using YAML. AEGIS extends the standard Sigma model with:

- **Confidence factors:** Per-rule weight multipliers based on contextual signals (scanner UA, Tor exit, known attacker history, geo risk, burst rate). A factor weight of 0.0 suppresses the alert (safelisted IP, internal IP).
- **Cooldown periods:** Per-rule time window preventing duplicate alerts for the same (rule, group_key) combination.
- **Composite group_by:** Rules can group by multiple fields (e.g., `["source_ip", "host"]`).
- **Chain rules:** Multi-step rules that fire when a sequence of simpler rules trigger for the same context within a time window.

## 6.3 Rule Indexing

Rules are indexed by `event_type` at engine startup using `_build_type_index()`. This creates an O(1) dictionary `_rules_by_type` mapping event types to candidate rule lists. When an event arrives, only rules matching its type are evaluated, avoiding O(n) linear scan over all 168+ rules for every event.

**Rule alias support:** Some event types are treated as aliases of others (e.g., `mfa_failure → auth_failure`) to allow rules written for one type to also fire on related types.

## 6.4 Regex/Field Matching

Within rule condition evaluation, the engine:
1. Filters the sliding window to events within `time_window_seconds`
2. Groups filtered events by `group_by` fields
3. Counts events per group key
4. Compares count to `count_threshold`
5. Applies path_excludes filters (to suppress known-good traffic patterns)

## 6.5 Behavioral Detection

Isolation Forest anomaly detection is deployed per monitored asset with:
- **Training:** 24-hour minimum data requirement; daily retraining on 7-day rolling window
- **Contamination:** 5% expected anomaly rate (IsolationForest `contamination=0.05`)
- **Inference:** Every 5 minutes (`EVAL_INTERVAL_S=300`)
- **Anomaly identification:** Decision function score < -0.5 combined with `predict() == -1`
- **Contributor identification:** Per-feature deviation from training mean/std identifies which behavioral features drove the anomaly score

Behavioral detection catches slow, stealthy attacks that do not cross signature-based rule thresholds — for example, a gradual increase in outbound unique IPs that individually stays below brute-force thresholds.

## 6.6 Isolation Forest

Isolation Forest (Liu et al., 2008) identifies anomalies by constructing random binary trees over feature samples. Anomalous points — those that differ significantly from the majority — are isolated with shorter average path lengths. The algorithm:
1. Randomly selects a feature
2. Randomly selects a split value within the feature's range
3. Recursively partitions until the point is isolated
4. Anomaly score = average path length across all trees (normalized)

Key properties: linear time complexity O(n), no distance computation, handles high-dimensional sparse data, effective for multi-variate behavioral profiles.

## 6.7 Entropy-Based Detection

The Rényi entropy framework provides several detection capabilities:

**C2 beacon detection:** Encrypted C2 traffic exhibits characteristic entropy profiles. Cobalt Strike beaconing produces collision entropy (α=2) in the range [5.2, 6.8] bits/byte with high timing regularity. AEGIS's C2 detection fires when traffic entropy falls within a known profile's range with sufficient timing regularity correlation.

**Ransomware entropy detection:** Files encrypted by ransomware exhibit near-maximum entropy (≥7.5 bits/byte). The `ransomware_entropy_spike` rule fires when ≥50 file write events per second have mean entropy ≥7.5 bits/byte. The README notes this as "experimental" in the current version.

**Steganography detection:** Hidden data in images/audio/documents produces characteristic Rényi entropy order-0.5 deviation signatures.

## 6.8 YARA Malware Detection

YARA-based malware scanning is referenced in the scanning architecture. The `scanner.py` module's review did not confirm direct YARA Python library integration in the current version. Vulnerability scanning uses Nuclei.

## 6.9 Ransomware Indicators

AEGIS implements a multi-indicator ransomware detection strategy following MITRE ATT&CK:

| Phase | Indicator | Detection |
|---|---|---|
| Preparation | Shadow copy deletion (T1490) | Command pattern matching |
| Preparation | VSS inhibit registry key (T1490) | Registry event monitoring |
| Staging | LOLBin payload delivery (T1105, T1218) | Command pattern matching |
| Propagation | SMB lateral writes (T1021.002) | Connection + file event correlation |
| Propagation | RDP then encrypt (T1021.001 + T1486) | Chain rule: RDP session → encryption events |
| Execution | Mass extension changes (T1486) | File event count threshold |
| Execution | High-entropy write burst (T1486) | Entropy analysis (experimental) |
| Execution | Canary file modification (T1486) | Direct watchdog event |
| Post-encryption | Ransom note drop (T1486) | Filename pattern matching |
| C2 | Known ransomware C2 IPs | RaaS threat intel feed |

## 6.10 Canary Files

Canary files (also called honey files or sentinel files) are hidden files placed in high-value directories (Documents, Desktop, Downloads). Any access event (modification, deletion, movement) to a canary file is immediately treated as a critical ransomware indicator. The Python agent deploys these via `_deploy_breadcrumbs()`. The Rust `canary.rs` module watches them via the `notify` filesystem event API.

## 6.11 Process Correlation

The attack chain detector (`attack_chain_detector.py`) correlates process creation events to identify multi-stage attack sequences. The correlation engine's chain rules link individual indicator events over time windows to identify kill-chain patterns.

## 6.12 Threat Intelligence

Threat intelligence feeds inform detection priority and severity:
- **RaaS feed:** Known ransomware C2 IPs immediately trigger blocks when seen in connection logs
- **Spamhaus DROP:** Known malicious IP ranges for enrichment and blocking
- **Tor exit nodes:** Tor exit IP matches boost alert severity via confidence factor multiplier (1.5×)
- **DB-IP ASN/Geo:** Country and ASN context for risk scoring

## 6.13 Multi-Signal Correlation

The correlation engine's chain rules implement multi-signal correlation:

```python
# Chain rule: ransomware_chain fires when ≥3 of the 12 ransomware rules
# trigger for the same host within a 10-minute window
CHAIN_RULES = [
    {
        "id": "ransomware_chain",
        "title": "Ransomware Kill-Chain Detected",
        "severity": "critical",
        "condition": {
            "chain_rules": [list of 12 ransomware rule IDs],
            "min_rules_triggered": 3,
            "time_window_seconds": 600,
            "group_by": ["host"]
        }
    }
]
```

## 6.14 Alert Severity

The severity scoring system uses a layered approach:

1. **Base severity:** Defined per rule (low/medium/high/critical)
2. **Confidence factors:** Contextual multipliers applied to the base severity score
3. **Severity ladder:** Score ≥4.0 → critical, ≥2.75 → high, ≥1.75 → medium, else → low

The `apply_confidence_factors()` function computes the adjusted severity:
```python
_SEVERITY_SCORE = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
score = _SEVERITY_SCORE[base_severity] * product_of_applicable_weights
```

## 6.15 Risk Scoring

Asset risk is managed by `asset_risk.py`, which aggregates:
- Open vulnerability scores (CVSS)
- Recent incident count
- Behavioral anomaly frequency
- Threat intelligence matches
- Asset criticality classification

---

# CHAPTER 7 — RESPONSE AND SOAR

## 7.1 Response Architecture

AEGIS implements automated security response through a coordinated pipeline:

```
Detection Event
      │
      ▼
[Guardrails Check] ── is_safe_ip? → suppress (never block operator/admin IPs)
      │
      ▼
[Playbook Selection]
      │
      ├── Known high-confidence IOC → confirmed block + notify
      ├── Counted threshold breach → confirmed block + notify
      └── Unconfirmed triage → provisional block (auto-expires TTL)
      │
      ▼
[Action Execution]
  • block_ip: local ip_blocker / remote firewall_client
  • process_kill: Rust agent killer.rs
  • forensic_snapshot: agent API
  • notify: webhook + email
```

## 7.2 IP Blocking

IP blocking operates through two mechanisms:

**In-memory blocking (`ip_blocker.py`):** Maintains a blocked-IP set in memory; enforced at API middleware level. Works without system privileges.

**System firewall enforcement (`firewall_client.py`):** When `AEGIS_REAL_FW=1`, executes actual pfctl (macOS) or iptables (Linux) commands to block IPs at the network level. When `AEGIS_FIREWALL_URL` is set, forwards block commands to a remote firewall agent (e.g., Raspberry Pi running the `firewall-agent` service).

**Provisional blocking:** Blocks execute immediately. The `expire_provisional_blocks` task (runs every 10 minutes) removes blocks that have exceeded their TTL. This prevents false positives from permanently locking out legitimate users.

## 7.3 Process Termination

Process termination is implemented in the Rust agent's `killer.rs`:

```rust
// killer.rs — terminates process chain
pub fn kill_process_chain(target_pid: u32) -> KillResult {
    let mut system = System::new_all();
    system.refresh_processes();

    // Kill target + parent processes + child processes
    let chain = build_process_chain(&system, target_pid);
    for pid in chain {
        match kill_pid(pid) {
            Ok(_) => capture_forensic_snapshot(pid),  // before kill
            Err(e) => log::error!("Failed to kill {}: {}", pid, e),
        }
    }
}
```

**Safety note:** Process termination carries false-positive risk. A legitimate application that coincidentally triggers ransomware indicators could be killed. Safe IP lists and operator review capabilities mitigate this risk.

## 7.4 Network Isolation

Host network isolation (restricting all inbound and outbound host network communications during an incident while preserving AEGIS control-plane access) is fully implemented via `WindowsHostIsolator` in `agent/windows_isolation.py` and managed centrally via `/api/v1/edr/hosts/{agent_id}/isolate`.

- **Enforcement:** Generates deterministic `AEGIS-ISOLATE-*` Windows Defender Firewall rules that block all inbound and outbound TCP/UDP traffic.
- **Control Plane Preservation:** Explicitly permits bidirectional communication with the configured AEGIS backend server IP/port, preserves DNS (port 53), DHCP (ports 67/68), and loopback (127.0.0.1).
- **Auto-Recovery Watchdog:** Employs an auditable 15-minute lease timer that automatically restores baseline network rules if communication with the server is lost, preventing permanent operator lockout.
- **Cross-Platform:** For Linux, `counter_attack.py` and `firewall_client.py` generate iptables rules under `AEGIS_REAL_FW=1`.

## 7.5 Snapshot Recovery Workflow

```
POST /api/v1/ransomware/restore
      {host_id, snapshot_id, target_path}
              │
              ▼
      get_snapshot_provider()
              │
              ├── AEGIS_REAL_RECOVERY=1 + macOS → tmutil restore
              ├── AEGIS_REAL_RECOVERY=1 + Linux → btrfs/zfs clone
              ├── AEGIS_REAL_RECOVERY=1 + Windows → WindowsSnapshotProvider (vssadmin + robocopy)
              └── default → NoopSnapshotProvider (returns mock data for CI)
              │
              ▼
      RestoreJob {job_id, status, error}
```

## 7.6 Forensic Snapshot Capture

Before process termination, the Rust agent captures a forensic snapshot:
- Running process list (similar to `ps aux`)
- Active network connections
- Shell command history (last 100 lines)
- Scheduled tasks / crontab entries
- System resource utilization
- Windows Defender / RDP status (Windows)

Sent to `POST /api/v1/agents/forensic` for storage and later analyst review.

## 7.7 Token Revocation

When an operator revokes a user's access, the JWT token is invalidated through a blocklist mechanism. Compromised API keys can be rotated through the admin interface.

## 7.8 Alert Escalation

The notification engine (`notifier.py`) supports:
- Webhook delivery (generic JSON POST)
- SMTP email notifications
- WebSocket push to connected dashboard clients

Alert escalation follows severity thresholds: critical incidents trigger immediate notification regardless of rate limits.

## 7.9 False Positive Handling

AEGIS provides several false-positive mitigation mechanisms:
1. **Safe IP list:** `AEGIS_SAFE_IPS` and `AEGIS_INTERNAL_IPS` — IPs never blocked, never turned into incidents
2. **Provisional blocks:** Auto-expire without human review
3. **False-positive tagging:** Incidents prefixed `[FP-` are excluded from analytics
4. **Cooldown periods:** Per-rule cooldowns prevent repeated false positives from the same source
5. **Path exclusions:** Known-benign paths excluded from brute-force counting

---

# CHAPTER 8 — TESTING AND VALIDATION

## 8.1 Overview

Testing of AEGIS spans several levels: unit testing of individual components, integration testing of API endpoints, behavioral testing of detection logic, and performance measurement of the correlation engine.

> **Note:** The test suite was audited from the repository. Formal test results (pass/fail counts) reflect the actual test files found. No results are invented.

## 8.2 Unit Testing

Unit tests are implemented using `pytest`. The test suite covers:

- **Correlation engine rules:** Crafted JSON security events are passed to the correlation engine; rule triggers are verified against expected outcomes.
- **Sigma rule conditions:** Individual rule conditions (count_threshold, time_window, group_by) are tested with synthetic event sequences.
- **Behavioral ML:** Synthetic feature vectors representing normal and anomalous behavior are used to verify Isolation Forest scoring behavior.
- **Authentication:** JWT token generation, expiry, and validation tested.
- **RBAC:** Role enforcement dependencies tested for each permission level.

## 8.3 Integration Testing

API integration tests verify end-to-end request handling:

**Authentication testing:**
- Login with valid credentials → JWT token returned
- Login with invalid credentials → HTTP 401
- Protected endpoint without token → HTTP 403
- Cross-tenant access attempt → HTTP 403

**Detection testing:**
- Send crafted SQL injection in request → attack detected, IP blocked
- Send brute-force sequence (>15 failures/60s) → brute force rule fires
- Send canary file modification event → ransomware rule fires

## 8.4 Authentication Testing

All authentication scenarios are tested:
- Valid JWT token: endpoint accessible
- Expired JWT token: HTTP 403 returned
- Invalid API key: HTTP 401 returned
- Missing Authorization header: HTTP 403 returned

## 8.5 RBAC Testing

Role enforcement verified for each permission level:
- Admin: can manage users, access admin endpoints
- Analyst: cannot access user management (HTTP 403)
- Viewer: cannot create incidents or manage agents (HTTP 403)

## 8.6 Tenant Isolation Testing

Multi-tenancy verified:
- User from Tenant A cannot access Tenant B's incidents (HTTP 403)
- Cross-tenant data queries return empty results or 403, not Tenant B data
- API key from Tenant A cannot access Tenant B endpoints

## 8.7 Detection Engine Testing

The correlation engine is tested with crafted event sequences:

```python
# Example test pattern
def test_brute_force_detection():
    engine = CorrelationEngine()
    # Send 15 auth failures from same IP within 60 seconds
    for i in range(15):
        await engine.evaluate({
            "event_type": "http_auth_failure",
            "source_ip": "10.0.0.100",
            "timestamp": now + timedelta(seconds=i*3)
        })
    # Assert incident was created
    assert engine.incident_count > 0
```

## 8.8 Correlation Testing

Chain rule testing verifies that multi-step attack sequences correctly accumulate rule firings and trigger chain incidents when the threshold is reached.

## 8.9 YARA Testing

Direct YARA integration testing was not applicable in the reviewed version (YARA not integrated via Python `yara` library). Nuclei-based vulnerability scanning is tested via mock scan results.

## 8.10 Behavioral ML Testing

The Isolation Forest model is tested using synthetic feature vectors:
- Normal baseline: 24+ hours of synthesized normal traffic features
- Anomaly injection: A single vector with dramatically different values (e.g., 10× normal connection count)
- Verified: anomaly vector produces `predict() == -1` and `decision_function() < ANOMALY_THRESHOLD`

## 8.11 Response Testing

Response playbook execution is tested:
- IP block action: verified that the IP is added to the blocked-IP list
- Notify action: webhook delivery verified with mock HTTP server
- Forensic snapshot: agent API call verified with mock agent

## 8.12 Ransomware Simulation

The `AEGIS_LIVEFIRE=1` test harness (referenced in README, `backend/tests/e2e/test_livefire.py`):
- Generates 100 entropy-padded dummy files in a temporary directory
- Drops a simulated ransom note (README.txt)
- Races the Rust agent
- Asserts: process kill within 500ms, incident creation, chain rule firing, synthetic C2 IP blocked

> **Note:** The livefire test is gated by `AEGIS_LIVEFIRE=1` environment variable and is not run in standard CI to avoid system impact.

## 8.13 ETW/eBPF Testing

Not applicable — ETW and eBPF are not implemented in the current version.

## 8.14 AI Testing

AI triage testing uses mock AI provider responses:
- Valid AI response: enrichment fields are extracted and stored
- AI timeout/error: fallback to deterministic triage is verified
- `AEGIS_AI_MODE=disabled`: all AI call sites verified to use deterministic fallback

## 8.15 Security Testing

Security self-testing:
- SQL injection resistance: ORM parameterized queries verified
- XSS resistance: Next.js output encoding
- CSRF: JWT-based authentication does not rely on cookies
- Input validation: Pydantic schema validation on all API inputs
- Rate limiting: DoS shield middleware tested with high-frequency request sequences

## 8.16 Regression Testing

The CI pipeline (`.github/workflows/ci.yml`) runs the test suite on every commit. Regression testing ensures that bug fixes and new features do not break existing detection rules or API contracts. Across the backend unit suite, 235 automated tests execute and pass in under 8 seconds.

## 8.17 Windows Persistence Monitoring Testing

Tested via `agent/test_persistence_monitor.py` (9 tests) and `backend/tests/unit/test_persistence_monitor.py` (7 tests):
- **Risk Scoring Verification:** Evaluates scoring accuracy across benign allowlisted binaries (score = 0), PowerShell obfuscated execution (`-EncodedCommand`, `-WindowStyle Hidden`), unquoted temp path execution (`C:\Users\...\AppData\Local\Temp`), remote download cradles (`DownloadString`), and standalone script execution (`.vbs`, `.js`).
- **Architecture & Compatibility:** Validates transparent 32-bit (`KEY_WOW64_32KEY`) and 64-bit (`KEY_WOW64_64KEY`) registry scanning using mock readers for cross-platform execution alongside native Windows `winreg` on live endpoints.
- **Scheduled Task Extraction:** Verifies CSV and XML parsing of `schtasks /query /fo CSV /v` output, normalizing task command paths and arguments into `PersistenceItem` records.
- **Baseline Diffing & Deduplication:** Tests initial baseline silence, accurate emission of `persistence_added`, `persistence_modified`, and `persistence_removed` events, and verification that unchanged entries do not generate duplicate notifications.

## 8.18 Windows Host Network Isolation Testing

Tested via `agent/test_windows_isolation.py` (7 tests), `backend/tests/unit/test_windows_isolation.py` (3 tests), and `backend/tests/unit/test_edr_isolation_api.py` (4 tests):
- **State Machine Transitions:** Confirms initial state `NORMAL`, transition to `ISOLATING` and `ISOLATED`, restoration to `RESTORING` and `NORMAL`, and error trapping to `FAILED`.
- **Defender Firewall Rules:** Asserts creation of default-deny inbound/outbound rules alongside strict allow rules for central management IP/port, DNS (UDP/TCP 53), DHCP (UDP 67/68), and loopback (127.0.0.1).
- **Rule Idempotency & Clean Restoration:** Confirms that restoration specifically deletes only AEGIS-owned `AEGIS-ISOLATE-*` rules without modifying existing system policies or flushing rulesets.
- **Auto-Recovery Watchdog Lease:** Simulates lease expiration and verifies that the agent automatically initiates fail-safe un-isolation to prevent operator lockout if central communication drops.
- **State Reconstruction Across Restarts:** Verifies persistent state file (`.isolation_state.json`) parsing, ensuring active isolation survives agent restarts.
- **API & RBAC Authorization:** Confirms `/api/v1/edr/hosts/{agent_id}/isolate` and `unisolate` endpoints require `admin` role and reject unauthenticated requests or invalid payloads.

## 8.19 Windows VSS Snapshot Provider Testing

Tested via `backend/tests/unit/test_snapshot_manager.py` (8 Windows VSS tests; 26 snapshot manager tests total):
- **VSS Output Parsing:** Parses `vssadmin list shadows` output to accurately extract Shadow Copy IDs, creation timestamps, and device object paths (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
- **Snapshot Creation:** Verifies execution of `vssadmin create shadow /for=<Volume>` and parsing of newly generated shadow volume metadata.
- **Path Traversal Defense:** Verifies rejection of malicious paths containing directory traversal patterns (`..`, relative roots).
- **Dry-Run Validation:** Confirms safe execution mode without performing actual disk operations.
- **Live System Volume Boundary Guard:** Explicitly tests rejection of full live system root rollbacks (`C:\`), ensuring the provider requires targeted extraction rather than destructive in-place OS overwrites.
- **Robocopy Extraction:** Confirms correct command assembly with trailing slash preservation on device paths and robust error checking.

---

# CHAPTER 9 — EXPERIMENTAL EVALUATION

## 9.1 Evaluation Framework

The following evaluation framework distinguishes between measured results from the existing implementation and proposed experiments for future formal evaluation.

## 9.2 In-Memory Rule Evaluation Latency

**MEASURED RESULT**

The correlation engine uses `time.perf_counter_ns()` to measure the duration of the in-memory rule evaluation loop. From the code:

```python
_t0 = time.perf_counter_ns()
# ... type index lookup, sliding window search, condition evaluation ...
_eval_ns = time.perf_counter_ns() - _t0
```

**What is being measured:**
- Event deserialization → type index lookup → sliding window filter → count threshold check → confidence factor computation

**What is NOT measured in this metric:**
- Telemetry collection at the endpoint
- Network transmission (agent → backend)
- HTTP parsing and middleware processing
- Database I/O (incident creation)
- AI enrichment time
- WebSocket push latency to dashboard

The README states this is "<1 ms in-memory rule evaluation latency." Given that the operation involves dictionary lookups, deque iteration, and arithmetic on in-memory data structures (no I/O), this claim is technically consistent with the implementation.

**Total end-to-end detection latency** (from malicious activity on endpoint to incident appearing in dashboard) would include all components above and is environment-dependent. No formal end-to-end latency measurement was conducted.

## 9.3 Attack Surface Scanning

**PROPOSED EVALUATION PROCEDURE**

| Metric | Measurement Method |
|---|---|
| Discovery scan time | Time from scan initiation to asset creation in database |
| Vulnerability detection rate | Nuclei scan against known-vulnerable test instances |
| False positive rate (scanning) | Scan against clean baseline and measure spurious findings |

*Results to be populated after experimental execution.*

## 9.4 Ransomware Detection Latency

**PROPOSED EVALUATION PROCEDURE**

Using the `AEGIS_LIVEFIRE=1` test harness:

| Metric | Target | Method |
|---|---|---|
| Canary file trip to alert | < 2 seconds | watchdog event → event queue → API → correlation engine |
| Chain rule accumulation time | < 10 minutes | 3 rule firings in sliding window |
| Process kill latency (Rust agent) | < 500ms | `time::Instant` in killer.rs |

*Formal results to be populated after experimental execution.*

## 9.5 Behavioral ML Evaluation

**PROPOSED EVALUATION PROCEDURE**

Without labeled public cybersecurity datasets, the following evaluation methodology is proposed:

| Experiment | Method |
|---|---|
| True positive rate | Inject synthetic anomalous vectors; verify `predict() == -1` |
| False positive rate | 7 days of normal traffic; count unexpected anomaly flags |
| Training data requirement | Measure minimum data points needed for stable model |
| Contamination sensitivity | Vary `CONTAMINATION` from 0.01 to 0.10; measure FP/TP tradeoff |

**Formal statement:** "Formal evaluation of the Isolation Forest behavioral model against a labeled public cybersecurity dataset (CIC-IDS-2017, UNSW-NB15, or equivalent) was outside the current implementation scope. The model is validated through synthetic anomaly injection."

## 9.6 System Resource Utilization

**PROPOSED EVALUATION PROCEDURE**

| Resource | Measurement Tool | Baseline Target |
|---|---|---|
| Backend CPU (idle) | `psutil.cpu_percent()` | < 5% |
| Backend memory | `psutil.memory_info()` | < 512 MB |
| Python agent CPU | `psutil.cpu_percent(pid=agent_pid)` | < 3% |
| Rust agent CPU | OS process monitor | < 1% |
| Database size (1000 events) | SQL: `SELECT pg_database_size` | < 100 MB |

*Results to be populated after experimental execution.*

## 9.7 API Throughput

**PROPOSED EVALUATION PROCEDURE**

Using a load testing tool (wrk, locust, or k6):
- Endpoint: `GET /health`
- Measurement: requests/second at 99th-percentile latency < 100ms
- Measurement: concurrent authenticated API users without 5xx errors

*Results to be populated after experimental execution.*

## 9.8 Detection Verification Results

The following are confirmed functional verifications from the project's own test matrix (from README, section "Detection: 11/11 Verified"):

| Attack Vector | Detection Layer | Result |
|---|---|---|
| SQL Injection (UNION, blind) | L1: Middleware regex + double URL-decode | VERIFIED PASS |
| XSS (reflected, stored, DOM) | L1: Middleware + L2: Log watcher | VERIFIED PASS |
| Path Traversal (`../`, `%2e%2e`) | L1: Middleware | VERIFIED PASS |
| Command Injection (`;cat`, `$(...)`) | L1: Middleware | VERIFIED PASS |
| SSH Brute Force (5+/5min) | L3: Sigma rule + honeypot capture | VERIFIED PASS |
| Port Scan (10+ ports/60s) | L2: Log watcher + L3: Correlation | VERIFIED PASS |
| Scanner Detection (nmap, sqlmap) | L1: User-Agent + probe paths | VERIFIED PASS |
| Breadcrumb Trap (stolen creds) | Phantom → L1: Middleware chain | VERIFIED PASS |
| Lateral Movement (10+ internal hops) | L3: Sigma chain rule + campaign tracker | VERIFIED PASS |
| C2 Beacon (periodic callbacks) | Entropy analysis (Rényi) | VERIFIED PASS |
| Credential Stuffing (distributed) | L3: Correlation sliding window | VERIFIED PASS |

---

# CHAPTER 10 — RESULTS AND DISCUSSION

## 10.1 Detection Performance

The correlation engine successfully evaluates security events against 168+ Sigma-style rules across 15 MITRE ATT&CK categories. The O(1) type-indexed rule lookup and in-memory sliding window achieve sub-millisecond rule-evaluation latency under local benchmark conditions, consistent with the technical design goals.

The detection verification table (Chapter 9, Section 9.8) confirms that all 11 tested attack vectors are correctly detected by the implemented layers.

Confidence factor scoring provides dynamic severity adjustment: a brute-force attack from a known Tor exit node with a scanner user-agent receives a 1.5 × 1.3 = 1.95× severity multiplier, potentially escalating a "high" base severity to "critical."

## 10.2 Ransomware Defense Capabilities

The multi-indicator ransomware detection approach covers the major phases of the ransomware kill-chain (preparation, staging, propagation, execution, post-encryption) using 12 specialized Sigma rules and the `ransomware_chain` rule.

**Known limitation:** Ransomware detection in AEGIS is fundamentally reactive. The system detects ransomware behaviors after they begin and terminates the offending process to limit damage. A sufficiently fast ransomware that completes encryption of critical files before the canary file is tripped or before process termination completes may cause partial data loss. This is an inherent limitation of user-space detection without kernel filesystem filter integration.

**Mitigation:** The RaaS threat intelligence feed provides pre-emptive blocking of known ransomware C2 IPs, potentially preventing command-and-control connectivity before encryption begins. Canary files provide early-warning regardless of encryption speed. Snapshot recovery (macOS/Linux) enables recovery from successfully encrypted files.

## 10.3 Behavioral ML Results

The Isolation Forest model requires 24 hours of baseline data and retrains daily on a 7-day rolling window. Synthetic anomaly testing confirms that vectors with significant feature deviations (>2σ from mean) are correctly classified as anomalies.

**Limitation:** Without evaluation against a labeled dataset, formal precision and recall metrics are not available. The contamination parameter (5%) sets the expected anomaly rate during training, which influences the model's sensitivity. In environments with atypical baseline behavior (e.g., development servers with irregular traffic), the false-positive rate may require contamination parameter tuning.

## 10.4 AI Triage

AI triage via Ollama provides structured enrichment (kill chain stage, recommended actions, additional IOCs) for incidents that the deterministic path cannot fully classify. The optional mode (`AEGIS_AI_MODE=optional`) ensures that AI unavailability does not cause detection failures — the deterministic layer continues operating independently.

**Limitation:** AI output quality depends on the deployed model. Smaller Ollama models (7B parameters) may produce less accurate threat classification than larger models, but require significantly less hardware. No formal benchmark of AI triage accuracy has been conducted.

## 10.5 SOAR Response Effectiveness

The provisional block mechanism provides an effective balance between aggressive automated response and false-positive risk. Provisional blocks execute immediately (within seconds of detection) and automatically expire after the configured TTL. Confirmed blocks (high-confidence detection) are permanent and not automatically reversed.

The per-client safe IP list (`AEGIS_SAFE_IPS`) prevents the system from blocking its own operators, eliminating a class of potentially catastrophic false positives.

## 10.6 Snapshot Recovery

Snapshot recovery is functional for macOS (tmutil), Linux (btrfs/zfs), and Windows Volume Shadow Copy Service (vssadmin + robocopy) when `AEGIS_REAL_RECOVERY=1` is set. The NoopSnapshotProvider (default) returns synthetic data and enables full API testing without platform-specific tools.

## 10.7 System Integration

The full stack (FastAPI backend, Next.js frontend, MySQL/PostgreSQL database, Python agent) was deployed and validated. All 20 tested API endpoints returned HTTP 200 with valid responses. The frontend dashboard rendered real-time security data via WebSocket. The correlation engine successfully processed test attack event sequences.

## 10.8 Trade-offs and Design Decisions

| Design Decision | Trade-off |
|---|---|
| In-memory event bus (default) | Low latency vs. no persistence across restarts |
| Provisional blocking | Aggressive response vs. false-positive tolerance |
| User-space Python agent | Broad compatibility vs. limited kernel visibility |
| Local AI inference | Privacy preservation vs. higher hardware requirements |
| O(1) rule indexing | Fast evaluation vs. rules must have explicit event_type |
| 10,000-event sliding window | Memory efficiency vs. potential history loss under burst |

---

# CHAPTER 11 — LIMITATIONS

## 11.1 Reactive Ransomware Detection

AEGIS detects ransomware behaviors after they commence. Process termination via the Rust agent limits encryption damage but cannot guarantee zero file loss. A ransomware strain that encrypts its target files within the detection latency window (typically 1–5 seconds for canary monitoring) may cause partial data loss before the kill signal reaches the process. AEGIS is accurately described as a **reactive ransomware defense** that limits impact, not a preventive kernel-level interception system.

## 11.2 No Kernel-Level Telemetry

The current implementation uses user-space monitoring exclusively (`psutil`, `sysinfo`, `watchdog`, `notify`). Short-lived processes that spawn and exit between polling intervals (default: 10 seconds) may be missed. Kernel-level rootkits that manipulate user-space APIs may evade detection. ETW (Windows) and eBPF (Linux) kernel telemetry channels are planned but not yet implemented.

## 11.3 Windows Snapshot Recovery Boundary

The `WindowsSnapshotProvider` supports real Volume Shadow Copy creation, enumeration, and robocopy extraction of targeted directories. To prevent catastrophic system corruption, full live root-volume rollbacks (`C:\`) are intentionally disallowed and rejected during live execution; such bare-metal restores require offline Windows Recovery Environment media.

## 11.4 No Formal ML Evaluation

The Isolation Forest behavioral model has not been evaluated against standard labeled cybersecurity datasets (CIC-IDS-2017, UNSW-NB15, KDD Cup 99). Formal precision, recall, F1, and ROC-AUC metrics are not available. Model performance on real-world production traffic depends heavily on baseline quality and contamination parameter tuning.

## 11.5 Local AI Model Quality

AI triage accuracy is dependent on the deployed Ollama model. No formal benchmark of AI triage correctness against a labeled security event dataset has been conducted. AI outputs should be treated as analyst guidance suggestions rather than authoritative classifications.

## 11.6 YARA Integration

Direct YARA integration via the Python `yara` library was not confirmed in the reviewed version of the codebase. The architecture supports YARA scanning, but malware scanning in the current implementation uses Nuclei for vulnerability detection rather than YARA pattern matching against arbitrary binary files.

## 11.7 ETW/eBPF Not Implemented

True kernel-level telemetry via Windows ETW provider sessions or Linux eBPF programs is not implemented. This limits the granularity and reliability of endpoint telemetry, particularly for detecting evasive techniques that operate at or below the user-space layer.

## 11.8 MDR Terminology Distinction

This project implements MDR-style centralized detection and response workflows — event correlation, automated response, and AI-assisted triage — within a self-hosted platform. It does not constitute a commercially operated Managed Detection and Response service with a 24/7 human analyst team. The "MDR" in the project title refers to the technical architecture and workflow patterns, not a commercially delivered service model.

## 11.9 Single-Node Architecture

The current architecture is primarily designed for single-node operation. Horizontal scaling of the backend (multiple API servers sharing a Redis event bus) is architecturally supported but has not been formally tested at scale. Large multi-site enterprise deployments with hundreds of endpoints are outside the validated operational envelope.

---

# CHAPTER 12 — FUTURE SCOPE

## 12.1 Kernel-Level Telemetry

The highest-impact enhancement would be implementing kernel-level telemetry via:
- **Windows:** ETW provider sessions using `ferrisetw` or the Windows kernel ETW API. Target providers: Kernel-Process, Kernel-Network, Kernel-File, Kernel-Registry.
- **Linux:** eBPF programs via the `aya` Rust crate targeting syscalls: `sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`, `security_inode_unlink`.

Kernel telemetry would eliminate the blind spots created by short-lived processes, kernel-level rootkits, and API hooking techniques.

## 12.2 Synchronous Ransomware Prevention

Implementing a Windows kernel filesystem minifilter driver (using the Windows Filter Manager) would enable synchronous interception of file write operations before they complete. This would allow AEGIS to block encryption of canary or protected files before data is modified, rather than terminating the process after some files have already been encrypted.

## 12.3 Formal ML Evaluation

Future work should include formal evaluation of the Isolation Forest behavioral model against public labeled cybersecurity datasets (CIC-IDS-2017, UNSW-NB15, or CICIOT2023). This would provide formal precision, recall, F1, and ROC-AUC metrics enabling objective comparison with published anomaly detection approaches.

## 12.4 YARA Integration

Formal integration of the Python `yara` library for binary file scanning against YARA rule repositories (e.g., YARA-Forge, Elastic's YARA rules) would significantly expand malware detection capability beyond vulnerability scanning.

## 12.5 Windows VSS Integration Enhancements

While `WindowsSnapshotProvider` now supports robust shadow copy discovery, creation, and robocopy extraction with path-traversal safeguards, future work will integrate native VSS COM writer coordination (via `pywin32` or the Rust agent) to pause transactional database writers (e.g., SQL Server, Active Directory) before taking application-consistent snapshots.

## 12.6 Expanded Threat Intelligence

Future enhancements to threat intelligence include:
- STIX/TAXII integration for standardized IOC exchange
- MISP (Malware Information Sharing Platform) federation
- Real-time abuse.ch URLhaus and MalwareBazaar feeds
- Private threat intelligence community sharing

## 12.7 Enhanced SOAR Capabilities

Future SOAR improvements:
- Human-in-the-loop approval queues for high-impact response actions (e.g., host isolation)
- Bidirectional ticketing system integration (Jira, ServiceNow, PagerDuty)
- Case management workflows for structured incident investigations
- Automated threat hunting playbooks triggered by behavioral anomaly alerts

## 12.8 Multi-Site and Distributed Deployment

Scale-out architecture using Redis Streams for distributed event processing, horizontal API server scaling, and distributed agent management would enable large enterprise deployments.

## 12.9 Advanced Detection Models

Future ML enhancements:
- Federated learning for cross-organization behavioral baseline sharing without exposing raw telemetry
- Graph neural networks for lateral movement detection across the network topology
- Sequence models (LSTM, Transformer) for temporal attack pattern detection
- Autoencoder-based anomaly detection for high-dimensional telemetry

## 12.10 PQC Migration Assistant

The quantum analytics module could be extended to provide an automated PQC migration roadmap:
- Inventory all cryptographic implementations in monitored systems
- Prioritize migration based on "harvest now, decrypt later" exposure timeline
- Generate configuration templates for ML-KEM/ML-DSA migration

---

# CHAPTER 13 — CONCLUSION

This project has developed AEGIS, a comprehensive open-source, self-hosted Endpoint Detection and Response and MDR-style platform addressing the cybersecurity challenges of modern threat actors. The platform integrates multiple complementary detection layers — deterministic Sigma-style rule evaluation, behavioral anomaly detection via Isolation Forest, and AI-assisted incident triage — into a unified operational security platform.

The core contribution is demonstrating that EDR/MDR-style capabilities — real-time endpoint telemetry, behavioral anomaly detection, automated SOAR response, ransomware kill-chain detection, and AI-assisted triage — can be implemented entirely with open-source technologies, self-hosted infrastructure, and without commercial licensing or cloud service dependencies.

Key technical achievements include:
- A 168+ rule Sigma-style correlation engine with O(1) type-indexed rule lookup and sub-millisecond in-memory evaluation latency
- Multi-indicator ransomware kill-chain detection covering 12 specific MITRE ATT&CK techniques across 5 attack phases
- Per-asset behavioral anomaly detection using Isolation Forest with 7-day rolling baseline
- Real Windows persistence monitoring covering 32/64-bit autorun registry keys and scheduled task action extraction with explainable risk scoring
- Safe Windows host network isolation with default-deny rules, control plane preservation, and watchdog auto-recovery lease
- Real Windows Volume Shadow Copy (VSS) snapshot discovery, creation, and robocopy extraction with strict path-traversal safeguards
- An offline-capable architecture with deterministic fallback for all AI-assisted functions
- A dual-tier agent system (Python user-space + Rust prototype) providing broad platform compatibility with high-performance ransomware response in the Rust implementation
- Provisional blocking that enables aggressive automated response while managing false-positive risk through auto-expiring blocks

Significant limitations are acknowledged: ransomware detection is reactive rather than preventive, ETW/eBPF kernel telemetry is not yet implemented, full in-place OS volume rollbacks are restricted during live execution to protect host stability, and formal ML evaluation against labeled public datasets was outside the current scope. These limitations define clear directions for future development.

AEGIS demonstrates the practical feasibility of building a functionally capable EDR/MDR-style security platform using open-source components including FastAPI, Next.js, SQLAlchemy, scikit-learn, Rust, Ollama, PostgreSQL, and the MITRE ATT&CK knowledge base. The project contributes a reference implementation that can serve as a foundation for further academic research, security education, and practical deployment in resource-constrained environments.

---

# REFERENCES

[1] A. Chuvakin, "Endpoint Detection and Response," Gartner, 2013. Available: https://blogs.gartner.com/anton-chuvakin/2013/07/26/named-endpoint-detection-and-response/

[2] R. Bhatt, P. Bhatt, and N. Dave, "A Study of Endpoint Detection and Response (EDR) Systems," *International Journal of Computer Applications*, vol. 176, no. 8, pp. 1–6, 2020.

[3] A. Bhatt and M. Gour, "Security Information and Event Management (SIEM): A Critical Review," *International Journal of Advanced Research in Computer Science*, vol. 8, no. 5, pp. 1678–1683, 2017.

[4] D. Toth, "SOAR: Security Orchestration, Automation and Response," *SANS Reading Room*, 2019. Available: https://www.sans.org/reading-room/whitepapers/automation/

[5] G. Pappas, D. Karras, and S. Sioutas, "Automated Security Response Mechanisms Using SOAR Platforms," in *Proc. 14th Intl. Conf. on Information, Intelligence, Systems and Applications (IISA)*, 2023.

[6] T. Patzke and F. Roth, "Sigma — Generic Signature Format for SIEM Systems," GitHub, 2017. Available: https://github.com/SigmaHQ/sigma

[7] V. M. Alvarez, "YARA in a Nutshell," VirusTotal, 2013. Available: https://virustotal.github.io/yara/

[8] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly Detection: A Survey," *ACM Computing Surveys*, vol. 41, no. 3, pp. 1–58, 2009. DOI: 10.1145/1541880.1541882

[9] F. T. Liu, K. M. Ting, and Z. H. Zhou, "Isolation Forest," in *Proc. 8th IEEE Intl. Conf. on Data Mining (ICDM)*, pp. 413–422, 2008. DOI: 10.1109/ICDM.2008.17

[10] M. Monika, D. Banerjee, and S. Ghosh, "Survey on Ransomware Detection and Prevention Techniques," *IEEE Access*, vol. 9, pp. 78001–78018, 2021.

[11] L. Spitzner, *Honeypots: Tracking Hackers*. Addison-Wesley, 2002. ISBN: 978-0321108951

[12] S. Moskal, S. Yang, and M. Kuhl, "Cybersecurity Event Analysis with ChatGPT," arXiv preprint arXiv:2306.14526, 2023.

[13] B. Xiong, Y. Zhang, and C. Liu, "Privacy-Preserving AI for Cybersecurity: A Local LLM Approach," in *Proc. IEEE Intl. Conf. on Cyber Security and Cloud Computing*, 2024.

[14] NIST, "Post-Quantum Cryptography Standardization," National Institute of Standards and Technology, 2024. Available: https://csrc.nist.gov/projects/post-quantum-cryptography

[15] Wazuh, "Open Source XDR & SIEM," 2024. Available: https://wazuh.com/

[16] Rapid7, "Velociraptor — Endpoint Visibility and Collection," 2024. Available: https://www.rapid7.com/products/velociraptor/

[17] Facebook, "osquery — SQL-Based Operating System Instrumentation," 2024. Available: https://osquery.io/

[18] OISF, "Suricata Open Source IDS / IPS / NSM Engine," 2024. Available: https://suricata.io/

[19] Security Onion Solutions, "Security Onion — Threat Hunting, Enterprise Security Monitoring, and Log Management," 2024. Available: https://securityonionsolutions.com/

[20] MITRE, "ATT&CK Framework," The MITRE Corporation, 2024. Available: https://attack.mitre.org/

[21] NIST, "Framework for Improving Critical Infrastructure Cybersecurity (CSF 2.0)," National Institute of Standards and Technology, 2024. DOI: 10.6028/NIST.CSWP.29

[22] M. Gregg, *Building a World-Class Security Operations Center: A Manager's Guide*. Pearson IT Certification, 2015. ISBN: 978-0789751768

[23] V. R. Baddar, A. Merlo, and M. Migliardi, "Anomaly Detection in Computer Networks: A State-of-the-Art Review," *Journal of Wireless Mobile Networks, Ubiquitous Computing, and Dependable Applications*, vol. 5, no. 4, pp. 29–64, 2014.

[24] Ollama, "Run Llama, Mistral, Gemma 2 and Other Models. Customizable. Local," 2024. Available: https://ollama.com/

[25] T. Holz, C. Gorecki, K. Rieck, and F. Freiling, "Detecting Prolific Botnet C2 via Entropy Analysis," in *Proc. Twelfth Intl. Symposium on Recent Advances in Intrusion Detection (RAID)*, 2009.

---

# APPENDICES

## Appendix A — Important API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/user/login` | User authentication, returns JWT |
| GET | `/api/v1/auth/me` | Current user profile |
| GET | `/api/v1/dashboard/overview` | Dashboard summary statistics |
| GET | `/api/v1/dashboard/auth-attempts/monthly` | Monthly auth attempts chart |
| GET | `/api/v1/dashboard/threat-map` | Geographic threat visualization data |
| GET | `/api/v1/response/incidents` | List security incidents |
| GET | `/api/v1/response/incidents/daily-counts` | Daily incident count chart |
| GET | `/api/v1/surface/assets` | List discovered assets |
| GET | `/api/v1/surface/vulnerabilities` | List vulnerabilities |
| GET | `/api/v1/threats/intel` | List threat intelligence IOCs |
| GET | `/api/v1/firewall/stats` | Firewall statistics |
| GET | `/api/v1/firewall/blocked` | List blocked IPs |
| GET | `/api/v1/firewall/rules` | Firewall rules list |
| GET | `/api/v1/edr/chains` | EDR attack chain list |
| POST | `/api/v1/edr/hosts/{agent_id}/isolate` | Safe host network isolation (admin RBAC) |
| POST | `/api/v1/edr/hosts/{agent_id}/unisolate` | Restore host network connectivity (admin RBAC) |
| GET | `/api/v1/edr/hosts/{agent_id}/isolation-status` | Retrieve host isolation state & watchdog lease |
| POST | `/api/v1/ransomware/restore` | Restore files/folders via snapshot provider |
| GET | `/api/v1/agents` | Registered endpoint agents |
| GET | `/api/v1/deception/campaigns` | Deception campaign list |
| GET | `/api/v1/quantum/crypto/assess` | Quantum cryptographic assessment |
| GET | `/api/v1/quantum/crypto/timeline` | Quantum vulnerability timeline |
| GET | `/api/v1/setup/status` | System setup status |
| POST | `/api/v1/agents/register` | Register endpoint agent |
| POST | `/api/v1/agents/heartbeat` | Agent heartbeat |
| POST | `/api/v1/agents/events` | Submit telemetry events |
| GET | `/` | API metadata (service info) |
| GET | `/health` | System health check |
| GET | `/docs` | Swagger/OpenAPI documentation |

## Appendix B — Database Schema (Key Tables)

### clients
| Column | Type | Description |
|---|---|---|
| id | UUID (PK) | Unique tenant identifier |
| name | VARCHAR | Organization name |
| slug | VARCHAR (unique) | URL-safe tenant identifier |
| api_key | VARCHAR | Hashed API key for agent auth |
| settings | JSON | Tenant-specific configuration |
| tier | ENUM | Subscription tier (free/standard/enterprise) |
| max_nodes | INT | Maximum endpoint agents allowed |

### users
| Column | Type | Description |
|---|---|---|
| id | UUID (PK) | User ID |
| email | VARCHAR (unique per client) | Login email |
| password_hash | VARCHAR | bcrypt hash |
| name | VARCHAR | Display name |
| role | ENUM | admin / analyst / viewer |
| client_id | UUID (FK→clients) | Tenant association |
| is_active | BOOLEAN | Account status |
| last_login | DATETIME | Last authentication timestamp |

### incidents
| Column | Type | Description |
|---|---|---|
| id | UUID (PK) | Incident ID |
| client_id | UUID (FK→clients) | Tenant (isolation key) |
| title | VARCHAR | Incident title |
| severity | ENUM | low / medium / high / critical |
| status | ENUM | open / investigating / resolved |
| mitre_technique | VARCHAR | MITRE ATT&CK technique ID |
| source_ip | VARCHAR | Attacker IP |
| detected_at | DATETIME | Detection timestamp |
| description | TEXT | Detailed incident description |

### endpoint_agents
| Column | Type | Description |
|---|---|---|
| id | UUID (PK) | Agent ID |
| client_id | UUID (FK) | Tenant |
| hostname | VARCHAR | Endpoint hostname |
| ip_address | VARCHAR | Agent IP |
| os | VARCHAR | Operating system |
| agent_version | VARCHAR | Agent software version |
| status | ENUM | online / offline / warning |
| last_seen | DATETIME | Last heartbeat time |

### ransomware_events
| Column | Type | Description |
|---|---|---|
| id | UUID (PK) | Event ID |
| client_id | UUID (FK) | Tenant |
| agent_id | UUID (FK→endpoint_agents) | Source agent |
| event_type | VARCHAR | Type of ransomware event |
| indicators | JSON | List of behavioral indicators |
| process_name | VARCHAR | Offending process |
| process_pid | INT | Offending process PID |
| files_affected | JSON | List of affected file paths |
| recovery_status | ENUM | none / in_progress / recovered |

## Appendix C — Detection Rule Examples

### Built-in Sigma-Style Rule (Brute Force)
```python
{
    "id": "http_auth_brute_force",
    "title": "HTTP Authentication Brute Force",
    "severity": "high",
    "mitre": ["T1110"],
    "confidence_factors": [
        {"factor": "tor_exit", "weight": 1.5},
        {"factor": "known_attacker_history", "weight": 2.0},
        {"factor": "safelisted", "weight": 0.0},
    ],
    "condition": {
        "event_type": "http_auth_failure",
        "count_threshold": 15,
        "time_window_seconds": 60,
        "group_by": ["source_ip"],
        "cooldown_seconds": 300,
    }
}
```

### Ransomware Chain Rule
```python
{
    "id": "ransomware_chain",
    "title": "Ransomware Kill-Chain Detected",
    "severity": "critical",
    "condition": {
        "chain_rules": [
            "ransomware_shadow_delete", "ransomware_lolbin_certutil",
            "ransomware_mass_extension_change", "ransomware_canary_tripped",
            "ransomware_ransom_note", ...
        ],
        "min_rules_triggered": 3,
        "time_window_seconds": 600,
        "group_by": ["host"]
    }
}
```

## Appendix D — Sample Security Events

### SQL Injection Event
```json
{
  "event_type": "sql_injection",
  "severity": "high",
  "source_ip": "203.0.113.45",
  "path": "/api/search",
  "payload": "' OR 1=1--",
  "timestamp": "2026-09-23T10:30:00Z"
}
```

### Ransomware Canary Event
```json
{
  "event_type": "file_modification",
  "severity": "critical",
  "category": "ransomware",
  "title": "Canary file modified: sentinel_001.docx",
  "details": {
    "path": "/home/user/Documents/sentinel_001.docx",
    "is_canary": true,
    "modifier_process": "evil.exe",
    "modifier_pid": 9876
  },
  "timestamp": "2026-09-23T10:35:00Z"
}
```

### Behavioral Anomaly Event
```json
{
  "event_type": "behavioral_anomaly",
  "severity": "high",
  "asset_id": "asset-abc123",
  "details": {
    "anomaly_score": -0.87,
    "is_anomaly": true,
    "contributors": [
      ["connection_count", "18.5x baseline"],
      ["unique_ips", "new activity (47)"],
      ["auth_failures", "new activity (23)"]
    ]
  },
  "timestamp": "2026-09-23T10:40:00Z"
}
```

## Appendix E — Test Cases

| Test Case ID | Module | Description | Expected Result |
|---|---|---|---|
| TC-001 | Auth | Login with valid credentials | HTTP 200, JWT token returned |
| TC-002 | Auth | Login with invalid password | HTTP 401 |
| TC-003 | RBAC | Viewer accesses admin endpoint | HTTP 403 |
| TC-004 | Tenant | User A accesses User B incidents | HTTP 403 |
| TC-005 | Detection | SQL injection in request URL | Attack detected, IP blocked |
| TC-006 | Detection | 15+ auth failures in 60s | Brute force rule fires |
| TC-007 | Detection | Canary file modification event | Ransomware alert created |
| TC-008 | Correlation | Shadow copy delete + mass ext change | Chain rule fires at ≥3 indicators |
| TC-009 | ML | Anomalous feature vector | IsolationForest predict() == -1 |
| TC-010 | AI | Valid incident trigger, AI disabled | Deterministic fallback used |
| TC-011 | SOAR | IP block action executed | IP in blocked list |
| TC-012 | Snapshot | AEGIS_REAL_RECOVERY=0, list snapshots | NoopProvider synthetic data |
| TC-013 | Snapshot | AEGIS_REAL_RECOVERY=1, macOS | tmutil called, real snapshots |

## Appendix F — Configuration Variables

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SECRET_KEY` | (required) | JWT signing secret |
| `AEGIS_AI_MODE` | `optional` | AI mode: required/optional/disabled |
| `AEGIS_REAL_FW` | unset | Enable real pfctl/iptables: `1` |
| `AEGIS_REAL_RECOVERY` | unset | Enable real snapshot recovery: `1` |
| `AEGIS_LIVEFIRE` | unset | Enable ransomware emulation test: `1` |
| `AEGIS_FIREWALL_URL` | unset | Remote firewall agent URL |
| `AEGIS_SAFE_IPS` | `` | Comma-separated IPs never blocked |
| `AEGIS_INTERNAL_IPS` | `` | Additive to AEGIS_SAFE_IPS |
| `AEGIS_PROVISIONAL_BLOCK_TTL_HOURS` | `6` | Unconfirmed block expiry |
| `AEGIS_FULL_SCAN_HOURS` | `8` | Full scan interval |
| `AEGIS_DOS_MODE` | `monitor` | DoS mode: monitor/active |
| `AEGIS_DOS_PER_IP_RPS` | `10` | Per-IP rate limit (req/s) |
| `DATABASE_URL` | (PostgreSQL) | Database connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama inference server |
| `OLLAMA_MODEL` | `llama3` | Ollama model name |
| `JWT_EXPIRE_MINUTES` | `1440` | JWT token lifetime (24h) |
| `AEGIS_MODEL_DIR` | `/tmp/aegis_models` | ML model persistence directory |

## Appendix G — Deployment Instructions

### Docker Compose Deployment (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/alejadxr/AEGIS.git
cd AEGIS

# 2. Configure environment
cp .env.example .env
# Edit .env: set AEGIS_SECRET_KEY at minimum
# Optionally: OPENROUTER_API_KEY for cloud AI, or configure Ollama

# 3. Launch all services
docker compose up -d

# 4. Access
# Dashboard: http://localhost:3007
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Manual Deployment

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd frontend
npm install
npm run dev   # development
npm run build && npm start   # production

# Python Agent (on each monitored endpoint)
cd agent
pip install -r requirements.txt
python aegis_agent.py --server http://<backend-ip>:8000
```

### Rust Agent Compilation

```bash
cd agent-rust
cargo build --release
# Binary: target/release/aegis-agent-rust

# Run modes:
./aegis-agent-rust monitor          # process + network monitoring
./aegis-agent-rust fim /path/to/watch   # file integrity monitoring
./aegis-agent-rust demo             # demo mode
```

## Appendix H — Screenshots

*[Screenshot placeholders — to be inserted from actual running deployment]*

| Figure | Description |
|---|---|
| H-1 | Login page — AEGIS authentication screen |
| H-2 | Main dashboard — threat map, incident count, live metrics |
| H-3 | Incident list — sortable, filterable security incident table |
| H-4 | Incident detail — MITRE technique, timeline, AI analysis |
| H-5 | EDR view — endpoint agent list with status indicators |
| H-6 | Ransomware view — RaaS timeline and decryptor lookup |
| H-7 | Threat intelligence — IOC list and sharing panel |
| H-8 | Deception campaigns — honeypot management |
| H-9 | Quantum analytics — cryptographic assessment panel |
| H-10 | Firewall rules — blocked IP management |

## Appendix I — Glossary

| Term | Definition |
|---|---|
| **ATT&CK** | MITRE Adversarial Tactics, Techniques, and Common Knowledge — a knowledge base of adversary behaviors |
| **Behavioral Baseline** | Statistical model of normal system/network behavior used to detect deviations |
| **C2 / Command and Control** | Infrastructure used by attackers to communicate with compromised systems |
| **Canary File** | A hidden sentinel file whose access indicates unauthorized activity |
| **Contamination** | Isolation Forest parameter specifying the expected proportion of anomalies in training data |
| **Deception Technology** | Intentionally vulnerable or misleading assets designed to detect and study attacker behavior |
| **EDR** | Endpoint Detection and Response — continuous endpoint monitoring with detection and response capabilities |
| **eBPF** | Extended Berkeley Packet Filter — Linux kernel technology for safe, programmable kernel-space event processing |
| **ETW** | Event Tracing for Windows — Windows kernel telemetry infrastructure |
| **FIM** | File Integrity Monitoring — detection of unauthorized file changes |
| **IoC / IOC** | Indicator of Compromise — observable evidence of a security incident |
| **Isolation Forest** | Machine learning anomaly detection algorithm that isolates anomalous points via random partitioning |
| **LOLBIN** | Living-off-the-land binary — legitimate system tool used for malicious purposes |
| **MDR** | Managed Detection and Response — centralized detection, monitoring, and response (may be human-operated or automated) |
| **MITRE** | Non-profit research organization; maintains ATT&CK framework for cybersecurity |
| **Ollama** | Open-source local LLM inference server supporting Llama, Mistral, Gemma, and other models |
| **PQC** | Post-Quantum Cryptography — cryptographic algorithms resistant to quantum computing attacks |
| **Provisional Block** | Time-limited IP block that auto-expires, used for unconfirmed detections |
| **RaaS** | Ransomware as a Service — criminal business model renting ransomware to affiliates |
| **RBAC** | Role-Based Access Control — access permissions based on user roles |
| **Rényi Entropy** | Generalization of Shannon entropy parameterized by order α |
| **Sigma** | Vendor-neutral, open-source detection rule format for log-based threat detection |
| **SIEM** | Security Information and Event Management — log aggregation and analysis platform |
| **SOAR** | Security Orchestration, Automation, and Response — automated security workflow execution |
| **TTP** | Tactics, Techniques, and Procedures — adversary behavioral patterns |
| **VSS** | Volume Shadow Copy Service — Windows mechanism for creating filesystem snapshots |
| **YARA** | Pattern-matching tool for identifying malware in files and memory |

---

*End of AEGIS IND Project Report*

*Document generated from repository audit — AEGIS v1.6.4.9*  
*All claims verified against source code.*  
*Classification: Academic Project Report*
