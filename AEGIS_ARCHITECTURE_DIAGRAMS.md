# AEGIS Architecture & Technical Diagrams

This document contains high-fidelity Mermaid diagrams detailing the architecture, telemetry flows, detection engines, response mechanisms, and AI workflows implemented in the AEGIS platform.

---

## Figure 1: Overall AEGIS Architecture

```mermaid
graph TB
    subgraph "Endpoint Layer"
        PA["Python Agent (User-Space)<br/>• psutil (Process/Net)<br/>• watchdog (FIM/Canary)<br/>• win32evtlog"]
        RA["Rust Agent (Prototype)<br/>• notify (FIM/Canary)<br/>• sysinfo (Process)<br/>• entropy.rs / killer.rs"]
    end

    subgraph "Ingestion & Edge Security Layer (FastAPI)"
        MW_DOS["DoS Shield Middleware<br/>(Rate-limits, Slowloris, Flood)"]
        MW_ATK["Attack Detector Middleware<br/>(Mega-Regex, Double URL-Decode)"]
        MW_AUTH["Authentication & RBAC<br/>(JWT HS256, API-Key, Multi-Tenant)"]
    end

    subgraph "Message Bus & In-Memory Pipeline"
        EB["Event Bus (In-Memory / Optional Redis)<br/>• 4 Streams: process, network, fim, alert"]
        NORM["Event Normalizer<br/>(Typed Event Mapping)"]
    end

    subgraph "Detection & Correlation Core"
        CORR["Correlation Engine<br/>• 168+ Sigma-style Rules<br/>• O(1) Type-Indexed Rule Lookup<br/>• 10,000-Event Sliding Window<br/>• 6 Attack Chain Rules"]
        BML["Behavioral ML Engine<br/>• Isolation Forest (8 Features)<br/>• 7-Day Rolling Baseline (24h min)<br/>• Contamination = 0.05"]
        QTM["Quantum Security Analytics<br/>• Rényi Entropy (Orders 0.5, 1.0, 2.0, inf)<br/>• Grover/Shor Mathematical Modeling"]
    end

    subgraph "Decision, SOAR & Intelligence"
        AI["AI Engine (Ollama / Local LLM)<br/>• Fast Deterministic Triage (<300ms)<br/>• Async Enrichment<br/>• Offline Fallback (Jinja2)"]
        SOAR["Playbook Engine & SOAR<br/>• Provisional & Confirmed Blocking<br/>• Safe-IP Guardrails<br/>• Process Termination via Agent"]
        TI["Threat Intelligence<br/>• RaaS Feed (RansomLook + CISA)<br/>• DB-IP GeoIP & ASN<br/>• Spamhaus DROP / Tor Exits"]
        SNAP["Snapshot Manager<br/>• macOS (tmutil)<br/>• Linux (btrfs/zfs)<br/>• Gated by AEGIS_REAL_RECOVERY=1"]
    end

    subgraph "Persistence Layer"
        DB[("Relational Database<br/>PostgreSQL 16 / MySQL 8.0<br/>23 Core Tables")]
        AUDIT["Immutable Audit Log"]
    end

    subgraph "Presentation Layer"
        UI["Frontend Dashboard (Next.js 14)<br/>• Real-time WebSocket Updates<br/>• MITRE ATT&CK Matrix<br/>• Threat Map & Incident Timelines"]
    end

    PA -->|HTTP POST /api/v1/agents/events| MW_DOS
    RA -->|HTTP POST /api/v1/agents/events| MW_DOS
    MW_DOS --> MW_ATK --> MW_AUTH --> NORM --> EB

    EB --> CORR
    EB --> BML
    EB --> QTM

    CORR -->|Rule Triggered| AI
    BML -->|Anomaly Triggered| AI
    TI -->|C2 / Malicious Indicators| CORR

    AI --> SOAR
    SOAR --> SNAP
    SOAR -->|Update Blocklists| MW_ATK
    SOAR --> DB
    SOAR --> AUDIT

    DB --> UI
    EB -.->|WebSocket Push| UI
```

---

## Figure 2: Endpoint Telemetry Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Host as Monitored Host OS
    participant Agent as Endpoint Agent (Python/Rust)
    participant Edge as Edge Middleware (FastAPI)
    participant Normalizer as Event Normalizer
    participant Bus as Event Bus

    loop Telemetry Collection (5s - 10s cycles)
        Agent->>Host: Sample processes (psutil / sysinfo)
        Agent->>Host: Enumerate active network sockets (TCP/UDP)
        Host-->>Agent: Raw OS Telemetry
    end

    alt File Modification Detected
        Host->>Agent: Filesystem event (watchdog / notify)
        Agent->>Agent: Check if Canary / Sentinel file modified
    end

    Agent->>Agent: Batch events into JSON queue
    Agent->>Edge: POST /api/v1/agents/events (Bearer Token / API Key)
    Edge->>Edge: Verify Tenant Scope (client_id) & DoS Limits
    Edge->>Normalizer: Raw telemetry payload
    Normalizer->>Normalizer: Map to typed schema (process_creation, connection, etc.)
    Normalizer->>Bus: publish(event_type, event_data)
```

---

## Figure 3: Threat Detection Pipeline

```mermaid
flowchart TD
    E[Incoming Event from Bus] --> T{Event Type Lookup}
    
    subgraph "Layer 1: Type-Indexed Rule Candidate Selection"
        T -->|O 1 Dictionary Lookup| R[Candidate Rules for Event Type]
    end

    subgraph "Layer 2: Sliding Window & Condition Evaluation"
        R --> SW[Inspect In-Memory Deque max 10,000 events]
        SW --> W{Event within time_window?}
        W -->|Yes| G[Group by Group-By Keys e.g. source_ip]
        G --> C{Count >= count_threshold?}
        C -->|Yes| CD{Rule in Cooldown?}
        CD -->|No| CF[Evaluate Confidence Factors]
        CD -->|Yes| DROP[Suppress Alert - Cooldown Active]
        W -->|No| DROP
        C -->|No| DROP
    end

    subgraph "Layer 3: Scoring & Incident Emission"
        CF --> SF{Factor Weight == 0?}
        SF -->|Yes - Safelisted/Internal| DROP
        SF -->|No| SC[Calculate Adjusted Severity Score]
        SC --> INC[Emit correlation_triggered Event]
        INC --> ASYNC[Async Incident Creation in DB]
    end
```

---

## Figure 4: Event Correlation & Chain Detection

```mermaid
stateDiagram-v2
    [*] --> Idle: Engine Listening
    Idle --> Step1_Detected: Sub-Rule 1 Fires (e.g., Shadow-Copy Delete)
    Step1_Detected --> Step2_Detected: Sub-Rule 2 Fires within 10m (e.g., Mass Extension Change)
    Step2_Detected --> Chain_Triggered: Sub-Rule 3 Fires within 10m (e.g., Canary Tripped)
    
    Step1_Detected --> Idle: Window Expires (>10m without subsequent triggers)
    Step2_Detected --> Idle: Window Expires (>10m without subsequent triggers)

    Chain_Triggered --> Critical_Incident: Emit 'ransomware_chain' (Severity: CRITICAL)
    Critical_Incident --> Immediate_Containment: Trigger Automated SOAR Playbook
    Immediate_Containment --> [*]
```

---

## Figure 5: Automated Response (SOAR) Workflow

```mermaid
flowchart TD
    AL[Incident Generated] --> GR{Is Target in Safe-IP List?}
    GR -->|Yes| LOG_IGN[Log Guardrail Suppression & Abort Block]
    GR -->|No| PB[Select Playbook via Static Map or AI]

    PB --> CONF{Threat Confidence Classification}
    
    CONF -->|High / Confirmed IOC| PERM[Execute Permanent IP Block]
    CONF -->|Unconfirmed / Heuristic| PROV[Execute Provisional Block<br/>Default TTL: 6 Hours]

    PERM --> FW_ACT{System Firewall Enabled?<br/>AEGIS_REAL_FW=1}
    PROV --> FW_ACT

    FW_ACT -->|Yes - Local/Pi| KERNEL[Execute pfctl / iptables / Pi Sync]
    FW_ACT -->|No - Default| MEM[Add to In-Memory Blocklist<br/>Enforced via 403 Middleware]

    KERNEL --> DB_ACT[Record Action in Database & Audit Log]
    MEM --> DB_ACT

    subgraph "Background Reversibility Loop"
        TIMER[Cron Task: Every 10 Minutes] --> CHK[Query Expired Provisional Blocks]
        CHK --> LIFT[Remove Block & Restore Access]
        LIFT --> LOG_REV[Log Reversal in Audit Trail]
    end
```

---

## Figure 6: Multi-Stage Ransomware Kill-Chain Detection & Response

```mermaid
flowchart LR
    subgraph "Attacker Execution Phase"
        A1["1. Preparation<br/>vssadmin delete shadows"] --> A2["2. Staging<br/>certutil -urlcache payload"]
        A2 --> A3["3. Propagation<br/>SMB / RDP Lateral Move"]
        A3 --> A4["4. Destruction<br/>Mass File Encryption + Note Drop"]
    end

    subgraph "AEGIS Detection Matrix"
        D1["Rule: ransomware_shadow_delete<br/>(T1490)"]
        D2["Rule: ransomware_lolbin_certutil<br/>(T1105)"]
        D3["Rule: ransomware_smb_lateral<br/>(T1021.002)"]
        D4["Rules: canary_tripped & mass_extension_change<br/>(T1486)"]
    end

    subgraph "Defensive Response Actions"
        R1["Kill Process Chain<br/>(Rust Agent killer.rs)"]
        R2["Isolate Host & Block C2<br/>(Firewall Client)"]
        R3["Rollback Snapshot<br/>(tmutil / btrfs / zfs)"]
    end

    A1 -.-> D1
    A2 -.-> D2
    A3 -.-> D3
    A4 -.-> D4

    D1 & D2 & D3 & D4 --> CR[Chain Rule: ransomware_chain]
    CR --> R1 --> R2 --> R3
```

---

## Figure 7: AI-Assisted Incident Triage (Offline vs Cloud)

```mermaid
flowchart TD
    INC[Triggered Incident Data] --> MODE{AEGIS_AI_MODE Configuration}

    MODE -->|disabled| DET[Deterministic Path Only<br/>• MITRE Heuristic Mapping<br/>• Jinja2 Pre-Compiled Templates<br/>• Static Playbook Lookup]
    
    MODE -->|optional / default| FT[Fast Deterministic Triage <300ms]
    MODE -->|required| MAND[Enforce AI Response]

    FT --> CONF{High Confidence Rule?}
    CONF -->|Yes| DET
    CONF -->|No| CALL_AI[Query Local Ollama Service]

    MAND --> CALL_AI

    CALL_AI --> PROV{Provider Priority}
    PROV -->|1. Local| OLLAMA[Ollama Llama-3 / Local Model]
    PROV -->|2. Gateway| OMNI[OmniRoute Self-Hosted Gateway]
    PROV -->|3. Cloud Fallback| CLOUD[OpenRouter / Gemini / Anthropic]

    OLLAMA --> RES[Parse Structured JSON Triage<br/>• Root Cause<br/>• MITRE Kill-Chain Stage<br/>• Recommended Next Steps]
    OMNI --> RES
    CLOUD --> RES

    CALL_AI -.->|Network/Service Failure| FALLBACK[Fall back to Deterministic Templates]
    FALLBACK --> RES
```

---

## Figure 8: Behavioral ML Anomaly Detection Workflow

```mermaid
flowchart TD
    subgraph "Telemetry Aggregation"
        TELEM[5-Minute Rolling Host Telemetry] --> EXT[Feature Extraction Vector<br/>1. connection_count<br/>2. unique_ips<br/>3. request_rate<br/>4. error_rate<br/>5. new_ports<br/>6. data_volume<br/>7. auth_failures<br/>8. unique_user_agents]
    end

    subgraph "Baseline Training Engine (24h Retrain Cycle)"
        HIST[(7-Day History Deque)] --> LEN{History >= 24 Hours?}
        LEN -->|No| SKIP[Bypass Inference - Insufficient Data]
        LEN -->|Yes| FIT[Fit IsolationForest<br/>contamination=0.05, n_estimators=100]
        FIT --> PERSIST[Serialize Model to MODEL_DIR]
    end

    subgraph "Inference & Scoring Engine"
        EXT --> INF[Compute decision_function x]
        INF --> PRED{predict x == -1?}
        PRED -->|No: Inlier| NORM[Normal Behavior Recorded]
        PRED -->|Yes: Outlier| ANOM[Anomaly Detected<br/>Score < -0.5]
        ANOM --> CONTRIB[Identify Feature Deviations > 2 sigma]
        CONTRIB --> EVT[Emit behavioral_anomaly Event]
    end
```
