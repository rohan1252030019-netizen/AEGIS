from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Core
    AEGIS_ENV: str = "development"
    AEGIS_SECRET_KEY: str = "aegis-dev-secret-key-change-in-production"
    # Read from .env via pydantic (os.environ does NOT carry .env values);
    # the boot guard and admin seed both read this field, not os.environ.
    AEGIS_ADMIN_PASSWORD: str = "changeme-on-first-login"
    AEGIS_API_PORT: int = 8000

    # --- Public demo -------------------------------------------------------
    # The hosted demo intentionally publishes its admin login + API key. When
    # demo mode is on, that identity is confined to a read-only sandbox (see
    # app.core.demo). Self-hosted deployments should leave this off.
    AEGIS_DEMO_MODE: bool = False
    # Defence in depth: this is the one API key that is public in the repo and
    # in the hosted dashboard. It is *always* sandboxed, even if demo mode was
    # left off by mistake, because anybody on the internet knows it.
    AEGIS_PUBLIC_DEMO_API_KEY: str = "c6_vOoMiwHmU50GfuPUMp5G2doB0eXZaslXfpSAof7tBgQ"
    # Master switch for the request sandbox. Do not disable on a public host.
    AEGIS_DEMO_SANDBOX: bool = True

    # Open self-service signup. Off by default so a public demo/host cannot be
    # used to create unlimited tenants (each signup also creates an admin).
    AEGIS_ALLOW_SIGNUP: bool = False

    # Shared secret expected by the threat-sharing hub write endpoints. When
    # empty, remote writes are rejected in production and accepted in dev.
    AEGIS_HUB_SHARED_SECRET: str = ""

    # AI Mode & Local Ollama
    AEGIS_AI_MODE: str = "local"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # OpenRouter (optional cloud fallback)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    # OmniRoute self-hosted gateway (optional). When set, it becomes the
    # PRIMARY AI provider; the direct providers below remain as fallback.
    AEGIS_OMNIROUTE_URL: str = ""

    # Database (PostgreSQL only)
    DATABASE_URL: str = "postgresql+asyncpg://aegis:aegis_secret@localhost:5432/aegis"

    # Redis / Event bus
    REDIS_URL: str = "redis://localhost:6379"
    USE_MEMORY_BUS: bool = True
    USE_REDIS_STREAMS: bool = False

    # Scanning tools
    NUCLEI_PATH: str = "/usr/bin/nuclei"
    NMAP_PATH: str = "/usr/bin/nmap"
    SUBFINDER_PATH: str = "/usr/bin/subfinder"
    HTTPX_PATH: str = "/usr/bin/httpx"

    # Notifications
    WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440  # 24 hours

    # PayPal
    PAYPAL_CLIENT_ID: str = ""
    PAYPAL_SECRET: str = ""
    PAYPAL_API_URL: str = "https://api-m.paypal.com"

    # Inception Labs (Mercury-2 diffusion LLM)
    INCEPTION_API_KEY: str = ""
    INCEPTION_BASE_URL: str = "https://api.inceptionlabs.ai/v1"

    # Google Gemini (Generative Language API) — cheap+fast, default model
    # gemini-flash-lite-latest. Suitable for enrichment + triage on hot path.
    GEMINI_API_KEY: str = ""
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta"
    GEMINI_DEFAULT_MODEL: str = "gemini-flash-lite-latest"

    # Community Threat Intel Hub
    AEGIS_MONGODB_URI: str = ""     # Direct MongoDB connection (for self-hosted hubs)
    AEGIS_HUB_URL: str = ""         # HTTP hub URL (connect to another AEGIS instance)

    # Log watcher — comma-separated list of PM2 app names to tail.
    # Prevents AEGIS from monitoring unrelated projects on the same host
    # (which produced self-referential SQLi false positives from other apps'
    # traceback dividers). Empty string = tail all apps (legacy behavior).
    AEGIS_MONITORED_APPS: str = "cayde6-api,cayde6-frontend"

    # Extra log paths to tail in addition to PM2 stdout/stderr.
    # Colon-separated, supports glob patterns. Used to point AEGIS at the
    # unified aegis-feed.jsonl that web apps write to.
    # Example: AEGIS_EXTRA_LOG_PATHS=/Users/alejandxr/web-logs/aegis-feed.jsonl
    AEGIS_EXTRA_LOG_PATHS: str = ""

    # Attacker allow-list — comma-separated IPs that bypass the internal-IP
    # filter even if they would otherwise be classified as private/Tailscale.
    # Use this for pentest lab machines that need to generate real incidents
    # despite living in Tailscale CGNAT (100.64.0.0/10).
    # Example: AEGIS_ATTACKER_IPS="203.0.113.10,203.0.113.11"
    AEGIS_ATTACKER_IPS: str = ""

    # Safe-IP allow-lists — comma-separated literal IPs and/or CIDR ranges that
    # are NEVER blocked and NEVER turned into an incident, on every detection
    # path. Both names are additive and feed the same gate
    # (attack_detector._is_safe_ip); use whichever reads better for the entry.
    #
    # These MUST be declared here even though attack_detector reads them,
    # because model_config sets extra="ignore" — an undeclared key present in
    # .env is silently dropped by pydantic and never reaches settings, which
    # would leave the operator's entire safelist inert.
    AEGIS_SAFE_IPS: str = ""
    AEGIS_INTERNAL_IPS: str = ""

    # External firewall API URL (e.g. AEGIS Firewall Agent on Raspberry Pi).
    # When set, AEGIS uses this for real iptables blocking + threat intel.
    AEGIS_FIREWALL_URL: str = ""

    # Shared secret for the Mac Pro <-> firewall agent channel. Must match the
    # value configured on the agent (X-AEGIS-FW-Auth header). Declared here so
    # values loaded from .env by pydantic are actually visible to the client
    # (os.environ alone does not carry .env values).
    AEGIS_FIREWALL_SECRET: str = ""

    # Filesystem roots from which /edr/quarantine-file may move files. Empty =
    # endpoint disabled (the safe default). Comma-separated absolute paths.
    AEGIS_QUARANTINE_ROOTS: str = ""
    AEGIS_QUARANTINE_MAX_BYTES: int = 104857600  # 100 MB

    # Verify TLS certificates for database connections (MySQL/TiDB). Never
    # disable on a network you do not control.
    AEGIS_DB_SSL_VERIFY: bool = True

    # Seconds a new /ws connection has to send its first auth message.
    AEGIS_WS_AUTH_TIMEOUT: float = 10.0

    # Opt-in incident reconciliation: when enabled, the firewall sync pass will
    # auto-resolve incidents whose source_ip is no longer in the Pi blocklist.
    # Set to True (or AEGIS_AUTO_RECONCILE_INCIDENTS=1 in .env) to activate.
    # Default OFF to avoid surprising existing deployments.
    AEGIS_AUTO_RECONCILE_INCIDENTS: bool = False

    # Opt-in Pi → Mac Pro blocklist pull. When enabled, each firewall sync cycle
    # appends any Pi-blocked IPs missing from the local blocked_ips.txt so the
    # FastAPI 403 middleware enforces them too. Default OFF (push-only).
    AEGIS_FIREWALL_PULL_FROM_PI: bool = False

    # ----------------------------------------------------------------------
    # DoS Shield (v1.6.4.0) — L7 flood detection / mitigation.
    # SAFE DEFAULTS: MODE=monitor (detect+emit only, NEVER 429/block) and the
    # network tier is gated off (NETSHIELD=False). Flipping to active or
    # enabling netshield is an explicit human decision — see deploy_notes.
    # ----------------------------------------------------------------------
    # 'monitor' = detect + log + emit dos.* events, NEVER 429/block.
    # 'active'   = enforce (429 + escalate). Runtime-overridable via /dos/mode.
    AEGIS_DOS_MODE: str = "monitor"
    # Network-tier master gate. False/0 = firewall_client network methods and
    # /dos/netshield endpoints are no-ops. Guards against locking the Mac Pro
    # out of its own Pi gateway. Must be explicitly enabled by an operator.
    AEGIS_DOS_NETSHIELD: bool = False

    # --- Per-IP sliding window ---
    # Baseline peak legit IP = 2 req/s → 5x headroom. Above trips dos.http_flood.
    AEGIS_DOS_PER_IP_RPS: float = 10.0
    AEGIS_DOS_PER_IP_WINDOW: int = 10   # seconds; budget = RPS*WINDOW = 100/10s

    # --- Per-/24-subnet aggregate window (catches clustered botnets) ---
    AEGIS_DOS_SUBNET_RPS: float = 40.0
    AEGIS_DOS_SUBNET_WINDOW: int = 10

    # --- Global aggregate window (catches fully-distributed floods) ---
    # Real API ~0.7 req/s, probe peak ~16.7 req/s → ~70x headroom on real traffic.
    AEGIS_DOS_GLOBAL_RPS: float = 50.0
    AEGIS_DOS_GLOBAL_WINDOW: int = 10

    # --- Expensive-endpoint budget (AI inference, scan triggers) ---
    AEGIS_DOS_EXPENSIVE_RPM: float = 6.0   # per-IP req/min = 1 per 10s
    AEGIS_DOS_EXPENSIVE_PATHS: str = (
        "/api/v1/ask,/api/v1/surface/scan,/api/v1/surface/scan/now"
    )

    # --- Slow-loris heuristics ---
    AEGIS_DOS_CONCURRENCY_PER_IP: int = 20   # max concurrent in-flight per IP
    AEGIS_DOS_SLOW_REQUEST_SECONDS: int = 25  # handler duration => slow-request tick

    # --- Escalation / body / adaptive knobs ---
    AEGIS_DOS_BLOCK_DURATION: int = 900       # seconds an escalated IP stays blocked
    AEGIS_DOS_MAX_BODY_BYTES: int = 10485760  # 10 MB → 413 above this
    AEGIS_DOS_UNDER_ATTACK_FACTOR: float = 0.5  # tighten budgets under attack
    AEGIS_DOS_EVENT_COOLDOWN: int = 30        # min seconds between same (ip,reason) event

    # Direct-peer IPs from which X-Forwarded-For is trusted for client-IP
    # derivation. Default = loopback + RFC1918 (Docker/Render/Cloudflare
    # proxies all connect from private ranges). Any other peer uses the real
    # socket IP, defeating XFF spoofing of rate-limit accounting.
    AEGIS_DOS_TRUSTED_PROXIES: str = (
        "127.0.0.1,::1,100.64.0.0/10,"
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    )

    # --- Network tier (gated by AEGIS_DOS_NETSHIELD) ---
    AEGIS_DOS_NETSHIELD_SYN_RATE: int = 50    # per-source SYN pkts/sec (iptables hashlimit)
    AEGIS_DOS_NETSHIELD_CONNLIMIT: int = 100  # max concurrent conns/source (iptables connlimit)

    # CORS — comma-separated explicit allow-list. Wildcard ("*") is invalid
    # combined with allow_credentials=True and is never used here (P0-10).
    # Prod overrides via env with the real dashboard origin(s).
    AEGIS_CORS_ORIGINS: str = (
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:3007,http://127.0.0.1:3007"
    )

    model_config = {"env_file": [".env", "../.env"], "extra": "ignore"}


settings = Settings()
