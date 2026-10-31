/**
 * AEGIS Live WebSocket client.
 *
 * Single persistent connection to /ws with:
 *   - Auto-reconnect (exponential backoff, max 30s)
 *   - Topic subscribe/unsubscribe API
 *   - Ping heartbeat every 25s
 *   - Multi-callback per topic
 *
 * Usage:
 *   const ws = getLiveWS();
 *   const off = ws.subscribe("incidents.new", (msg) => { ... });
 *   off(); // unsubscribe
 */

type Handler = (data: unknown) => void;

export interface WSMessage {
  type: string;
  topic?: string;
  data?: unknown;
  timestamp?: string;
  severity?: string;
}

export type WSStatus = "idle" | "connecting" | "open" | "closed" | "error";

class LiveWS {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers = new Map<string, Set<Handler>>();
  private statusHandlers = new Set<(s: WSStatus) => void>();
  private status: WSStatus = "idle";
  private reconnectAttempt = 0;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private closedByUser = false;
  private authFailed = false;
  private lastToken = "";
  private subscribedTopics = new Set<string>();

  constructor(url: string) {
    this.url = url;
  }

  private setStatus(s: WSStatus) {
    this.status = s;
    this.statusHandlers.forEach((h) => {
      try {
        h(s);
      } catch {
        /* noop */
      }
    });
  }

  getStatus(): WSStatus {
    return this.status;
  }

  onStatus(cb: (s: WSStatus) => void): () => void {
    this.statusHandlers.add(cb);
    cb(this.status);
    return () => this.statusHandlers.delete(cb);
  }

  connect() {
    if (typeof window === "undefined") return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const token =
      localStorage.getItem("aegis_jwt_token") ||
      localStorage.getItem("aegis_api_key") ||
      "";
    if (!token) {
      // No credentials yet (login page). Do not open or retry a socket that
      // the server will reject.
      this.setStatus("idle");
      return;
    }

    // A new login/logout cycle replaces the token: clear the permanent
    // auth-failure latch so the freshly stored credentials are tried.
    if (token !== this.lastToken) {
      this.lastToken = token;
      this.authFailed = false;
    }
    if (this.authFailed) return;

    this.closedByUser = false;
    this.setStatus("connecting");

    try {
      this.ws = new WebSocket(this.url);
    } catch (err) {
      console.error("[ws] failed to construct WebSocket", err);
      this.setStatus("error");
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.setStatus("open");
      // Authenticate as the very first frame. Messages are ordered, so the
      // subscribe frames that follow are processed after auth succeeds.
      this.sendRaw({ type: "auth", token });
      if (this.subscribedTopics.size > 0) {
        this.sendRaw({
          type: "subscribe",
          topics: Array.from(this.subscribedTopics),
        });
      }
      this.startPing();
    };

    this.ws.onmessage = (ev) => {
      let msg: WSMessage;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.type === "auth_error") {
        this.authFailed = true;
        this.setStatus("error");
        return;
      }
      if (
        msg.type === "pong" ||
        msg.type === "auth_ok" ||
        msg.type === "filters_updated" ||
        msg.type === "subscribed" ||
        msg.type === "unsubscribed"
      ) {
        return;
      }
      // Dispatch by topic (msg.topic preferred; fallback to msg.type)
      const topic = (msg.topic || msg.type || "").toString();
      this.dispatch(topic, msg);
      // Wildcard "*" subscribers always receive
      this.dispatch("*", msg);
    };

    this.ws.onerror = () => {
      this.setStatus("error");
    };

    this.ws.onclose = (ev) => {
      this.stopPing();
      this.setStatus(this.authFailed || ev.code === 4401 ? "error" : "closed");
      this.ws = null;
      // 4401 = authentication failure; reconnecting with the same token only
      // produces a hot loop.
      if (ev.code === 4401) {
        this.authFailed = true;
      }
      if (!this.closedByUser && !this.authFailed) {
        this.scheduleReconnect();
      }
    };
  }

  private dispatch(topic: string, msg: WSMessage) {
    const set = this.handlers.get(topic);
    if (!set || set.size === 0) return;
    // Most widgets want the inner payload
    const payload = (msg.data !== undefined ? msg.data : msg) as unknown;
    set.forEach((h) => {
      try {
        h(payload);
      } catch (err) {
        console.error(`[ws] handler error on topic ${topic}`, err);
      }
    });
  }

  private scheduleReconnect() {
    if (this.reconnectTimer !== null) return;
    const delay = Math.min(30_000, 500 * Math.pow(2, this.reconnectAttempt));
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private startPing() {
    this.stopPing();
    this.pingTimer = window.setInterval(() => {
      this.sendRaw({ type: "ping" });
    }, 25_000);
  }

  private stopPing() {
    if (this.pingTimer !== null) {
      window.clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private sendRaw(obj: Record<string, unknown>) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(JSON.stringify(obj));
    } catch (err) {
      console.error("[ws] send failed", err);
    }
  }

  /**
   * Subscribe a handler to a topic. Returns an unsubscribe function.
   */
  subscribe(topic: string, handler: Handler): () => void {
    let set = this.handlers.get(topic);
    if (!set) {
      set = new Set();
      this.handlers.set(topic, set);
    }
    set.add(handler);

    if (topic !== "*" && !this.subscribedTopics.has(topic)) {
      this.subscribedTopics.add(topic);
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.sendRaw({ type: "subscribe", event_types: [topic] });
      }
    }

    return () => this.unsubscribe(topic, handler);
  }

  unsubscribe(topic: string, handler: Handler) {
    const set = this.handlers.get(topic);
    if (!set) return;
    set.delete(handler);
    if (set.size === 0) {
      this.handlers.delete(topic);
      // We keep subscribedTopics populated — the backend treats topics additively.
    }
  }

  close() {
    this.closedByUser = true;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopPing();
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* noop */
      }
      this.ws = null;
    }
    this.setStatus("closed");
  }
}

let _singleton: LiveWS | null = null;

/**
 * Resolve the WebSocket root.
 *
 * Precedence:
 *   1. NEXT_PUBLIC_WS_URL        — explicit, e.g. wss://api.example.com
 *   2. NEXT_PUBLIC_API_URL       — derive from the API origin
 *   3. localhost / 127.0.0.1     — ws://localhost:8000 for local dev
 *   4. same origin               — wss://<dashboard-host>/ws
 *
 * There is deliberately no hard-coded backend: every deployment talks to its
 * own backend instead of a third-party origin.
 */
function toWsRoot(raw: string): string {
  const value = raw.trim();
  if (!value) return "";
  if (value.startsWith("/")) {
    if (typeof window === "undefined") return "";
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}${value}`;
  }
  return value.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
}

function buildWsUrl(): string {
  let root = "";

  if (process.env.NEXT_PUBLIC_WS_URL) {
    root = toWsRoot(process.env.NEXT_PUBLIC_WS_URL);
  }

  if (!root && process.env.NEXT_PUBLIC_API_URL) {
    const api = process.env.NEXT_PUBLIC_API_URL.trim();
    // Strip the API prefix so https://host/api/v1 becomes wss://host/ws.
    root = toWsRoot(api.replace(/\/api\/v1\/?$/i, ""));
  }

  if (!root && typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
      root = "ws://localhost:8000";
    } else {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      root = `${proto}//${window.location.host}`;
    }
  }

  if (!root) return "";
  const base = root.replace(/\/+$/, "").replace(/\/ws$/i, "");
  return `${base}/ws`;
}

export function getLiveWS(): LiveWS {
  if (!_singleton) {
    _singleton = new LiveWS(buildWsUrl());
  }
  if (typeof window !== "undefined") {
    // Idempotent: opens the socket on first use and re-opens it when a token
    // was stored after the singleton was created on the login page.
    _singleton.connect();
  }
  return _singleton;
}

/**
 * React-friendly hook wrapper (used by widgets).
 * Subscribes on mount, cleans up on unmount.
 */
export function subscribeTopic(topic: string, handler: Handler): () => void {
  const ws = getLiveWS();
  return ws.subscribe(topic, handler);
}
