#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import sqlite3
import subprocess
import threading
import uuid
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("HONEYPOT_DB_PATH", DATA_DIR / "honeypot.db"))
BLOCKCHAIN_EVENT_SCRIPT = BASE_DIR / "scripts" / "log_event.js"
BLOCKCHAIN_STATUS_SCRIPT = BASE_DIR / "scripts" / "contract_status.js"
BLOCKCHAIN_DEPLOYMENT = BASE_DIR / "blockchain" / "deployment.json"
SECRET_SALT = os.environ.get("HONEYPOT_SECRET_SALT", "dev-only-change-this-salt")
EVENT_LOCK = threading.Lock()


TRAPS = {
    "/admin": {
        "trap_type": "login",
        "trap_name": "Fake Admin Login",
        "base_score": 20,
    },
    "/api/internal/config": {
        "trap_type": "api",
        "trap_name": "Dummy Internal Config API",
        "base_score": 35,
    },
}


def now_iso():
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_secret(value):
    return hmac.new(SECRET_SALT.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def severity_from_score(score):
    if score >= 80:
        return "critical"
    if score >= 51:
        return "high"
    if score >= 21:
        return "medium"
    return "low"


def init_db():
    DATA_DIR.mkdir(exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                trap_type TEXT NOT NULL,
                trap_name TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                src_ip_hash TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                session_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                payload_summary TEXT NOT NULL,
                severity_score INTEGER NOT NULL,
                severity_label TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                blockchain_status TEXT NOT NULL,
                chain_tx_hash TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_hash TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def db_rows(query, params=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, params).fetchall()


def db_one(query, params=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, params).fetchone()


def latest_event_hash():
    row = db_one("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1")
    return row["event_hash"] if row else "GENESIS"


def recent_session_count(session_id):
    row = db_one(
        """
        SELECT COUNT(*) AS total
        FROM events
        WHERE session_id = ?
        """,
        (session_id,),
    )
    return int(row["total"])


def summarize_payload(handler, content_type, body_bytes):
    body = body_bytes.decode("utf-8", errors="replace")
    if not body:
        return "No request body"

    if "application/x-www-form-urlencoded" in content_type:
        fields = parse_qs(body)
        summary = {}
        for key, value in fields.items():
            item = value[0] if value else ""
            if key.lower() in {"password", "pass", "token", "secret"}:
                summary[key] = f"hashed:{hash_secret(item)}"
            else:
                summary[key] = item[:80]
        return canonical_json(summary)

    return body[:300].replace("\r", "\\r").replace("\n", "\\n")


def calculate_score(path, method, user_agent, payload_summary, session_id):
    score = TRAPS[path]["base_score"]
    ua = user_agent.lower()

    if path == "/admin" and method == "POST":
        score += 25
    if path == "/api/internal/config":
        score += 15
    if any(tool in ua for tool in ["sqlmap", "nikto", "nmap", "gobuster", "dirsearch", "wpscan", "python-requests", "curl"]):
        score += 20
    if recent_session_count(session_id) >= 1:
        score += 20
    if any(marker in payload_summary.lower() for marker in ["../", "select ", "union ", "<script", "' or '1'='1"]):
        score += 25

    return min(score, 100)


def write_blockchain_proof(event_record):
    if not BLOCKCHAIN_DEPLOYMENT.exists():
        return "not_configured", None
    if not BLOCKCHAIN_EVENT_SCRIPT.exists():
        return "script_missing", None

    payload = {
        "eventId": event_record["event_id"],
        "eventHash": event_record["event_hash"],
        "previousHash": event_record["prev_hash"],
        "ipHash": event_record["src_ip_hash"],
        "severity": event_record["severity_score"],
    }
    try:
        result = subprocess.run(
            ["node", str(BLOCKCHAIN_EVENT_SCRIPT), canonical_json(payload)],
            cwd=BASE_DIR,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        data = json.loads(result.stdout.strip())
        return "anchored", data.get("transactionHash")
    except Exception as exc:
        return f"failed:{exc.__class__.__name__}", None


def record_event(handler, path, body_bytes=b""):
    with EVENT_LOCK:
        parsed = urlparse(handler.path)
        trap = TRAPS[path]
        method = handler.command
        user_agent = handler.headers.get("User-Agent", "")
        content_type = handler.headers.get("Content-Type", "")
        session_id = handler.session_id
        src_ip = handler.client_address[0]
        timestamp = now_iso()
        payload_summary = summarize_payload(handler, content_type, body_bytes)
        payload_hash = sha256_text(body_bytes.decode("utf-8", errors="replace"))
        src_ip_hash = hash_secret(src_ip)
        severity_score = calculate_score(path, method, user_agent, payload_summary, session_id)
        severity_label = severity_from_score(severity_score)
        prev_hash = latest_event_hash()
        event_id = str(uuid.uuid4())

        event_core = {
            "event_id": event_id,
            "timestamp": timestamp,
            "trap_type": trap["trap_type"],
            "trap_name": trap["trap_name"],
            "path": parsed.path,
            "method": method,
            "src_ip_hash": src_ip_hash,
            "user_agent": user_agent,
            "session_id": session_id,
            "payload_hash": payload_hash,
            "payload_summary": payload_summary,
            "severity_score": severity_score,
            "severity_label": severity_label,
            "prev_hash": prev_hash,
        }
        event_hash = sha256_text(canonical_json(event_core))
        event_record = {**event_core, "event_hash": event_hash}
        blockchain_status, chain_tx_hash = write_blockchain_proof(event_record)

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, trap_type, trap_name, path, method,
                    src_ip_hash, user_agent, session_id, payload_hash, payload_summary,
                    severity_score, severity_label, prev_hash, event_hash,
                    blockchain_status, chain_tx_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    trap["trap_type"],
                    trap["trap_name"],
                    parsed.path,
                    method,
                    src_ip_hash,
                    user_agent,
                    session_id,
                    payload_hash,
                    payload_summary,
                    severity_score,
                    severity_label,
                    prev_hash,
                    event_hash,
                    blockchain_status,
                    chain_tx_hash,
                ),
            )
            if severity_score >= 51:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO blocked_ips (ip_hash, reason, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (src_ip_hash, f"{severity_label} severity trap activity", timestamp),
                )
            conn.commit()

        return event_record | {"blockchain_status": blockchain_status, "chain_tx_hash": chain_tx_hash}


def verify_event_chain():
    rows = db_rows("SELECT * FROM events ORDER BY id ASC")
    previous = "GENESIS"
    for row in rows:
        event_core = {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "trap_type": row["trap_type"],
            "trap_name": row["trap_name"],
            "path": row["path"],
            "method": row["method"],
            "src_ip_hash": row["src_ip_hash"],
            "user_agent": row["user_agent"],
            "session_id": row["session_id"],
            "payload_hash": row["payload_hash"],
            "payload_summary": row["payload_summary"],
            "severity_score": row["severity_score"],
            "severity_label": row["severity_label"],
            "prev_hash": row["prev_hash"],
        }
        expected_hash = sha256_text(canonical_json(event_core))
        if row["prev_hash"] != previous:
            return False, f"Chain break before event {row['event_id']}"
        if row["event_hash"] != expected_hash:
            return False, f"Modified event detected at {row['event_id']}"
        previous = row["event_hash"]
    return True, f"Verified {len(rows)} event(s)"


def scalar(query, params=(), default=0):
    row = db_one(query, params)
    if not row:
        return default
    return next(iter(dict(row).values()))


def grouped_counts(column):
    rows = db_rows(f"SELECT {column} AS name, COUNT(*) AS total FROM events GROUP BY {column} ORDER BY total DESC")
    return {row["name"]: row["total"] for row in rows}


def blockchain_overview():
    anchored = scalar("SELECT COUNT(*) AS total FROM events WHERE blockchain_status = 'anchored'")
    failed = scalar("SELECT COUNT(*) AS total FROM events WHERE blockchain_status LIKE 'failed:%'")
    pending = scalar("SELECT COUNT(*) AS total FROM events WHERE blockchain_status != 'anchored'")
    overview = {
        "configured": BLOCKCHAIN_DEPLOYMENT.exists(),
        "contract": "not deployed",
        "rpc": "not configured",
        "deployed_at": "not available",
        "anchored": anchored,
        "failed": failed,
        "pending": pending,
        "contract_events": "unavailable",
    }
    if BLOCKCHAIN_DEPLOYMENT.exists():
        try:
            data = json.loads(BLOCKCHAIN_DEPLOYMENT.read_text())
            overview["contract"] = data.get("address", "unknown")
            overview["rpc"] = data.get("rpcUrl", "unknown")
            overview["deployed_at"] = data.get("deployedAt", "unknown")
        except json.JSONDecodeError:
            overview["contract"] = "deployment file unreadable"
        if BLOCKCHAIN_STATUS_SCRIPT.exists():
            try:
                result = subprocess.run(
                    ["node", str(BLOCKCHAIN_STATUS_SCRIPT)],
                    cwd=BASE_DIR,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                raw = result.stdout
                status = json.loads(raw[raw.index("{") :])
                overview["contract_events"] = status.get("eventCount", "unknown")
            except Exception:
                overview["contract_events"] = "unavailable"
    return overview


def page(title, body, surface="trap"):
    if surface == "dashboard":
        links = [
            ("/dashboard", "Dashboard"),
            ("/verify", "Verify"),
            ("/api/events", "Events API"),
        ]
        label = "Internal Security Console"
        nav = "".join(f'<a href="{href}">{html.escape(text)}</a>' for href, text in links)
        nav_html = f"""
  <nav>
    <div class="brand">{html.escape(label)}</div>
    <div class="nav-links">{nav}</div>
  </nav>"""
    else:
        nav_html = ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>{nav_html}
  <main>{body}</main>
</body>
</html>"""


class BaseHoneypotHandler(BaseHTTPRequestHandler):
    server_version = "DeceptionHoneypot/1.0"

    def setup(self):
        super().setup()
        self.session_id = None
        self.needs_session_cookie = False

    def ensure_session(self):
        raw_cookie = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw_cookie)
        if "hp_session" in jar:
            self.session_id = jar["hp_session"].value
        else:
            self.session_id = str(uuid.uuid4())
            self.needs_session_cookie = True

    def send_html(self, body, status=200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if self.needs_session_cookie:
            self.send_header("Set-Cookie", f"hp_session={self.session_id}; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, data, status=200):
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if self.needs_session_cookie:
            self.send_header("Set-Cookie", f"hp_session={self.session_id}; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(encoded)

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def home(self):
        body = """
        <section class="hero">
          <h1>Deception Based Security Mechanism</h1>
          <p>Two active traps are implemented: a fake admin login and a dummy internal API.</p>
          <!-- Scanner-visible decoy: /api/internal/config -->
        </section>
        <section class="grid">
          <article>
            <h2>Trap 1</h2>
            <p><strong>/admin</strong> records fake login interaction as suspicious activity.</p>
          </article>
          <article>
            <h2>Trap 2</h2>
            <p><strong>/api/internal/config</strong> records dummy API access attempts.</p>
          </article>
          <article>
            <h2>Audit Proof</h2>
            <p>Each event is linked to the previous event by hash and can be anchored to Ganache.</p>
          </article>
        </section>
        """
        self.send_html(page("Honeypot", body, "trap"))

    def admin_form(self):
        record_event(self, "/admin")
        body = """
        <section class="login-panel">
          <h1>Administrator Login</h1>
          <form method="post" action="/admin">
            <label>Username <input name="username" autocomplete="username"></label>
            <label>Password <input name="password" type="password" autocomplete="current-password"></label>
            <label class="check"><input type="checkbox" name="remember"> Remember me</label>
            <button type="submit">Sign in</button>
            <a href="#">Forgot password?</a>
          </form>
        </section>
        """
        self.send_html(page("Admin Login", body, "trap"))

    def admin_submit(self):
        body_bytes = self.read_body()
        event = record_event(self, "/admin", body_bytes)
        body = f"""
        <section class="login-panel">
          <h1>Login unavailable</h1>
          <p>Authentication service is temporarily unavailable.</p>
          <p class="muted">Event recorded: {html.escape(event["event_id"])}</p>
        </section>
        """
        self.send_html(page("Admin Login", body, "trap"), 401)

    def api_trap(self):
        body_bytes = self.read_body()
        event = record_event(self, "/api/internal/config", body_bytes)
        self.send_json(
            {
                "service": "internal-config",
                "status": "maintenance",
                "request_id": event["event_id"],
                "message": "configuration backend temporarily unavailable",
            },
            503,
        )

    def events_api(self):
        rows = db_rows("SELECT * FROM events ORDER BY id DESC LIMIT 100")
        self.send_json(
            {
                "integrity": verify_event_chain()[1],
                "blockchain": blockchain_overview(),
                "events": [dict(row) for row in rows],
            }
        )

    def dashboard(self):
        rows = db_rows("SELECT * FROM events ORDER BY id DESC LIMIT 50")
        blocked = db_rows("SELECT * FROM blocked_ips ORDER BY id DESC LIMIT 20")
        ok, message = verify_event_chain()
        status_class = "ok" if ok else "bad"
        total_events = scalar("SELECT COUNT(*) AS total FROM events")
        high_events = scalar("SELECT COUNT(*) AS total FROM events WHERE severity_label IN ('high', 'critical')")
        unique_sessions = scalar("SELECT COUNT(DISTINCT session_id) AS total FROM events")
        blocked_count = scalar("SELECT COUNT(*) AS total FROM blocked_ips")
        trap_counts = grouped_counts("trap_type")
        severity_counts = grouped_counts("severity_label")
        chain = blockchain_overview()
        trap_items = "".join(
            f"<li><span>{html.escape(name)}</span><strong>{total}</strong></li>"
            for name, total in trap_counts.items()
        )
        severity_items = "".join(
            f"<li><span class=\"dot {html.escape(name)}\"></span>{html.escape(name)}<strong>{total}</strong></li>"
            for name, total in severity_counts.items()
        )
        event_rows = "".join(
            f"""
            <tr>
              <td>{html.escape(row["timestamp"])}</td>
              <td>{html.escape(row["trap_type"])}</td>
              <td>{html.escape(row["method"])} {html.escape(row["path"])}</td>
              <td><span class="sev {html.escape(row["severity_label"])}">{html.escape(row["severity_label"])}</span></td>
              <td>{row["severity_score"]}</td>
              <td><code title="{html.escape(row["event_id"])}">{html.escape(row["event_id"][:8])}</code></td>
              <td><code>{html.escape((row["chain_tx_hash"] or row["blockchain_status"])[:18])}</code></td>
            </tr>
            """
            for row in rows
        )
        blocked_rows = "".join(
            f"<li><code>{html.escape(row['ip_hash'][:16])}</code> - {html.escape(row['reason'])}</li>"
            for row in blocked
        )
        tx_rows = "".join(
            f"""
            <tr>
              <td><code>{html.escape(row["event_id"][:8])}</code></td>
              <td>{html.escape(row["severity_label"])}</td>
              <td><code>{html.escape((row["chain_tx_hash"] or "not anchored")[:32])}</code></td>
            </tr>
            """
            for row in rows
            if row["chain_tx_hash"]
        )
        body = f"""
        <section class="toolbar">
          <div>
            <p class="eyebrow">Task 3 deception monitor</p>
            <h1>Security Dashboard</h1>
          </div>
          <div class="status {status_class}">{html.escape(message)}</div>
        </section>
        <section class="metrics">
          <article><span>Total Events</span><strong>{total_events}</strong></article>
          <article><span>High Risk</span><strong>{high_events}</strong></article>
          <article><span>Sessions</span><strong>{unique_sessions}</strong></article>
          <article><span>Blocked IP Hashes</span><strong>{blocked_count}</strong></article>
        </section>
        <section class="split">
          <article>
            <h2>Trap Activity</h2>
            <ul class="stat-list">{trap_items or '<li><span>No activity</span><strong>0</strong></li>'}</ul>
          </article>
          <article>
            <h2>Severity Mix</h2>
            <ul class="stat-list">{severity_items or '<li><span>No severity records</span><strong>0</strong></li>'}</ul>
          </article>
          <article>
            <h2>Ganache Blockchain</h2>
            <dl class="chain">
              <dt>Contract</dt><dd><code>{html.escape(chain["contract"])}</code></dd>
              <dt>RPC</dt><dd><code>{html.escape(chain["rpc"])}</code></dd>
              <dt>Local anchored events</dt><dd>{chain["anchored"]}</dd>
              <dt>Contract event count</dt><dd>{html.escape(str(chain["contract_events"]))}</dd>
              <dt>Pending/failed</dt><dd>{chain["pending"]}</dd>
            </dl>
          </article>
        </section>
        <section>
          <h2>Recent Events</h2>
          <table>
            <thead>
              <tr><th>Time</th><th>Trap</th><th>Request</th><th>Severity</th><th>Score</th><th>Event</th><th>Chain proof</th></tr>
            </thead>
            <tbody>{event_rows or '<tr><td colspan="7">No trap events yet.</td></tr>'}</tbody>
          </table>
        </section>
        <section>
          <h2>Blockchain Transactions</h2>
          <table>
            <thead><tr><th>Event</th><th>Severity</th><th>Transaction hash</th></tr></thead>
            <tbody>{tx_rows or '<tr><td colspan="3">No blockchain transactions recorded yet.</td></tr>'}</tbody>
          </table>
        </section>
        <section>
          <h2>Auto-Block Simulation</h2>
          <ul>{blocked_rows or '<li>No high-severity IP hashes blocked yet.</li>'}</ul>
        </section>
        """
        self.send_html(page("Dashboard", body, "dashboard"))

    def verify_page(self):
        event_id = parse_qs(urlparse(self.path).query).get("event_id", [""])[0]
        ok, message = verify_event_chain()
        detail = ""
        if event_id:
            row = db_one("SELECT * FROM events WHERE event_id = ?", (event_id,))
            if row:
                detail = f"""
                <dl>
                  <dt>Event ID</dt><dd><code>{html.escape(row["event_id"])}</code></dd>
                  <dt>Event hash</dt><dd><code>{html.escape(row["event_hash"])}</code></dd>
                  <dt>Previous hash</dt><dd><code>{html.escape(row["prev_hash"])}</code></dd>
                  <dt>Blockchain status</dt><dd>{html.escape(row["blockchain_status"])}</dd>
                  <dt>Transaction hash</dt><dd><code>{html.escape(row["chain_tx_hash"] or "not anchored")}</code></dd>
                </dl>
                """
            else:
                detail = "<p>No event found for that ID.</p>"
        body = f"""
        <section class="toolbar">
          <h1>Verify Audit Chain</h1>
          <div class="status {'ok' if ok else 'bad'}">{html.escape(message)}</div>
        </section>
        <form class="verify" method="get" action="/verify">
          <label>Event ID <input name="event_id" value="{html.escape(event_id)}"></label>
          <button type="submit">Verify</button>
        </form>
        {detail}
        """
        self.send_html(page("Verify", body, "dashboard"))

    def styles(self):
        css = """
        :root { color-scheme: light; font-family: Inter, Arial, sans-serif; }
        body { margin: 0; background: #111418; color: #e8edf2; }
        nav { display: flex; justify-content: space-between; align-items: center; gap: 18px; padding: 16px 28px; background: #151a20; border-bottom: 1px solid #2f3a45; }
        .brand { color: #d7dee7; font-weight: 800; }
        .nav-links { display: flex; gap: 16px; flex-wrap: wrap; }
        nav a { color: #aeb9c6; text-decoration: none; font-weight: 700; }
        nav a:hover { color: #ffffff; }
        main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
        h1, h2 { margin: 0 0 14px; }
        section { margin: 0 0 28px; }
        .hero { padding: 28px 0; border-bottom: 1px solid #29323c; }
        .hero h1 { font-size: 34px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; }
        article, .login-panel { background: #1a2027; border: 1px solid #2d3641; border-radius: 8px; padding: 22px; box-shadow: 0 10px 28px rgba(0, 0, 0, .22); }
        .login-panel { max-width: 420px; margin: 36px auto; }
        label { display: grid; gap: 6px; margin: 0 0 14px; font-weight: 700; }
        label.check { display: flex; align-items: center; gap: 8px; font-weight: 500; }
        input { border: 1px solid #3a4654; border-radius: 6px; padding: 10px 12px; font: inherit; background: #111820; color: #e8edf2; }
        button { border: 0; border-radius: 6px; padding: 11px 16px; background: #3b82f6; color: white; font-weight: 800; cursor: pointer; }
        table { width: 100%; border-collapse: collapse; background: #1a2027; border: 1px solid #2d3641; border-radius: 8px; overflow: hidden; }
        th, td { padding: 11px 12px; border-bottom: 1px solid #2d3641; text-align: left; font-size: 14px; vertical-align: top; }
        th { background: #202832; color: #cbd5df; }
        code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; gap: 18px; }
        .eyebrow { margin: 0 0 6px; color: #94a3b8; font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: 0; }
        .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
        .metrics article { padding: 18px; }
        .metrics span { display: block; color: #94a3b8; font-size: 13px; font-weight: 800; }
        .metrics strong { display: block; margin-top: 8px; font-size: 32px; line-height: 1; }
        .split { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
        .stat-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
        .stat-list li { display: flex; align-items: center; justify-content: space-between; gap: 10px; border-bottom: 1px solid #2d3641; padding-bottom: 8px; }
        .dot { width: 10px; height: 10px; display: inline-block; border-radius: 99px; margin-right: 8px; background: #64748b; }
        .dot.medium { background: #ca8a04; }
        .dot.high { background: #dc2626; }
        .dot.critical { background: #7f1d1d; }
        .chain { padding: 0; border: 0; }
        .chain dt { color: #94a3b8; font-size: 13px; }
        .chain dd { margin-bottom: 10px; }
        .status { border-radius: 6px; padding: 10px 12px; font-weight: 800; }
        .status.ok { background: #123524; color: #86efac; }
        .status.bad { background: #3f1518; color: #fca5a5; }
        .sev { border-radius: 999px; padding: 4px 9px; color: white; font-weight: 800; }
        .sev.low { background: #64748b; }
        .sev.medium { background: #ca8a04; }
        .sev.high { background: #dc2626; }
        .sev.critical { background: #7f1d1d; }
        .muted { color: #94a3b8; }
        .verify { display: flex; gap: 12px; align-items: end; }
        .verify label { flex: 1; }
        dl { background: #1a2027; border: 1px solid #2d3641; border-radius: 8px; padding: 18px; }
        dt { font-weight: 800; margin-top: 10px; }
        dd { margin: 4px 0 10px; overflow-wrap: anywhere; }
        ul { background: #1a2027; border: 1px solid #2d3641; border-radius: 8px; padding: 18px 24px; }
        @media (max-width: 720px) {
          .toolbar, .verify { display: block; }
          nav { align-items: flex-start; flex-direction: column; }
          .metrics, .split { grid-template-columns: 1fr; }
          table { display: block; overflow-x: auto; }
        }
        """
        encoded = css.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/css; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        return


class TrapHandler(BaseHoneypotHandler):
    def do_GET(self):
        self.ensure_session()
        path = urlparse(self.path).path
        if path == "/":
            self.home()
        elif path == "/admin":
            self.admin_form()
        elif path == "/api/internal/config":
            self.api_trap()
        elif path == "/static/style.css":
            self.styles()
        else:
            self.send_html(page("Not Found", "<h1>Not found</h1>", "trap"), 404)

    def do_POST(self):
        self.ensure_session()
        path = urlparse(self.path).path
        if path == "/admin":
            self.admin_submit()
        elif path == "/api/internal/config":
            self.api_trap()
        else:
            self.send_html(page("Not Found", "<h1>Not found</h1>", "trap"), 404)

    def do_PUT(self):
        self.ensure_session()
        if urlparse(self.path).path == "/api/internal/config":
            self.api_trap()
        else:
            self.send_html(page("Not Found", "<h1>Not found</h1>", "trap"), 404)


class DashboardHandler(BaseHoneypotHandler):
    def do_GET(self):
        self.ensure_session()
        path = urlparse(self.path).path
        if path == "/":
            self.dashboard()
        elif path == "/dashboard":
            self.dashboard()
        elif path == "/verify":
            self.verify_page()
        elif path == "/api/events":
            self.events_api()
        elif path == "/static/style.css":
            self.styles()
        else:
            self.send_html(page("Not Found", "<h1>Not found</h1>", "dashboard"), 404)

    def do_POST(self):
        self.ensure_session()
        self.send_html(page("Not Found", "<h1>Not found</h1>", "dashboard"), 404)

    def do_PUT(self):
        self.ensure_session()
        self.send_html(page("Not Found", "<h1>Not found</h1>", "dashboard"), 404)


def main():
    parser = argparse.ArgumentParser(description="Run the deception honeypot servers")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mode", choices=["trap", "dashboard", "both"], default="both")
    parser.add_argument("--port", type=int, help="Port for single-server trap/dashboard mode")
    parser.add_argument("--trap-port", default=8000, type=int)
    parser.add_argument("--dashboard-port", default=9000, type=int)
    args = parser.parse_args()
    init_db()

    if args.mode == "trap":
        port = args.port or args.trap_port
        server = ThreadingHTTPServer((args.host, port), TrapHandler)
        print(f"Trap server running at http://{args.host}:{port}")
        server.serve_forever()

    if args.mode == "dashboard":
        port = args.port or args.dashboard_port
        server = ThreadingHTTPServer((args.host, port), DashboardHandler)
        print(f"Dashboard server running at http://{args.host}:{port}")
        server.serve_forever()

    trap_server = ThreadingHTTPServer((args.host, args.trap_port), TrapHandler)
    dashboard_server = ThreadingHTTPServer((args.host, args.dashboard_port), DashboardHandler)
    trap_thread = threading.Thread(target=trap_server.serve_forever, daemon=True)
    trap_thread.start()
    print(f"Trap server running at http://{args.host}:{args.trap_port}")
    print(f"Dashboard server running at http://{args.host}:{args.dashboard_port}")
    try:
        dashboard_server.serve_forever()
    finally:
        trap_server.shutdown()
        dashboard_server.shutdown()


if __name__ == "__main__":
    main()
