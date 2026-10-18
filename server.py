#!/usr/bin/env python3
"""Agent Verify — server-backed verification service for Koola10.

When the owner's AI agent acts on his behalf with a business, the business
gets a verification code and checks it here. Live records only — no demo
data is stored in the database.

Endpoints:
  GET  /                        public verify page (static)
  GET  /api/verify/:code        PUBLIC (rate-limited) — verify a code
  POST /api/issue               admin — issue a new code
  POST /api/revoke/:code        admin — revoke a code
  GET  /api/audit/:code         admin — audit trail for a code

Admin auth: header X-Admin-Key == AGENT_VERIFY_ADMIN_KEY (env or .env).
Zero third-party dependencies — stdlib only.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "agent_verify.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")
PUBLIC_DIR = BASE_DIR  # index.html served from build dir

CODE_RE = re.compile(r"^KOOLA10-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # unambiguous chars

RATE_LIMIT = 30          # public verify requests
RATE_WINDOW = 60         # per this many seconds, per IP
DEFAULT_EXPIRY_DAYS = 7

_rate_buckets: dict = {}


# ---------------------------------------------------------------- key / env

def load_admin_key() -> str:
    key = os.environ.get("AGENT_VERIFY_ADMIN_KEY")
    if key:
        return key
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("AGENT_VERIFY_ADMIN_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    key = secrets.token_urlsafe(32)
    with open(ENV_PATH, "w") as f:
        f.write(f"AGENT_VERIFY_ADMIN_KEY={key}\n")
    os.chmod(ENV_PATH, 0o600)
    return key


ADMIN_KEY = load_admin_key()


# ---------------------------------------------------------------- database

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS records (
               code TEXT PRIMARY KEY,
               representative TEXT NOT NULL,
               principal TEXT NOT NULL,
               purpose TEXT NOT NULL,
               scope TEXT NOT NULL,
               authority TEXT NOT NULL,
               issued_at TEXT NOT NULL,
               expires_at TEXT NOT NULL,
               revoked_at TEXT,
               revoked_reason TEXT,
               check_count INTEGER NOT NULL DEFAULT 0
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               code TEXT NOT NULL,
               checked_at TEXT NOT NULL,
               ip TEXT,
               result TEXT NOT NULL
           )"""
    )
    conn.commit()
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_status(row) -> str:
    if row["revoked_at"]:
        return "revoked"
    if datetime.now(timezone.utc) >= datetime.fromisoformat(row["expires_at"]):
        return "expired"
    return "active"


def generate_code(conn) -> str:
    for _ in range(10):
        code = "KOOLA10-" + "-".join(
            "".join(secrets.choice(CODE_ALPHABET) for _ in range(4)) for _ in range(3)
        )
        if not conn.execute("SELECT 1 FROM records WHERE code=?", (code,)).fetchone():
            return code
    raise RuntimeError("could not generate unique code")


# ---------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "AgentVerify/1.0"

    # -- helpers ----------------------------------------------------
    def _json(self, obj, status=200, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def _admin_ok(self) -> bool:
        given = self.headers.get("X-Admin-Key") or ""
        return bool(given) and hmac.compare_digest(given, ADMIN_KEY)

    def _rate_ok(self) -> bool:
        ip = self.client_address[0]
        now = time.time()
        bucket = [t for t in _rate_buckets.get(ip, []) if now - t < RATE_WINDOW]
        if len(bucket) >= RATE_LIMIT:
            return False
        bucket.append(now)
        _rate_buckets[ip] = bucket
        return True

    def log_message(self, *args):
        pass  # quiet

    # -- routing ----------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            return self._serve_static("index.html", "text/html; charset=utf-8")
        m = re.fullmatch(r"/api/verify/([^/]+)", path)
        if m:
            return self._verify_public(unquote(m.group(1)).strip().upper())
        m = re.fullmatch(r"/api/audit/([^/]+)", path)
        if m:
            return self._audit(unquote(m.group(1)).strip().upper())
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/issue":
            return self._issue()
        m = re.fullmatch(r"/api/revoke/([^/]+)", path)
        if m:
            return self._revoke(unquote(m.group(1)).strip().upper())
        self._json({"error": "not found"}, 404)

    def _serve_static(self, name, ctype):
        fp = os.path.join(PUBLIC_DIR, name)
        if not os.path.exists(fp):
            self._json({"error": "not found"}, 404)
            return
        with open(fp, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # -- public verify ----------------------------------------------
    def _verify_public(self, code):
        if not self._rate_ok():
            self._json(
                {"error": "rate limit exceeded, try again shortly"},
                429,
                {"Retry-After": "60"},
            )
            return
        conn = db()
        try:
            row = conn.execute("SELECT * FROM records WHERE code=?", (code,)).fetchone()
            ip = self.client_address[0]
            if not row:
                conn.execute(
                    "INSERT INTO audit (code, checked_at, ip, result) VALUES (?,?,?,?)",
                    (code, now_iso(), ip, "not_found"),
                )
                conn.commit()
                self._json(
                    {
                        "code": code,
                        "status": "not_found",
                        "message": "No record found for this code. "
                                   "Do not proceed on the basis of an unverified claim.",
                    },
                    404,
                )
                return
            status = record_status(row)
            conn.execute(
                "UPDATE records SET check_count = check_count + 1 WHERE code=?", (code,)
            )
            conn.execute(
                "INSERT INTO audit (code, checked_at, ip, result) VALUES (?,?,?,?)",
                (code, now_iso(), ip, status),
            )
            conn.commit()
            if status == "active":
                self._json(
                    {
                        "code": code,
                        "status": "active",
                        "record_type": "live",
                        "representative": row["representative"],
                        "principal": row["principal"],
                        "purpose": row["purpose"],
                        "scope": row["scope"],
                        "authority": row["authority"],
                        "issued_at": row["issued_at"],
                        "expires_at": row["expires_at"],
                        "verification_count": row["check_count"] + 1,
                    }
                )
            else:
                # Expired/revoked: status + principal name only, never full details.
                self._json(
                    {
                        "code": code,
                        "status": status,
                        "record_type": "live",
                        "principal": row["principal"],
                        "message": (
                            "This code has expired."
                            if status == "expired"
                            else "This code has been revoked by the owner."
                        )
                        + " Do not proceed on the basis of an unverified claim.",
                    }
                )
        finally:
            conn.close()

    # -- admin: issue ------------------------------------------------
    def _issue(self):
        if not self._admin_ok():
            self._json({"error": "unauthorized"}, 401)
            return
        body = self._read_json()
        purpose = (body.get("purpose") or "").strip()
        scope = (body.get("scope") or "").strip()
        authority = (body.get("authority") or "").strip()
        if not purpose or not scope or not authority:
            self._json(
                {"error": "purpose, scope and authority are all required"}, 400
            )
            return
        representative = (body.get("representative") or "Muse").strip()
        principal = (body.get("principal") or "George Gardner").strip()

        expires_at = body.get("expires_at")
        if body.get("expires_in_seconds"):
            try:
                expires_at = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=int(body["expires_in_seconds"]))
                ).isoformat()
            except (ValueError, TypeError):
                expires_at = None
        elif body.get("expires_in_days"):
            try:
                expires_at = (
                    datetime.now(timezone.utc)
                    + timedelta(days=float(body["expires_in_days"]))
                ).isoformat()
            except (ValueError, TypeError):
                expires_at = None
        if not expires_at:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=DEFAULT_EXPIRY_DAYS)
            ).isoformat()
        else:
            try:
                dt = datetime.fromisoformat(expires_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt <= datetime.now(timezone.utc):
                    self._json({"error": "expires_at must be in the future"}, 400)
                    return
                expires_at = dt.isoformat()
            except (ValueError, TypeError):
                self._json({"error": "expires_at must be ISO-8601"}, 400)
                return

        conn = db()
        try:
            code = generate_code(conn)
            conn.execute(
                """INSERT INTO records
                   (code, representative, principal, purpose, scope, authority,
                    issued_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    code, representative, principal, purpose, scope, authority,
                    now_iso(), expires_at,
                ),
            )
            conn.commit()
            self._json(
                {
                    "code": code,
                    "status": "active",
                    "representative": representative,
                    "principal": principal,
                    "purpose": purpose,
                    "scope": scope,
                    "authority": authority,
                    "issued_at": now_iso(),
                    "expires_at": expires_at,
                },
                201,
            )
        finally:
            conn.close()

    # -- admin: revoke -----------------------------------------------
    def _revoke(self, code):
        if not self._admin_ok():
            self._json({"error": "unauthorized"}, 401)
            return
        body = self._read_json()
        reason = (body.get("reason") or "revoked by owner").strip()
        conn = db()
        try:
            row = conn.execute("SELECT * FROM records WHERE code=?", (code,)).fetchone()
            if not row:
                self._json({"error": "code not found"}, 404)
                return
            conn.execute(
                "UPDATE records SET revoked_at=?, revoked_reason=? WHERE code=?",
                (now_iso(), reason, code),
            )
            conn.execute(
                "INSERT INTO audit (code, checked_at, ip, result) VALUES (?,?,?,?)",
                (code, now_iso(), self.client_address[0], "revoked"),
            )
            conn.commit()
            self._json({"code": code, "status": "revoked", "reason": reason})
        finally:
            conn.close()

    # -- admin: audit -------------------------------------------------
    def _audit(self, code):
        if not self._admin_ok():
            self._json({"error": "unauthorized"}, 401)
            return
        conn = db()
        try:
            row = conn.execute("SELECT * FROM records WHERE code=?", (code,)).fetchone()
            if not row:
                self._json({"error": "code not found"}, 404)
                return
            rows = conn.execute(
                "SELECT checked_at, ip, result FROM audit WHERE code=? ORDER BY id",
                (code,),
            ).fetchall()
            self._json(
                {
                    "code": code,
                    "status": record_status(row),
                    "verification_count": row["check_count"],
                    "revoked_at": row["revoked_at"],
                    "revoked_reason": row["revoked_reason"],
                    "events": [
                        {
                            "checked_at": r["checked_at"],
                            "ip": r["ip"],
                            "result": r["result"],
                        }
                        for r in rows
                    ],
                }
            )
        finally:
            conn.close()


def main():
    port = int(os.environ.get("PORT", "8791"))
    db().close()  # ensure tables exist
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"Agent Verify listening on 0.0.0.0:{port} (db: {DB_PATH})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
