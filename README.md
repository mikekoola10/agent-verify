# Agent Verify — server-backed verification service

Self-hosted Koola10 replacement for third-party agent-verification services.
When Muse acts on the owner's behalf, the business gets an assignment code
(`KOOLA10-XXXX-XXXX-XXXX`) and checks it on the public page. Live records
only — the database never holds demo data.

## Run

```bash
cd ~/workspace/builds/agent-verify
python3 server.py            # listens on 127.0.0.1:8791 (PORT env overrides)
```

First run generates the admin key into `.env` (chmod 600). **The admin key
is never printed or committed.** The key lives only in `.env`; read it from
there when calling admin endpoints.

SQLite database: `agent_verify.db` (created on first run, same directory).

## API

Public (rate-limited: 30 req/min per IP):

- `GET /api/verify/:code` → full record when active; for expired/revoked
  codes only status + principal name; 404 + "not found" otherwise.
  Every check is written to the audit log.

Admin — header `X-Admin-Key: <key from .env>`:

- `POST /api/issue` — body JSON:
  `purpose`, `scope`, `authority` (required);
  `representative` (default "Muse"), `principal` (default "George Gardner");
  expiry: `expires_in_days` (default 7), `expires_in_seconds`, or ISO
  `expires_at`. Returns `201` with the new code.
- `POST /api/revoke/:code` — body JSON `{"reason": "..."}` → `{"status":"revoked"}`.
- `GET /api/audit/:code` — status, verification count, revocation info,
  and the full check history (timestamp, IP, result per check).

Example (key read from .env, never pasted):

```bash
KEY=$(grep AGENT_VERIFY_ADMIN_KEY .env | cut -d= -f2)
curl -s -X POST localhost:8791/api/issue -H "X-Admin-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"purpose":"Request and compare service quotes",
       "scope":"Ask questions, collect written terms, return options for owner review",
       "authority":"No purchase or binding commitment"}'
```

## Public page

`GET /` — verify page in the prototype's teal/lime/ivory style (dark mode
supported). Enter a code to see the live record; `KOOLA10-DEMO` renders a
clearly-marked SAMPLE layout preview that never touches the database.

## Deploy (needs owner approval — not done yet)

Recommended: Render free tier, like his other sites (Nova Apex, Spiral
Academy). Needs: this directory as the repo/service root, start command
`python3 server.py`, `PORT` env provided by Render, `AGENT_VERIFY_ADMIN_KEY`
set as a Render env var (then no `.env` file is used), and a persistent disk
for `agent_verify.db` (Render free disks persist per deploy; alternatively
back up the sqlite file). Custom domain later for the "domain-backed" trust
badge to mean something.
