# WORLDC2 C2 - Developer Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        C2 Server                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ TCP/TLS  │  │   HTTP   │  │WebSocket │  │    DNS     │ │
│  │ :8443    │  │  :8445   │  │  :8446   │  │ (opt-in)   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
│       └──────────────┴──────────────┴──────────────┘        │
│                            │                                │
│  ┌─────────────────────────┼──────────────────────────────┐ │
│  │                    Session Manager                      │ │
│  │  (State Machine: New → KeyExchange → Active → Dead)    │ │
│  └─────────────────────────┼──────────────────────────────┘ │
│                            │                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ REST API │  │  SOCKS5  │  │  Vault   │  │   Files    │ │
│  │  :9090   │  │  Proxy   │  │  Creds   │  │   Loot     │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴────┐ ┌────┴──────┐
        │  Agent    │ │ Agent  │ │  Agent    │
        │ (Linux)   │ │(Windows│ │ (macOS)   │
        │           │ │  /PS)  │ │           │
        └───────────┘ └────────┘ └───────────┘
```

## Protocol Flow

The envelope flow below is identical on every listener. The agent's fallback chain is
`TLS (8443) → TCP (8443) → HTTP long-poll (8445) → WebSocket (8446) → WebRTC (8447) → DNS (opt-in)`;
all five carry the same length-prefixed protobuf envelopes, so sessions are transport-agnostic.
The four fallback ports are defaults: non-default deployments pass matching
`-http-port` / `-ws-port` / `-webrtc-port` / `-dns-port` flags to the agent (validated, and
silently-rejected-with-log values fall back to the defaults — see `normalizePort`).

### 1. Connection & Key Exchange

> **HTTP long-poll specifics (port 8445):** `POST /register` with no `X-Session-ID`
> creates a session (empty body required) and returns the id in the `X-Session-ID`
> response header; subsequent `POST /register` requests carry agent→server frames in
> the body and answer an empty 200 ack. Server→agent data flows via `POST /poll`,
> which long-polls up to 25 s for the next queued frame. Each direction keeps its own
> FIFO queue, so frame order is preserved across HTTP hops. Idle agents are reaped
> after 10 minutes without inbound data (agents heartbeat every 25-35 s).

```
Agent                              Server
  │                                  │
  │────── TCP Connect ──────────────>│
  │                                  │
  │────── KEY_EXCHANGE (raw) ───────>│  Contains: Agent X25519 public key
  │                                  │
  │<───── KEY_EXCHANGE (raw) ────────│  Contains: Server X25519 public key + salt
  │                                  │
  │  [Both derive shared secret]     │
  │  [HKDF → encKey, hmacKey, token] │
  │                                  │
  │────── SESSION_INIT (encrypted) ─>│  Contains: hostname, OS, user, agentID
  │                                  │
  │<───── ACK (encrypted) ───────────│
  │                                  │
  │  [Session established]           │
  │                                  │
  │<───── TASK ──────────────────────│  Command to execute
  │────── TASK_RESULT ──────────────>│  Command output
  │                                  │
  │<───── HEARTBEAT ─────────────────│
  │────── HEARTBEAT ────────────────>│
```

### 2. Message Format

```
┌─────────────────────────────────────────────────────────────┐
│                    Length-Prefixed Frame                    │
├──────────────┬──────────────────────────────────────────────┤
│ 4 bytes      │ Variable length                              │
│ Big-Endian   │ Protobuf Envelope                            │
│ Length       │ ┌──────────────────────────────────────────┐ │
│              │ │ Id, Type, Timestamp, Nonce, Ciphertext   │ │
│              │ └──────────────────────────────────────────┘ │
└──────────────┴──────────────────────────────────────────────┘

After key exchange, Ciphertext = XChaCha20-Poly1305(EnvelopeInner)

┌─────────────────────────────────────────────────────────────┐
│                    EnvelopeInner (encrypted)                 │
├──────────────────┬──────────────────────────────────────────┤
│ Id (uint64)      │ Sequence number                          │
│ Type (enum)      │ TASK, TASK_RESULT, HEARTBEAT, etc.       │
│ Timestamp (uint64)│ Unix nanoseconds                        │
│ SessionToken     │ HMAC-based token for authentication       │
│ Payload (oneof)  │ Task, TaskResult, Heartbeat, etc.        │
└──────────────────┴──────────────────────────────────────────┘
```

## Crypto Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X25519 | Ephemeral key pair per session |
| Encryption | XChaCha20-Poly1305 | Message confidentiality + integrity |
| Key Derivation | HKDF-SHA256 | Derive encKey, hmacKey, sessionToken |
| Session Token | HMAC-SHA256 | Message authentication |
| Password Hash | bcrypt (cost 10) | Operator password storage |
| Module HMAC | HMAC-SHA256 | Module integrity verification |

## Session States

```
                    ┌─────────┐
                    │   New   │
                    └────┬────┘
                         │
                    ┌────▼─────┐
                    │KeyExchange│
                    └────┬─────┘
                         │
                    ┌────▼─────┐
              ┌─────│  Active  │─────┐
              │     └────┬─────┘     │
              │          │           │
         ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
         │Passive │ │Disconnect│ │ Killed │
         └────────┘ └──────────┘ └────────┘
```

## Adding a New Module

1. Create module directory: `modules/<name>/`
2. Add `manifest.json`:
```json
{
  "name": "mymodule",
  "version": "1.0.0",
  "platform": "windows",
  "type": "ps1",
  "description": "My custom module",
  "commands": ["mycommand", "mycommand2"],
  "files": {"script.ps1": "<base64 content>"}
}
```
3. Register via API: `POST /api/modules`
4. Push to agent: `POST /api/modules/push`

## API Quick Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Liveness only (`{"status":"ok"}` — no telemetry) |
| GET | `/api/status` | Yes | Operational telemetry: active sessions, listeners, uptime (`sessions:list`) |
| GET | `/api/metrics` | Yes | Operational metrics in **Prometheus text format** (round 16, `sessions:list`): gauges for sessions active/total, tasks, vault count, loot count, webhook delivery ledger, listeners, uptime and Go runtime. Counts only — never credential material or session identifiers. Scrapes are per-request queries (no stale cache) |
| GET | `/api/sessions` | Yes | List sessions (includes `AgentVersion`, `Transport`, `Privilege`, `Fingerprint` observability fields). Round 16: optional `?days=1..90` window — sessions last seen before the cutoff are excluded; the shared `parseDaysWindow` answers 400 on `0`, negatives, `>90`, non-numeric or overflowing values; no parameter keeps the full listing |
| GET | `/api/sessions/:id` | Yes | Session detail |
| DELETE | `/api/sessions/:id` | Yes | Kill agent; add `?purge=true` to hard-delete the record together with its tasks and persisted loot (`sessions:kill`) |
| POST | `/api/cmd` | Yes | Execute command |
| POST | `/api/broadcast` | Yes | Broadcast command |
| GET | `/api/vault` | Yes | List credentials (`vault:read`); search with `?q=...` (round 15: the term is capped at 256 characters — longer answers 400) |
| POST | `/api/vault` | Yes | Store credential (`vault:create`). Round-14 caps (transversal pass): `username` ≤ 128, `password` ≤ 512, `domain` ≤ 128, `host` ≤ 255, `service` ≤ 64, `source` ≤ 128, `notes` ≤ 2000; at least one identifying field (username/password/domain/host/service/source) must be non-empty; non-GET/POST methods answer 405. Round 15: persistence errors now surface as 500 — the old flow logged the failure and still answered `{id, status:"stored"}` for a row that was never saved; IDs are crypto/rand `cred-<hex>` (were predictable `cred-<UnixNano>`) |
| DELETE | `/api/vault?id=...` | Admin | Delete a single credential (`vault:delete` — the permission existed in rbac.go since day one, round 15 wires the endpoint). 404 on unknown ids; the console Vault view exposes it with a confirm dialog |
| GET | `/api/files` | Yes | List files (current run + persisted `file_records` rows from previous runs). Round 16: optional `?days=1..90` window on `created`; same strict parser and default as sessions |
| POST | `/api/files` | Yes | Upload file |
| DELETE | `/api/files` | Yes | Purge ALL loot — blobs on disk, current listing and persisted rows (`files:delete`, same capability as the single-file route) |
| GET | `/api/modules` | Yes | List modules |
| POST | `/api/modules` | Yes | Register module |
| POST | `/api/modules/push` | Yes | Push to agent |
| GET/POST/DELETE | `/api/socks` | Yes | SOCKS proxy |
| GET/POST/DELETE | `/api/portfwd` | Yes | Port forwarding |
| GET/POST/DELETE | `/api/operators` | Admin | Operator management |
| POST | `/api/login` | No | Authenticate, returns access + refresh JWT |
| POST | `/api/refresh` | No | Rotate: consumes the presented refresh token and returns a new access token **plus a new refresh token** (store both; replaying a consumed refresh returns 401) |
| GET/DELETE | `/api/modules/:name` | Yes | Delete module (`modules:delete`) |
| GET | `/api/files/download/:id` | Yes | Download exfiltrated file |
| DELETE | `/api/files/:id` | Yes | Purge a single loot artifact — blob on disk, current listing and persisted record (`files:delete`, admin only) |
| GET/POST | `/api/notes` | Yes | Session notes — GET requires `collab:read` (all roles), POST `collab:write` (admin/operator). POST caps: `session_id` ≤ 128 chars, `content` ≤ 10000 chars (notes live in SQLite forever) |
| POST | `/api/lock` | Yes | Lock/unlock session (`collab:write`) |
| GET/POST | `/api/profiles` | Yes | Agent config profiles — GET `collab:read` (all roles), POST `collab:write` (admin/operator). POST validates: `name` 1–64 chars (trimmed), `beacon_interval` 1–3600 s (0 → default 5), `jitter` 0–0.95 (0 → default 0.3), `transport` in the allowlist `dns/http/tcp/tls/webrtc/ws` (empty → `tls`) |
| DELETE | `/api/profiles/:id` | Yes | Delete an agent profile (`collab:write`); 404 on unknown ids, 400 on control characters in the id |
| GET | `/api/report` | Yes | Generate engagement report (`report:generate`). `format` = `text` (default) / `csv` / `json` — anything else answers 400. `days` = 1..90 (default 1, round 15) sets the report window and **filters** the content: sessions with `last_seen` before the cutoff and credentials captured before it are excluded, and `Summary.TotalSessions/TotalCredentials` count the filtered rows (they used to be seeded pre-filter). Default response is the JSON envelope `{path, status}`; add `&download=1` to receive the report CONTENT as an attachment (`Content-Disposition`, correct `Content-Type` per format) — the console's Download report button uses this mode |
| GET/POST/DELETE | `/api/webhooks` | Admin | SIEM webhook destinations (persisted in `webhooks`, migration 9; re-hydrated on start; DELETE takes `?id=...` from the POST response). POST validation (round 13): absolute http(s) URL ≤ 2048 chars, ≤ 16 headers (keys ≤ 128 non-empty, values ≤ 1024), `timeout_ms` 100–60000 (0 → default 5000 — the old 0 meant an unlimited client timeout), `events` entries validated against the event-type allowlist (empty list = forward everything). GET answers `id/url/headers/timeout_ms/events/stats` with the timeout in milliseconds and a per-destination **delivery ledger** (round 15): `delivered`/`failed` counters, `last_delivery` (RFC3339) and `last_status` (`"ok"` or `"error: ..."` capped at 200 chars). Removing a webhook drops its ledger; deliveries in flight for a removed ID are not recorded |
| POST | `/api/mtls/cert` | Admin | Issue mTLS client certificate. `agent_id` (optional — auto-generated when empty) becomes the X.509 CommonName and is validated: 1–64 characters of `[A-Za-z0-9._-]`, else 400; validation runs before the mTLS-enabled gate |
| GET/POST/DELETE | `/api/operators/:id` | Admin | Delete operator — resolves the account by numeric id, revokes its JWTs by username, 404 on unknown ids |

## Roles and permissions matrix

| Capability | Permission | admin | operator | viewer | auditor |
|---|---|:-:|:-:|:-:|:-:|
| List sessions | `sessions:list` | ✅ | ✅ | ✅ | ✅ |
| View session detail | `sessions:view` | ✅ | ✅ | ✅ | ✅ |
| Kill / purge session | `sessions:kill` | ✅ | ❌ | ❌ | ❌ |
| Execute commands | `commands:execute` | ✅ | ✅ | ❌ | ❌ |
| Broadcast commands | `commands:broadcast` | ✅ | ✅ | ❌ | ❌ |
| List modules | `modules:list` | ✅ | ✅ | ✅ | ✅ |
| Push modules | `modules:push` | ✅ | ✅ | ❌ | ❌ |
| Delete modules | `modules:delete` | ✅ | ❌ | ❌ | ❌ |
| Read vault (credentials) | `vault:read` | ✅ | ✅ | ✅ | ✅ |
| Create vault entries | `vault:create` | ✅ | ✅ | ❌ | ❌ |
| Delete vault entries | `vault:delete` | ✅ | ❌ | ❌ | ❌ |
| Download loot | `files:download` | ✅ | ✅ | ✅ | ✅ |
| Upload loot | `files:upload` | ✅ | ✅ | ❌ | ❌ |
| Purge loot (single or all) | `files:delete` | ✅ | ❌ | ❌ | ❌ |
| SOCKS / port forwarding | `socks:start`, `portfwd:start` | ✅ | ✅ | ❌ | ❌ |
| Read notes & profiles | `collab:read` | ✅ | ✅ | ✅ | ✅ |
| Write notes, lock, profiles | `collab:write` | ✅ | ✅ | ❌ | ❌ |
| Generate reports | `report:generate` | ✅ | ✅ | ❌ | ❌ |
| Read audit log | `audit:read` | ✅ | ❌ | ❌ | ✅ |
| Manage operators / webhooks / mTLS | admin-only routes | ✅ | ❌ | ❌ | ❌ |

Notes: GET routes on `/api/files` and `/api/modules` use the read permission of
their family; DELETE `/api/files` reuses `files:delete` (same capability as the
per-id route). `collab:read` was added in round 9 — previously the read-only
roles could not view operator notes. Custom roles can be defined in config and
are validated against the same permission strings.

## mTLS end-to-end flow

1. **Enable mTLS on the server** (`config.yaml`):
   ```yaml
   tls:
     enabled: true
     auto_cert: true   # server generates its own CA if none is present
     mtls: true        # agents must present a client certificate issued by that CA
   ```
   With `auto_cert: true` the server creates and persists a CA (in the
   encrypted `server_secrets` store) on first start; the CA is reused across
   restarts, so previously issued agent certificates keep working.

2. **Issue an agent certificate** (admin token required):
   ```bash
   curl -X POST https://<c2>:9090/api/mtls/cert \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"agent_id": "lab-agent-01"}'
   ```
   The response contains `ca_pem`, `cert_pem` and `key_pem` (PEM blocks).
   `agent_id` is optional — the server generates one when omitted. Save the
   three blocks to files; the key is shown **only once**.

3. **Start the agent with its client certificate**:
   ```bash
   worldc2-agent -server <c2-host>:8443 \
                 -tls-cert lab-agent-01.crt -tls-key lab-agent-01.key
   ```

4. **What the server enforces**: with `tls.mtls: true` a TLS handshake
   without a certificate issued by the server's CA fails before any C2
   protocol bytes are exchanged. When the connection is admitted, the
   SHA-256 fingerprint of the client certificate is persisted in the
   session's `fingerprint` column (round 4) and shown by the console's
   session detail panel.

## Development

### Build
```bash
make build          # Server + Agent
make build-agent-all # All agent platforms
make test           # Go tests
make docker         # Docker environment
```

### Run Tests
```bash
python3 tests/run_tests.py        # Functional
python3 tests/stress_test.py      # Stress
python3 tests/integration_test.py # Integration
python3 tests/benchmark.py        # Performance
```

### Browser E2E (console)
`tests/e2e/` hosts a Playwright suite (round 16) that drives the real console
end to end: login, dashboard render, sessions filters (including the `?days=`
select), vault create → debounced search → CSV export → two-step delete
(`ConfirmModal`: Esc cancels, purge-style variants require typing a phrase)
and logout.

```bash
cd tests/e2e && npm install && npx playwright install chromium   # once
make test-e2e                        # against a running server on :19090
E2E_BASE_URL=https://c2.lab:8443 E2E_USER=alice E2E_PASS='...' make test-e2e
```

Design notes: a `setup` project logs in once and stores the JWT
(`.auth/operator.json`, gitignored) via `storageState` — the console keeps its
token in localStorage, so plain cookie state would not authenticate the tests;
every spec still runs in an isolated context. The first test clears storage and
performs a real login so the authentication flow itself stays covered. Run it
against a throwaway server only: the suite creates and deletes real credentials.

### Security Audit
```bash
python3 scripts/harden.py --apply
```
