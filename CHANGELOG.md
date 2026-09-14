# WorldC2 — Changelog

## v1.11.0 — Round 10: refresh token rotation with replay denial (2026-09-14)

Tenth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Changed (Bugs/Seguridad)

- **Refresh tokens now rotate on every use** — `POST /api/refresh` consumes the
  presented refresh token (identified by a new `jti` claim) and returns a **new
  refresh token** alongside the new access token. Replaying an already-consumed
  refresh token returns 401: a stolen token loses its value as soon as the
  legitimate client refreshes once. Legacy jti-less refresh tokens rotate once and
  converge to rotatable tokens as sessions refresh. Deliberate design note: family-wide
  revocation on reuse was NOT implemented — the console shares `localStorage` across
  tabs and a stale second tab would lock its operator out; per-device binding is the
  proper follow-up. The console (`web/src/utils/api.js`) persists the replacement on
  every refresh.

## v1.10.0 — Round 9: collaborative reads for read-only roles, loot filtering, session→loot deep-link (2026-09-14)

Ninth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Fixed (Bugs/Seguridad)

- **Read-only roles can now read session notes and config profiles** — `GET /api/notes`
  and `GET /api/profiles` were gated by `collab:write`, a permission only admin and
  operator hold: the `viewer` and `auditor` roles (whose stated purpose is read-only
  review) could read captured credentials (`vault:read`) but not the operator notes an
  auditor exists to review. A new `collab:read` permission (held by all four roles)
  now guards the reads; writes stay behind `collab:write`. RBAC contract pinned by
  tests (`TestCollabReadIsUniversal`, `TestCollabWriteStaysPrivileged`).

### Added (Implementaciones)

- **Loot filtering in the Files view** — search box plus session and module selects
  (options derived from the listing), a matched/total badge, and a dedicated empty
  state when filters exclude everything. Select-all now scopes to the filtered rows.
- **Session → loot deep-link** — each session row gains a "view loot" action that
  navigates to `/files?session=<id>` with the session filter pre-applied (Files reads
  the query param on mount and on subsequent navigations), completing the
  observability→action path across views.

### Documentation (Pulimiento)

- DEVELOPER_GUIDE: notes/profiles rows now document the read/write split; OpenAPI
  notes GET annotated with its real permission.

## v1.9.0 — Round 8: operator revocation hardened, version deep-links, selective loot purge (2026-09-14)

Eighth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Fixed (Bugs/Seguridad)

- **Deleted operators now lose API access immediately — and permanently** — three
  stacked defects made operator deletion toothless: (1) the in-memory JWT revocation
  was keyed by the raw URL segment (a numeric id) while tokens carry the username, so
  `RevokeUser` silently revoked nothing; (2) the revocation map loses its entries on
  restart while the persisted signing key does not, resurrecting the deleted
  operator's tokens; (3) deleting an unknown id returned a false success. Fixed by
  resolving the account before deletion (404 on unknown ids, 400 on malformed ones),
  revoking by username, and adding an operators-table existence check to the auth
  middleware — a deleted username is rejected on every request, restart or not.
- **`RevokeUser` keying fixed at the handler** — `DELETE /api/operators/:id` now
  resolves the operator first (new `GetOperatorByID`) and revokes the JWT subject it
  actually carried. Response includes the removed username; audit log records both.

### Added (Implementaciones)

- **Agent-version filter in Sessions** — a third select (values derived from the live
  sessions) completes the filter row; the text filter still matches versions too.
- **Fleet version chips are now deep-links** — clicking an agent-version chip in the
  dashboard navigates to `/sessions?version=x` with the filter pre-applied
  (`?transport=` keeps working; both query params are watched by Sessions). This
  closes the fleet deep-link loop opened in round 7.
- **Selective loot purge** — the Files view gains per-row checkboxes (with select-all
  in the header) and a "Purge selected (N)" action that purges the chosen artifacts
  one by one, reporting partial failures honestly instead of all-or-nothing.

### Documentation (Pulimiento)

- **mTLS end-to-end flow in DEVELOPER_GUIDE** — CA generation/persistence, client
  certificate issuance via `/api/mtls/cert`, agent startup with `-tls-cert/-tls-key`,
  and what the server enforces (dragged since round 2).
- OpenAPI: `/api/operators/{id}` delete documented with its real semantics (400/404,
  username in the response, revocation notes).

## v1.8.0 — Round 7: bulk loot purge, fleet deep-links, configurable CORS, proxy-aware audit logs (2026-09-14)

Seventh maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **Bulk loot purge** — `DELETE /api/files` wipes every exfiltrated artifact everywhere
  it lives: blobs on disk, the current-run listing and the persisted `file_records` rows
  of previous runs. `FileManager.PurgeAll` reuses the per-record `Delete` path, so the
  containment guards (tampered/foreign paths only drop records, never the referenced
  file) and the strict DB semantics carry over. The console Files view gains a "Purge
  all" button (design-system `.btn-danger`, confirm-guarded, reports the purged count).
  Gated by `files:delete` — the same capability the single-file route enforces, via the
  new method-aware `filesPerm` middleware on `/api/files` (GET→files:download,
  POST→files:upload, DELETE→files:delete).
- **Fleet chips deep-link into Sessions** — clicking a transport chip in the dashboard
  "Implant fleet" panel navigates to `/sessions?transport=<name>`, with the Sessions
  view applying the filter from the query param on mount and on subsequent navigations
  (`watch` on `$route.query.transport`). Version chips stay informational.

### Changed (Bugs/Seguridad)

- **CORS allowlist is now configuration, not code** — the hardcoded dev origins
  (`localhost:9090/5173`, `127.0.0.1:9090`) are gone from the binary; the allowlist
  comes from `api.allowed_origins` in `config.yaml`. Empty (the default) means no
  cross-origin browser access at all — the bundled console is same-origin and needs
  none. Wildcard entries are rejected at startup (fail-fast panic, mirroring the
  trusted-proxies behavior); matched responses now also carry `Vary: Origin`.
  Documented in `config.example.yaml`.
- **Audit logs are trusted-proxy aware** — `auth_failed`, `auth_success` (SIEM
  `operator_login.remote`) and the per-request `api_call` entries used the raw
  `RemoteAddr`; behind a reverse proxy every failed attempt was blamed on the proxy IP.
  All three now go through `RateLimiter.ResolveClientIP`, the exact resolution the rate
  limiter uses for its buckets, so audit trail and rate limiting can never disagree
  about who the client is.

## v1.7.0 — Round 6: public health hardened, authenticated status endpoint, implant fleet view (2026-09-15)

Sixth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **Implant fleet panel in the dashboard** — a new panel breaks the current sessions
  down by transport and by agent version (chips with counts, most common version first).
  Agent-version chips that are not the most common one are visually flagged as behind
  (`is-outdated`), so outdated implants stand out at a glance. The panel renders only
  when there is data and reuses the existing design system.
- **Transport filter in the Sessions view** — a dedicated select next to the state
  filter (values derived from the live sessions), completing the observability loop of
  rounds 4–5: transport and version are now queryable, not just visible.

### Changed (Bugs/Seguridad)

- **`/api/health` is now liveness-only** — the public payload shrinks to
  `{"status":"ok"}`: no active session counts, listener details or uptime leak to
  unauthenticated callers anymore (the Docker healthcheck only needs the HTTP 200, the
  console badge only needs liveness). The full telemetry moved to a new authenticated
  `GET /api/status` gated by `sessions:list`. `scripts/console.py` and
  `scripts/monitor.py` were updated in the same round to consume `/api/status` with
  their existing Bearer tokens.
- **`?purge=true` on an unknown session id now returns 404** instead of silently
  succeeding: `PurgeSession` checks `GetSession` before the hard delete so a typo'd id
  cannot look like a successful purge. Deleting a known-but-inactive session still
  works; covered by a contract test pinning the db-layer behavior (`DeleteSession`
  stays a no-op on unknown ids, `GetSession` signals `sql.ErrNoRows`).

### Documentation

- DEVELOPER_GUIDE documents `GET /api/status` and the reduced public payload;
  OpenAPI spec adds `/api/status` and aligns the `/api/health` response schema;
  CHANGELOG entry v1.7.0 (this one).

## v1.6.0 — Round 5: individual loot purge, session metadata in console, enforced FK cleanup (2026-09-15)

Fifth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **Individual loot purge** — `DELETE /api/files/{id}` (permission `files:delete`,
  admin-only) removes one exfiltrated artifact everywhere it lives: the blob in the loot
  directory, the current-run listing and the persisted `file_records` row. New
  `FileManager.Delete` (with a containment guard: a tampered stored path that escapes the
  loot base dir gets its records dropped but the foreign file is never touched) and
  `db.DeleteFileRecord` (distinguishes unknown ids via `sql.ErrNoRows`). The console Files
  view gains a trash action with a confirmation dialog. Covered by tests for the full
  purge path, the unknown-id contract and the foreign-path containment guard; the
  `files:delete` permission existed in RBAC since round 1 and was previously unused.
- **Session purge** — `DELETE /api/sessions/{id}?purge=true` hard-deletes the session
  record together with its tasks and persisted loot in one transaction (`PurgeSession`;
  the default kill keeps the row as historical record with state `killed`, unchanged).
  The console Sessions view gains a second destructive action next to Kill with its own
  confirmation text. This also gives `db.DeleteSession` its first production caller.
- **Session observability fields surface in the console** — the Sessions view now shows
  a Transport column (`transport · v<version>`) and the detail panel includes Transport /
  Agent version, Privilege and the TLS fingerprint (rendered as "no mTLS pin" for plain
  transports). The search filter also matches transport and agent version. The data has
  traveled through `GET /api/sessions` since round 4; this round makes it visible.

### Fixed (Bugs/Seguridad)

- **`DeleteSession` now clears `file_records` in the same transaction** — the round-4
  report claimed this fix, but it never landed in the code: with loot persistence live
  (round 4) and `PRAGMA foreign_keys=ON`, deleting any session that owned persisted loot
  failed the whole transaction with `FOREIGN KEY constraint failed` (reproduced
  empirically with a regression test before the fix). Verified end-to-end in the round
  smoke: `?purge=true` on a live session with persisted loot returns 200 and leaves zero
  rows in `sessions`, `tasks` and `file_records`. A dedicated audit pass also verified
  this time that each report claim matches the actual code (round-4 lesson).

### Documentation

- README loot row updated (individual purge + console action); DEVELOPER_GUIDE documents
  `DELETE /api/files/:id` and the `?purge=true` variant of session kill; OpenAPI spec
  adds the new file endpoint and the purge query parameter with their permission and
  error codes; CHANGELOG entry v1.6.0 (this one).

## v1.5.0 — Round 4: session observability, persistent loot listing, legacy ciphertext convergence (2026-09-15)

Fourth maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **Session records now carry observability fields** — `sessions.agent_version`,
  `transport`, `fingerprint` and `privilege` (columns existed since migration 2 but were
  never written). `UpsertSession` persists them; the admission path fills `AgentVersion`
  from the agent's `SessionInit`, `Transport` from the listener that admitted the
  connection, `Privilege` from the admin flag (`user`/`admin`) and `Fingerprint` with the
  SHA-256 of the mTLS client certificate when the transport presents one (plain transports
  stay empty; a later plain re-upsert does not clobber an existing fingerprint). All four
  surface through `GET /api/sessions` and session detail.
- **Loot listing is now persistent** — the `file_records` table (migration 5, previously
  unused) receives one row per `Store`/`Finalize` operation; `GET /api/files` merges the
  current run's in-memory records with the persisted rows from previous runs
  (deduplicated by id), `Get`/`Read` fall back to the persisted record so downloads keep
  working after a server restart. `DeleteSession` cleans the session's `file_records`
  rows (enforced FK) alongside its tasks. Covered by unit tests (persistence across
  manager instances, cross-restart `Read`, nil-safety without a DB) and verified live in
  the round's smoke (exfil → restart → download returns the original bytes).

### Changed

- **Legacy at-rest ciphertext converges to the v2 format** (`Bugs/Seguridad`): on startup
  with `WORLDC2_MASTER_KEY` configured, columns encrypted with the pre-v2 bare-sha256 key
  (`server_secrets.value`, `credentials.password`, `credentials.notes`) are decrypted with
  the legacy key and re-encrypted with the PBKDF2-stretched one (`[DB] re-encrypted N
  legacy column value(s) to v2 format`). Rows that do not decrypt (plaintext values from
  databases that never used a master key) are skipped in place. This closes the mixed-
  format window opened by the round-3 KDF upgrade; encrypted databases now converge to a
  single ciphertext generation instead of staying mixed forever. Covered by a test that
  seeds a legacy database, reopens it with the master key and asserts the on-disk values
  are `v2.`, values survive, and a second open is idempotent.
- **Removed dead code** (`Pulimiento`): none this round — the remaining `migrations.go`
  helpers (`Rollback`, `GetMigrationVersion`, `splitSQL`/`splitLines`/`trimSpace`) are
  used internally by `Migrate`/`Rollback` and were kept as the maintenance surface.

### Documentation

- README loot row and Known-gaps block updated (loot persistence + legacy convergence);
  DEVELOPER_GUIDE documents the merged file listing and the new session observability
  fields; CHANGELOG entry v1.5.0 (this one).

## v1.4.0 — Round 3: hardened at-rest crypto, tunnel lifecycle, persistent webhooks, agent port flags (2026-09-15)

Third maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **Agent transport ports are configurable without recompiling** — new CLI flags
  `-http-port` / `-ws-port` / `-webrtc-port` / `-dns-port` (defaults 8445/8446/8447/8444,
  matching `config.example.yaml`). Values are validated (`normalizePort`: digits only,
  1-65535); empty values keep the defaults and invalid values are logged and fall back,
  so a typo can never silently break a transport. Covered by unit tests for the
  validator and the setter semantics, and verified end-to-end in the round's live
  smoke (agent connected through the HTTP long-poll fallback on a non-default port
  and executed a command with its result round-tripping).

### Changed

- **SIEM webhooks now persist across restarts** — `POST /api/webhooks` stores the
  destination in the new `webhooks` table (migration 9) before activating it in the
  forwarder, minting a random `wh-…` id (crypto/rand); the server re-hydrates all
  persisted destinations into the SIEM forwarder on startup (`[SIEM] hydrated N
  webhook(s)`). New `DELETE /api/webhooks?id=...` (admin) removes a destination from
  both the forwarder and the database, answering 404 for unknown ids; POST now
  answers 201 with `{"status":"added","id":...}` and additionally accepts optional
  `headers` and `timeout_ms`. OpenAPI spec updated accordingly.
- **Removed dead code** (`Pulimiento`): the unused agent-side `AgentProxy` (~80 lines,
  `internal/socks`) and the unused HMAC pair `GenerateSessionToken`/`VerifySessionToken`
  (`internal/crypto/keyx.go`, only ever referenced by their own tests) were pruned.
  `Session.OnClose` was kept: this round wires it as the integration point for tunnel
  teardown (below).

### Fixed (Bugs/Seguridad)

- **At-rest encryption key is now stretched (PBKDF2-HMAC-SHA256, 600 000 iterations,
  per-database salt)** — previously the AES-256-GCM column key was a bare
  `sha256(masterKey)`, letting a weak operator key be brute-forced at GPU speed.
  The salt is generated once and persisted in the new `_kdf_meta` table (migration 10),
  so the derived key is stable across restarts. New ciphertext carries a `v2.` version
  prefix; legacy (un-stretched) values remain readable, so existing encrypted databases
  keep working transparently. Covered by new tests: v2 roundtrip + prefix, legacy
  compat through the v2 encryptor, wrong-key and wrong-salt rejection, salt stability
  across reopens, and an end-to-end open→write→read-raw test proving on-disk values
  are `v2.`.
- **Abandoned tunnels no longer leak** — tunnels were only removed on an explicit
  close or a wire error; one whose session died otherwise stayed in the map forever.
  `TunnelManager` now tracks last activity per tunnel (either direction), watches each
  admitted session via `Session.OnClose` (a session close tears down its tunnels
  locally immediately) and runs a reaper (30 s sweep, 15 min idle timeout) for tunnels
  whose session went stale without closing. Covered by new race-tested unit tests.

### Documentation

- README feature table gained the SIEM webhooks row and the Known-gaps block was
  rewritten for the round; QUICK_REFERENCE ports section documents the new agent
  flags; DEVELOPER_GUIDE documents the flag semantics and the webhook API surface;
  CHANGELOG entry v1.4.0 (this one).

## v1.3.0 — Agent round 2: HTTP long-poll transport repaired end-to-end (2026-09-15)

Second maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Added (Implementaciones)

- **HTTP long-poll transport is now fully functional** (`transport/http.go`, port 8445).
  Round 1 found it unreachable end-to-end: the agent fallback dialled raw TCP, the
  server→agent path (`GetPendingWrite`) had zero call sites, and `httpConn.Read` held a
  mutex its own `Write` needed (deadlock) while discarding framing surplus. The transport
  was rewritten around two explicit endpoints — `POST /register` (agent→server frames,
  immediate ack, session assignment via `X-Session-ID`) and `POST /poll` (long-poll,
  server→agent frames, up to 25 s) — with per-direction FIFO queues (frame order
  preserved), partial-read buffering on both halves (no data loss at any buffer
  boundary), deadlines honoured per the `net.Conn` contract (expired deadlines fail
  fast; a zero `time.Time` really clears them), a 10-minute idle reap replacing the
  missing kernel keepalive, and `net.Listen` moved into `Start()` so bind errors surface
  synchronously and `Addr()` reports the real bound address. The dead request/response
  `HTTPAgent` was replaced by the live `DialHTTP` client, and the agent's HTTP fallback
  now speaks the protocol (trying HTTPS first, then plaintext, mirroring WebRTC).
  Covered by 7 loopback tests: framing roundtrip with the real admission peek,
  3 MiB frame both directions, concurrent read/write (deadlock regression), server and
  client deadline semantics, session close propagation and wire guards.
- **Trusted reverse-proxy support for rate limiting** — new `server.trusted_proxies`
  config key (IPs/CIDRs). When the API socket peer is a trusted proxy, the rate-limit
  key is resolved from `X-Forwarded-For` (rightmost non-trusted hop; leftmost when all
  hops are trusted; malformed entries skipped). Without trusted proxies (default) the
  header is ignored, so a spoofed `X-Forwarded-For` can never rotate the bucket.
  Invalid CIDRs fail at startup instead of silently trusting a spoofable header.

### Fixed (Bugs/Seguridad)

- **Operator roles are validated at creation** (`auth.IsValidRole`): the API rejects
  unknown roles with 400, config seeding skips them with a clear log line, and token
  refresh fails with a 403 naming the real cause. Previously a missing/typo'd role
  (e.g. an operator entry without `role:`) produced an operator that logged in but
  failed every RBAC check with a misleading `authentication required`.
- **Session detail no longer reports `TaskCount: 0`** — `GetSession` omitted the
  `task_count` subquery that `ListSessions` had, so `/api/sessions/{id}` contradicted
  its own task list.
- **Registration guard on the HTTP transport:** a registration request carrying a
  non-empty body is rejected (400) instead of silently dropping the bytes, and
  `/poll` answers 410 once a session is closed so agents reconnect promptly.

### Removed (Pulimiento)

- **Dead offline task-queue layer pruned** (`QueuedTask`, `QueueTask`, `GetPendingTasks`,
  `MarkTaskDelivered`, `CompleteTask`, `ListQueuedTasks`, `DeleteQueuedTask`,
  `scanQueuedTasks` — ~100 lines, zero callers). Migration 7 stays in the ledger so
  existing databases keep their applied-history integrity; the dormant `task_queue`
  table is simply left alone.

### Documentation (Pulimiento)

- README feature table and known-gaps block updated: the HTTP long-poll transport is
  documented as working (round-1 "experimental" claim retired), with the transport
  fallback chain spelled out.
- QUICK_REFERENCE port table: 8445 no longer marked experimental.
- DEVELOPER_GUIDE: transport fallback chain documented, HTTP long-poll wire semantics
  (`/register`, `/poll`, ordering, idle reap) added to Protocol Flow.
- `config.example.yaml` documents `server.trusted_proxies`.

## v1.2.1 — Agent round 1: audit fixes, security hardening, honest docs (2026-09-14)

First maintenance round executed by the four-agent flow (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Reports live in `docs/agentes/`.

### Fixed (Bugs/Seguridad)

- **Console commands are now persisted and audited.** `CreateTaskWithContext` (used by
  `/api/cmd` and `/api/broadcast`) never called `InsertTask`/`LogAction`, so dashboard
  commands were invisible in the tasks table and audit log. Both are now recorded, and the
  trailing `UpdateTaskResult` actually has a row to update.
- **Data races and busy-spins in accept loops.** `PortForward.running` and SOCKS
  `Server.running` are now `atomic.Bool` (read by accept-loop, written by Stop) and both
  loops back off 100 ms on transient accept errors instead of spinning at 100% CPU.
- **Shutdown WaitGroup race.** Listener accept-loops now run on their own `acceptWG`;
  `Stop()` waits for it before `wg.Wait()`, closing the window where a late `wg.Add(1)`
  for a just-accepted connection could panic with `WaitGroup misuse`.
- **`max_sessions` TOCTOU and orphaned rows.** The session cap is enforced *before* the
  DB row is written, count+store are serialized under an admission mutex, and rejected
  sessions are closed. Rejected connections no longer leave phantom `active` sessions.
- **Nine handlers decoded JSON without checking the error** (socks, vault, files, portfwd,
  notes, lock, profiles, webhooks, mtls) — a truncated body used to create empty records
  with HTTP 200. All now return 400.
- **`Content-Disposition` injection hardening:** download filenames are now escaped with
  `mime.FormatMediaType` instead of raw string interpolation.
- **Webhook URLs validated:** only absolute `http(s)` URLs are accepted (SSRF guard);
  `GET /api/webhooks` now returns the real list (as the OpenAPI spec always claimed).
- **Decryption fallback is no longer silent:** if an at-rest-encrypted secret fails AES-GCM
  decryption, the server logs a warning before returning the raw (legacy) value.
- **Engagement reports** attribute to the authenticated operator (was hardcoded `admin`)
  and surface DB errors instead of ignoring them.

### Added (Implementaciones)

- **`-no-persist` agent flag** — disables first-run auto-persistence (cron/bashrc, registry/
  schtasks, LaunchAgent). Recommended for authorized labs, CI and demos; the auto-persistence
  behavior itself is now documented in the README (honesty policy).
- **JWT revocation per operator** — deleting an operator revokes every token issued up to
  that moment (`TokenManager.RevokeUser`, minimum-`iat` registry), closing a 12-hour
  exposure window since the signing key persists across restarts.
- **Dedicated login rate limit** — `/api/login` gets its own 10 req/min bucket on top of the
  global 60 req/min API limiter, blunting password brute-force.
- **`auth` package test suite** — 9 tests covering roundtrip, expiry, refresh/access
  separation, algorithm pinning, signature tampering, revocation semantics and concurrency.

### Changed (Pulimiento)

- Removed 12 `var _ =` import-forcing markers (plus orphaned imports) and a `min()` that
  shadowed the Go 1.21+ builtin.
- Fixed incomplete ANSI color codes in all 10 test scripts (regression of v1.1.2).
- README honesty pass: HTTP long-poll listener marked experimental (not agent-reachable),
  agent auto-persistence documented, `-no-persist` shown in Agents/Security sections.
- QUICK_REFERENCE: added port 8447 (WebRTC), corrected 8445 note, agent flag example.
- DEVELOPER_GUIDE: API table completed with 10 previously missing endpoints; DNS listener
  labeled opt-in.
- `openapi.yaml`: `auditor` role added to the role enum.
- `.gitignore`: added `reports/` and `dist/`.
- Verification: `go build`, `go vet` clean; `go test -race ./...` all green; live smoke test
  of login, revocation, JSON validation, webhooks and rate limiting.

## v1.2.0 — Roadmap completion: WebRTC transport, resumable exfil, DNS in the agent chain (2026-09-11)

All three features the feature matrix marked as *Planned/Experimental* are now real, wired
end-to-end and covered by tests (`go test ./... -race` green, including loopback integration
tests for the new transports).

### Added

- **WebRTC transport (Pion)** — `internal/transport/webrtc.go`:
  - Server: `WebRTCListener` with an HTTP(S) signaling endpoint (`POST /webrtc/offer`,
    non-trickle ICE, mDNS candidates disabled), data channels detached and adapted to
    `net.Conn` so the existing C2 session/envelope protocol runs unchanged.
  - Agent: `transport.DialWebRTC` performs the client half of signaling and joins the
    transport fallback chain (TLS → TCP → HTTP → WebSocket → **WebRTC** → DNS), port 8447.
  - Config: `transport.webrtc_port` (0 disables); TLS signaling reuses the server cert.
  - Test: in-process loopback roundtrip (signaling + ICE + data channel + adapter).
- **Resumable chunked file exfiltration** — `internal/c2/exfil.go`, `internal/agent/exfil.go`:
  - New agent commands: `exfil:<path>` (file or directory, auto-zip) and
    `exfil_find:<root>|<pattern>`.
  - Deterministic transfer IDs (`sha256(hostname|path|size|mtime)[:16]`) so retries map to
    the same partial upload; server assembles chunks into `<loot>/.parts/<id>.part`,
    verifying a SHA-256 digest on completion.
  - Resume: gaps trigger an `__exfil_resume <id> <offset>` task back to the agent, which
    seeks and continues. Partial data survives agent reconnects **and** server restarts.
  - Files finalize into the normal loot listing (`FileManager.Finalize`).
- **DNS transport integrated in the agent fallback chain** (opt-in): new
  `-dns-domain` flag; server keeps `transport.dns_port` + `dns_domains`.

### Fixed

- **DNS protocol bugs** (the tunnel previously corrupted or dropped data):
  - Client sent unpadded URL-base64 labels; server decoded with padded StdEncoding — labels
    whose length was not a multiple of 4 silently failed. Both sides now use `RawURLEncoding`.
  - Server decoded the session-id label as payload (garbage prefix on every message); the
    session label is now skipped.
  - Client truncated payloads at 50 chars (data loss for anything bigger); payloads now split
    across labels with write-side chunking that respects the 253-byte DNS name limit.
  - Client TXT parser ignored per-string length bytes (corruption on >255-byte responses);
    parser now walks every character-string.
  - `buildDNSResponse` allocated `len(query)+256` bytes and wrote beyond it for larger
    payloads (server panic); buffer is now sized from the payload.
  - Per-packet goroutines could reorder tunnel bytes; queries are now handled FIFO.
  - Agent reads poll with bounded retries instead of failing the session on the first
    empty response.


## v1.1.2 — Polish pass (2026-09-11)

Third review round: static-analysis cleanliness and spec-vs-handler alignment.

### Fixed

- **`go vet` is now 100% clean**: the five `unsafe.Pointer` misuse warnings in the evasion
  package are gone — XOR loops operate through a single `unsafe.Slice` view, `MarkSensitive`
  takes a caller-provided pointer instead of a raw `uintptr` round-trip, and the dead
  `SpoofCallStack` stub (whose comment promised an `asm_amd64.s` that never existed) was removed.
- **CI XSS-sink check false positive**: the gate greps for `v-html|innerHTML` in `web/src` — a
  code *comment* mentioning innerHTML tripped it on every push. Comment reworded; real sinks
  remain zero.
- **CI secrets-scan false positive**: the credential pattern matched `argparse help="Password"`
  strings. `add_argument` joined the exclusion list — genuine assignments still fail the build.
- **`api/openapi.yaml` aligned with the actual handlers**: `/api/mtls/cert` is POST (issue
  certificate, JSON `cert_pem/key_pem/ca_pem`) not GET; `/api/notes` POST requires `content`
  (not `note`) and GET requires the `session_id` query parameter; `TaskResult` fields are
  `snake_case` as the protobuf tags really emit; `/api/report` documents its JSON
  `{path, status}` response.
- **Broken ANSI colors in `tests/run_all.sh` + `docker_test.sh`**: color vars were defined as
  `"\033"` (no SGR code) — banners and status markers printed as garbage. Full codes now.

### Removed

- `scripts/healthcheck.sh` (orphaned — the Dockerfile inlines its own HEALTHCHECK).
- Dead volume `./data:/app/data` in `docker-compose.yml` (nothing writes there; DB is a file in
  `/app`, loot and modules have their own mounts).

## v1.1.1 — QA pass (2026-09-11)

Second review round: everything the first pass missed or broke.

### Fixed

- **Agents could never connect (found live)**: the server unconditionally enforced
  `RequireAndVerifyClientCert` (mTLS) while the agent shipped no client certificate and no
  provisioning flow existed — under TLS 1.3 the dial succeeded and the first write died with
  `broken pipe`. mTLS is now opt-in (`tls.mtls: true`), the CA is persisted in the secrets store
  (previously regenerated every boot, invalidating issued certs), and the agent accepts
  `-tls-cert/-tls-key` on every transport (TLS/WebSocket) for hardened deployments. Default
  mode: server TLS + agent-side certificate pinning (TOFU), as documented.
- **Files view rendered empty rows**: `Files.vue` read PascalCase fields (`f.Filename`) while the
  API returns lowercase JSON (`filename`) — every cell showed "—". Field names aligned.
- **Topbar showed `0 sess · 0 listeners` after login**: health was only fetched on the 5s
  interval, never immediately after authentication. Now refreshed on route change.
- **Example config login**: the bcrypt hash shipped in `config.example.yaml` did **not** match
  `admin` — the documented demo login (and with it the whole API test suite) returned 401.
  Replaced with a verified hash of `admin`, clearly marked FOR TESTING ONLY.
- **Test tooling looked for binaries in the wrong place**: `e2e_test.py`, `pentest.py` and
  `quick_test.sh` referenced the deleted 21 MB `src/go/server` commit; they now use the Makefile
  output at `dist/`.
- **CI double-start**: the E2E and pentest steps started an external server *and* the test
  scripts started their own — guaranteed port conflicts. Scripts now self-manage.
- **`make` was completely broken**: recipes were indented with 8 spaces instead of TABs
  ("missing separator"). All targets now parse; `clean` paths fixed (coverage artifacts live in
  `src/go/`).

### Security / correctness

- **Module manifest HMAC is now enforced**: manifests signed through the API are re-verified at
  load and pack time (tampered or foreign-key manifests are rejected); `Verify()` no longer
  mutates shared state; the signing key is derived via HKDF from the persisted JWT secret so
  signatures survive restarts.
- **At-rest encryption is reachable**: `WORLDC2_MASTER_KEY` environment variable enables the
  AES-256-GCM encryptor for vault secrets and notes (previously dead code).
- **Logging is configurable**: `logging.level/output/file` in YAML and `WORLDC2_LOG_LEVEL` env
  are honoured (previously hardcoded INFO/stderr and a dead compose env).
- **`tls.min_version` is honoured** (`1.2`/`1.3`) for server-side TLS.
- Non-mutating module `Verify()` (race-safe against concurrent `List()`).

### Removed

- Dead code: `c2/validation.go` (superseded by `handlers/validate.go`), `db/audit_rotation.go`
  (never instantiated). Config fields that described agent behavior the server cannot control
  (`heartbeat_interval`, `reconnect_max_backoff`) and the unsupported `database.driver` option.

### Docs / packaging

- `api/openapi.yaml`: removed duplicated `BearerAuth` definitions, fixed `uptime` →
  `uptime_seconds`, fixed a corrupted `required` field, added the 12 missing routes
  (login/refresh, operators, notes, lock, profiles, report, webhooks, mTLS cert, file download,
  module delete).
- Dockerfile: CGO_ENABLED=0 (modernc.org/sqlite is pure Go), honest comment, added
  `.dockerignore` (node_modules/dist/db files no longer enter the build context).
- `docker-compose.yml`: dropped obsolete `version:` key; `WORLDC2_LOG_LEVEL` is now live.
- `scripts/healthcheck.sh` was dropped in v1.1.2 (the Dockerfile inlines an honest HEALTHCHECK);
  `tests/run_all.sh` uses `docker compose` v2.
- Developer guide / quick reference: corrected target names and bcrypt cost.

## v1.1 — Engineering overhaul (2026-09-11)

Full audit-driven pass: critical bug fixes, control-plane hardening, honest docs, rebuilt console.

### C2 server (Go)

- **Fixed deadlock** in `TunnelManager.HandleTunnelResult`: closing a tunnel after `tunnel_err`
  took `Lock()` while holding `RLock()` — permanent self-deadlock. Closes are now performed
  outside the read lock, and tunnel results are routed by exact tunnel ID instead of substring
  matching (cross-routing bug).
- **Fixed session leak**: finished/stale sessions were never removed from the sessions map —
  unbounded growth and task routing to dead sessions. Sessions are now deleted on disconnect,
  kill and stale cleanup; live sessions are preferred when resolving an agent.
- **Fixed panic on startup** when `web/dist` exists: both `handlers` and `c2.setupAPI` registered
  `/` on the same mux.
- **TLS fail-hard**: `tls.enabled` with no usable certificate now aborts startup instead of
  silently listening in plaintext. `cert_file`/`key_file` are actually loaded now.
- **JWT hardening**: refresh tokens carry `token_use=refresh` and are rejected by every API
  route; `alg` header is pinned to HS256; refresh validates the operator still exists (no more
  minted tokens with invented roles).
- **RBAC enforced everywhere**: `/api/sessions/:id` (view vs kill by HTTP method), vault, files,
  modules, notes, report, socks, portfwd now require permissions; read vs mutating methods are
  separated. Added `collab:write` / `report:generate` permissions.
- **Session write framing**: per-session write mutex + single `Write` for length-prefix + payload
  (concurrent writes previously interleaved and corrupted the stream). `LastSeen` is atomic
  (data race fixed); `Session.Close()` is unconditional and idempotent — killing an agent no
  longer leaks the socket, goroutines and pending tasks.
- **Request limits**: global body size limit (1 MiB JSON / 64 MiB uploads), API server timeouts
  (slowloris), `max_sessions` enforced, accept-loop backoff.
- **Path traversal**: `session_id` in file storage and module names/manifest filenames sanitized.
- **Module HMAC actually verifies now** (sign & verify over the same canonical serialization;
  previously indented-vs-compact JSON mismatch made `Verify` always false). In v1.1.1 verification
  is enforced: manifests signed via the API are re-checked at load and pack time, and the signing
  key is derived (HKDF) from the persisted JWT secret so signatures survive restarts.
- **SQLite migrations run inside transactions**; `splitSQL` splits statements properly
  (quotes/comments aware) instead of concatenating everything into one statement.
- **Bootstrap admin**: no more silent `admin/admin` — a random password is generated and printed
  once when no operators are configured. Port flags validated; DSN no longer printed to stdout.
- Dangling-task `CreateTask` no longer returns `(nil, nil)`; heartbeat last_seen DB writes are
  debounced; health endpoint reports real uptime.

### Agent (Go)

- **Fixed goroutine leak on reconnect**: heartbeat/task/result loops are bound to a per-connection
  `done` channel instead of ranging shared channels forever.
- WebSocket framing hardening: all frame reads use `io.ReadFull` (TCP fragmentation safe);
  client-to-server frames are now masked per RFC 6455.

### Web console (Vue 3 — full rebuild)

- New minimalist dark design system (single violet accent, 10-12px radii, 1px borders).
- Single `api.js` layer: Bearer auth, single-flight token refresh with request queue, 401
  handling; removed per-view duplicated fetch logic.
- Toast notifications use `textContent` only (XSS sink removed) and are actually imported now.
- Honest "Command Runner" (was a fake "Terminal" with cosmetic connect state); login stores
  refresh token + expiry; all views handle 401/403 properly.

### Scripts & tests

- Fixed `deploy_mass.py` dispatch (3 of 4 methods crashed with TypeError), `autoexec.py`
  NameError + hardcoded zip password (now `secrets.token_urlsafe`), monitor.py auth (Basic →
  Bearer), port 8000 hardcodes, shell-injection-prone `subprocess` calls (argument lists),
  `gen_certs.py` openssl invocation, console.py history permissions and URL quoting.
- Removed dead/broken tooling: `encoder.py` (mathematically undecryptable output), `packer.py`
  (nonce/tag/ciphertext layout no stub could decrypt), `ultra-stager.py` (unwired, marketing
  claims), `tests/evasion_test.py` + `tests/evasion_payload_test.py` (tested their own inline
  reimplementations).
- Tests de-personalized: removed hardcoded `/mnt/c/Users/...` paths; `run_all.sh` now runs
  `go test ./...` and no longer swallows failures; benchmark uses Bearer auth.

### CI / packaging

- CI: fixed binary output paths, added frontend job (npm ci/build + XSS-sink check), security job
  that can actually fail (secret patterns + hardening audit), docker smoke test aligned with the
  real build.
- Dockerfile: multi-stage (Node web build + Go build), non-root user, HEALTHCHECK, no nonexistent
  `COPY` sources; `Dockerfile.agent` aligned; Go 1.25 everywhere.
- Makefile rebuilt (working targets, `docker compose` v2, real `test-all`).
- `api/openapi.yaml`: BasicAuth replaced with the actual Bearer JWT scheme.
- Removed committed 21 MB ELF binary and legacy incompatible `src/agents/` (C/PS/PY agents that
  could not talk to the server); `.gitignore` extended.

### Docs

- README rewritten around what the code really does; false claims removed (WebRTC/Pion, Pulse-*
  agent matrix, Let's Encrypt, exfil resume); screenshots + demo GIF added from a live run.

---

## v1.0 — Initial public release

- Go C2 server: multi-transport listeners, protobuf envelope protocol, X25519 + XChaCha20-Poly1305
  session crypto, JWT auth with RBAC, SQLite persistence, SIEM hooks, SOCKS5 / port-forward
  tunneling, module store with HMAC manifests.
- Vue 3 operator console, Go implant, operator scripts and test suite.
