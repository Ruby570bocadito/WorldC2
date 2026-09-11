# WorldC2 — Changelog

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
- `scripts/healthcheck.sh`: uses the public `/api/health` endpoint instead of inventing Basic
  auth; `tests/run_all.sh` uses `docker compose` v2.
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
