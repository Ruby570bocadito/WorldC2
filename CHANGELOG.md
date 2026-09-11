# WorldC2 — Changelog

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
  previously indented-vs-compact JSON mismatch made `Verify` always false).
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
