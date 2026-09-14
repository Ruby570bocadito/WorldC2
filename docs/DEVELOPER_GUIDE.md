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
| GET | `/api/health` | No | Server health |
| GET | `/api/sessions` | Yes | List sessions |
| GET | `/api/sessions/:id` | Yes | Session detail |
| DELETE | `/api/sessions/:id` | Yes | Kill agent |
| POST | `/api/cmd` | Yes | Execute command |
| POST | `/api/broadcast` | Yes | Broadcast command |
| GET | `/api/vault` | Yes | List credentials |
| POST | `/api/vault` | Yes | Store credential |
| GET | `/api/files` | Yes | List files |
| POST | `/api/files` | Yes | Upload file |
| GET | `/api/modules` | Yes | List modules |
| POST | `/api/modules` | Yes | Register module |
| POST | `/api/modules/push` | Yes | Push to agent |
| GET/POST/DELETE | `/api/socks` | Yes | SOCKS proxy |
| GET/POST/DELETE | `/api/portfwd` | Yes | Port forwarding |
| GET/POST/DELETE | `/api/operators` | Admin | Operator management |
| POST | `/api/login` | No | Authenticate, returns access + refresh JWT |
| POST | `/api/refresh` | No | Exchange refresh token for a new access token |
| GET/DELETE | `/api/modules/:name` | Yes | Delete module (`modules:delete`) |
| GET | `/api/files/download/:id` | Yes | Download exfiltrated file |
| GET/POST | `/api/notes` | Yes | Session notes (`collab:write`) |
| POST | `/api/lock` | Yes | Lock/unlock session (`collab:write`) |
| GET/POST | `/api/profiles` | Yes | Agent config profiles (`collab:write`) |
| GET | `/api/report` | Yes | Generate engagement report (`report:generate`) |
| GET/POST/DELETE | `/api/webhooks` | Admin | SIEM webhook destinations (persisted in `webhooks`, migration 9; re-hydrated on start; DELETE takes `?id=...` from the POST response) |
| POST | `/api/mtls/cert` | Admin | Issue mTLS client certificate |
| GET/POST/DELETE | `/api/operators/:id` | Admin | Delete operator (revokes their JWTs) |

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

### Security Audit
```bash
python3 scripts/harden.py --apply
```
