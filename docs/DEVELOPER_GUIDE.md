# WORLDC2 C2 - Developer Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        C2 Server                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ TCP/TLS  │  │   HTTP   │  │WebSocket │  │    DNS     │ │
│  │ :8443    │  │  :8445   │  │  :8446   │  │   :53      │ │
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

### 1. Connection & Key Exchange

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
| Password Hash | bcrypt (cost 12) | Operator password storage |
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

## Development

### Build
```bash
make build          # Server + Agent
make build-all      # All platforms
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
