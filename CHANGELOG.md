# WORLDC2 C2 - Changelog de Mejoras

## Sesión de Desarrollo - 2026-05-15

### Bugs Críticos Corregidos

#### 1. `scripts/console.py` - Código copiado en `do_push` (líneas 256-259)
**Problema:** Código de `do_files` copiado accidentalmente en el bloque `else` de `do_push`, usando variable `f` no definida.
**Fix:** Eliminado código erróneo.

#### 2. `scripts/payload.py` - Ruta incorrecta para agente C (línea 125)
**Problema:** `PROJECT_ROOT/"agent"/"c"/"agent.c"` no existe. La ruta correcta es `src/agents/c/agent.c`.
**Fix:** Corregida la ruta a `PROJECT_ROOT/"src"/"agents"/"c"/"agent.c"`.

#### 3. `src/go/internal/c2/server.go` - Indentación inconsistente (línea 61)
**Problema:** `portFwds:` tenía un espacio menos que el resto de campos.
**Fix:** Alineada la indentación.

#### 4. `src/go/internal/c2/server.go` - Path duplicado en `findWebDist()` (línea 891)
**Problema:** `"../../web/dist"` aparecía dos veces en el slice de candidatos.
**Fix:** Reemplazado el duplicado por `"../../../web/dist"`.

#### 5. `src/go/internal/transport/websocket.go` - SHA256 en lugar de SHA1 (línea 70)
**Problema:** El cálculo de `Sec-WebSocket-Accept` usaba SHA256 en lugar de SHA1 como especifica RFC 6455. Esto hacía que el handshake WebSocket fallara con clientes estándar.
**Fix:** Cambiado a `sha1.New()` y actualizado el import.

#### 6. `src/go/internal/transport/websocket.go` - `writeWSFrame` no escribía datos (línea 269)
**Problema:** La función construía el frame pero nunca llamaba a `c.conn.Write()`. Los datos nunca se enviaban.
**Fix:** Añadido `c.conn.Write(frame)` antes del return.

#### 7. `src/go/internal/transport/websocket.go` - Generación débil de WebSocket key (líneas 294-296)
**Problema:** La key se generaba usando `time.Now().UnixNano()` de forma predecible.
**Fix:** Usado `crypto/rand.Read()` para generación criptográficamente segura.

#### 8. `scripts/deploy.py` - Ruta de compilación incorrecta (línea 64)
**Problema:** `server_dir` apuntaba a `Path(__file__).parent.parent / "server"` que no existe.
**Fix:** Corregido a `Path(__file__).parent.parent / "src" / "go"`.

#### 9. `src/go/internal/agent/modules.go` - `fileSearch` buscaba paths inexistentes (línea 338)
**Problema:** Buscaba simultáneamente en paths de Linux y Windows (`C:\Users` en Linux causaba errores).
**Fix:** Paths ahora son específicos por sistema operativo con verificación de existencia.

#### 10. `src/go/internal/agent/modules.go` - Ruta de crontab incorrecta (línea 196)
**Problema:** `os.ExpandEnv("$HOME/.config/cron.tab")` no es una ruta válida para crontab.
**Fix:** Cambiado a `filepath.Join(os.Getenv("HOME"), ".bty_cron")`.

#### 11. `src/go/internal/module/module.go` - HMAC no se guardaba en disco (línea 129)
**Problema:** El HMAC se computaba después de guardar el manifest, por lo que nunca se persistía.
**Fix:** Se re-escribe el manifest después de computar el HMAC.

#### 12. `src/go/internal/evasion/camouflage.go` - Uso de `math/rand` en lugar de `crypto/rand`
**Problema:** Todos los valores aleatorios para evasión (jitter, heartbeat, HTTP preamble) usaban `math/rand` que es predecible.
**Fix:** Reemplazado completamente por `crypto/rand` con `rand.Int(rand.Reader, big.NewInt())`.

### Mejoras de Seguridad

#### 1. Rate Limiting en API REST
**Archivo:** `src/go/internal/c2/ratelimit.go` (nuevo)
**Descripción:** Implementado token bucket rate limiter por IP (60 req/min).
**Aplicado a:** Todos los endpoints de la API REST.

#### 2. CORS Restrictivo
**Archivo:** `src/go/internal/c2/server.go`
**Descripción:** Cambiado `Access-Control-Allow-Origin: *` a whitelist de orígenes permitidos (localhost, 127.0.0.1, Vite dev server).

#### 3. Logging de intentos fallidos de autenticación
**Archivo:** `src/go/internal/c2/server.go`
**Descripción:** Los intentos fallidos de login ahora se registran en el audit log.

#### 4. Corrección de realm en Basic Auth
**Archivo:** `src/go/internal/c2/server.go`
**Descripción:** Cambiado `BYOB C2` a `WORLDC2 C2` en el realm de autenticación.

#### 5. Passwords bcrypt en config.yaml
**Archivo:** `config.yaml`, `src/go/cmd/server/main.go`, `src/go/internal/db/database.go`
**Descripción:** 
- Password de admin ahora está hasheado con bcrypt ($2b$12$)
- Añadida función `CreateOperatorWithHash()` para usar hashes pre-computados
- Server ahora lee operadores del config.yaml con sus hashes

#### 6. TLS habilitado por defecto
**Archivo:** `config.yaml`
**Descripción:** TLS ahora está habilitado por defecto con auto-cert.

#### 7. Permisos de archivos endurecidos
**Archivos:** `config.yaml` (600), `data/` (700)
**Descripción:** Permisos restringidos para archivos sensibles.

### Nuevas Herramientas

#### 1. Test Suite Funcional
**Archivo:** `tests/run_tests.py`
**Categorías:** Health, Auth, CORS, Sessions, API Endpoints, Vault, Files, Modules, Error Handling

#### 2. Stress Test Suite
**Archivo:** `tests/stress_test.py`
**Tests:** Concurrent health checks, concurrent sessions, rate limiting validation, invalid request handling

#### 3. Integration Test Suite
**Archivo:** `tests/integration_test.py`
**Flujo:** Server connectivity → Agent connection → Command execution → Vault → Files → Modules → Broadcast

#### 4. Security Hardening Script
**Archivo:** `scripts/harden.py`
**Checks:** Permisos, credenciales, TLS, gitignore, database, API security

#### 5. TLS Certificate Generator
**Archivo:** `scripts/gen_certs.py`
**Funcionalidad:** Genera certificados RSA-4096 auto-firmados con SAN

#### 6. Docker Health Check
**Archivo:** `scripts/healthcheck.sh`
**Funcionalidad:** Verifica estado del servidor C2 en Docker

### Infraestructura

#### 1. Docker Compose
**Archivo:** `docker-compose.yml`
**Servicios:** c2-server, agent-linux-1, agent-linux-2, test-runner
**Red:** 172.20.0.0/16 con IPs fijas

#### 2. Dockerfiles
**Archivos:** `Dockerfile`, `Dockerfile.agent`
**Base:** Alpine 3.20 con Go 1.25 para compilación

#### 3. Makefile
**Archivo:** `Makefile`
**Targets:** build, test, docker, harden, certs, clean, fmt, lint, help

### Configuración

#### 1. Config Example Seguro
**Archivo:** `config.example.yaml`
**Contenido:** Configuración de ejemplo con TLS habilitado y bcrypt hashes

#### 2. .gitignore Mejorado
**Archivo:** `.gitignore`
**Añadido:** certs/, *.crt, *.key, *.pem, .env, tests/__pycache__/

### Tests Unitarios

#### 1. Crypto Tests
**Archivo:** `src/go/internal/crypto/keyx_test.go`
**Tests:** KeyPair generation, shared secret, encrypt/decrypt, session tokens, salt generation
**Benchmarks:** Encrypt y Decrypt

### Documentación

#### 1. Changelog
**Archivo:** `CHANGELOG.md`
**Contenido:** Registro completo de todos los bugs corregidos y mejoras

### Próximas Mejoras Planificadas
1. Documentación de API OpenAPI/Swagger ✅
2. Tests E2E con Selenium para dashboard web
3. Sistema de plugins para módulos
4. WebRTC Transport como transporte alternativo
5. Command streaming en tiempo real ✅
6. Multi-operator support ✅

---

## Sesión de Desarrollo - Continuación 2

### Autenticación y Autorización

#### 1. JWT Authentication System
**Archivo:** `src/go/internal/auth/jwt.go`
**Implementación:**
- JWT con HMAC-SHA256 (sin dependencias externas)
- Token generation con expiración configurable
- Refresh tokens (24h)
- Signature verification con constant-time comparison
- Payload: sub, role, iat, exp

#### 2. Operators Management API
**Archivos:** `src/go/internal/c2/server.go`, `src/go/internal/db/database.go`
**Endpoints:**
- `GET /api/operators` - List all operators (sin password hashes)
- `POST /api/operators` - Create new operator (bcrypt auto-hash)
- `DELETE /api/operators/:id` - Delete operator
- Audit logging para todas las operaciones

### Logging

#### 3. Structured Logging System
**Archivo:** `src/go/internal/logger/logger.go`
**Features:**
- JSON structured logs
- 5 niveles: DEBUG, INFO, WARN, ERROR, FATAL
- Caller info automático (file:line)
- Child loggers con campos adicionales
- Default logger instance con funciones package-level

### DNS Tunneling

#### 4. Encrypted DNS Tunneling
**Archivo:** `src/go/internal/transport/dns.go`
**Mejoras:**
- Cifrado XChaCha20-Poly1305 en DNS queries/responses
- Base64 URL-safe encoding para subdomains
- TXT record responses con chunking (255 bytes)
- Proper DNS response building (QR, ANCOUNT, TTL)
- Session management con queues

### WebSocket

#### 5. WebSocket Implementation Fixed
**Archivo:** `src/go/internal/transport/websocket.go`
**Fixes:**
- SHA1 para Sec-WebSocket-Accept (RFC 6455)
- writeWSFrame ahora escribe datos al socket
- Crypto/rand para WebSocket key
- Ping/Pong frame handling
- Client masking (RFC requirement)
- Proper frame parsing con opcode handling

### Dashboard Web

#### 6. Vue Router Guards
**Archivo:** `web/src/main.js`
**Features:**
- Auth guard (requiresAuth)
- Admin guard (requiresAdmin)
- Guest redirect (logged users → /)
- Dynamic page titles
- Wildcard route redirect
- Error handler

#### 7. Notification System
**Archivo:** `web/src/utils/notifications.js`
**Features:**
- Toast notifications (success, error, warning, info)
- Auto-dismiss (4s default)
- Slide in/out animations
- Global API: `window.WORLDC2.notify.success/error/warning/info`

#### 8. Operators View
**Archivo:** `web/src/views/Operators.vue`
**Features:**
- Add operator form (username, password, role)
- Operators table with role badges
- Delete operator (confirm dialog)
- Current user indicator
- Admin-only access

### Command Execution

#### 9. Command Output Streaming
**Archivo:** `src/go/internal/agent/streaming.go`
**Features:**
- StreamCommand() - channel-based output streaming
- ExecuteLongRunningCommand() - progress updates cada 100 líneas
- ExecuteAndEncodeFile() - file transfer en chunks de 32KB base64
- Timeout support
- Stdout/stderr separation

### CI/CD

#### 10. GitHub Actions Pipeline
**Archivo:** `.github/workflows/ci.yml`
**Jobs:**
- **test**: Go tests + race + coverage, Python syntax, functional tests
- **build**: Cross-compile para linux, windows, darwin (amd64, arm64)
- **docker**: Build + health check
- **security**: Security audit + hardcoded secrets check

### Documentation

#### 11. OpenAPI Specification
**Archivo:** `api/openapi.yaml`
**Coverage:** Todos los endpoints documentados con schemas, security schemes, examples

### Tools

#### 12. API Benchmark Tool
**Archivo:** `tests/benchmark.py`
**Features:**
- Concurrent request testing
- P50/P95/P99 latency metrics
- Requests per second calculation
- Rate limiting detection
- Multi-endpoint benchmarking

#### 13. Project Report Generator
**Archivo:** `scripts/report.py`
**Features:**
- File count, lines of code by type
- Directory structure summary
- Security status check
- Test coverage listing
- Infrastructure status

### Métricas Actuales
- **Archivos:** 100
- **Líneas de código:** 17,523
- **Go:** 10,114 líneas
- **Python:** 2,602 líneas
- **Test files:** 4
- **Docker files:** 3
- **CI/CD:** Yes

---

## Sesión de Desarrollo - Continuación

### Implementación de Funcionalidades Faltantes

#### 1. `sleepmask.go` - lockMemoryRegions() implementado
**Archivos:** `src/go/internal/evasion/sleepmask_unix.go`, `sleepmask_windows.go`
**Descripción:** 
- Linux/macOS: Usa `syscall.Mprotect()` para cambiar RWX → RX durante sleep
- Windows: Usa `VirtualProtect()` para cambiar PAGE_EXECUTE_READWRITE → PAGE_EXECUTE_READ
- Memory regions se restauran correctamente al despertar

#### 2. Anti-Sandbox / VM Detection
**Archivos:** `src/go/internal/evasion/anti_sandbox.go`, `anti_sandbox_unix.go`
**Checks implementados (Windows):**
- Uptime (requiere >10 min)
- RAM (requiere >2GB)
- Disk space (requiere >10GB libre)
- CPU cores (requiere >=2)
- VM processes (VirtualBox, VMware, Xen, Sandboxie)
- MAC addresses (prefijos VM conocidos)
- USB devices
- Screen resolution (requiere >=800x600)

**Checks implementados (Linux/macOS):**
- Uptime via /proc/uptime (requiere >5 min)
- RAM via /proc/meminfo (requiere >1GB)
- Disk space via syscall.Statfs (requiere >5GB)
- CPU cores
- VM files (/sys/class/dmi/id, lsmod)
- MAC addresses via /sys/class/net

#### 3. Anti-Debug
**Windows:** IsDebuggerPresent(), NtQueryInformationProcess(ProcessDebugPort)
**Linux:** /proc/self/status TracerPid check

### Mejoras de Seguridad

#### 4. Input Validation en API
**Archivo:** `src/go/internal/c2/validation.go`
**Validaciones:**
- Command length max 10000 chars
- Blocked dangerous patterns (rm -rf /, fork bombs, etc.)
- Required fields validation (agent_id, command)
- Timeout max 300 seconds

#### 5. Reconexión con Fallback de Transporte
**Archivo:** `src/go/internal/agent/agent.go`
**Fallback chain:** TLS → Plain TCP → HTTP
**Descripción:** El agente intenta múltiples transports antes de fallar

### Mejoras de DNS Tunneling

#### 6. DNS Response Builder Corregido
**Archivo:** `src/go/internal/transport/dns.go`
**Fix:** Implementado buildDNSResponse() con estructura DNS correcta (QR bit, ANCOUNT, TXT record)

### Mejoras del Dashboard Web

#### 7. Error Handling y Loading States
**Archivo:** `web/src/App.vue`
**Mejoras:**
- Loading overlay con spinner
- Error banner con retry button
- Connection status indicator (verde/rojo)
- Uptime display formateado
- AbortSignal.timeout para health checks
- Auto-retry con backoff exponencial (max 10 retries → pausa 30s)

### Testing

#### 8. Session Manager Tests
**Archivo:** `src/go/internal/c2/session/session_test.go`
**Tests:** 18 tests unitarios + 2 benchmarks
**Coverage:** State transitions, sequence numbers, pending tasks, close handling, crypto setup, ID uniqueness

### Infraestructura

#### 9. Installation Script
**Archivo:** `scripts/install.sh`
**Funcionalidad:**
- Auto-detect OS (Linux/macOS)
- Instala Go, Python3, build tools
- Compila server y agente
- Genera certificados TLS
- Verifica todos los componentes

### Herramientas de Evasión Mejoradas

#### 10. Crypto/rand en Camouflage
**Archivo:** `src/go/internal/evasion/camouflage.go`
**Fix:** Reemplazado math/rand por crypto/rand en:
- HTTP preamble generation
- Jitter calculation
- Heartbeat intervals
- Traffic shaping delays
