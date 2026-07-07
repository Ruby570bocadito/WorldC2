#!/usr/bin/env python3
"""
WORLDC2 C2 - Evasion & Payload Testing Framework
Tests anti-sandbox, sleepmask, camouflage, stagers, and evasion techniques.
"""
import subprocess, json, time, sys, os, struct, hashlib, base64
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class EvasionTestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def result(self, test, passed, detail=""):
        if passed:
            self.passed += 1
            print(f"  {GREEN}[PASS]{RESET} {test}")
        else:
            self.failed += 1
            self.errors.append((test, detail))
            print(f"  {RED}[FAIL]{RESET} {test}: {detail}")

    def test_evasion_files_exist(self):
        """Verify all evasion source files exist and are valid"""
        print(f"\n{BOLD}[1] Evasion Module Structure{RESET}")
        base = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/evasion")
        expected = [
            "sleepmask.go", "sleepmask_unix.go", "sleepmask_windows.go",
            "camouflage.go", "anti_sandbox.go", "anti_sandbox_unix.go",
            "evasion_windows.go", "amsi_bypass.go", "etw_bypass.go",
        ]
        for f in expected:
            p = base / f
            self.result(f"{f} exists", p.exists())
            if p.exists():
                content = p.read_text()
                self.result(f"{f} non-empty", len(content) > 50, f"{len(content)} bytes")

    def test_sleepmask_crypto_rand(self):
        """Verify sleepmask uses crypto/rand not time.Now() for jitter"""
        print(f"\n{BOLD}[2] Sleepmask Crypto Randomness{RESET}")
        f = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/evasion/sleepmask.go")
        content = f.read_text()
        # Should use crypto/rand
        self.result("Uses crypto/rand", "crypto/rand" in content or "cryptoRandFloat" in content)
        # Should NOT use time.Now() for jitter
        import re
        jitter_patterns = re.findall(r'time\.Now\(\)\.UnixNano\(\).*jitter|jitter.*time\.Now\(\)', content, re.IGNORECASE)
        self.result("No time.Now() in jitter", len(jitter_patterns) == 0,
                   f"Found {len(jitter_patterns)} time.Now() jitter patterns")

    def test_camouflage_crypto_rand(self):
        """Verify camouflage uses crypto/rand"""
        print(f"\n{BOLD}[3] Camouflage Crypto Randomness{RESET}")
        f = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/evasion/camouflage.go")
        content = f.read_text()
        self.result("Uses crypto/rand", "crypto/rand" in content)
        import re
        bad_patterns = re.findall(r'time\.Now\(\)\.UnixNano\(\).*%', content)
        self.result("No predictable time-based jitter", len(bad_patterns) == 0)

    def test_anti_sandbox_checks(self):
        """Verify anti-sandbox has sufficient checks"""
        print(f"\n{BOLD}[4] Anti-Sandbox Checks{RESET}")
        f_win = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/evasion/anti_sandbox.go")
        f_unix = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/evasion/anti_sandbox_unix.go")

        win_content = f_win.read_text() if f_win.exists() else ""
        unix_content = f_unix.read_text() if f_unix.exists() else ""
        all_content = win_content + unix_content

        checks = {
            "uptime": "uptime" in all_content.lower(),
            "ram": "ram" in all_content.lower() or "meminfo" in all_content.lower(),
            "disk": "disk" in all_content.lower() or "statfs" in all_content.lower(),
            "cpu": "cpu" in all_content.lower() or "processor" in all_content.lower(),
            "debug": "debug" in all_content.lower() or "tracer" in all_content.lower(),
            "vm_detection": "vmware" in all_content.lower() or "virtualbox" in all_content.lower() or "hyperv" in all_content.lower(),
        }
        for check, found in checks.items():
            self.result(f"Anti-sandbox: {check} check", found)

    def test_stager_generation(self):
        """Test stager script generation"""
        print(f"\n{BOLD}[5] Stager Generation{RESET}")
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        r = subprocess.run(["python3", "scripts/stager.py", "--help"],
                          capture_output=True, text=True, timeout=10)
        self.result("Stager script runs", r.returncode == 0 or "usage" in r.stdout.lower() or "usage" in r.stderr.lower())

        # Test direct generation
        r = subprocess.run(["python3", "scripts/stager.py"],
                          capture_output=True, text=True, timeout=10,
                          input="1\n")  # Select option 1
        self.result("Stager interactive mode", r.returncode == 0 or len(r.stdout) > 0,
                   r.stderr[:100] if r.returncode != 0 else "")

    def test_ultra_stager_generation(self):
        """Test ultra-stager generation"""
        print(f"\n{BOLD}[6] Ultra-Stager Generation{RESET}")
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        r = subprocess.run(["python3", "scripts/ultra-stager.py"],
                          capture_output=True, text=True, timeout=10,
                          input="1\n")
        self.result("Ultra-stager runs", r.returncode == 0 or len(r.stdout) > 0,
                   r.stderr[:100] if r.returncode != 0 else "")

    def test_payload_generation(self):
        """Test payload generation script"""
        print(f"\n{BOLD}[7] Payload Generation{RESET}")
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        # Test with --help first
        r = subprocess.run(["python3", "scripts/payload.py", "--help"],
                          capture_output=True, text=True, timeout=10)
        self.result("Payload script --help", r.returncode == 0 or "usage" in r.stdout.lower() or "usage" in r.stderr.lower())

        # Check dist/ has pre-built agents
        dist = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/dist")
        if dist.exists():
            files = list(dist.iterdir())
            self.result(f"Dist directory has {len(files)} files", len(files) > 0)
            for f in files:
                if f.is_file() and f.stat().st_size > 1000000:  # > 1MB
                    self.result(f"  {f.name} ({f.stat().st_size/1024/1024:.1f} MB)", True)

    def test_encoder_script(self):
        """Test payload encoder"""
        print(f"\n{BOLD}[8] Payload Encoder{RESET}")
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        r = subprocess.run(["python3", "scripts/encoder.py", "--help"],
                          capture_output=True, text=True, timeout=10)
        self.result("Encoder script exists and runs", r.returncode == 0 or "usage" in r.stdout.lower() or "usage" in r.stderr.lower())

    def test_proto_messages(self):
        """Verify protobuf messages are well-defined"""
        print(f"\n{BOLD}[9] Protocol Buffers{RESET}")
        proto_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/proto")
        pb_go = proto_dir / "messages.pb.go"
        self.result("messages.pb.go exists", pb_go.exists())
        if pb_go.exists():
            content = pb_go.read_text()
            types = ["Envelope", "EnvelopeInner", "Task", "TaskResult", "Heartbeat",
                    "KeyExchange", "SessionInit", "Acknowledge"]
            for t in types:
                self.result(f"Proto type: {t}", f"type {t} struct" in content)

    def test_transport_implementations(self):
        """Verify all transport implementations"""
        print(f"\n{BOLD}[10] Transport Implementations{RESET}")
        transport_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/transport")
        expected = {
            "transport.go": "Transport interface",
            "tls.go": "TLS transport",
            "http.go": "HTTP long-poll transport",
            "websocket.go": "WebSocket transport",
            "dns.go": "DNS tunneling",
        }
        for f, desc in expected.items():
            p = transport_dir / f
            exists = p.exists()
            self.result(f"{desc} ({f})", exists)
            if exists:
                content = p.read_text()
                self.result(f"  {f} has implementation", len(content) > 100, f"{len(content)} bytes")

    def test_c2_operations(self):
        """Verify C2 operational features"""
        print(f"\n{BOLD}[11] C2 Operational Features{RESET}")
        c2_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/c2")
        features = {
            "server.go": "Main server",
            "session/session.go": "Session FSM",
            "operations.go": "SOCKS/Vault/Files",
            "tunnel.go": "Tunnel manager",
            "ratelimit.go": "Rate limiting",
            "validation.go": "Input validation",
        }
        for f, desc in features.items():
            p = c2_dir / f
            self.result(f"{desc} ({f})", p.exists())

    def test_module_system(self):
        """Verify dynamic module system"""
        print(f"\n{BOLD}[12] Dynamic Module System{RESET}")
        # Check module store
        module_go = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/module/module.go")
        self.result("Module store implementation", module_go.exists())

        # Check module manifests
        modules_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/modules")
        if modules_dir.exists():
            manifests = list(modules_dir.glob("*/manifest.json"))
            self.result(f"Found {len(manifests)} module manifests", len(manifests) > 0)
            for m in manifests:
                try:
                    data = json.loads(m.read_text())
                    self.result(f"  Module: {data.get('name', 'unknown')} v{data.get('version', '?')}", True)
                except:
                    self.result(f"  Invalid manifest: {m.name}", False)

    def test_agent_modules(self):
        """Verify agent built-in modules"""
        print(f"\n{BOLD}[13] Agent Built-in Modules{RESET}")
        modules_go = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/agent/modules.go")
        self.result("Agent modules file", modules_go.exists())
        if modules_go.exists():
            content = modules_go.read_text()
            module_names = ["sysinfo", "ps", "netinfo", "screenshot", "keylogger", "persistence", "find"]
            for m in module_names:
                self.result(f"  Module: {m}", m.lower() in content.lower())

    def test_post_exploitation(self):
        """Verify post-exploitation capabilities"""
        print(f"\n{BOLD}[14] Post-Exploitation Features{RESET}")
        agent_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/agent")
        features = {
            "agent.go": "Main agent loop",
            "modules.go": "Built-in modules",
            "fingerprint.go": "System fingerprinting",
            "exfil.go": "File exfiltration",
            "persistence.go": "Persistence mechanisms",
            "killswitch.go": "Kill switch / anti-analysis",
        }
        for f, desc in features.items():
            p = agent_dir / f
            self.result(f"{desc} ({f})", p.exists())

    def test_crypto_implementation(self):
        """Verify cryptographic implementation"""
        print(f"\n{BOLD}[15] Cryptographic Implementation{RESET}")
        crypto_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/crypto")
        keyx_go = crypto_dir / "keyx.go"
        self.result("Crypto implementation", keyx_go.exists())
        if keyx_go.exists():
            content = keyx_go.read_text()
            checks = {
                "X25519 key exchange": "curve25519" in content,
                "XChaCha20-Poly1305": "chacha20poly1305" in content,
                "HKDF key derivation": "hkdf" in content,
                "Random nonce generation": "rand.Read" in content,
                "Session token (HMAC)": "hmac" in content.lower(),
            }
            for desc, found in checks.items():
                self.result(f"  {desc}", found)

    def test_auth_implementation(self):
        """Verify authentication implementation"""
        print(f"\n{BOLD}[16] Authentication Implementation{RESET}")
        auth_go = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/auth/jwt.go")
        self.result("JWT implementation", auth_go.exists())
        if auth_go.exists():
            content = auth_go.read_text()
            checks = {
                "HMAC-SHA256": "HS256" in content,
                "Token generation": "GenerateToken" in content,
                "Token validation": "ValidateToken" in content,
                "Expiration check": "ExpiresAt" in content or "exp" in content,
                "Refresh tokens": "RefreshToken" in content,
                "Crypto/rand for secret": "rand.Read" in content,
            }
            for desc, found in checks.items():
                self.result(f"  {desc}", found)

    def test_database_schema(self):
        """Verify database schema and migrations"""
        print(f"\n{BOLD}[17] Database Schema{RESET}")
        db_go = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/db/database.go")
        migrations_go = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/src/go/internal/db/migrations.go")
        self.result("Database implementation", db_go.exists())
        self.result("Migrations system", migrations_go.exists())

        if migrations_go.exists():
            content = migrations_go.read_text()
            # Count migrations
            import re
            versions = re.findall(r'Version:\s*(\d+)', content)
            self.result(f"  {len(versions)} migrations defined", len(versions) >= 6)

            # Check for server_secrets table (our addition)
            self.result("  server_secrets table (JWT persistence)", "server_secrets" in content)

    def test_docker_config(self):
        """Verify Docker configuration"""
        print(f"\n{BOLD}[18] Docker Configuration{RESET}")
        base = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        files = {
            "Dockerfile": "Server + agent build",
            "Dockerfile.agent": "Agent-only build",
            "docker-compose.yml": "Multi-container setup",
        }
        for f, desc in files.items():
            p = base / f
            self.result(f"{desc} ({f})", p.exists())
            if p.exists():
                content = p.read_text()
                self.result(f"  {f} valid config", len(content) > 50)

    def test_web_dashboard(self):
        """Verify web dashboard"""
        print(f"\n{BOLD}[19] Web Dashboard{RESET}")
        web_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/web")
        self.result("Web directory exists", web_dir.exists())
        if web_dir.exists():
            self.result("  package.json", (web_dir / "package.json").exists())
            self.result("  vite.config.js", (web_dir / "vite.config.js").exists())
            src = web_dir / "src"
            if src.exists():
                views = list(src.glob("views/*.vue"))
                self.result(f"  {len(views)} Vue views", len(views) > 0)

    def test_scripts(self):
        """Verify all utility scripts"""
        print(f"\n{BOLD}[20] Utility Scripts{RESET}")
        scripts_dir = Path("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master/scripts")
        expected = [
            "deploy.py", "payload.py", "stager.py", "ultra-stager.py",
            "console.py", "encoder.py", "monitor.py", "report.py",
            "harden.py", "gen_certs.py", "install.sh", "healthcheck.sh",
        ]
        for f in expected:
            p = scripts_dir / f
            self.result(f"{f}", p.exists())

    def run_all(self):
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{CYAN}  WORLDC2 C2 - Evasion & Payload Testing{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")

        self.test_evasion_files_exist()
        self.test_sleepmask_crypto_rand()
        self.test_camouflage_crypto_rand()
        self.test_anti_sandbox_checks()
        self.test_stager_generation()
        self.test_ultra_stager_generation()
        self.test_payload_generation()
        self.test_encoder_script()
        self.test_proto_messages()
        self.test_transport_implementations()
        self.test_c2_operations()
        self.test_module_system()
        self.test_agent_modules()
        self.test_post_exploitation()
        self.test_crypto_implementation()
        self.test_auth_implementation()
        self.test_database_schema()
        self.test_docker_config()
        self.test_web_dashboard()
        self.test_scripts()

        total = self.passed + self.failed
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"  {BOLD}TOTAL: {total} tests{RESET}")
        print(f"  {GREEN}PASSED: {self.passed}{RESET}")
        print(f"  {RED}FAILED: {self.failed}{RESET}")
        if self.errors:
            print(f"\n{RED}{BOLD}Failures:{RESET}")
            for name, detail in self.errors:
                print(f"  - {name}: {detail}")
        print(f"{'='*60}")
        return self.failed == 0


if __name__ == "__main__":
    runner = EvasionTestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
