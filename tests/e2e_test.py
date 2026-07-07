#!/usr/bin/env python3
"""
WORLDC2 C2 - End-to-End Testing Framework
Tests real agent-server connection, command execution, and all operational flows.
"""
import subprocess, json, time, sys, os, signal, urllib.request, urllib.error
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class E2ETestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        self.server_proc = None
        self.agent_proc = None
        self.token = None

    def result(self, test, passed, detail=""):
        if passed:
            self.passed += 1
            print(f"  {GREEN}[PASS]{RESET} {test}")
        else:
            self.failed += 1
            self.errors.append((test, detail))
            print(f"  {RED}[FAIL]{RESET} {test}: {detail}")

    def start_server(self, tls=False):
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        if os.path.exists("worldc2.db"):
            os.remove("worldc2.db")
        args = ["./worldc2-server", "-config", "config.yaml"]
        if not tls:
            args.append("-no-tls")
        self.server_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(4)
        try:
            proto = "https" if tls else "http"
            r = urllib.request.urlopen(f"{proto}://127.0.0.1:9090/api/health", timeout=5)
            return r.status == 200
        except:
            return False

    def start_agent(self):
        os.chdir("/mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master")
        self.agent_proc = subprocess.Popen(
            ["./worldc2-agent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(5)

    def stop_all(self):
        if self.agent_proc:
            self.agent_proc.terminate()
            try: self.agent_proc.wait(timeout=3)
            except: self.agent_proc.kill()
            self.agent_proc = None
        if self.server_proc:
            self.server_proc.terminate()
            try: self.server_proc.wait(timeout=5)
            except: self.server_proc.kill()
            self.server_proc = None
        time.sleep(2)

    def login(self):
        data = json.dumps({"username":"admin","password":"admin"}).encode()
        req = urllib.request.Request("http://127.0.0.1:9090/api/login",
                                     data=data, headers={"Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.token = json.loads(r.read())["token"]

    def api(self, method, path, data=None):
        url = f"http://127.0.0.1:9090{path}"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data.encode() if data else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, {"_body": e.read().decode()}
        except Exception as e:
            return 0, {"_error": str(e)}

    def wait_for_agent(self, timeout=30):
        """Wait for agent to connect and return session ID"""
        start = time.time()
        while time.time() - start < timeout:
            s, sessions = self.api("GET", "/api/sessions")
            if s == 200 and isinstance(sessions, list) and len(sessions) > 0:
                return sessions[0]
            time.sleep(1)
        return None

    def send_command(self, agent_id, command, timeout=15):
        """Send command to agent and return result"""
        s, r = self.api("POST", "/api/cmd",
                       json.dumps({"agent_id": agent_id, "command": command, "timeout": timeout}))
        return s, r

    def test_e2e_connection(self):
        """Test: Agent connects to server successfully"""
        print(f"\n{BOLD}[1] E2E: Agent Connection{RESET}")
        self.stop_all()
        if not self.start_server():
            self.result("Server starts", False, "Failed to start")
            return
        self.login()
        self.start_agent()

        session = self.wait_for_agent(timeout=20)
        self.result("Agent connects to server", session is not None,
                   "No sessions found after 20s")

        if session:
            print(f"  Agent: {session.get('Hostname', '?')} | {session.get('OS', '?')} | {session.get('Username', '?')}")
            self.result("Session has hostname", session.get('Hostname') is not None and session.get('Hostname') != '')
            self.result("Session has OS", session.get('OS') in ('linux', 'darwin', 'windows'))
            self.result("Session has username", session.get('Username') is not None and session.get('Username') != '')
            self.result("Session is active", session.get('State') == 'active', f"State: {session.get('State')}")

    def test_e2e_command_execution(self):
        """Test: Execute commands on connected agent"""
        print(f"\n{BOLD}[2] E2E: Command Execution{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False, "No active session")
            return

        agent_id = session.get('ID', '')

        # Test whoami
        s, r = self.send_command(agent_id, "whoami")
        self.result("Command: whoami", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")
        if s == 200 and r.get('success'):
            print(f"    Output: {r.get('output', '')[:80].strip()}")

        # Test hostname
        s, r = self.send_command(agent_id, "hostname")
        self.result("Command: hostname", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

        # Test id
        s, r = self.send_command(agent_id, "id")
        self.result("Command: id", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

        # Test pwd
        s, r = self.send_command(agent_id, "pwd")
        self.result("Command: pwd", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

        # Test echo
        s, r = self.send_command(agent_id, "echo 'WORLDC2 E2E Test OK'")
        self.result("Command: echo", s == 200 and r.get('success', False) and 'WORLDC2 E2E Test OK' in r.get('output', ''),
                   f"HTTP {s}, output={r.get('output', '')[:50]}")

    def test_e2e_modules(self):
        """Test: Built-in modules work on connected agent"""
        print(f"\n{BOLD}[3] E2E: Built-in Modules{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return
        agent_id = session.get('ID', '')

        # Test sysinfo module
        s, r = self.send_command(agent_id, "sysinfo")
        self.result("Module: sysinfo", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")
        if s == 200 and r.get('success'):
            output = r.get('output', '')
            self.result("  sysinfo has hostname", 'hostname' in output.lower() or 'host' in output.lower())
            self.result("  sysinfo has os info", 'linux' in output.lower() or 'os' in output.lower())

        # Test ps module
        s, r = self.send_command(agent_id, "ps")
        self.result("Module: ps", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

        # Test netinfo module
        s, r = self.send_command(agent_id, "netinfo")
        self.result("Module: netinfo", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

        # Test modules list
        s, r = self.send_command(agent_id, "modules")
        self.result("Module: list modules", s == 200 and r.get('success', False),
                   f"HTTP {s}, success={r.get('success')}")

    def test_e2e_file_search(self):
        """Test: File search module"""
        print(f"\n{BOLD}[4] E2E: File Search{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return
        agent_id = session.get('ID', '')

        # Search for common files
        s, r = self.send_command(agent_id, "find:*.go")
        self.result("File search: *.go", s == 200, f"HTTP {s}")

        s, r = self.send_command(agent_id, "find:*.py")
        self.result("File search: *.py", s == 200, f"HTTP {s}")

    def test_e2e_vault(self):
        """Test: Credential vault operations with active agent"""
        print(f"\n{BOLD}[5] E2E: Credential Vault{RESET}")
        # Add credential
        s, r = self.api("POST", "/api/vault",
                       json.dumps({"username":"e2e_test","password":"e2e_pass","domain":"E2E.LOCAL","service":"http"}))
        self.result("Vault: add", s == 200 and "id" in r)

        # Search
        s, r = self.api("GET", "/api/vault?q=e2e_test")
        self.result("Vault: search", s == 200 and isinstance(r, list) and len(r) > 0)

        # List
        s, r = self.api("GET", "/api/vault")
        self.result("Vault: list", s == 200 and isinstance(r, list))

    def test_e2e_session_detail(self):
        """Test: Session detail endpoint"""
        print(f"\n{BOLD}[6] E2E: Session Detail{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return

        agent_id = session.get('ID', '')
        s, r = self.api("GET", f"/api/sessions/{agent_id}")
        self.result("Session detail endpoint", s == 200, f"HTTP {s}")
        if s == 200:
            self.result("  Has session data", "session" in r)
            self.result("  Has tasks data", "tasks" in r)

    def test_e2e_broadcast(self):
        """Test: Broadcast command to all agents"""
        print(f"\n{BOLD}[7] E2E: Broadcast Command{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return

        s, r = self.api("POST", "/api/broadcast",
                       json.dumps({"command": "uptime"}))
        self.result("Broadcast endpoint", s == 200, f"HTTP {s}")
        if s == 200 and isinstance(r, dict):
            self.result(f"  Broadcast to {len(r)} agent(s)", len(r) > 0)

    def test_e2e_heartbeat(self):
        """Test: Agent sends heartbeats and session stays active"""
        print(f"\n{BOLD}[8] E2E: Heartbeat & Session Persistence{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return

        agent_id = session.get('ID', '')

        # Wait for a heartbeat cycle (agent sends every 25-35s)
        # Check session is still active after 10s
        time.sleep(10)
        s, sessions = self.api("GET", "/api/sessions")
        still_active = any(sess.get('ID') == agent_id and sess.get('State') == 'active'
                          for sess in sessions) if isinstance(sessions, list) else False
        self.result("Session still active after 10s", still_active)

        # Verify we can still send commands
        s, r = self.send_command(agent_id, "echo heartbeat_test")
        self.result("Command works after heartbeat", s == 200 and r.get('success', False))

    def test_e2e_multiple_agents(self):
        """Test: Multiple agents can connect simultaneously"""
        print(f"\n{BOLD}[9] E2E: Multiple Agents{RESET}")
        # Start a second agent
        agent2 = subprocess.Popen(
            ["./worldc2-agent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "HOME": os.path.expanduser("~")}
        )
        time.sleep(8)

        s, sessions = self.api("GET", "/api/sessions")
        if isinstance(sessions, list):
            self.result(f"Multiple agents connected ({len(sessions)})", len(sessions) >= 2,
                       f"Only {len(sessions)} sessions")
            if len(sessions) >= 2:
                # Send command to second agent
                agent2_id = sessions[1].get('ID', '')
                s2, r2 = self.send_command(agent2_id, "echo agent2_test")
                self.result("Command to second agent", s2 == 200 and r2.get('success', False))
        else:
            self.result("Multiple agents connected", False, str(sessions))

        agent2.terminate()
        try: agent2.wait(timeout=3)
        except: agent2.kill()

    def test_e2e_kill_agent(self):
        """Test: Kill agent session"""
        print(f"\n{BOLD}[10] E2E: Kill Agent{RESET}")
        session = self.wait_for_agent(timeout=10)
        if not session:
            self.result("Agent connected", False)
            return

        agent_id = session.get('ID', '')

        # Kill via API
        s, r = self.api("DELETE", f"/api/sessions/{agent_id}")
        self.result("Kill agent via API", s == 200, f"HTTP {s}")

        # Verify agent is killed
        time.sleep(2)
        s, sessions = self.api("GET", "/api/sessions")
        if isinstance(sessions, list):
            still_active = any(sess.get('ID') == agent_id and sess.get('State') == 'active'
                              for sess in sessions)
            self.result("Agent no longer active after kill", not still_active)

    def run_all(self):
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{CYAN}  WORLDC2 C2 - End-to-End Testing{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")

        try:
            self.test_e2e_connection()
            self.test_e2e_command_execution()
            self.test_e2e_modules()
            self.test_e2e_file_search()
            self.test_e2e_vault()
            self.test_e2e_session_detail()
            self.test_e2e_broadcast()
            self.test_e2e_heartbeat()
            self.test_e2e_multiple_agents()
            self.test_e2e_kill_agent()
        finally:
            self.stop_all()

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
    runner = E2ETestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
