#!/usr/bin/env python3
"""
WORLDC2 C2 - Integration Test
Prueba el flujo completo: deploy → conectar agentes → ejecutar comandos → módulos → tunneling.

Uso:
    python3 integration_test.py [--server http://127.0.0.1:9090]
"""

import sys, os, json, time, argparse, subprocess
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class IntegrationTest:
    def __init__(self, server, user, password):
        self.server = server.rstrip("/")
        self.token = None
        self.auth_header = None
        self._login(user, password)
        self.passed = 0
        self.failed = 0

    def _login(self, user, password):
        import urllib.request, urllib.error, json
        url = f"{self.server}/api/login"
        data = json.dumps({"username": user, "password": password}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = json.loads(r.read())
                self.token = resp["token"]
                self.auth_header = f"Bearer {self.token}"
        except Exception as e:
            print(f"Warning: Could not login: {e}")

    def _api(self, method, path, data=None):
        import urllib.request, urllib.error
        url = f"{self.server}{path}"
        headers = {"Authorization": self.auth_header, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"_http_error": e.code}
        except Exception as e:
            return {"_error": str(e)}

    def report(self, test, passed, detail=""):
        if passed:
            self.passed += 1
            print(f"  {GREEN}[PASS]{RESET} {test}")
        else:
            self.failed += 1
            print(f"  {RED}[FAIL]{RESET} {test}: {detail}")

    def run_all(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 Integration Test{RESET}")
        print(f"  Server: {self.server}\n")

        # Step 1: Server health
        print(f"{BOLD}[Step 1] Server Connectivity{RESET}")
        h = self._api("GET", "/api/health")
        self.report("Server reachable", "_error" not in h, h.get("_error", ""))
        self.report("Health status ok", h.get("status") == "ok", f"Got: {h.get('status')}")
        self.report("Listeners active", h.get("listeners", 0) > 0, f"Listeners: {h.get('listeners', 0)}")

        # Step 2: Initial state
        print(f"\n{BOLD}[Step 2] Initial State{RESET}")
        sessions = self._api("GET", "/api/sessions")
        self.report("Sessions endpoint works", isinstance(sessions, list))
        initial_count = len(sessions) if isinstance(sessions, list) else 0
        print(f"  Initial sessions: {initial_count}")

        # Step 3: Docker agent connection
        print(f"\n{BOLD}[Step 3] Agent Connection (Docker){RESET}")
        print(f"  Checking for Docker agents...")
        time.sleep(5)  # Wait for agents to connect

        sessions = self._api("GET", "/api/sessions")
        if isinstance(sessions, list) and len(sessions) > initial_count:
            self.report("New agent connected", True)
            for s in sessions:
                print(f"    - {s.get('ID','?')[:12]} | {s.get('Hostname','?')} | {s.get('OS','?')} | {s.get('State','?')}")
        else:
            self.report("New agent connected", False, f"Still {len(sessions) if isinstance(sessions, list) else 0} sessions")

        # Step 4: Command execution
        print(f"\n{BOLD}[Step 4] Command Execution{RESET}")
        sessions = self._api("GET", "/api/sessions")
        if isinstance(sessions, list) and len(sessions) > 0:
            agent_id = sessions[0]["ID"]

            # Test whoami
            result = self._api("POST", "/api/cmd", json.dumps({
                "agent_id": agent_id,
                "command": "whoami",
                "timeout": 10
            }))
            if "_http_error" not in result:
                self.report("Command: whoami", result.get("success", False), result.get("output", "")[:100])
            else:
                self.report("Command: whoami", False, f"HTTP {result['_http_error']}")

            # Test hostname
            result = self._api("POST", "/api/cmd", json.dumps({
                "agent_id": agent_id,
                "command": "hostname",
                "timeout": 10
            }))
            if "_http_error" not in result:
                self.report("Command: hostname", result.get("success", False), result.get("output", "")[:100])
            else:
                self.report("Command: hostname", False, f"HTTP {result['_http_error']}")

            # Test sysinfo
            result = self._api("POST", "/api/cmd", json.dumps({
                "agent_id": agent_id,
                "command": "sysinfo",
                "timeout": 10
            }))
            if "_http_error" not in result:
                self.report("Command: sysinfo", result.get("success", False), result.get("output", "")[:100])
            else:
                self.report("Command: sysinfo", False, f"HTTP {result['_http_error']}")
        else:
            self.report("Command execution", False, "No active sessions")

        # Step 5: Credential Vault
        print(f"\n{BOLD}[Step 5] Credential Vault{RESET}")
        cred = json.dumps({"username": "test_integration", "password": "p@ssw0rd", "domain": "TEST.LOCAL", "service": "http"})
        r = self._api("POST", "/api/vault", cred)
        self.report("Vault: add credential", "id" in r, str(r))

        r = self._api("GET", "/api/vault?q=test_integration")
        self.report("Vault: search credential", isinstance(r, list) and len(r) > 0, str(r))

        # Step 6: File Management
        print(f"\n{BOLD}[Step 6] File Management{RESET}")
        r = self._api("GET", "/api/files")
        self.report("Files: list endpoint", isinstance(r, list))

        # Step 7: Modules
        print(f"\n{BOLD}[Step 7] Dynamic Modules{RESET}")
        r = self._api("GET", "/api/modules")
        self.report("Modules: list endpoint", isinstance(r, list))

        # Step 8: Session detail
        print(f"\n{BOLD}[Step 8] Session Detail{RESET}")
        sessions = self._api("GET", "/api/sessions")
        if isinstance(sessions, list) and len(sessions) > 0:
            agent_id = sessions[0]["ID"]
            r = self._api("GET", f"/api/sessions/{agent_id}")
            self.report("Session detail endpoint", "_http_error" not in r, str(r))
        else:
            self.report("Session detail", False, "No sessions")

        # Step 9: Broadcast (if multiple agents)
        print(f"\n{BOLD}[Step 9] Broadcast Command{RESET}")
        sessions = self._api("GET", "/api/sessions")
        if isinstance(sessions, list) and len(sessions) > 0:
            r = self._api("POST", "/api/broadcast", json.dumps({"command": "id"}))
            self.report("Broadcast endpoint", "_http_error" not in r, str(r)[:100])
        else:
            self.report("Broadcast", False, "No sessions")

        # Summary
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  Total: {self.passed + self.failed} | {GREEN}Passed: {self.passed}{RESET} | {RED}Failed: {self.failed}{RESET}")
        print(f"{'='*50}")
        return self.failed == 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090")
    p.add_argument("--user", "-u", default="admin")
    p.add_argument("--password", "-p", default="admin")
    args = p.parse_args()

    test = IntegrationTest(args.server, args.user, args.password)
    success = test.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
