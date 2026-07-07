#!/usr/bin/env python3
"""
WORLDC2 C2 - Test Suite Runner
Ejecuta todos los tests contra el servidor C2.

Uso:
    python3 run_tests.py [--server http://172.20.0.10:9090] [--user admin] [--password admin]
"""

import sys, os, json, time, argparse, base64
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, name):
        self.passed += 1
        print(f"  {GREEN}[PASS]{RESET} {name}")

    def add_fail(self, name, reason=""):
        self.failed += 1
        self.errors.append((name, reason))
        print(f"  {RED}[FAIL]{RESET} {name}: {reason}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  Total: {total} | {GREEN}Passed: {self.passed}{RESET} | {RED}Failed: {self.failed}{RESET}")
        if self.errors:
            print(f"\n{RED}{BOLD}Failures:{RESET}")
            for name, reason in self.errors:
                print(f"  - {name}: {reason}")
        print(f"{'='*50}")
        return self.failed == 0


class WORLDC2TestSuite:
    def __init__(self, server, user, password):
        self.server = server.rstrip("/")
        self.token = None
        self.auth_header = None
        self._setup_auth(user, password)
        self.results = TestResult()

    def _setup_auth(self, user, password):
        import urllib.request
        import urllib.error
        url = f"{self.server}/api/login"
        data = json.dumps({"username": user, "password": password}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = json.loads(r.read())
                self.token = resp.get("token")
                self.auth_header = f"Bearer {self.token}"
        except Exception as e:
            print(f"{RED}Warning: Could not authenticate: {e}{RESET}")
            self.auth_header = None

    def _request(self, method, path, data=None):
        import urllib.request
        import urllib.error
        url = f"{self.server}{path}"
        headers = {"Content-Type": "application/json"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"_http_error": e.code, "_body": e.read().decode()}
        except Exception as e:
            return {"_error": str(e)}

    def run_all(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 Test Suite{RESET}")
        print(f"  Server: {self.server}\n")

        self.test_health()
        self.test_auth()
        self.test_cors()
        self.test_sessions()
        self.test_api_endpoints()
        self.test_vault()
        self.test_files()
        self.test_modules()
        self.test_error_handling()

        return self.results.summary()

    def test_health(self):
        print(f"\n{BOLD}[1] Health Check{RESET}")
        r = self._request("GET", "/api/health")
        if "_error" in r:
            self.results.add_fail("Health endpoint", f"Cannot connect: {r['_error']}")
            return
        self.results.add_pass("Health endpoint reachable")
        if r.get("status") == "ok":
            self.results.add_pass("Status is 'ok'")
        else:
            self.results.add_fail("Status check", f"Expected 'ok', got '{r.get('status')}'")
        if "active_sessions" in r:
            self.results.add_pass("Active sessions field present")
        if "listeners" in r:
            self.results.add_pass("Listeners field present")

    def test_auth(self):
        print(f"\n{BOLD}[2] Authentication{RESET}")
        import urllib.request, urllib.error

        # Test login with wrong password
        url = f"{self.server}/api/login"
        data = json.dumps({"username": "admin", "password": "wrongpassword"}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.results.add_fail("Auth rejection", "Wrong password was accepted!")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.results.add_pass("Wrong password rejected (401)")
            else:
                self.results.add_fail("Auth rejection", f"Expected 401, got {e.code}")

        # Test without auth on protected endpoint
        req = urllib.request.Request(f"{self.server}/api/sessions")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.results.add_fail("No auth rejection", "Request without auth was accepted!")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.results.add_pass("No auth rejected (401)")
            else:
                self.results.add_fail("No auth rejection", f"Expected 401, got {e.code}")

        # Test with invalid token
        req = urllib.request.Request(f"{self.server}/api/sessions", headers={"Authorization": "Bearer invalid.token.here"})
        try:
            urllib.request.urlopen(req, timeout=10)
            self.results.add_fail("Invalid token rejection", "Invalid token was accepted!")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.results.add_pass("Invalid token rejected (401)")
            else:
                self.results.add_fail("Invalid token rejection", f"Expected 401, got {e.code}")

    def test_cors(self):
        print(f"\n{BOLD}[3] CORS Configuration{RESET}")
        import urllib.request

        url = f"{self.server}/api/health"
        req = urllib.request.Request(url, method="OPTIONS")
        req.add_header("Origin", "http://evil.com")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*":
                    self.results.add_fail("CORS", "Wildcard CORS (*) detected - security risk!")
                else:
                    self.results.add_pass("CORS restricted")
        except Exception as e:
            self.results.add_fail("CORS check", str(e))

    def test_sessions(self):
        print(f"\n{BOLD}[4] Sessions API{RESET}")
        r = self._request("GET", "/api/sessions")
        if r is None:
            self.results.add_fail("Sessions format", "Empty response")
        elif isinstance(r, list):
            self.results.add_pass("Sessions returns list")
        else:
            self.results.add_fail("Sessions format", f"Expected list, got {type(r).__name__}")

    def test_api_endpoints(self):
        print(f"\n{BOLD}[5] API Endpoints{RESET}")

        # Test each endpoint
        endpoints = [
            ("GET", "/api/health", 200),
            ("GET", "/api/sessions", 200),
            ("GET", "/api/modules", 200),
            ("GET", "/api/vault", 200),
            ("GET", "/api/files", 200),
        ]

        for method, path, expected in endpoints:
            r = self._request(method, path)
            if r is None:
                self.results.add_fail(f"{method} {path}", "Empty response")
            elif "_error" in r:
                self.results.add_fail(f"{method} {path}", f"Error: {r['_error']}")
            elif "_http_error" in r:
                self.results.add_fail(f"{method} {path}", f"HTTP {r['_http_error']}")
            else:
                self.results.add_pass(f"{method} {path}")

    def test_vault(self):
        print(f"\n{BOLD}[6] Credential Vault{RESET}")

        # Add credential
        cred = json.dumps({"username": "test_user", "password": "test_pass", "domain": "TEST", "service": "http"})
        r = self._request("POST", "/api/vault", cred)
        if "id" in r:
            self.results.add_pass("Vault: add credential")
        else:
            self.results.add_fail("Vault: add credential", str(r))

        # Search credential
        r = self._request("GET", "/api/vault?q=test_user")
        if isinstance(r, list) and len(r) > 0:
            self.results.add_pass("Vault: search credential")
        else:
            self.results.add_fail("Vault: search", f"Expected list with results, got {r}")

        # List all
        r = self._request("GET", "/api/vault")
        if isinstance(r, list):
            self.results.add_pass("Vault: list credentials")
        else:
            self.results.add_fail("Vault: list", str(r))

    def test_files(self):
        print(f"\n{BOLD}[7] File Management{RESET}")

        # List files (should be empty or list)
        r = self._request("GET", "/api/files")
        if isinstance(r, list):
            self.results.add_pass("Files: list endpoint")
        else:
            self.results.add_fail("Files: list", str(r))

    def test_modules(self):
        print(f"\n{BOLD}[8] Dynamic Modules{RESET}")

        # List modules
        r = self._request("GET", "/api/modules")
        if isinstance(r, list):
            self.results.add_pass("Modules: list endpoint")
        else:
            self.results.add_fail("Modules: list", str(r))

    def test_error_handling(self):
        print(f"\n{BOLD}[9] Error Handling{RESET}")

        # Test invalid JSON
        r = self._request("POST", "/api/cmd", "not json")
        if "_http_error" in r and r["_http_error"] == 400:
            self.results.add_pass("Invalid JSON rejected (400)")
        else:
            self.results.add_fail("Invalid JSON handling", str(r))

        # Test non-existent session
        cmd = json.dumps({"agent_id": "nonexistent", "command": "whoami"})
        r = self._request("POST", "/api/cmd", cmd)
        if "_http_error" in r and r["_http_error"] == 500:
            self.results.add_pass("Non-existent session returns error")
        else:
            self.results.add_fail("Non-existent session", str(r))

        # Test invalid endpoint
        r = self._request("GET", "/api/nonexistent")
        if "_http_error" in r and r["_http_error"] == 404:
            self.results.add_pass("Invalid endpoint returns 404")
        else:
            self.results.add_fail("Invalid endpoint", str(r))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090")
    p.add_argument("--user", "-u", default="admin")
    p.add_argument("--password", "-p", default="admin")
    args = p.parse_args()

    suite = WORLDC2TestSuite(args.server, args.user, args.password)
    success = suite.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
