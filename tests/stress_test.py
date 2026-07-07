#!/usr/bin/env python3
"""
WORLDC2 C2 - Stress Test
Pruebas de carga y concurrencia contra el servidor C2.

Uso:
    python3 stress_test.py [--server http://127.0.0.1:9090] [--concurrent 50]
"""

import sys, os, json, time, argparse, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class StressTest:
    def __init__(self, server, user, password, concurrent=50):
        self.server = server.rstrip("/")
        self.concurrent = concurrent
        self.results = {"success": 0, "failed": 0, "rate_limited": 0, "errors": []}
        self.lock = threading.Lock()
        self.auth_header = None
        self._login(user, password)

    def _login(self, user, password):
        import urllib.request, urllib.error, json
        url = f"{self.server}/api/login"
        data = json.dumps({"username": user, "password": password}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = json.loads(r.read())
                self.auth_header = f"Bearer {resp['token']}"
        except Exception as e:
            print(f"Warning: Could not login: {e}")

    def _request(self, method, path, data=None):
        import urllib.request
        import urllib.error
        url = f"{self.server}{path}"
        headers = {"Authorization": self.auth_header, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, {"_body": e.read().decode()}
        except Exception as e:
            return 0, {"_error": str(e)}

    def test_concurrent_health(self):
        """Test: Multiple concurrent health checks."""
        print(f"\n{BOLD}[Stress] Concurrent Health Checks ({self.concurrent} threads){RESET}")

        def health_check(i):
            start = time.time()
            status, resp = self._request("GET", "/api/health")
            elapsed = time.time() - start
            with self.lock:
                if status == 200:
                    self.results["success"] += 1
                elif status == 429:
                    self.results["rate_limited"] += 1
                else:
                    self.results["failed"] += 1
                    self.results["errors"].append(f"Health #{i}: HTTP {status}")
            return elapsed

        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            futures = [executor.submit(health_check, i) for i in range(self.concurrent)]
            times = [f.result() for f in as_completed(futures)]

        avg_time = sum(times) / len(times) if times else 0
        print(f"  Success: {self.results['success']} | Failed: {self.results['failed']} | Rate Limited: {self.results['rate_limited']}")
        print(f"  Avg response time: {avg_time*1000:.0f}ms | Min: {min(times)*1000:.0f}ms | Max: {max(times)*1000:.0f}ms")

    def test_concurrent_sessions(self):
        """Test: Multiple concurrent session list requests."""
        print(f"\n{BOLD}[Stress] Concurrent Session List ({self.concurrent} threads){RESET}")

        def list_sessions(i):
            status, resp = self._request("GET", "/api/sessions")
            with self.lock:
                if status == 200:
                    self.results["success"] += 1
                elif status == 429:
                    self.results["rate_limited"] += 1
                else:
                    self.results["failed"] += 1

        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            futures = [executor.submit(list_sessions, i) for i in range(self.concurrent)]
            for f in as_completed(futures):
                f.result()

        print(f"  Success: {self.results['success']} | Failed: {self.results['failed']} | Rate Limited: {self.results['rate_limited']}")

    def test_rate_limiting(self):
        """Test: Verify rate limiting kicks in after threshold."""
        print(f"\n{BOLD}[Stress] Rate Limiting Test (100 rapid requests){RESET}")

        rate_limited = 0
        allowed = 0

        for i in range(100):
            status, _ = self._request("GET", "/api/health")
            if status == 429:
                rate_limited += 1
            elif status == 200:
                allowed += 1

        print(f"  Allowed: {allowed} | Rate Limited: {rate_limited}")
        if rate_limited > 0:
            print(f"  {GREEN}[PASS]{RESET} Rate limiting is active")
        else:
            print(f"  {YELLOW}[WARN]{RESET} Rate limiting may not be configured")

    def test_invalid_requests(self):
        """Test: Server resilience against malformed requests."""
        print(f"\n{BOLD}[Stress] Invalid Request Handling{RESET}")

        import urllib.request, urllib.error

        tests = [
            ("POST /api/cmd with empty body", lambda: self._request("POST", "/api/cmd", "")),
            ("POST /api/cmd with invalid JSON", lambda: self._request("POST", "/api/cmd", "not json")),
            ("GET /api/nonexistent", lambda: self._request("GET", "/api/nonexistent")),
            ("DELETE /api/sessions/invalid", lambda: self._request("DELETE", "/api/sessions/nonexistent")),
        ]

        for name, test_fn in tests:
            try:
                status, resp = test_fn()
                if status in (400, 401, 404, 405, 429, 500):
                    print(f"  {GREEN}[PASS]{RESET} {name} → HTTP {status}")
                else:
                    print(f"  {RED}[FAIL]{RESET} {name} → HTTP {status} (unexpected)")
            except Exception as e:
                print(f"  {RED}[FAIL]{RESET} {name} → Exception: {e}")

    def run_all(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 Stress Test Suite{RESET}")
        print(f"  Server: {self.server} | Concurrent: {self.concurrent}\n")

        self.test_concurrent_health()
        self.test_concurrent_sessions()
        self.test_rate_limiting()
        self.test_invalid_requests()

        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  Total Success: {self.results['success']}")
        print(f"  Total Failed: {self.results['failed']}")
        print(f"  Rate Limited: {self.results['rate_limited']}")
        print(f"{'='*50}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090")
    p.add_argument("--user", "-u", default="admin")
    p.add_argument("--password", "-p", default="admin")
    p.add_argument("--concurrent", "-c", type=int, default=50)
    args = p.parse_args()

    test = StressTest(args.server, args.user, args.password, args.concurrent)
    test.run_all()


if __name__ == "__main__":
    main()
