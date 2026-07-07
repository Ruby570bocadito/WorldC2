#!/usr/bin/env python3
"""
WORLDC2 C2 - API Benchmark Tool
Measures API endpoint performance under load.

Uso:
    python3 benchmark.py [--server http://127.0.0.1:9090] [--requests 1000] [--concurrent 10]
"""

import sys, os, json, time, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class Benchmark:
    def __init__(self, server, user, password, requests=1000, concurrent=10):
        self.server = server.rstrip("/")
        import base64
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth_header = f"Basic {creds}"
        self.requests = requests
        self.concurrent = concurrent

    def _request(self, method, path, data=None):
        import urllib.request
        import urllib.error
        url = f"{self.server}{path}"
        headers = {"Authorization": self.auth_header, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return time.time() - start, r.status, len(r.read())
        except urllib.error.HTTPError as e:
            return time.time() - start, e.code, len(e.read())
        except Exception as e:
            return time.time() - start, 0, 0

    def endpoint(self, method, path, data=None):
        times = []
        statuses = []
        errors = 0

        def make_request(i):
            elapsed, status, size = self._request(method, path, data)
            return elapsed, status, size

        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            futures = [executor.submit(make_request, i) for i in range(self.requests)]
            for f in as_completed(futures):
                try:
                    elapsed, status, size = f.result()
                    times.append(elapsed)
                    statuses.append(status)
                except Exception:
                    errors += 1

        if not times:
            return {"error": "no successful requests"}

        times.sort()
        p50 = times[len(times) // 2]
        p95 = times[int(len(times) * 0.95)]
        p99 = times[int(len(times) * 0.99)]

        return {
            "total": len(times),
            "errors": errors,
            "rps": len(times) / sum(times),
            "avg_ms": sum(times) / len(times) * 1000,
            "p50_ms": p50 * 1000,
            "p95_ms": p95 * 1000,
            "p99_ms": p99 * 1000,
            "min_ms": min(times) * 1000,
            "max_ms": max(times) * 1000,
            "status_200": statuses.count(200),
            "status_429": statuses.count(429),
            "status_other": len(statuses) - statuses.count(200) - statuses.count(429),
        }

    def run(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 API Benchmark{RESET}")
        print(f"  Server: {self.server}")
        print(f"  Requests: {self.requests} | Concurrent: {self.concurrent}\n")

        endpoints = [
            ("GET", "/api/health", None, "Health Check"),
            ("GET", "/api/sessions", None, "List Sessions"),
            ("GET", "/api/modules", None, "List Modules"),
            ("GET", "/api/vault", None, "List Vault"),
            ("GET", "/api/files", None, "List Files"),
        ]

        results = {}
        for method, path, data, name in endpoints:
            print(f"{BOLD}[>] Benchmarking: {name} ({method} {path}){RESET}")
            result = self.endpoint(method, path, data)
            results[name] = result

            if "error" in result:
                print(f"  {RED}Error: {result['error']}{RESET}")
            else:
                print(f"  {GREEN}{result['rps']:.0f} req/s{RESET} | "
                      f"Avg: {result['avg_ms']:.0f}ms | "
                      f"P50: {result['p50_ms']:.0f}ms | "
                      f"P95: {result['p95_ms']:.0f}ms | "
                      f"P99: {result['p99_ms']:.0f}ms")
                if result['status_429'] > 0:
                    print(f"  {YELLOW}Rate limited: {result['status_429']}{RESET}")

        # Summary
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"  {'Endpoint':<20} {'Req/s':>8} {'Avg':>8} {'P95':>8} {'P99':>8}")
        print(f"  {'-'*60}")
        for name, r in results.items():
            if "error" not in r:
                print(f"  {name:<20} {r['rps']:>7.0f} {r['avg_ms']:>6.0f}ms {r['p95_ms']:>6.0f}ms {r['p99_ms']:>6.0f}ms")
        print(f"{'='*60}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090")
    p.add_argument("--user", "-u", default="admin")
    p.add_argument("--password", "-p", default="admin")
    p.add_argument("--requests", "-n", type=int, default=1000)
    p.add_argument("--concurrent", "-c", type=int, default=10)
    args = p.parse_args()

    bench = Benchmark(args.server, args.user, args.password, args.requests, args.concurrent)
    bench.run()


if __name__ == "__main__":
    main()
