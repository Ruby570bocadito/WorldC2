#!/usr/bin/env python3
"""
WORLDC2 C2 - Real-time Monitor
Monitorea el servidor C2 en tiempo real mostrando sesiones, comandos y estadísticas.

Uso:
    python3 monitor.py [--server http://127.0.0.1:9090] [--interval 5]
"""

import os, json, time, argparse

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class Monitor:
    def __init__(self, server, user, password, interval=5):
        self.server = server.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        self.interval = interval
        self.history = []
        self.max_history = 60

    def _login(self):
        """POST /api/login (JSON) and store the Bearer token.

        The API is Bearer-only: Basic auth is not accepted on protected routes.
        Mirrors console.py.
        """
        import urllib.request
        url = f"{self.server}/api/login"
        data = json.dumps({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                resp = json.loads(r.read())
                self.token = resp.get("token")
                if not self.token:
                    print(f"\n{RED}[AUTH ERROR]{RESET} Login response had no token")
                    return False
                return True
        except Exception as e:
            print(f"\n{RED}[AUTH ERROR]{RESET} Login failed on {url}: {e}")
            self.token = None
            return False

    def _api(self, path):
        import urllib.request
        import urllib.error
        if not self.token and not self._login():
            return None
        url = f"{self.server}{path}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode(errors="replace")[:200]
            except Exception:
                pass
            if e.code == 401:
                # Token expired/invalid — re-authenticate once and retry
                if self._login():
                    req = urllib.request.Request(
                        url, headers={"Authorization": f"Bearer {self.token}"})
                    try:
                        with urllib.request.urlopen(req, timeout=5) as r:
                            return json.loads(r.read())
                    except Exception as e2:
                        print(f"\n{RED}[API ERROR]{RESET} {path}: {e2}")
                        return None
            print(f"\n{RED}[API ERROR]{RESET} {path}: HTTP {e.code} {body}".rstrip())
            return None
        except Exception as e:
            print(f"\n{RED}[API ERROR]{RESET} {path}: {e}")
            return None

    def run(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 - Real-time Monitor{RESET}")
        print(f"  Server: {self.server} | Interval: {self.interval}s\n")
        print(f"  Press Ctrl+C to stop\n")

        try:
            while True:
                self.refresh()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"\n{GREEN}Monitor stopped.{RESET}")

    def refresh(self):
        health = self._api("/api/health")
        sessions = self._api("/api/sessions")

        if health is None:
            print(f"\r{RED}[OFFLINE]{RESET} Cannot connect to server", end="", flush=True)
            return

        # Clear and redraw
        os.system('clear' if os.name == 'posix' else 'cls')

        print(f"{BOLD}{CYAN}WORLDC2 C2 Monitor{RESET}  {time.strftime('%H:%M:%S')}")
        print(f"{'='*60}")

        # Health stats
        active = health.get('active_sessions', 0)
        listeners = health.get('listeners', 0)
        uptime = health.get('uptime', 0)
        uptime_str = time.strftime('%H:%M:%S', time.gmtime(time.time() - uptime))

        print(f"  Status:    {GREEN}● Online{RESET}")
        print(f"  Uptime:    {uptime_str}")
        print(f"  Listeners: {listeners}")
        print(f"  Sessions:  {GREEN}{active} active{RESET}")

        # History
        self.history.append(active)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

        # Session graph
        if len(self.history) > 1:
            max_val = max(self.history) or 1
            print(f"\n  Sessions over time:")
            bar = ""
            for v in self.history[-40:]:
                h = int((v / max_val) * 5)
                bar += "▁▂▃▄▅▆▇█"[h] if h > 0 else " "
            print(f"  {bar}")

        # Sessions detail
        if sessions and isinstance(sessions, list) and len(sessions) > 0:
            print(f"\n  {'ID':<14} {'Hostname':<20} {'User':<10} {'OS':<8} {'State':<12}")
            print(f"  {'-'*64}")
            for s in sessions[:10]:
                sid = s.get('ID', '?')[:12]
                host = s.get('Hostname', '?')[:18]
                user = s.get('Username', '?')[:8]
                os_name = s.get('OS', '?')[:6]
                state = s.get('State', '?')
                state_color = GREEN if state == 'active' else YELLOW
                print(f"  {sid:<14} {host:<20} {user:<10} {os_name:<8} {state_color}{state:<12}{RESET}")
            if len(sessions) > 10:
                print(f"  ... and {len(sessions) - 10} more")
        else:
            print(f"\n  {YELLOW}No active sessions{RESET}")

        print(f"\n  {'='*60}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090")
    p.add_argument("--user", "-u", default="admin")
    p.add_argument("--password", "-p", default="admin")
    p.add_argument("--interval", "-i", type=int, default=5)
    args = p.parse_args()

    monitor = Monitor(args.server, args.user, args.password, args.interval)
    monitor.run()


if __name__ == "__main__":
    main()
