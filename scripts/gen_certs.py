#!/usr/bin/env python3
"""
WORLDC2 C2 - TLS Certificate Generator
Genera certificados TLS auto-firmados para el servidor C2.

Uso:
    python3 gen_certs.py                    # Certificados básicos
    python3 gen_certs.py --domain c2.evil.com  # Con dominio personalizado
    python3 gen_certs.py --days 365         # Validez personalizada
"""

import os, sys, argparse
from pathlib import Path
from datetime import datetime, timedelta

GREEN = "\033[92m"; BLUE = "\033[94m"; YELLOW = "\033[93m"
RED = "\033[91m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def generate_certs(output_dir, domain, days, key_size):
    """Generate self-signed TLS certificates using OpenSSL."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cert_file = output_dir / "server.crt"
    key_file = output_dir / "server.key"

    print(f"{BOLD}{CYAN}WORLDC2 C2 - TLS Certificate Generator{RESET}\n")
    print(f"  Domain:  {domain}")
    print(f"  Days:    {days}")
    print(f"  Key:     RSA-{key_size}")
    print(f"  Output:  {output_dir}\n")

    # Check for openssl
    import shutil
    openssl = shutil.which("openssl")
    if not openssl:
        print(f"{RED}[✗]{RESET} openssl not found in PATH")
        sys.exit(1)

    # Generate private key
    print(f"{BLUE}[>]{RESET} Generating RSA-{key_size} private key...")
    cmd = f"{openssl} genrsa -out {key_file} {key_size} 2>/dev/null"
    os.system(cmd)

    if not key_file.exists():
        print(f"{RED}[✗]{RESET} Failed to generate private key")
        sys.exit(1)
    print(f"{GREEN}[✓]{RESET} Private key: {key_file}")

    # Generate self-signed certificate
    print(f"{BLUE}[>]{RESET} Generating self-signed certificate...")
    cmd = (
        f"{openssl} req -new -x509 "
        f"-key {key_file} "
        f"-out {cert_file} "
        f"-days {days} "
        f"-subj '/CN={domain}/O=WORLDC2 C2/C=US' "
        f"-addext 'subjectAltName=DNS:{domain},DNS:localhost,IP:127.0.0.1' "
        f"2>/dev/null"
    )
    os.system(cmd)

    if not cert_file.exists():
        print(f"{RED}[✗]{RESET} Failed to generate certificate")
        sys.exit(1)
    print(f"{GREEN}[✓]{RESET} Certificate: {cert_file}")

    # Set permissions
    os.chmod(key_file, 0o600)
    os.chmod(cert_file, 0o644)

    # Show fingerprint
    cmd = f"{openssl} x509 -in {cert_file} -noout -fingerprint -sha256 2>/dev/null"
    result = os.popen(cmd).read().strip()
    print(f"\n{CYAN}SHA256 Fingerprint:{RESET} {result}")

    # Show expiry
    cmd = f"{openssl} x509 -in {cert_file} -noout -enddate 2>/dev/null"
    expiry = os.popen(cmd).read().strip()
    print(f"{CYAN}Expires:{RESET} {expiry}")

    # Generate config snippet
    config_snippet = f"""
tls:
  enabled: true
  auto_cert: false
  cert_file: "{cert_file}"
  key_file: "{key_file}"
  min_version: "1.3"
"""
    print(f"\n{BOLD}{GREEN}Config snippet for config.yaml:{RESET}")
    print(config_snippet)

    print(f"{GREEN}{BOLD}Done!{RESET} Place these files in your C2 server directory.")


def main():
    p = argparse.ArgumentParser(description="WORLDC2 C2 TLS Certificate Generator")
    p.add_argument("--domain", "-d", default="localhost", help="Certificate domain")
    p.add_argument("--days", type=int, default=365, help="Certificate validity in days")
    p.add_argument("--key-size", type=int, default=4096, choices=[2048, 4096], help="RSA key size")
    p.add_argument("--output", "-o", default="certs", help="Output directory")
    args = p.parse_args()

    generate_certs(args.output, args.domain, args.days, args.key_size)


if __name__ == "__main__":
    main()
