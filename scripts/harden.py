#!/usr/bin/env python3
"""
WORLDC2 C2 - Security Hardening Script
Verifica y aplica mejoras de seguridad automáticamente.

Uso:
    python3 harden.py              # Verificación completa
    python3 harden.py --apply      # Aplicar mejoras automáticamente
"""

import os, sys, argparse, stat
from pathlib import Path

GREEN = "\033[92m"; BLUE = "\033[94m"; YELLOW = "\033[93m"
RED = "\033[91m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

class SecurityAudit:
    def __init__(self, project_root, apply=False):
        self.root = Path(project_root)
        self.apply = apply
        self.issues = []
        self.fixed = []

    def check(self, name, condition, fix_fn=None, severity="medium"):
        if condition:
            print(f"  {GREEN}[PASS]{RESET} {name}")
        else:
            sev_color = {"high": RED, "medium": YELLOW, "low": BLUE}.get(severity, CYAN)
            print(f"  {sev_color}[{severity.upper()}]{RESET} {name}")
            self.issues.append((name, severity))
            if fix_fn and self.apply:
                try:
                    fix_fn()
                    self.fixed.append(name)
                    print(f"    {GREEN}[FIXED]{RESET}")
                except Exception as e:
                    print(f"    {RED}[ERROR]{RESET} {e}")

    def run(self):
        print(f"\n{BOLD}{CYAN}WORLDC2 C2 - Security Audit{RESET}")
        print(f"  Project: {self.root}")
        print(f"  Mode:    {'Apply' if self.apply else 'Audit'}\n")

        self.check_permissions()
        self.check_credentials()
        self.check_tls()
        self.check_gitignore()
        self.check_database()
        self.check_api_security()

        self.summary()

    def check_permissions(self):
        print(f"{BOLD}[1] File Permissions{RESET}")

        # Check config.yaml permissions
        config = self.root / "config.yaml"
        if config.exists():
            mode = oct(config.stat().st_mode)[-3:]
            self.check(
                "config.yaml permissions (should be 600)",
                mode == "600",
                lambda: os.chmod(config, 0o600)
            )

        # Check database directory
        data_dir = self.root / "data"
        if data_dir.exists():
            mode = oct(data_dir.stat().st_mode)[-3:]
            self.check(
                "data/ directory permissions (should be 700)",
                mode == "700",
                lambda: os.chmod(data_dir, 0o700)
            )

        # Check loot directory
        loot_dir = self.root / "loot"
        if loot_dir.exists():
            mode = oct(loot_dir.stat().st_mode)[-3:]
            self.check(
                "loot/ directory permissions (should be 700)",
                mode == "700",
                lambda: os.chmod(loot_dir, 0o700)
            )

    def check_credentials(self):
        print(f"\n{BOLD}[2] Credential Security{RESET}")

        config = self.root / "config.yaml"
        if config.exists():
            content = config.read_text()

            # Check for default password
            self.check(
                "No default 'admin/admin' credentials",
                "password: \"admin\"" not in content and "password: 'admin'" not in content,
                severity="high"
            )

            # Check for plaintext passwords
            import re
            plain_passwords = re.findall(r'password:\s*["\']([^"\']*)["\']', content)
            bcrypt_hashes = [p for p in plain_passwords if p.startswith("$2a$") or p.startswith("$2b$")]
            self.check(
                f"Passwords are bcrypt hashed ({len(bcrypt_hashes)}/{len(plain_passwords)})",
                len(bcrypt_hashes) == len(plain_passwords) and len(plain_passwords) > 0,
                severity="high"
            )

    def check_tls(self):
        print(f"\n{BOLD}[3] TLS Configuration{RESET}")

        config = self.root / "config.yaml"
        if config.exists():
            content = config.read_text()

            self.check(
                "TLS is enabled",
                "enabled: true" in content and "tls:" in content,
                severity="high"
            )

            self.check(
                "TLS min version is 1.3",
                'min_version: "1.3"' in content,
                severity="medium"
            )

            self.check(
                "Auto-cert is disabled (use real certs)",
                "auto_cert: false" in content,
                severity="low"
            )

        # Check if cert files exist
        certs_dir = self.root / "certs"
        if certs_dir.exists():
            cert = certs_dir / "server.crt"
            key = certs_dir / "server.key"
            self.check("TLS certificate exists", cert.exists(), severity="high")
            self.check("TLS key exists", key.exists(), severity="high")
            if key.exists():
                mode = oct(key.stat().st_mode)[-3:]
                self.check(
                    "TLS key permissions (should be 600)",
                    mode == "600",
                    lambda: os.chmod(key, 0o600)
                )

    def check_gitignore(self):
        print(f"\n{BOLD}[4] Git Security{RESET}")

        gitignore = self.root / ".gitignore"
        if gitignore.exists():
            content = gitignore.read_text()

            sensitive = ["loot/", "data/", "*.db", "certs/", "*.key", "*.pem"]
            for pattern in sensitive:
                self.check(
                    f".gitignore blocks '{pattern}'",
                    pattern in content,
                    lambda: self._add_to_gitignore(pattern)
                )
        else:
            print(f"  {RED}[FAIL]{RESET} No .gitignore found")

    def _add_to_gitignore(self, pattern):
        gitignore = self.root / ".gitignore"
        with open(gitignore, "a") as f:
            f.write(f"\n# Added by harden.py\n{pattern}\n")

    def check_database(self):
        print(f"\n{BOLD}[5] Database Security{RESET}")

        # Check if database exists with wrong permissions
        db_files = list(self.root.glob("*.db")) + list((self.root / "data").glob("*.db"))
        for db in db_files:
            mode = oct(db.stat().st_mode)[-3:]
            self.check(
                f"{db.name} permissions (should be 600)",
                mode == "600",
                lambda db=db: os.chmod(db, 0o600)
            )

    def check_api_security(self):
        print(f"\n{BOLD}[6] API Security{RESET}")

        # Check server.go for rate limiting
        server_go = self.root / "src" / "go" / "internal" / "c2" / "server.go"
        if server_go.exists():
            content = server_go.read_text()
            self.check(
                "Rate limiting implemented",
                "RateLimiter" in content or "rateLimiter" in content
            )

            self.check(
                "CORS is not wildcard",
                '"Access-Control-Allow-Origin", "*"' not in content,
                severity="high"
            )

            self.check(
                "Auth failures are logged",
                "auth_failed" in content or "LogAction" in content
            )

    def summary(self):
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  Issues found: {len(self.issues)}")
        print(f"  Issues fixed: {len(self.fixed)}")

        high = [i for i in self.issues if i[1] == "high"]
        medium = [i for i in self.issues if i[1] == "medium"]
        low = [i for i in self.issues if i[1] == "low"]

        if high:
            print(f"\n  {RED}HIGH:{RESET}")
            for name, _ in high:
                print(f"    - {name}")
        if medium:
            print(f"\n  {YELLOW}MEDIUM:{RESET}")
            for name, _ in medium:
                print(f"    - {name}")
        if low:
            print(f"\n  {BLUE}LOW:{RESET}")
            for name, _ in low:
                print(f"    - {name}")

        if not self.issues:
            print(f"\n  {GREEN}{BOLD}All checks passed!{RESET}")

        print(f"\n{'='*50}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--apply", action="store_true", help="Apply fixes automatically")
    p.add_argument("--project", default=".", help="Project root directory")
    args = p.parse_args()

    audit = SecurityAudit(args.project, args.apply)
    audit.run()


if __name__ == "__main__":
    main()
