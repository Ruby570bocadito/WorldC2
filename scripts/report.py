#!/usr/bin/env python3
"""
WORLDC2 C2 - Project Report Generator
Genera un reporte completo del estado del proyecto.

Uso:
    python3 report.py
"""

import os, sys
from pathlib import Path
from datetime import datetime

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def count_lines(directory, extensions):
    total = 0
    by_ext = {}
    for ext in extensions:
        count = 0
        for f in Path(directory).rglob(f"*{ext}"):
            if '/node_modules/' not in str(f) and '/.git/' not in str(f):
                try:
                    count += len(f.read_text().splitlines())
                except:
                    pass
        by_ext[ext] = count
        total += count
    return total, by_ext

def count_files(directory, exclude_dirs=None):
    exclude_dirs = exclude_dirs or ['.git', 'node_modules']
    count = 0
    for f in Path(directory).rglob("*"):
        if f.is_file() and not any(d in str(f) for d in exclude_dirs):
            count += 1
    return count

def main():
    root = Path(__file__).parent.parent

    print(f"\n{BOLD}{CYAN}WORLDC2 C2 - Project Report{RESET}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # File count
    total_files = count_files(root)
    print(f"{BOLD}Files:{RESET} {total_files}")

    # Lines of code
    extensions = ['.go', '.py', '.js', '.vue', '.sh', '.yaml', '.yml', '.json', '.md']
    total_lines, by_ext = count_lines(root, extensions)
    print(f"{BOLD}Lines of Code:{RESET} {total_lines:,}")

    print(f"\n{BOLD}Breakdown by type:{RESET}")
    for ext, count in sorted(by_ext.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f"  {ext:<8} {count:>6,} lines")

    # Directory structure
    print(f"\n{BOLD}Directory Structure:{RESET}")
    for item in sorted(root.iterdir()):
        if item.is_dir() and item.name not in ['.git', 'node_modules']:
            files = len(list(item.rglob("*")))
            print(f"  {item.name}/ ({files} files)")

    # Security status
    print(f"\n{BOLD}Security Status:{RESET}")
    config = root / "config.yaml"
    if config.exists():
        content = config.read_text()
        tls_enabled = "enabled: true" in content and "tls:" in content
        bcrypt = "$2a$" in content or "$2b$" in content
        print(f"  TLS enabled:     {'Yes' if tls_enabled else 'No'}")
        print(f"  Bcrypt passwords: {'Yes' if bcrypt else 'No'}")

    # Check rate limiting
    server_go = root / "src/go/internal/c2/server.go"
    if server_go.exists():
        content = server_go.read_text()
        print(f"  Rate limiting:   {'Yes' if 'RateLimiter' in content else 'No'}")
        print(f"  CORS restricted: {'Yes' if '\"*\"' not in content else 'No'}")
        print(f"  Input validation:{'Yes' if 'ValidateCommand' in content else 'No'}")

    # Test coverage
    print(f"\n{BOLD}Test Coverage:{RESET}")
    test_files = list(root.rglob("*_test.go")) + list(root.rglob("test*.py")) + list(root.rglob("*_test.py"))
    print(f"  Test files: {len(test_files)}")
    for f in test_files:
        print(f"    - {f.relative_to(root)}")

    # Docker
    print(f"\n{BOLD}Infrastructure:{RESET}")
    docker_files = list(root.glob("Dockerfile*")) + list(root.glob("docker-compose*"))
    print(f"  Docker files: {len(docker_files)}")
    makefile = root / "Makefile"
    print(f"  Makefile: {'Yes' if makefile.exists() else 'No'}")
    ci = root / ".github/workflows/ci.yml"
    print(f"  CI/CD: {'Yes' if ci.exists() else 'No'}")

    print(f"\n{BOLD}{'='*50}{RESET}")


if __name__ == "__main__":
    main()
