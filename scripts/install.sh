#!/bin/bash
# WORLDC2 C2 - Automated Installation Script
# Installs dependencies, compiles binaries, and sets up the environment.

set -e

GREEN="\033[92m"; BLUE="\033[94m"; YELLOW="\033[93m"
RED="\033[91m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

echo -e "${BOLD}${CYAN}"
echo "   ╔══════════════════════════════════════════════╗"
echo "   ║         WORLDC2 C2 - Automated Installer         ║"
echo "   ╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

echo -e "${BOLD}Detected:${RESET} ${OS} ${ARCH}"

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!]${RESET} Some operations may require sudo"
fi

# === Phase 1: Install Dependencies ===
echo -e "\n${BOLD}[Phase 1] Installing Dependencies${RESET}"

install_go() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}')
        echo -e "  ${GREEN}[✓]${RESET} Go already installed: ${GO_VERSION}"
        return
    fi

    echo -e "  ${BLUE}[>]${RESET} Installing Go 1.25..."
    GO_URL="https://go.dev/dl/go1.25.0.${OS}-${ARCH}.tar.gz"

    if [ "$OS" = "darwin" ]; then
        GO_URL="https://go.dev/dl/go1.25.0.${OS}-${ARCH}.tar.gz"
    fi

    curl -sL "$GO_URL" -o /tmp/go.tar.gz 2>/dev/null || {
        echo -e "  ${YELLOW}[!]${RESET} Could not download Go, trying alternative..."
        if command -v apt &> /dev/null; then
            apt install -y golang-go
        elif command -v yum &> /dev/null; then
            yum install -y golang
        elif command -v brew &> /dev/null; then
            brew install go
        fi
        return
    }

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    export PATH=$PATH:/usr/local/go/bin
    echo -e "  ${GREEN}[✓]${RESET} Go installed"
}

install_python() {
    if command -v python3 &> /dev/null; then
        echo -e "  ${GREEN}[✓]${RESET} Python3 already installed"
        return
    fi

    echo -e "  ${BLUE}[>]${RESET} Installing Python3..."
    if command -v apt &> /dev/null; then
        sudo apt install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3
    elif command -v brew &> /dev/null; then
        brew install python
    fi
    echo -e "  ${GREEN}[✓]${RESET} Python3 installed"
}

install_build_tools() {
    echo -e "  ${BLUE}[>]${RESET} Installing build tools..."
    if command -v apt &> /dev/null; then
        sudo apt install -y build-essential curl git openssl
    elif command -v yum &> /dev/null; then
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y curl git openssl-devel
    elif command -v brew &> /dev/null; then
        brew install curl git openssl
    fi
    echo -e "  ${GREEN}[✓]${RESET} Build tools installed"
}

install_go
install_python
install_build_tools

# === Phase 2: Compile ===
echo -e "\n${BOLD}[Phase 2] Compiling WORLDC2 C2${RESET}"

cd "$(dirname "$0")"

if command -v go &> /dev/null; then
    echo -e "  ${BLUE}[>]${RESET} Building server..."
    cd src/go
    CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../worldc2-server ./cmd/server/main.go
    echo -e "  ${GREEN}[✓]${RESET} Server compiled: $(ls -lh ../../worldc2-server | awk '{print $5}')"

    echo -e "  ${BLUE}[>]${RESET} Building agent..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../worldc2-agent ./cmd/agent/main.go
    echo -e "  ${GREEN}[✓]${RESET} Agent compiled: $(ls -lh ../../worldc2-agent | awk '{print $5}')"
    cd ../..
else
    echo -e "  ${YELLOW}[!]${RESET} Go not found, skipping compilation"
fi

# === Phase 3: Setup ===
echo -e "\n${BOLD}[Phase 3] Setting Up Environment${RESET}"

# Create directories
mkdir -p data loot modules payloads certs web/dist
chmod 700 data loot
chmod 600 config.yaml 2>/dev/null || true

echo -e "  ${GREEN}[✓]${RESET} Directories created"

# Generate TLS certificates if openssl available
if command -v openssl &> /dev/null; then
    echo -e "  ${BLUE}[>]${RESET} Generating TLS certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
        -days 365 -nodes -subj "/CN=localhost/O=WORLDC2 C2" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    chmod 600 certs/server.key
    echo -e "  ${GREEN}[✓]${RESET} TLS certificates generated"
fi

# === Phase 4: Verification ===
echo -e "\n${BOLD}[Phase 4] Verification${RESET}"

# Check binaries
if [ -f "worldc2-server" ]; then
    echo -e "  ${GREEN}[✓]${RESET} worldc2-server: $(ls -lh worldc2-server | awk '{print $5}')"
else
    echo -e "  ${YELLOW}[!]${RESET} worldc2-server not found"
fi

if [ -f "worldc2-agent" ]; then
    echo -e "  ${GREEN}[✓]${RESET} worldc2-agent: $(ls -lh worldc2-agent | awk '{print $5}')"
else
    echo -e "  ${YELLOW}[!]${RESET} worldc2-agent not found"
fi

# Check Python scripts
for script in scripts/deploy.py scripts/payload.py scripts/console.py scripts/harden.py; do
    if python3 -m py_compile "$script" 2>/dev/null; then
        echo -e "  ${GREEN}[✓]${RESET} $(basename $script)"
    else
        echo -e "  ${RED}[✗]${RESET} $(basename $script)"
    fi
done

# === Summary ===
echo -e "\n${BOLD}${GREEN}Installation Complete!${RESET}"
echo -e "\n${BOLD}Quick Start:${RESET}"
echo -e "  ${CYAN}1.${RESET} Deploy C2:    ${GREEN}python3 scripts/deploy.py${RESET}"
echo -e "  ${CYAN}2.${RESET} Dashboard:    ${GREEN}http://<your-ip>:9090${RESET}"
echo -e "  ${CYAN}3.${RESET} Login:        ${GREEN}admin / admin${RESET}"
echo -e "  ${CYAN}4.${RESET} CLI Console:  ${GREEN}python3 scripts/console.py${RESET}"
echo -e "  ${CYAN}5.${RESET} Security:     ${GREEN}python3 scripts/harden.py --apply${RESET}"

echo -e "\n${BOLD}Documentation:${RESET}"
echo -e "  README:  ${CYAN}cat README.md${RESET}"
echo -e "  Make:    ${CYAN}make help${RESET}"
echo -e "  Tests:   ${CYAN}make test-all${RESET}"

echo -e "\n${YELLOW}Disclaimer: This tool is for authorized security testing only.${RESET}"
