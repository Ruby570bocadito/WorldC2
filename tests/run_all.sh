#!/bin/bash
# WORLDC2 C2 - Full Test Pipeline
# Ejecuta todo el testing: build, deploy, integration, stress, security

set -e

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

SERVER="http://127.0.0.1:9090"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BOLD}${CYAN}"
echo "   ╔══════════════════════════════════════════════╗"
echo "   ║         WORLDC2 C2 - Full Test Pipeline          ║"
echo "   ╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# === Phase 1: Code Quality ===
echo -e "\n${BOLD}[Phase 1] Code Quality Checks${RESET}"

echo -e "${CYAN}[1.1] Checking Python syntax...${RESET}"
python3 -m py_compile "$SCRIPT_DIR/run_tests.py" && echo -e "  ${GREEN}[OK]${RESET} run_tests.py"
python3 -m py_compile "$SCRIPT_DIR/stress_test.py" && echo -e "  ${GREEN}[OK]${RESET} stress_test.py"
python3 -m py_compile "$SCRIPT_DIR/integration_test.py" && echo -e "  ${GREEN}[OK]${RESET} integration_test.py"
python3 -m py_compile "$PROJECT_DIR/scripts/console.py" && echo -e "  ${GREEN}[OK]${RESET} console.py"
python3 -m py_compile "$PROJECT_DIR/scripts/payload.py" && echo -e "  ${GREEN}[OK]${RESET} payload.py"
python3 -m py_compile "$PROJECT_DIR/scripts/deploy.py" && echo -e "  ${GREEN}[OK]${RESET} deploy.py"

echo -e "${CYAN}[1.2] Checking Go syntax (if go available)...${RESET}"
if command -v go &> /dev/null; then
    cd "$PROJECT_DIR/src/go"
    go vet ./... 2>&1 || echo -e "  ${YELLOW}[WARN]${RESET} go vet found issues"
    cd "$PROJECT_DIR"
else
    echo -e "  ${YELLOW}[SKIP]${RESET} Go not installed"
fi

# === Phase 2: Docker Environment ===
echo -e "\n${BOLD}[Phase 2] Docker Environment${RESET}"

if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo -e "${CYAN}[2.1] Building Docker images...${RESET}"
    cd "$PROJECT_DIR"
    docker-compose build --no-cache 2>&1 | tail -5

    echo -e "${CYAN}[2.2] Starting C2 server...${RESET}"
    docker-compose up -d c2-server

    echo -e "${CYAN}[2.3] Waiting for server health...${RESET}"
    for i in $(seq 1 30); do
        if curl -s -u admin:admin "$SERVER/api/health" | grep -q "ok"; then
            echo -e "  ${GREEN}[OK]${RESET} Server is healthy"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo

    echo -e "${CYAN}[2.4] Starting test agents...${RESET}"
    docker-compose up -d agent-linux-1 agent-linux-2

    echo -e "${CYAN}[2.5] Waiting for agent connections...${RESET}"
    sleep 10
else
    echo -e "  ${YELLOW}[SKIP]${RESET} Docker not available"
fi

# === Phase 3: Functional Tests ===
echo -e "\n${BOLD}[Phase 3] Functional Tests${RESET}"

echo -e "${CYAN}[3.1] Running API tests...${RESET}"
python3 "$SCRIPT_DIR/run_tests.py" --server "$SERVER" || echo -e "  ${YELLOW}[WARN]${RESET} Some tests failed"

echo -e "${CYAN}[3.2] Running integration tests...${RESET}"
python3 "$SCRIPT_DIR/integration_test.py" --server "$SERVER" || echo -e "  ${YELLOW}[WARN]${RESET} Integration tests had failures"

# === Phase 4: Stress Tests ===
echo -e "\n${BOLD}[Phase 4] Stress Tests${RESET}"

echo -e "${CYAN}[4.1] Running stress tests...${RESET}"
python3 "$SCRIPT_DIR/stress_test.py" --server "$SERVER" --concurrent 50 || echo -e "  ${YELLOW}[WARN]${RESET} Stress tests had issues"

# === Phase 5: Security Checks ===
echo -e "\n${BOLD}[Phase 5] Security Checks${RESET}"

echo -e "${CYAN}[5.1] Checking for hardcoded credentials...${RESET}"
if grep -r "password.*admin" "$PROJECT_DIR/config.yaml" > /dev/null 2>&1; then
    echo -e "  ${YELLOW}[WARN]${RESET} Default credentials in config.yaml"
fi

echo -e "${CYAN}[5.2] Checking CORS configuration...${RESET}"
CORS=$(curl -s -I -X OPTIONS "$SERVER/api/health" -H "Origin: http://evil.com" 2>/dev/null | grep -i "access-control-allow-origin" || echo "")
if echo "$CORS" | grep -q "\*"; then
    echo -e "  ${RED}[FAIL]${RESET} Wildcard CORS detected"
elif [ -n "$CORS" ]; then
    echo -e "  ${GREEN}[OK]${RESET} CORS is restricted"
else
    echo -e "  ${YELLOW}[INFO]${RESET} No CORS headers (may be OK)"
fi

echo -e "${CYAN}[5.3] Checking auth enforcement...${RESET}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/sessions")
if [ "$STATUS" = "401" ]; then
    echo -e "  ${GREEN}[OK]${RESET} Auth required for API"
else
    echo -e "  ${RED}[FAIL]${RESET} API accessible without auth (HTTP $STATUS)"
fi

# === Cleanup ===
echo -e "\n${BOLD}[Cleanup] Stopping Docker containers...${RESET}"
if command -v docker-compose &> /dev/null; then
    cd "$PROJECT_DIR"
    docker-compose down 2>/dev/null || true
fi

echo -e "\n${BOLD}${GREEN}Test pipeline complete!${RESET}"
