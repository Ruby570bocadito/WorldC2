#!/bin/bash
# WORLDC2 C2 - Docker Test Runner
# Runs comprehensive tests against a Docker-deployed C2 server

set -e

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

SERVER="http://127.0.0.1:9090"
TOKEN=""
PASS=0
FAIL=0

log() { echo -e "${BOLD}${CYAN}[TEST]${RESET} $1"; }
pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1: $2"; FAIL=$((FAIL+1)); }

# --- Helper functions ---
api_get() {
    curl -s -H "Authorization: Bearer $TOKEN" "$SERVER$1" 2>/dev/null
}

api_post() {
    curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
         -d "$2" "$SERVER$1" 2>/dev/null
}

login() {
    local resp
    resp=$(curl -s -X POST -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"admin"}' "$SERVER/api/login")
    TOKEN=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}Login failed${RESET}"
        exit 1
    fi
}

# --- Test suite ---
test_health() {
    log "Health endpoint"
    local resp
    resp=$(api_get "/api/health")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'" 2>/dev/null; then
        pass "Health returns ok"
    else
        fail "Health check" "$resp"
    fi
}

test_auth() {
    log "Authentication"
    
    # Wrong password
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"wrong"}' "$SERVER/api/login")
    if [ "$resp" = "401" ]; then
        pass "Wrong password rejected"
    else
        fail "Wrong password" "HTTP $resp"
    fi

    # No auth on protected endpoint
    resp=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/sessions")
    if [ "$resp" = "401" ]; then
        pass "No auth rejected"
    else
        fail "No auth" "HTTP $resp"
    fi

    # Invalid token
    resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid.token.here" "$SERVER/api/sessions")
    if [ "$resp" = "401" ]; then
        pass "Invalid token rejected"
    else
        fail "Invalid token" "HTTP $resp"
    fi
}

test_cors() {
    log "CORS configuration"
    local origin
    origin=$(curl -s -I -X OPTIONS -H "Origin: http://evil.com" "$SERVER/api/health" 2>/dev/null | grep -i "access-control-allow-origin" | tr -d '\r')
    if echo "$origin" | grep -q "evil.com"; then
        fail "CORS" "Allows evil.com origin"
    else
        pass "CORS restricted"
    fi
}

test_sessions() {
    log "Sessions API"
    local resp
    resp=$(api_get "/api/sessions")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "Sessions returns list"
    else
        fail "Sessions format" "$resp"
    fi
}

test_vault() {
    log "Credential Vault"
    
    # Add credential
    local resp
    resp=$(api_post "/api/vault" '{"username":"testuser","password":"testpass","domain":"TEST","service":"http"}')
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'id' in d" 2>/dev/null; then
        pass "Add credential"
    else
        fail "Add credential" "$resp"
    fi

    # Search credential
    resp=$(api_get "/api/vault?q=testuser")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d)>0" 2>/dev/null; then
        pass "Search credential"
    else
        fail "Search credential" "$resp"
    fi

    # List credentials
    resp=$(api_get "/api/vault")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "List credentials"
    else
        fail "List credentials" "$resp"
    fi
}

test_modules() {
    log "Dynamic Modules"
    local resp
    resp=$(api_get "/api/modules")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "List modules"
    else
        fail "List modules" "$resp"
    fi
}

test_files() {
    log "File Management"
    local resp
    resp=$(api_get "/api/files")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "List files"
    else
        fail "List files" "$resp"
    fi
}

test_error_handling() {
    log "Error Handling"
    
    # Invalid JSON
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" -d "not json" "$SERVER/api/cmd")
    if [ "$resp" = "400" ]; then
        pass "Invalid JSON rejected"
    else
        fail "Invalid JSON" "HTTP $resp"
    fi

    # Non-existent endpoint
    resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$SERVER/api/nonexistent")
    if [ "$resp" = "404" ]; then
        pass "Non-existent endpoint returns 404"
    else
        fail "Non-existent endpoint" "HTTP $resp"
    fi
}

test_rate_limiting() {
    log "Rate Limiting"
    local count=0
    for i in $(seq 1 70); do
        resp=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/health")
        if [ "$resp" = "429" ]; then
            count=$((count+1))
            break
        fi
    done
    if [ $count -gt 0 ]; then
        pass "Rate limiting active (429 after burst)"
    else
        fail "Rate limiting" "No 429 response after 70 requests"
    fi
}

test_security_headers() {
    log "Security Headers"
    local headers
    headers=$(curl -s -I "$SERVER/api/health" 2>/dev/null)
    
    if echo "$headers" | grep -qi "x-content-type-options: nosniff"; then
        pass "X-Content-Type-Options header"
    else
        fail "X-Content-Type-Options" "Missing"
    fi
    
    if echo "$headers" | grep -qi "x-frame-options: deny"; then
        pass "X-Frame-Options header"
    else
        fail "X-Frame-Options" "Missing"
    fi
}

# --- Main ---
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║         WORLDC2 C2 - Docker Test Runner          ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# Wait for server
echo -e "${YELLOW}Waiting for server...${RESET}"
for i in $(seq 1 30); do
    if curl -s "$SERVER/api/health" >/dev/null 2>&1; then
        echo -e "${GREEN}Server ready!${RESET}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}Server not ready after 30s${RESET}"
        exit 1
    fi
    sleep 1
done

login

test_health
test_auth
test_cors
test_sessions
test_vault
test_modules
test_files
test_error_handling
test_rate_limiting
test_security_headers

echo -e "\n${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}Passed: $PASS${RESET} | ${RED}Failed: $FAIL${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"

exit $FAIL
