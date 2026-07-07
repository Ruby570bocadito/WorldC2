#!/bin/bash
# WORLDC2 C2 - Full Integration Test
# Tests: Server startup, API, authentication, agent connection, commands, modules, tunnels

set -e

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

SERVER="http://127.0.0.1:9090"
TOKEN=""
PASS=0
FAIL=0
ERRORS=""

log() { echo -e "${BOLD}${CYAN}[$1]${RESET} $2"; }
pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1: $2"; FAIL=$((FAIL+1)); ERRORS="$ERRORS\n  - $1: $2"; }

api() {
    local method=$1 path=$2 data=$3
    local headers="-H Content-Type: application/json"
    if [ -n "$TOKEN" ]; then
        headers="$headers -H Authorization: Bearer $TOKEN"
    fi
    if [ -n "$data" ]; then
        curl -s -X "$method" $headers -d "$data" "$SERVER$path" 2>/dev/null
    else
        curl -s -X "$method" $headers "$SERVER$path" 2>/dev/null
    fi
}

login() {
    local resp
    resp=$(curl -s -X POST -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"admin"}' "$SERVER/api/login")
    TOKEN=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    [ -z "$TOKEN" ] && { echo -e "${RED}Login failed${RESET}"; return 1; }
    return 0
}

# ============================================
# TEST 1: Server Health
# ============================================
test_health() {
    log "TEST" "1. Server Health"
    local resp
    resp=$(api GET "/api/health")
    
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'" 2>/dev/null; then
        pass "Health status ok"
    else
        fail "Health status" "Expected ok, got: $resp"
    fi
    
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'active_sessions' in d" 2>/dev/null; then
        pass "Active sessions field"
    else
        fail "Active sessions field" "Missing"
    fi
    
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'listeners' in d" 2>/dev/null; then
        pass "Listeners field"
    else
        fail "Listeners field" "Missing"
    fi
}

# ============================================
# TEST 2: Authentication & Authorization
# ============================================
test_auth() {
    log "TEST" "2. Authentication"
    
    # Valid login
    local resp
    resp=$(curl -s -X POST -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"admin"}' "$SERVER/api/login")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'token' in d" 2>/dev/null; then
        pass "Valid login returns token"
    else
        fail "Valid login" "$resp"
    fi

    # Wrong password
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"wrongpass"}' "$SERVER/api/login")
    [ "$http_code" = "401" ] && pass "Wrong password rejected (401)" || fail "Wrong password" "HTTP $http_code"

    # No auth on protected endpoint
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/sessions")
    [ "$http_code" = "401" ] && pass "No auth rejected (401)" || fail "No auth" "HTTP $http_code"

    # Invalid token
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid.token.here" "$SERVER/api/sessions")
    [ "$http_code" = "401" ] && pass "Invalid token rejected (401)" || fail "Invalid token" "HTTP $http_code"

    # Refresh token
    local refresh_resp
    refresh_resp=$(curl -s -X POST -H "Content-Type: application/json" \
         -d "$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('{\"refresh_token\":\"'+d.get('refresh_token','')+'\"}')")" \
         "$SERVER/api/refresh")
    if echo "$refresh_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'token' in d" 2>/dev/null; then
        pass "Refresh token works"
    else
        fail "Refresh token" "$refresh_resp"
    fi
}

# ============================================
# TEST 3: CORS & Security Headers
# ============================================
test_security() {
    log "TEST" "3. Security"
    
    # CORS - evil.com should NOT be allowed
    local origin
    origin=$(curl -s -I -X OPTIONS -H "Origin: http://evil.com" "$SERVER/api/health" 2>/dev/null | grep -i "access-control-allow-origin" | tr -d '\r' | awk '{print $2}')
    if [ "$origin" != "http://evil.com" ]; then
        pass "CORS blocks evil.com"
    else
        fail "CORS" "Allows evil.com"
    fi

    # Security headers
    local headers
    headers=$(curl -s -I "$SERVER/api/health" 2>/dev/null)
    
    echo "$headers" | grep -qi "x-content-type-options: nosniff" && pass "X-Content-Type-Options" || fail "X-Content-Type-Options" "Missing"
    echo "$headers" | grep -qi "x-frame-options: deny" && pass "X-Frame-Options" || fail "X-Frame-Options" "Missing"
    echo "$headers" | grep -qi "strict-transport-security" && pass "HSTS header" || fail "HSTS" "Missing"
}

# ============================================
# TEST 4: Sessions API
# ============================================
test_sessions() {
    log "TEST" "4. Sessions API"
    
    local resp
    resp=$(api GET "/api/sessions")
    
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "Sessions returns list"
    else
        fail "Sessions format" "$resp"
    fi

    # Session detail (non-existent)
    resp=$(api GET "/api/sessions/nonexistent")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'session' in d or 'error' in d or d is None or d == {}" 2>/dev/null; then
        pass "Session detail endpoint works"
    else
        fail "Session detail" "$resp"
    fi
}

# ============================================
# TEST 5: Credential Vault
# ============================================
test_vault() {
    log "TEST" "5. Credential Vault"
    
    # Add
    local resp
    resp=$(api POST "/api/vault" '{"username":"admin","password":"P@ssw0rd!","domain":"CORP.LOCAL","service":"ldap","host":"dc01.corp.local"}')
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'id' in d" 2>/dev/null; then
        pass "Add credential"
    else
        fail "Add credential" "$resp"
    fi

    # Add another
    api POST "/api/vault" '{"username":"svc_account","password":"S3cret!","domain":"CORP.LOCAL","service":"mssql","host":"sql01.corp.local"}'

    # Search
    resp=$(api GET "/api/vault?q=admin")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list) and len(d)>0" 2>/dev/null; then
        pass "Search credential"
    else
        fail "Search credential" "$resp"
    fi

    # List
    resp=$(api GET "/api/vault")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list) and len(d)>=2" 2>/dev/null; then
        pass "List credentials (>=2)"
    else
        fail "List credentials" "$resp"
    fi
}

# ============================================
# TEST 6: Dynamic Modules
# ============================================
test_modules() {
    log "TEST" "6. Dynamic Modules"
    
    local resp
    resp=$(api GET "/api/modules")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "List modules"
    else
        fail "List modules" "$resp"
    fi
}

# ============================================
# TEST 7: File Management
# ============================================
test_files() {
    log "TEST" "7. File Management"
    
    local resp
    resp=$(api GET "/api/files")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list)" 2>/dev/null; then
        pass "List files"
    else
        fail "List files" "$resp"
    fi

    # Store file
    resp=$(api POST "/api/files" '{"session_id":"test-session","filename":"test.txt","module":"exfil","data":"SGVsbG8gV29ybGQ="}')
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'id' in d" 2>/dev/null; then
        pass "Store file"
    else
        fail "Store file" "$resp"
    fi
}

# ============================================
# TEST 8: Error Handling
# ============================================
test_errors() {
    log "TEST" "8. Error Handling"
    
    # Invalid JSON
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" -d "not json" "$SERVER/api/cmd")
    [ "$http_code" = "400" ] && pass "Invalid JSON (400)" || fail "Invalid JSON" "HTTP $http_code"

    # Missing agent_id
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" -d '{"command":"whoami"}' "$SERVER/api/cmd")
    [ "$http_code" = "400" ] && pass "Missing agent_id (400)" || fail "Missing agent_id" "HTTP $http_code"

    # Non-existent endpoint
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$SERVER/api/nonexistent")
    [ "$http_code" = "404" ] && pass "404 for unknown endpoint" || fail "404" "HTTP $http_code"

    # Method not allowed
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" "$SERVER/api/health")
    [ "$http_code" = "405" ] && pass "405 for wrong method" || fail "405" "HTTP $http_code"
}

# ============================================
# TEST 9: Rate Limiting
# ============================================
test_rate_limit() {
    log "TEST" "9. Rate Limiting"
    
    local rate_limited=0
    for i in $(seq 1 65); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/api/health")
        if [ "$http_code" = "429" ]; then
            rate_limited=1
            break
        fi
    done
    
    [ $rate_limited -eq 1 ] && pass "Rate limiting active (429)" || fail "Rate limiting" "No 429 after 65 requests"
}

# ============================================
# TEST 10: Operators Management
# ============================================
test_operators() {
    log "TEST" "10. Operators Management"
    
    # List operators
    local resp
    resp=$(api GET "/api/operators")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d,list) and len(d)>0" 2>/dev/null; then
        pass "List operators"
    else
        fail "List operators" "$resp"
    fi

    # Create operator
    resp=$(api POST "/api/operators" '{"username":"testop","password":"TestPass123","role":"operator"}')
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='created'" 2>/dev/null; then
        pass "Create operator"
    else
        fail "Create operator" "$resp"
    fi

    # Login as new operator
    local new_resp
    new_resp=$(curl -s -X POST -H "Content-Type: application/json" \
         -d '{"username":"testop","password":"TestPass123"}' "$SERVER/api/login")
    if echo "$new_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'token' in d" 2>/dev/null; then
        pass "New operator login"
    else
        fail "New operator login" "$new_resp"
    fi

    # Delete operator
    resp=$(api GET "/api/operators")
    local op_id
    op_id=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(o['id']) for o in d if o['username']=='testop']" 2>/dev/null)
    if [ -n "$op_id" ]; then
        local del_code
        del_code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $TOKEN" "$SERVER/api/operators/$op_id")
        [ "$del_code" = "200" ] && pass "Delete operator" || fail "Delete operator" "HTTP $del_code"
    else
        fail "Delete operator" "Could not find operator ID"
    fi
}

# ============================================
# MAIN
# ============================================
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║           WORLDC2 C2 - Integration Test Suite            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Wait for server
echo -e "${YELLOW}Waiting for server...${RESET}"
for i in $(seq 1 30); do
    if curl -s "$SERVER/api/health" >/dev/null 2>&1; then
        echo -e "${GREEN}Server ready!${RESET}\n"
        break
    fi
    [ $i -eq 30 ] && { echo -e "${RED}Server not ready after 30s${RESET}"; exit 1; }
    sleep 1
done

# Login
login || exit 1

# Run all tests
test_health
test_auth
test_security
test_sessions
test_vault
test_modules
test_files
test_errors
test_rate_limit
test_operators

# Summary
echo -e "\n${BOLD}══════════════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}Passed: $PASS${RESET} | ${RED}Failed: $FAIL${RESET} | Total: $((PASS+FAIL))"
if [ $FAIL -gt 0 ]; then
    echo -e "\n${RED}${BOLD}Failures:${RESET}$ERRORS"
fi
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"

exit $FAIL
