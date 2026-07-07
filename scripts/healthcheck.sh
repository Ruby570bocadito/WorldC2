#!/bin/bash
# WORLDC2 C2 - Docker Health Check
# Verifica que el servidor C2 está funcionando correctamente

SERVER="http://localhost:9090"
TIMEOUT=5

# Check API health
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u admin:admin "$SERVER/api/health" --max-time $TIMEOUT 2>/dev/null)

if [ "$RESPONSE" = "200" ]; then
    # Get session count
    SESSIONS=$(curl -s -u admin:admin "$SERVER/api/health" --max-time $TIMEOUT 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('active_sessions',0))" 2>/dev/null)
    echo "HEALTHY - Sessions: ${SESSIONS:-0}"
    exit 0
else
    echo "UNHEALTHY - HTTP $RESPONSE"
    exit 1
fi
