#!/bin/sh
# WorldC2 container health check — hits the public /api/health endpoint.
SERVER="${WORLDC2_HEALTH_URL:-http://localhost:9090}"
TIMEOUT=5

RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" "$SERVER/api/health" --max-time "$TIMEOUT" 2>/dev/null)

if [ "$RESPONSE" = "200" ]; then
    exit 0
fi
echo "UNHEALTHY - HTTP $RESPONSE"
exit 1
