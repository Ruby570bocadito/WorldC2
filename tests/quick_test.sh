#!/bin/bash
# WORLDC2 C2 - Quick Integration Test
# Starts server, runs tests, stops server

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR" || exit 1

# Server binary: Makefile output (dist/)
SERVER_BIN="$PROJECT_DIR/dist/worldc2-server"
if [ ! -x "$SERVER_BIN" ]; then
    echo "Server binary not found at $SERVER_BIN (build with: make build-server)" >&2
    exit 1
fi

# Clean DB
rm -f "$PROJECT_DIR/worldc2.db"

# Start server in background
"$SERVER_BIN" --no-tls &
SERVER_PID=$!

# Wait for server
for i in $(seq 1 15); do
    if curl -s http://127.0.0.1:9090/api/health >/dev/null 2>&1; then
        echo "Server ready"
        break
    fi
    sleep 1
done

# Run tests
python3 "$SCRIPT_DIR/run_tests.py" --server http://127.0.0.1:9090 --user admin --password admin
TEST_EXIT=$?

# Stop server
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

exit $TEST_EXIT
