#!/bin/bash
# WORLDC2 C2 - Quick Integration Test
# Starts server, runs tests, stops server

cd /mnt/c/Users/Rby/Desktop/WORLDC2-master/WORLDC2-master

# Clean DB
rm -f worldc2.db

# Start server in background
./worldc2-server --no-tls &
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
python3 tests/run_tests.py --server http://127.0.0.1:9090 --user admin --password admin
TEST_EXIT=$?

# Stop server
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

exit $TEST_EXIT
