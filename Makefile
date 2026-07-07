.PHONY: all build clean test docker test-all harden

# Build all binaries
all: build

build: build-server build-agent

build-server:
	@echo "Building C2 server..."
	cd src/go && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../worldc2-server ./cmd/server/main.go

build-agent:
	@echo "Building agent..."
	cd src/go && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../worldc2-agent ./cmd/agent/main.go

# Cross-compile agents for all platforms
build-all:
	@echo "Building agents for all platforms..."
	cd src/go && \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../../dist/worldc2-agent-linux ./cmd/agent/main.go && \
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../../dist/worldc2-agent-windows.exe ./cmd/agent/main.go && \
		CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ../../dist/worldc2-agent-darwin-amd64 ./cmd/agent/main.go && \
		CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ../../dist/worldc2-agent-darwin-arm64 ./cmd/agent/main.go

# Run Go tests
test:
	cd src/go && go test ./... -v -race

# Run Go tests with coverage
test-coverage:
	cd src/go && go test ./... -coverprofile=coverage.out -v
	cd src/go && go tool cover -html=coverage.out -o coverage.html

# Build and run Docker environment
docker:
	docker-compose up --build -d

# Stop Docker environment
docker-down:
	docker-compose down

# Run all tests
test-all:
	@echo "Running Python syntax checks..."
	python3 -m py_compile scripts/console.py scripts/payload.py scripts/deploy.py
	@echo "Running functional tests..."
	python3 tests/run_tests.py
	@echo "Running integration tests..."
	python3 tests/integration_test.py
	@echo "Running stress tests..."
	python3 tests/stress_test.py

# Security hardening
harden:
	python3 scripts/harden.py --apply

# Generate TLS certificates
certs:
	python3 scripts/gen_certs.py --domain localhost --days 365

# Clean build artifacts
clean:
	rm -f worldc2-server worldc2-agent
	rm -f dist/worldc2-agent-*
	rm -f src/go/coverage.out src/go/coverage.html
	rm -rf payloads/*
	touch payloads/.gitkeep

# Format Go code
fmt:
	cd src/go && gofmt -w .

# Lint Go code
lint:
	cd src/go && go vet ./...

# Show help
help:
	@echo "WORLDC2 C2 - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build server and agent"
	@echo "  build-server  - Build C2 server only"
	@echo "  build-agent   - Build agent only"
	@echo "  build-all     - Cross-compile agents for all platforms"
	@echo "  test          - Run Go unit tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  docker        - Build and start Docker environment"
	@echo "  docker-down   - Stop Docker environment"
	@echo "  test-all      - Run all tests (Python + Go)"
	@echo "  harden        - Apply security hardening"
	@echo "  certs         - Generate TLS certificates"
	@echo "  clean         - Remove build artifacts"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  help          - Show this help"
