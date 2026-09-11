.PHONY: all build build-server build-agent build-agent-all clean test test-coverage test-all \
        web web-dev docker docker-down harden certs fmt lint help

# Default target
all: build

## build: compile server and agent into dist/
build: build-server build-agent

build-server:
	@echo "Building C2 server..."
	cd src/go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-server ./cmd/server

build-agent:
	@echo "Building agent..."
	cd src/go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-agent ./cmd/agent

## build-agent-all: cross-compile the agent for all supported platforms
build-agent-all:
	@echo "Building agents for all platforms..."
	cd src/go && \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-agent-linux ./cmd/agent && \
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-agent-windows.exe ./cmd/agent && \
		CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-agent-darwin-amd64 ./cmd/agent && \
		CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o ../../dist/worldc2-agent-darwin-arm64 ./cmd/agent

## web: build the Vue dashboard into web/dist/
web:
	cd web && npm ci && npm run build

web-dev:
	cd web && npm run dev

clean:
	rm -rf dist worldc2-server worldc2-agent web/dist coverage.out coverage.html
	rm -f worldc2.db

## test: run Go tests with the race detector
test:
	cd src/go && go test ./... -race

test-coverage:
	cd src/go && go test ./... -coverprofile=coverage.out
	cd src/go && go tool cover -html=coverage.out -o coverage.html

## test-all: full pipeline — Go tests, Python syntax, frontend build
test-all:
	@echo "==> Go tests (race)..."
	cd src/go && go test ./... -race || exit 1
	@echo "==> Python syntax checks..."
	python3 -m py_compile scripts/*.py tests/*.py || exit 1
	@echo "==> Frontend build..."
	cd web && npm ci && npm run build || exit 1
	@echo "==> All tests passed."

## docker: build and start the docker-compose environment
docker:
	docker compose up --build -d

docker-down:
	docker compose down

## harden: run the security audit script (report only)
harden:
	python3 scripts/harden.py --project .

## certs: generate a self-signed TLS certificate for localhost
certs:
	python3 scripts/gen_certs.py --domain localhost --days 365

fmt:
	cd src/go && gofmt -w .

lint:
	cd src/go && go vet ./...

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /make /'
