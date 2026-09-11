# ---------- Frontend build ----------
FROM node:20-alpine AS webbuilder

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ .
RUN npm run build

# ---------- Go build ----------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /src
COPY src/go/go.mod src/go/go.sum ./
RUN go mod download

COPY src/go/ .

# modernc.org/sqlite is a pure-Go driver — CGO_ENABLED=0 keeps the build
# static, cross-compilable and consistent with Makefile/CI.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /worldc2-server ./cmd/server

# ---------- Runtime ----------
FROM alpine:3.20

RUN apk add --no-cache curl ca-certificates \
    && addgroup -S worldc2 \
    && adduser -S worldc2 -G worldc2

WORKDIR /app
COPY --from=builder /worldc2-server .
COPY --from=webbuilder /web/dist ./web/dist
COPY config.example.yaml ./config.yaml

RUN mkdir -p data loot modules \
    && chown -R worldc2:worldc2 /app

USER worldc2

EXPOSE 8443 8445 8446 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -sf http://localhost:9090/api/health || exit 1

CMD ["./worldc2-server", "-config", "config.yaml"]
