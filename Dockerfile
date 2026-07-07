FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /app
COPY src/go/go.mod src/go/go.sum ./
RUN go mod download

COPY src/go/ .

RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /worldc2-server ./cmd/server/main.go
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /worldc2-agent ./cmd/agent/main.go

FROM alpine:3.20

RUN apk add --no-cache curl ca-certificates

WORKDIR /app
COPY --from=builder /worldc2-server .
COPY --from=builder /worldc2-agent .
COPY config.yaml .
COPY web/dist ./web/dist

RUN mkdir -p web/dist data loot modules

EXPOSE 8443 8445 8446 9090

CMD ["./worldc2-server", "-config", "config.yaml"]
