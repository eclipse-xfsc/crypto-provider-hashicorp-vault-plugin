# ===== STAGE 1: Builder =====
FROM golang:1.24-alpine AS builder

# Benötigte Pakete (z.B. git, ca-certificates)
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Go Modules zuerst kopieren und Dependencies laden
COPY go.mod go.sum ./
RUN go mod download

# Restlichen Source-Code kopieren
COPY . .

# Optional: Setze GOFLAGS (z.B. für kleinere Binaries)
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Baue das Binary (pfad an dein main-Package anpassen)
RUN go build -o server ./cmd/server

# ===== STAGE 2: Runtime =====
# Variante 1: sehr schlank mit scratch
# FROM scratch

# Variante 2: klein, aber mit Debug-Möglichkeiten
FROM alpine:3.20

# CA-Zertifikate für TLS, DNS etc.
RUN apk add --no-cache ca-certificates

# Working dir im Runtime-Image
WORKDIR /app

# Binary aus Builder-Stage kopieren
COPY --from=builder /app/server /app/server

# (Falls du z.B. Migrations, Configs, TLS-Zertifikate mitkopieren willst:)
# COPY --from=builder /app/migrations /app/migrations
# COPY config.yaml /app/config.yaml

# Non-root User (empfohlen)
RUN adduser -D -g '' appuser
USER appuser

# gRPC läuft typischerweise auf 50051 (anpassen, falls nötig)
EXPOSE 50051

# Startkommando
ENTRYPOINT ["/app/server"]
