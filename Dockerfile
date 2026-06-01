# Multi-stage build for Symvault Vault
# Build stage
FROM golang:1.26-alpine AS build

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/bin/symvault .

# Final stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S symvault && adduser -S symvault -G symvault -h /home/symvault

COPY --from=build /usr/bin/symvault /usr/bin/symvault

RUN mkdir -p /home/symvault/.symvault && chown -R symvault:symvault /home/symvault/.symvault

USER symvault

VOLUME ["/home/symvault/.symvault"]

LABEL org.opencontainers.image.title="Symvault Vault"
LABEL org.opencontainers.image.description="Modern CLI password manager with age encryption"
LABEL org.opencontainers.image.url="https://github.com/danieljustus/symaira-vault"
LABEL org.opencontainers.image.source="https://github.com/danieljustus/symaira-vault"
LABEL org.opencontainers.image.licenses="MIT"

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["symvault", "version"]

ENTRYPOINT ["symvault"]
CMD ["--help"]
