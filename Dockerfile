# Minimal Dockerfile for Symaira Vault
# Uses scratch base for smallest possible image
# Build context: repository root with goreleaser-built binary

FROM scratch

# Copy CA certificates for HTTPS operations (git push/pull)
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary built by GoReleaser
COPY symaira /usr/bin/symaira

# Symaira Vault stores vault data in ~/.symaira by default
# In container context, users should mount a volume:
#   docker run -v ~/.symaira:/root/.symaira ghcr.io/danieljustus/symaira:latest
VOLUME ["/root/.symaira"]

ENTRYPOINT ["/usr/bin/symaira"]
CMD ["--help"]
