# Build stage
FROM rust:1.78-bookworm AS builder

WORKDIR /app

# Copy workspace files
COPY code/Cargo.toml code/Cargo.lock ./

# Copy only needed crates for relay
COPY code/vauchi-core ./vauchi-core
COPY code/vauchi-relay ./vauchi-relay

# Create stub Cargo.toml files for workspace members we don't need
# This allows the workspace to resolve without copying all source code
RUN mkdir -p vauchi-cli/src && \
    echo '[package]\nname = "vauchi-cli"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]' > vauchi-cli/Cargo.toml && \
    echo 'fn main() {}' > vauchi-cli/src/main.rs && \
    mkdir -p vauchi-mobile/src && \
    echo '[package]\nname = "vauchi-mobile"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib", "staticlib"]\n\n[dependencies]' > vauchi-mobile/Cargo.toml && \
    echo '' > vauchi-mobile/src/lib.rs && \
    mkdir -p vauchi-tui/src && \
    echo '[package]\nname = "vauchi-tui"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]' > vauchi-tui/Cargo.toml && \
    echo 'fn main() {}' > vauchi-tui/src/main.rs && \
    mkdir -p vauchi-desktop/src-tauri/src && \
    echo '[package]\nname = "vauchi-desktop"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\nname = "vauchi_desktop_lib"\ncrate-type = ["lib", "cdylib", "staticlib"]\n\n[dependencies]' > vauchi-desktop/src-tauri/Cargo.toml && \
    echo '' > vauchi-desktop/src-tauri/src/lib.rs

# Build release binary
RUN cargo build --release -p vauchi-relay

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/vauchi-relay /usr/local/bin/

# Create non-root user and data directory
RUN useradd -r -s /bin/false vauchi \
    && mkdir -p /data \
    && chown vauchi:vauchi /data

# Switch to non-root user
USER vauchi

LABEL service="vauchi-relay"

# Expose default port
EXPOSE 8080

# Data volume for persistent storage
VOLUME /data

# Environment variables with defaults
ENV RELAY_LISTEN_ADDR=0.0.0.0:8080
ENV RELAY_MAX_CONNECTIONS=1000
ENV RELAY_MAX_MESSAGE_SIZE=1048576
ENV RELAY_BLOB_TTL_SECS=7776000
ENV RELAY_RATE_LIMIT=60
ENV RELAY_CLEANUP_INTERVAL=3600
ENV RELAY_STORAGE_BACKEND=sqlite
ENV RELAY_DATA_DIR=/data
ENV RUST_LOG=vauchi_relay=info

# Healthcheck - verify the health endpoint returns 200 OK
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD bash -c 'printf "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" > /dev/tcp/localhost/8080 && head -n 1 < /dev/tcp/localhost/8080 | grep -q "200 OK"' || exit 1

CMD ["vauchi-relay"]
