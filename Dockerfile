# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Planner stage: generate recipe.json for dependency caching
FROM rust:1.93-bookworm AS planner
RUN cargo install cargo-chef
WORKDIR /app
COPY . ./relay
RUN cd relay && cargo chef prepare --recipe-path /app/recipe.json

# Cook stage: build dependencies only (cached layer)
FROM rust:1.93-bookworm AS cook
RUN cargo install cargo-chef
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage: compile the actual source (deps already cached)
FROM rust:1.93-bookworm AS builder
WORKDIR /app
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo
COPY . ./relay
RUN cd relay && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  ca-certificates \
  curl \
  libssl3 \
  && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/relay/target/release/vauchi-relay /usr/local/bin/

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8080/health || exit 1

CMD ["vauchi-relay"]
