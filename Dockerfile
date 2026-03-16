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
RUN cargo install cargo-chef \
    && apt-get update && apt-get install -y --no-install-recommends \
       musl-tools cmake clang perl \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json

# Build stage: compile the actual source (deps already cached)
FROM rust:1.93-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
       musl-tools cmake clang perl \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo
COPY . ./relay
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cd relay && cargo build --release --target x86_64-unknown-linux-musl
# Prepare build metadata (distroless has no shell, so we do it here)
ARG BUILD_INFO='{"sha":"development","ref":"local","built":"unknown"}'
RUN echo "${BUILD_INFO}" > /tmp/build-info.json \
    && mkdir -p /tmp/data && chown 65534:65534 /tmp/data

# Runtime stage — distroless/static for zero OS-level CVEs
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/relay/target/x86_64-unknown-linux-musl/release/vauchi-relay /usr/local/bin/
COPY --from=builder /tmp/build-info.json /usr/share/build-info.json
COPY --chown=nonroot:nonroot --from=builder /tmp/data /data

LABEL service="vauchi-relay"

# Expose default port
EXPOSE 8080

# Data volume for persistent storage
VOLUME /data

# Run as non-root (distroless provides uid 65534/nobody)
USER nonroot

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

# No HEALTHCHECK — distroless has no shell/curl.
# Kamal uses its own HTTP probe; Kubernetes uses tcpSocket probes.

ENTRYPOINT ["vauchi-relay"]
