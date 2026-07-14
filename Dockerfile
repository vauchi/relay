# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Defaults to the canonical Docker Hub path so `docker build .` works
# locally without any build args. CI overrides this to GitLab's
# group-level dependency proxy via
# `--build-arg HUB=${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}` so the
# Hub rate limit doesn't take builds down (see _private!1143 +
# relay!270 for the cross-repo cascade).
ARG HUB=docker.io/library

# Planner stage: generate recipe.json for dependency caching
FROM ${HUB}/rust:1.93-bookworm AS planner
RUN cargo install cargo-chef
WORKDIR /app
COPY . ./relay
RUN cd relay && cargo chef prepare --recipe-path /app/recipe.json

# Cook stage: build dependencies only (cached layer)
FROM ${HUB}/rust:1.93-bookworm AS cook
RUN cargo install cargo-chef
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage: compile the actual source (deps already cached)
FROM ${HUB}/rust:1.93-bookworm AS builder
WORKDIR /app
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo
COPY . ./relay
RUN cd relay && cargo build --release
# Prepare build metadata (distroless has no shell, so we do it here)
ARG BUILD_INFO='{"sha":"development","ref":"local","built":"unknown"}'
RUN echo "${BUILD_INFO}" > /tmp/build-info.json \
    && mkdir -p /tmp/data && chown 65534:65534 /tmp/data

# Runtime stage — distroless glibc without unused OpenSSL libraries
# Use :latest tag to get latest security patches for base OS libraries
# (zlib, libpng, glibc, etc.). Pinned distroless images accumulate CVEs.
FROM gcr.io/distroless/base-nossl-debian12:latest

COPY --from=builder /app/relay/target/release/vauchi-relay /usr/local/bin/
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
ENV RELAY_BLOB_TTL_SECS=10368000
ENV RELAY_RATE_LIMIT=60
ENV RELAY_CLEANUP_INTERVAL=3600
ENV RELAY_STORAGE_BACKEND=sqlite
ENV RELAY_DATA_DIR=/data
ENV RUST_LOG=vauchi_relay=info

# No HEALTHCHECK — distroless has no shell/curl.
# Kamal uses its own HTTP probe; Kubernetes uses tcpSocket probes.

ENTRYPOINT ["vauchi-relay"]
