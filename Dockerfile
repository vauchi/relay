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

# Shared chef base. kaniko unpacks the base rootfs once per stage that a
# COPY touches, and this image is ~1.5 GB — three independent
# `FROM rust:` stages cost three unpacks (~12 min each, ~35 of the ~53
# minute build, which is what pushed build:docker past its timeout).
# Deriving planner and builder from one prepared base also installs
# cargo-chef once instead of twice.
FROM ${HUB}/rust:1.93-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Planner stage: generate recipe.json for dependency caching
FROM chef AS planner
COPY . ./relay
RUN cd relay && cargo chef prepare --recipe-path /app/recipe.json

# Build stage: cook dependencies, then compile the source. Cooking in the
# same stage that builds keeps the dependency target/ and the cargo
# registry in place, replacing two large cross-stage COPYs of exactly the
# artifacts this stage is about to use.
FROM chef AS builder
# Pin one target dir for BOTH steps. `cargo chef cook` runs at /app and
# wrote /app/target, while the build ran in /app/relay against
# /app/relay/target — so the cooked dependencies were never reused and
# every image rebuilt the full tree from scratch. That, not the rootfs
# unpacks alone, is why this job outgrew its timeout.
ENV CARGO_TARGET_DIR=/app/target
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . ./relay
RUN cd relay && cargo build --release
# Prepare build metadata (distroless has no shell, so we do it here)
ARG BUILD_INFO='{"sha":"development","ref":"local","built":"unknown"}'
RUN echo "${BUILD_INFO}" > /tmp/build-info.json \
    && mkdir -p /tmp/data && chown 65534:65534 /tmp/data

# Stage libgcc_s.so.1 at its native multiarch path so the runtime COPY below
# is arch-agnostic: x86_64-linux-gnu on amd64, aarch64-linux-gnu on arm64.
# Required to build this image natively on the arm64 Pi runner.
RUN set -eux; \
    lib="$(find /lib /usr/lib -name 'libgcc_s.so.1' | head -n1)"; \
    mkdir -p "/staging$(dirname "$lib")"; \
    cp "$lib" "/staging$(dirname "$lib")/"

# Runtime stage — distroless glibc without unused OpenSSL libraries
# Use :latest tag to get latest security patches for base OS libraries
# (zlib, libpng, glibc, etc.). Pinned distroless images accumulate CVEs.
FROM gcr.io/distroless/base-nossl-debian12:latest

# Rust binaries still need libgcc_s for panic unwinding; base-nossl omits it.
# Staged arch-agnostically in the builder above (see the /staging copy).
COPY --from=builder /staging/ /

COPY --from=builder /app/target/release/vauchi-relay /usr/local/bin/
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
