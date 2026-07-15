#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Vauchi Relay Server Installer
#
# Install locally after review (do not pipe curl directly to bash):
#   curl -fsSL -o install.sh https://raw.githubusercontent.com/megloff1/Vauchi/v1.1.0/vauchi-relay/deploy/install.sh
#   # inspect install.sh, then:
#   sudo bash install.sh v1.1.0
#
# Pass an immutable release tag (e.g. v1.1.0) or a full commit SHA.
# Do not use "main" in production: it is mutable and rebuilds on every push.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RELEASE_REF=""
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/vauchi-relay"
SERVICE_USER="vauchi"
SERVICE_GROUP="vauchi"

log_info() { printf '%b\n' "${BLUE}[INFO]${NC} $1"; }
log_success() { printf '%b\n' "${GREEN}[OK]${NC} $1"; }
log_warn() { printf '%b\n' "${YELLOW}[WARN]${NC} $1"; }
log_error() { printf '%b\n' "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
    fi
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) log_error "Unsupported architecture: $ARCH" ;;
    esac

    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="macos" ;;
        *) log_error "Unsupported OS: $OS" ;;
    esac

    log_info "Detected platform: ${OS}-${ARCH}"
}

# Check dependencies
check_dependencies() {
    for cmd in curl sha256sum; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
        fi
    done
}

# Create service user
create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        log_info "Creating service user: $SERVICE_USER"
        useradd -r -s /bin/false "$SERVICE_USER"
        log_success "User created"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

# Download and install binary from the GitLab generic package registry.
# RELEASE_REF must be an immutable release tag (e.g. v1.1.0) or a full
# commit SHA. The downloaded artifact is verified against a SHA-256
# checksum before it is installed.
install_binary() {
    log_info "Installing binary (release ref: ${RELEASE_REF})..."

    if [ "$OS" != "linux" ]; then
        log_error "Pre-built binaries are only available for Linux. Build from source manually for ${OS}-${ARCH}."
    fi

    if [ "$ARCH" != "x86_64" ]; then
        log_error "Pre-built binaries are only available for x86_64. Build from source manually for ${OS}-${ARCH}."
    fi

    TEMP_DIR=$(mktemp -d)
    # shellcheck disable=SC2064
    trap 'rm -rf "${TEMP_DIR:?}"' EXIT

    local artifact="vauchi-relay-${OS}-${ARCH}"
    local package_name="vauchi-relay"
    local project_id="77874349"
    local base_url="${VAUCHI_RELAY_PACKAGE_BASE_URL:-https://gitlab.com/api/v4/projects/${project_id}/packages/generic/${package_name}/${RELEASE_REF}}"
    local bin_url="${base_url}/${artifact}"
    local checksum_url="${base_url}/${artifact}.sha256"

    log_info "Downloading ${artifact}@${RELEASE_REF}..."
    local curl_opts=(-fsSL)
    if [ -n "${GITLAB_TOKEN:-}" ]; then
        curl_opts+=(--header "JOB-TOKEN: ${GITLAB_TOKEN}")
    fi
    curl "${curl_opts[@]}" -o "${TEMP_DIR}/${artifact}" "${bin_url}"
    curl "${curl_opts[@]}" -o "${TEMP_DIR}/${artifact}.sha256" "${checksum_url}"

    log_info "Verifying checksum..."
    (cd "${TEMP_DIR}" && sha256sum -c "${artifact}.sha256")

    log_info "Installing binary..."
    install -m 755 "${TEMP_DIR}/${artifact}" "${INSTALL_DIR}/vauchi-relay"

    log_success "Binary installed to ${INSTALL_DIR}/vauchi-relay"
}

# Create data directory
create_data_dir() {
    log_info "Creating data directory: $DATA_DIR"
    mkdir -p "$DATA_DIR"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    log_success "Data directory created"
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."

    cat > /etc/systemd/system/vauchi-relay.service << 'EOF'
[Unit]
Description=Vauchi Relay Server
Documentation=https://github.com/megloff1/Vauchi
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vauchi
Group=vauchi
ExecStart=/usr/local/bin/vauchi-relay
Restart=always
RestartSec=5

# Environment
Environment=RELAY_LISTEN_ADDR=0.0.0.0:8080
Environment=RELAY_STORAGE_BACKEND=sqlite
Environment=RELAY_DATA_DIR=/var/lib/vauchi-relay
Environment=RELAY_MAX_CONNECTIONS=1000
Environment=RELAY_BLOB_TTL_SECS=7776000
Environment=RELAY_RATE_LIMIT=60
Environment=RUST_LOG=vauchi_relay=info

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/vauchi-relay
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

# Enable and start service
start_service() {
    log_info "Enabling and starting service..."
    systemctl enable vauchi-relay
    systemctl start vauchi-relay

    sleep 2
    if systemctl is-active --quiet vauchi-relay; then
        log_success "Service started successfully"
    else
        log_warn "Service may not have started correctly. Check: systemctl status vauchi-relay"
    fi
}

# Print summary
print_summary() {
    echo ""
    printf '%b\n' "${GREEN}========================================${NC}"
    printf '%b\n' "${GREEN} Vauchi Relay installed successfully!${NC}"
    printf '%b\n' "${GREEN}========================================${NC}"
    echo ""
    echo "Service commands:"
    echo "  systemctl status vauchi-relay   # Check status"
    echo "  systemctl restart vauchi-relay  # Restart"
    echo "  journalctl -u vauchi-relay -f   # View logs"
    echo ""
    echo "Configuration:"
    echo "  Edit /etc/systemd/system/vauchi-relay.service"
    echo "  Then: systemctl daemon-reload && systemctl restart vauchi-relay"
    echo ""
    echo "Data directory: $DATA_DIR"
    if [ "${VAUCHI_RELAY_INSTALL_BINARY_ONLY:-}" != "true" ]; then
        echo "Listening on: http://0.0.0.0:8080"
    fi
    echo ""
}

# Uninstall function
uninstall() {
    log_info "Uninstalling Vauchi Relay..."

    systemctl stop vauchi-relay 2>/dev/null || true
    systemctl disable vauchi-relay 2>/dev/null || true
    rm -f /etc/systemd/system/vauchi-relay.service
    systemctl daemon-reload

    rm -f "$INSTALL_DIR/vauchi-relay"

    echo ""
    log_warn "Data directory NOT removed: $DATA_DIR"
    log_warn "User NOT removed: $SERVICE_USER"
    echo "To fully remove: rm -rf $DATA_DIR && userdel $SERVICE_USER"

    log_success "Uninstall complete"
}

# Main
main() {
    echo ""
    printf '%b\n' "${BLUE}Vauchi Relay Server Installer${NC}"
    echo "================================"
    echo ""

    if [[ "${1:-}" == "uninstall" ]]; then
        check_root
        uninstall
        exit 0
    fi

    RELEASE_REF="${1:-}"
    if [ -z "$RELEASE_REF" ]; then
        log_error "RELEASE_REF required: pass an immutable release tag (e.g. v1.1.0) or a full commit SHA."
    fi

    check_root
    check_dependencies
    detect_platform
    create_user
    install_binary
    create_data_dir

    if [ "${VAUCHI_RELAY_INSTALL_BINARY_ONLY:-}" != "true" ]; then
        install_service
        start_service
    fi

    print_summary
}

main "$@"
