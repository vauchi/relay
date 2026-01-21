#!/usr/bin/env bash
#
# Vauchi Relay Server Installer
# Usage: curl -sSL https://raw.githubusercontent.com/megloff1/Vauchi/main/vauchi-relay/deploy/install.sh | bash
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="megloff1/Vauchi"
BINARY_NAME="vauchi-relay"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/vauchi-relay"
SERVICE_USER="vauchi"
SERVICE_GROUP="vauchi"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

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
    for cmd in curl tar; do
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

# Download and install binary
install_binary() {
    log_info "Building from source (release binary not available yet)..."

    # Check if cargo is available
    if command -v cargo &> /dev/null; then
        log_info "Rust toolchain found, building from source..."

        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"

        log_info "Cloning repository..."
        git clone --depth 1 "https://github.com/${REPO}.git" vauchi
        cd vauchi

        log_info "Building relay server (this may take a few minutes)..."
        cargo build --release -p vauchi-relay

        log_info "Installing binary..."
        cp target/release/vauchi-relay "$INSTALL_DIR/"
        chmod 755 "$INSTALL_DIR/vauchi-relay"

        cd /
        rm -rf "$TEMP_DIR"

        log_success "Binary installed to $INSTALL_DIR/vauchi-relay"
    else
        log_error "Rust toolchain not found. Install Rust first: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi
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
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN} Vauchi Relay installed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
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
    echo "Listening on: http://0.0.0.0:8080"
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
    echo -e "${BLUE}Vauchi Relay Server Installer${NC}"
    echo "================================"
    echo ""

    if [[ "${1:-}" == "uninstall" ]]; then
        check_root
        uninstall
        exit 0
    fi

    check_root
    check_dependencies
    detect_platform
    create_user
    install_binary
    create_data_dir
    install_service
    start_service
    print_summary
}

main "$@"
