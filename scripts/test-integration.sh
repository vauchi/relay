#!/bin/bash

# Relay Integration Test Runner

set -e

# Platform directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"

cd "$PROJECT_ROOT"

echo "🚀 Running relay integration tests..."
echo "Project root: $PROJECT_ROOT"

# Build the relay in debug mode
echo "🏗️ Building relay..."
cargo build -p vauchi-relay

# Run unit tests
echo "🧪 Running unit tests..."
cargo test -p vauchi-relay --lib

# Run integration tests
echo "🔗 Running integration tests..."
cargo test -p vauchi-relay --test relay_integration_test

# Run load tests
echo "⚡ Running load tests..."
cargo test -p vauchi-relay --test relay_load_test

# Run security tests
echo "🔒 Running security tests..."
cargo test -p vauchi-relay --test relay_load_test stress_tests::security_tests

# Check for memory leaks in debug build
echo "🔍 Checking for memory issues..."
if command -v valgrind >/dev/null 2>&1; then
    echo "Running valgrind checks..."
    cargo build -p vauchi-relay
    timeout 30s valgrind --leak-check=full --show-leak-kinds=all \
        ./target/debug/vauchi-relay --test-mode &
    VALGRIND_PID=$!
    
    # Run some basic operations while valgrind monitors
    sleep 5
    curl -s http://localhost:8080/health || true
    sleep 5
    
    kill $VALGRIND_PID 2>/dev/null || true
    wait $VALGRIND_PID 2>/dev/null || true
else
    echo "⚠️  valgrind not found, skipping memory leak detection"
fi

echo "✅ Relay integration tests complete!"

# Generate test report
echo ""
echo "📊 Test Summary:"
echo "  - Unit tests: $(cargo test -p vauchi-relay --lib --quiet --no-run 2>&1 | grep -c "test.*:" || echo "0")"
echo "  - Integration tests: $(cargo test -p vauchi-relay --test relay_integration_test --quiet --no-run 2>&1 | grep -c "test.*:" || echo "0")"
echo "  - Load tests: $(cargo test -p vauchi-relay --test relay_load_test --quiet --no-run 2>&1 | grep -c "test.*:" || echo "0")"