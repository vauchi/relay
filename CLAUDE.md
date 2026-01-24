# CLAUDE.md - vauchi-relay

> **Inherits**: See [/CLAUDE.md](/CLAUDE.md) for project-wide rules.

WebSocket relay server for message forwarding between clients.

## Component-Specific Rules

- **Stateless design**: Relay should not persist sensitive data
- **No decryption**: Relay forwards encrypted blobs, never decrypts
- Depends on `vauchi-core` for protocol types

## Commands

```bash
cargo run -p vauchi-relay                    # Start server
cargo test -p vauchi-relay                   # Run tests
RUST_LOG=debug cargo run -p vauchi-relay    # With debug logging
```

## Testing

Integration tests should use test relay instances. See `scripts/relay-test.sh`.
