<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# CLAUDE.md - vauchi-relay

> **Inherits**: See [CLAUDE.md](../CLAUDE.md) for project-wide rules.

WebSocket relay server for message forwarding between clients.

## Component-Specific Rules

- **Stateless design**: Relay should not persist sensitive data
- **No decryption**: Relay forwards encrypted blobs, never decrypts
- **Protocol types**: Uses `vauchi-protocol` crate (from `core/` repo) for shared message types; does **not** depend on `vauchi-core`

## Commands

```bash
cargo run -p vauchi-relay                    # Start server
just test relay                              # Run tests
just check relay                             # Format + lint + test
RUST_LOG=debug cargo run -p vauchi-relay    # With debug logging
```

## Testing

Integration tests should use test relay instances. Run with `just test relay`.
