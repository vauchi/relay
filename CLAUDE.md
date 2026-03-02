# CLAUDE.md - vauchi-relay

> **Inherits**: See [CLAUDE.md](../CLAUDE.md) for project-wide rules.

WebSocket relay server for message forwarding between clients.

## Rules

- **Stateless**: No persistent sensitive data. Forwards encrypted blobs, never decrypts.
- Uses `vauchi-protocol` (from `core/`) for shared message types. Does **not** depend on `vauchi-core`.
