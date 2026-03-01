<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# CLAUDE.md - vauchi-relay

> **Inherits**: See [CLAUDE.md](../CLAUDE.md) for project-wide rules.

WebSocket relay server for message forwarding between clients.

## Rules

- **Stateless**: No persistent sensitive data. Forwards encrypted blobs, never decrypts.
- Uses `vauchi-protocol` (from `core/`) for shared message types. Does **not** depend on `vauchi-core`.
