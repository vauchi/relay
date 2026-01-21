# Code Structure

## Module Organization

```
vauchi-relay/
├── src/
│   ├── main.rs         # Server entry point
│   ├── config.rs       # Configuration management
│   ├── handler.rs      # WebSocket connection handler
│   ├── storage.rs      # In-memory blob storage
│   └── rate_limit.rs   # Per-client rate limiting
└── Cargo.toml          # Crate configuration
```

## Components

### `main.rs` - Server Entry Point

Server startup, WebSocket listener, and connection dispatch.

| Function | Purpose |
|----------|---------|
| `main` | Async entry point, config loading, server start |
| `handle_connection` | Accepts WebSocket upgrade, spawns handler |

### `config.rs` - Configuration

Environment-based configuration.

| Item | Purpose |
|------|---------|
| `Config` | Server settings (port, limits, TTL) |
| `Config::from_env` | Load from environment variables |

### `handler.rs` - WebSocket Handler

Per-connection message processing.

| Function | Purpose |
|----------|---------|
| `ConnectionHandler::new` | Create handler for new connection |
| `handle_message` | Route incoming messages by type |
| `handle_handshake` | Process client authentication |
| `handle_encrypted_update` | Store and forward encrypted blobs |
| `deliver_pending` | Send stored messages to connected client |

### `storage.rs` - Blob Storage

Thread-safe in-memory storage with expiration.

| Item | Purpose |
|------|---------|
| `BlobStore` | Concurrent hashmap for blobs |
| `store` | Save blob with TTL |
| `retrieve` | Get blobs for recipient |
| `cleanup` | Remove expired blobs |

### `rate_limit.rs` - Rate Limiting

Token bucket algorithm per client.

| Item | Purpose |
|------|---------|
| `RateLimiter` | Per-client rate limit state |
| `check` | Verify client hasn't exceeded limit |
| `record` | Track client message |

## Message Flow

```
Client A                    Relay                     Client B
   │                          │                          │
   │──── Handshake ──────────►│                          │
   │◄─── Ack ─────────────────│                          │
   │                          │                          │
   │──── EncryptedUpdate ────►│  (store for B)           │
   │◄─── Ack ─────────────────│                          │
   │                          │                          │
   │                          │◄──── Handshake ──────────│
   │                          │───── Ack ───────────────►│
   │                          │───── EncryptedUpdate ───►│
   │                          │                          │
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `tokio-tungstenite` | WebSocket support |
| `serde` | JSON serialization |
| `dashmap` | Concurrent hashmap |
| `tracing` | Logging |
