# druto-session

[![Crates.io](https://img.shields.io/crates/v/druto-session.svg)](https://crates.io/crates/druto-session)
[![Documentation](https://docs.rs/druto-session/badge.svg)](https://docs.rs/druto-session)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Multi-driver HTTP session management, two-stage flash data storage, and session fixation defense for Druto.

Bridging `chirkut` (RFC 6265bis cookies), `gopon` (AEAD encryption), and `dhap` (middleware onion execution), `druto-session` provides stateful session primitives without binding to concrete HTTP server implementations.

---

## Features

- **Multi-Driver Session Storage (`SessionStore` Trait)**:
  - **`MemorySessionStore`**: In-memory hash map with TTL expiration, ideal for tests.
  - **`FileSessionStore`**: Atomic file writes (`.tmp` to final rename) preventing corruption, with automatic cleanup of expired records.
  - **`CookieSessionStore`**: Encrypted client-side sessions using authenticated encryption (`gopon`). Enforces payload size limits (~3800 bytes) to prevent truncation.
  - **`RedisSessionStore`**: Distributed session storage backed by `druto-redis` with native TTL expiration (`SETEX`), gated behind the `redis` feature.
- **Session Fixation Defense**:
  - 256-bit CSPRNG entropy (`getrandom`), formatted as unpadded URL-safe Base64 (`SessionId`).
  - Strict input validation rejecting path traversal attempts and corrupted identifiers.
  - Automatic session regeneration (`regenerate()`) post-authentication to prevent session fixation attacks.
- **Two-Stage Flash Messages**:
  - Guarantees $N \to N+1 \to N+2$ flash data isolation:
    - Data flashed in request $N$ is readable in request $N+1$ and cleared for request $N+2$.
    - Methods: `flash(key, value)`, `reflash()`, `keep(keys)`, and `old(key)`.
- **Defensive Cookie Configuration (`SessionConfig`)**:
  - Sensible security defaults: `HttpOnly = true`, `SameSite = Lax`, configurable `Secure` flags, rolling TTL extensions, and expire-on-close browser session support.
- **Onion Middleware Integration (`SessionMiddleware`)**:
  - Middleware for `dhap` pipelines automating cookie extraction, storage retrieval, and header emission on response commit.

---

## Installation

Add `druto-session` to your `Cargo.toml`:

```toml
[dependencies]
druto-session = "0.1.0"
```

For Redis session driver support:

```toml
[dependencies]
druto-session = { version = "0.1.0", features = ["redis"] }
```

---

## Quick Start

### Basic Session Manipulation

```rust
use std::sync::Arc;
use druto_session::{MemorySessionStore, SessionConfig, SessionManager};
use chirkut::CookieJar;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemorySessionStore::new());
    let config = SessionConfig::default();
    let manager = SessionManager::new(config, store);

    let jar = CookieJar::new();
    let mut session = manager.start(&jar).await?;

    // Session attributes
    session.put("user_id", 42)?;
    session.flash("status", "Logged in successfully")?;

    let user_id: Option<i32> = session.get("user_id")?;
    assert_eq!(user_id, Some(42));

    Ok(())
}
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
