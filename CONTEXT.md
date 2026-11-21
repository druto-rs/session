# `session` Crate Context

## Purpose

`session` provides multi-driver HTTP session management, flash message storage, and session fixation defense for the
Druto framework. It allows stateful user interactions across HTTP requests by bridging `cookie`, `gopon`, and
`dhap` without binding to concrete HTTP server implementations.

## Architecture Overview

`session` provides stateful session lifecycle primitives, session fixation defense, and pluggable storage backends
complying with RFC 6265bis HTTP State Management Mechanism specifications.

## Core Responsibilities

1. **Unified Multi-Driver Storage Architecture**:
    - Generic, runtime-agnostic, and object-safe storage contract (`trait SessionStore: Send + Sync + 'static`):
      -
      `load<'a>(&'a self, cookie_value: Option<&'a str>) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>>`:
      Retrieves session data. For server stores (`Memory`, `File`), looks up by session ID; for `CookieSessionStore`,
      decrypts and deserializes the ciphertext payload directly.
        -
      `save<'a>(&'a self, session_id: &'a SessionId, record: &'a SessionRecord, ttl: Duration) -> BoxFuture<'a, Result<String, SessionError>>`:
      Persists session payload. Server stores save the record and return `session_id.to_string()`;
      `CookieSessionStore`
      encrypts the payload and returns the ciphertext envelope string to stage into the cookie jar.
        - `destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>>`:
          Removes session record from server storage (no-op for cookie driver).
        - `touch<'a>(&'a self, session_id: &'a SessionId, ttl: Duration) -> BoxFuture<'a, Result<(), SessionError>>`:
          Refreshes session TTL without modifying payload.
    - Concrete driver implementations:
        - **`MemorySessionStore`**: Thread-safe in-memory map (`Arc<RwLock<HashMap<String, SessionRecord>>>`) with TTL
          expiration checks, ideal for automated test suites and stateless development.
        - **`FileSessionStore`**: Local disk-backed session persistence storing JSON-serialized session files in a
          configured
          directory (`<directory>/<session_id>.json`). Employs **atomic file writes** (writing to sibling `.tmp` files
          before
          `std::fs::rename`) to prevent partial-write corruption, with automatic cleanup of expired or malformed files.
        - **`CookieSessionStore`**: Stores the entire encrypted payload directly in a tamper-proof, AEAD-encrypted
          cookie via
          `crates/cookie` and `crates/crypto` (`Encrypter` with purpose binding `"session:cookie"`). Zero server-side
          state.
          Enforces a safe payload ceiling (~3800 bytes) with `SessionError::PayloadTooLarge` to prevent silent browser
          truncation,
          and gracefully falls back to a fresh session (`Ok(None)`) on decryption failure or key rotation mismatch.
        - **`RedisSessionStore`**: Asynchronous distributed key-value storage driver backed by `crates/redis`
          (`RedisCommands`), gated behind the optional `redis` feature flag. Stores serialized JSON session records
          with native TTL expiration (`SETEX`), configurable key prefixes (defaulting to `"druto:session:"`), and
          sliding TTL refresh (`EXPIRE`).

2. **Session Fixation Defense & ID Management**:
    - Session identifiers encapsulated in a validated newtype:
        - `struct SessionId(String)`: Generated from 256 bits (32 bytes) of CSPRNG entropy via `getrandom`, formatted as
          unpadded URL-safe Base64 (exactly 43 ASCII characters).
        - Strict validation on incoming cookie values rejects malformed tokens, preventing directory traversal in
          `FileSessionStore`
          and injection attacks.
    - Explicit lifecycle state machine:
        - `Fresh`: Minted during current request when no valid session cookie was supplied.
        - `Clean`: Loaded from storage without in-request modifications. Bypasses re-serialization on commit; only
          performs
          lightweight `touch` if rolling expiration is active.
        - `Modified`: Session key-values or flash messages were altered during the request. Serializes and writes on
          commit.
        - `Regenerated`: New session ID was issued during the request (e.g., post-authentication) while preserving data.
          Destroys the previous session ID in the persistent store upon commit.
        - `Destroyed`: Explicitly invalidated (e.g., post-logout); existing storage deleted and tombstone cookie
          (`Max-Age=0`) emitted.
    - `regenerate()`: Issues a fresh session ID while migrating all existing session and flash data, tracking prior ID
      for backend deletion.
    - `invalidate()`: Clears all session attributes and marks the session destroyed.

3. **Two-Stage Flash Data Lifecycle**:
    - Dedicated, isolated flash message partition guaranteeing the strict $N \to N+1 \to N+2$ lifecycle:
        - `flash_messages`: Data received from request $N$ available for read access during request $N+1$. Automatically
          purged at
          the end of request $N+1$.
        - `response_flash`: Staged data added during request $N+1$ to be written into the session store for
          request $N+2$.
    - Methods:
        - `flash(key, value)`: Stages a key-value pair into `response_flash`.
        - `reflash()`: Preserves all current `flash_messages` into `response_flash` for another request cycle.
        - `keep(keys)`: Preserves only specified keys from `flash_messages` into `response_flash`.
        - `old(key)`: Retrieves a flashed value from the previous request.

4. **Configuration & Policy Management**:
    - `struct SessionConfig`:
        - `cookie_name: String` (default: `"druto_session"`)
        - `lifetime: Duration` (default: 2 hours / 7200 seconds)
        - `path: String` (default: `"/"`)
        - `domain: Option<String>` (default: `None`)
        - `secure: bool` (default: `false` for dev, configurable for production HTTPS)
        - `http_only: bool` (default: `true`, strictly blocking XSS access)
        - `same_site: SameSite` (default: `SameSite::Lax`, mitigating CSRF)
        - `rolling: bool` (default: `true`, sliding window TTL on active requests)
        - `expire_on_close: bool` (default: `false`, browser session without cookie `Max-Age` while keeping server TTL)

5. **Pipeline Middleware Integration**:
    - Integrates cleanly with `dhap` and `crates/cookie::CookieJar`:
        - Direct lifecycle primitives: `SessionManager::start(&cookie_jar)` and
          `SessionManager::commit(session, &mut cookie_jar)`.
        - Generic middleware: `struct SessionMiddleware<Store>` implementing `dhap::Middleware<C, Output, Error>`
          bounded by
          `trait SessionContext` (`cookie_jar_mut()`, `set_session()`, `session_mut()`, `take_session()`).
        - Includes built-in `TestSessionContext` for end-to-end pipeline testing.

## Boundaries & Non-Responsibilities

- **Not Authentication**: Manages generic session state. User credentials, password hashing, and login guards belong in
  `crates/auth`.
- **Not an HTTP Server**: Integrates via request/response cookies and middleware abstractions without owning sockets or
  transport protocols.
- **Runtime Agnostic**: Relies on standard library async primitives (`Future`, `Pin`, `BoxFuture`), ensuring zero hard
  dependency on specific async runtimes.

## Implemented Public Surface

- `struct SessionId`: Strongly typed, validated 256-bit URL-safe session identifier.
- `struct Session`: Active request session providing typed getter/setter accessors:
    - `get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, SessionError>`
    - `put<T: Serialize>(&mut self, key: impl Into<String>, value: T) -> Result<(), SessionError>`
    - `has(&self, key: &str) -> bool`
    - `remove(&mut self, key: &str) -> Option<serde_json::Value>`
    - `pull<T: DeserializeOwned>(&mut self, key: &str) -> Result<Option<T>, SessionError>`
    - `clear(&mut self)`
    - `regenerate(&mut self) -> Result<(), SessionError>`
    - `invalidate(&mut self)`
    - `flash<T: Serialize>(&mut self, key: impl Into<String>, value: T) -> Result<(), SessionError>`
    - `reflash(&mut self)`
    - `keep(&mut self, keys: &[&str])`
    - `old<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, SessionError>`
- `struct SessionRecord`: Stored representation containing serialized data map, flash data, and expiry timestamp.
- `trait SessionStore`: Unified storage driver interface (`load`, `save`, `destroy`, `touch`).
- `struct MemorySessionStore`: In-memory driver for testing and development.
- `struct FileSessionStore`: Disk-based driver persisting JSON session records with atomic temp file renames.
- `struct CookieSessionStore`: Encrypted cookie driver with size ceiling and zero server-side storage.
- `struct RedisSessionStore`: Asynchronous Redis-backed session store gated behind the optional `redis` feature flag.
- `struct SessionManager`: Driver registry, configuration facade, and session factory (`start`, `commit`).
- `struct SessionConfig`: Configuration options (cookie name, lifetime/TTL, secure, http-only, same-site, rolling,
  expire-on-close).
- `trait SessionContext`: Contract for context types supporting session and cookie jar extraction.
- `struct SessionMiddleware`: Async onion pipeline middleware layer.
- `struct TestSessionContext`: Lightweight test context container.
- `enum SessionError`: Strongly typed errors for I/O failures, serialization/deserialization errors, expired sessions,
  payload too large, invalid session ID, and decryption failures.
