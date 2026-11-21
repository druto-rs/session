# `session` Agent Instructions

## Scope

This crate owns HTTP session state management, multi-driver storage backends, flash data, and session fixation defense.
It bridges `cookie`, `gopon`, and `dhap` without binding to concrete HTTP server implementations.

## Design Rules

1. **Session Fixation Defense Invariant**:
    - `regenerate()` must issue a completely new random 256-bit `SessionId` while retaining existing data and tracking
      the previous
      ID for destruction in persistent stores upon commit.
2. **Flash Lifecycle Invariant**:
    - Data stored via `flash()` is only accessible on the immediate subsequent request ($N+1$) and must be purged on the
      following request ($N+2$) unless `reflash()` or `keep()` is explicitly invoked.
3. **Async & Thread Safety**:
    - `SessionStore` implementations must be `Send + Sync + 'static` to allow concurrent access across worker threads,
      returning runtime-agnostic `BoxFuture` instances without coupling directly to an async runtime.
4. **Driver Durability & Safety**:
    - `FileSessionStore` must write to a sibling `.tmp` file and atomically rename (`std::fs::rename`) to
      `<session_id>.json`.
    - `CookieSessionStore` must enforce a safe size ceiling (~3800 bytes) and return `SessionError::PayloadTooLarge` to
      prevent
      silent browser truncation, and gracefully fall back to a fresh session on decryption error or rotated key absence.
    - `RedisSessionStore` must format keys with the configured prefix (`druto:session:` by default), delegate expiration
      to native Redis TTLs (`SETEX` and `EXPIRE`), and strictly validate incoming session IDs prior to executing Redis
      commands.
5. **Session ID Validation**:
    - Untrusted session ID strings from cookies must strictly validate character set (URL-safe base64) and length (43
      bytes),
      completely preventing directory traversal attacks.

## Testing Requirements

- **Driver Roundtrips**: Test store, retrieve, update, touch, and destroy across `MemorySessionStore`,
  `CookieSessionStore`, `FileSessionStore`, and `RedisSessionStore`.
- **Flash Data Lifecycle**: Verify that flash data exists on request $N+1$, and is automatically discarded by
  request $N+2$.
- **Reflash & Keep**: Verify `reflash` and `keep` preserve flash data across multiple requests.
- **Session Regeneration**: Test that `regenerate()` changes the session ID while retaining all existing data and
  marking
  the prior ID for deletion.
- **Session Invalidation**: Test that `invalidate()` clears all session state and produces a deletion tombstone for the
  session cookie.
- **Atomic File Replacement**: Test that `FileSessionStore` successfully persists sessions and automatically prunes
  expired/corrupt files.
- **Cookie Tamper Protection & Size Check**: For `CookieSessionStore`, verify that any client-side alteration of the
  encrypted cookie payload
  causes decryption failure and falls back to a fresh session without panicking, and payloads over 3800 bytes return
  `PayloadTooLarge`.
- **Pipeline Integration**: Test end-to-end middleware execution using `dhap::Pipeline` with `SessionMiddleware` and
  `TestSessionContext`.
