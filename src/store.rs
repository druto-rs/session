//! Session store trait definitions and runtime-agnostic asynchronous contracts.

use std::{future::Future, pin::Pin, time::Duration};

use crate::{error::SessionError, id::SessionId, record::SessionRecord};

/// A pinned, heap-allocated future that is thread-safe across executors.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Storage backend contract for persisting and retrieving session state.
///
/// Implementations must be thread-safe (`Send + Sync + 'static`) and runtime-agnostic.
pub trait SessionStore: Send + Sync + 'static {
    /// Loads a session record given an optional incoming cookie value.
    ///
    /// For server-side stores, `cookie_value` represents the raw session ID to look up.
    /// For client-side stores, `cookie_value` contains the encrypted session record payload.
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>>;

    /// Persists a session record and returns the string value to stage in the response cookie.
    ///
    /// For server-side stores, this saves the record under `session_id` and returns `session_id.to_string()`.
    /// For client-side stores, this serializes and encrypts the record, returning the ciphertext envelope.
    fn save<'a>(
        &'a self,
        session_id: &'a SessionId,
        record: &'a SessionRecord,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<String, SessionError>>;

    /// Removes a session record from persistent storage.
    fn destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>>;

    /// Refreshes the expiration TTL of an existing session record without altering its payload.
    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), SessionError>>;
}
