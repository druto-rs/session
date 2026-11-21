//! Asynchronous Redis session storage driver.
//!
//! Stores serialized [`SessionRecord`] JSON payloads in key-value stores
//! with automatic expiration matching the configured session lifetime.

use std::{sync::Arc, time::Duration};

use redis::RedisCommands;

use crate::{
    error::SessionError,
    id::SessionId,
    record::{SessionRecord, current_unix_timestamp},
    store::{BoxFuture, SessionStore},
};

/// Default key prefix for session keys stored in Redis.
pub const DEFAULT_REDIS_KEY_PREFIX: &str = "druto:session:";

/// Asynchronous Redis session storage driver backed by [`RedisCommands`].
#[derive(Debug, Clone)]
pub struct RedisSessionStore<C> {
    client: Arc<C>,
    prefix: String,
}

impl<C> RedisSessionStore<C> {
    /// Constructs a new Redis session store with the default key prefix (`druto:session:`).
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            prefix: DEFAULT_REDIS_KEY_PREFIX.to_string(),
        }
    }

    /// Constructs a new Redis session store with a custom key prefix.
    pub fn with_prefix(client: Arc<C>, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    /// Returns a reference to the underlying Redis client handle.
    pub fn client(&self) -> &Arc<C> {
        &self.client
    }

    /// Returns the configured key prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Formats the full storage key for a given session identifier.
    pub fn format_key(&self, session_id: &str) -> String {
        format!("{}{session_id}", self.prefix)
    }
}

impl<C: RedisCommands + 'static> SessionStore for RedisSessionStore<C> {
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>> {
        let client = Arc::clone(&self.client);
        let prefix = self.prefix.clone();

        Box::pin(async move {
            let Some(raw_id) = cookie_value else {
                return Ok(None);
            };

            let Ok(session_id) = SessionId::validate(raw_id) else {
                return Ok(None);
            };

            let key = format!("{prefix}{session_id}");
            let payload = client.get(&key).await?;

            let Some(json) = payload else {
                return Ok(None);
            };

            let record = SessionRecord::from_json(&json)?;
            Ok(Some(record))
        })
    }

    fn save<'a>(
        &'a self,
        session_id: &'a SessionId,
        record: &'a SessionRecord,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<String, SessionError>> {
        let client = Arc::clone(&self.client);
        let prefix = self.prefix.clone();
        let session_id_str = session_id.as_str().to_string();
        let mut persisted = record.clone();
        let seconds = ttl.as_secs().max(1);

        Box::pin(async move {
            let now = current_unix_timestamp();
            persisted.expires_at = now.saturating_add(seconds);
            let json = persisted.to_json()?;
            let key = format!("{prefix}{session_id_str}");

            client.set_ex(&key, &json, seconds).await?;

            Ok(session_id_str)
        })
    }

    fn destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>> {
        let client = Arc::clone(&self.client);
        let key = format!("{}{session_id}", self.prefix);

        Box::pin(async move {
            client.del(&key).await?;
            Ok(())
        })
    }

    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), SessionError>> {
        let client = Arc::clone(&self.client);
        let key = format!("{}{session_id}", self.prefix);
        let seconds = ttl.as_secs().max(1);

        Box::pin(async move {
            client.expire(&key, seconds).await?;
            Ok(())
        })
    }
}
