//! Encrypted client-side cookie session storage driver.

use std::{future::ready, sync::Arc, time::Duration};

use chirkut::security::ENCRYPTED_PREFIX;
use gopon::Encrypter;

use crate::{
    error::SessionError,
    id::SessionId,
    record::{SessionRecord, current_unix_timestamp},
    store::{BoxFuture, SessionStore},
};

/// Maximum safe payload size in bytes for a cookie value to prevent browser truncation.
pub const MAX_COOKIE_PAYLOAD_SIZE: usize = 3800;

/// Purpose binding used for AEAD authenticated encryption of session cookies.
pub const SESSION_COOKIE_PURPOSE: &str = "session:cookie";

/// A stateless, client-side session store persisting AEAD-encrypted payloads directly in HTTP cookies.
#[derive(Debug, Clone)]
pub struct CookieSessionStore {
    encrypter: Arc<Encrypter>,
    max_payload_size: usize,
}

impl CookieSessionStore {
    /// Constructs a new cookie session store using the provided encrypter.
    #[must_use]
    pub fn new(encrypter: Arc<Encrypter>) -> Self {
        Self {
            encrypter,
            max_payload_size: MAX_COOKIE_PAYLOAD_SIZE,
        }
    }

    /// Sets a custom maximum payload size limit.
    #[must_use]
    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Returns the maximum allowable payload size in bytes.
    #[must_use]
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl SessionStore for CookieSessionStore {
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>> {
        let Some(raw_value) = cookie_value else {
            return Box::pin(ready(Ok(None)));
        };

        let Some(ciphertext_envelope) = raw_value.strip_prefix(ENCRYPTED_PREFIX) else {
            return Box::pin(ready(Ok(None)));
        };

        let decrypted_json = match self
            .encrypter
            .decrypt_string_with_purpose(ciphertext_envelope, SESSION_COOKIE_PURPOSE)
        {
            Ok(json) => json,
            Err(_) => return Box::pin(ready(Ok(None))),
        };

        let record = match SessionRecord::from_json(&decrypted_json) {
            Ok(record) => record,
            Err(_) => return Box::pin(ready(Ok(None))),
        };

        let now = current_unix_timestamp();
        if record.is_expired(now) {
            Box::pin(ready(Ok(None)))
        } else {
            Box::pin(ready(Ok(Some(record))))
        }
    }

    fn save<'a>(
        &'a self,
        session_id: &'a SessionId,
        record: &'a SessionRecord,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<String, SessionError>> {
        let now = current_unix_timestamp();
        let mut persisted = record.clone();
        if persisted.id.is_none() {
            persisted.id = Some(session_id.clone());
        }
        persisted.expires_at = now.saturating_add(ttl.as_secs());

        let json_content = match persisted.to_json() {
            Ok(json) => json,
            Err(err) => return Box::pin(ready(Err(err))),
        };

        let encrypted = match self
            .encrypter
            .encrypt_string_with_purpose(&json_content, SESSION_COOKIE_PURPOSE)
        {
            Ok(ciphertext) => ciphertext,
            Err(err) => return Box::pin(ready(Err(SessionError::Crypto(err.to_string())))),
        };

        let wire_value = format!("{ENCRYPTED_PREFIX}{encrypted}");
        if wire_value.len() > self.max_payload_size {
            return Box::pin(ready(Err(SessionError::PayloadTooLarge(wire_value.len()))));
        }

        Box::pin(ready(Ok(wire_value)))
    }

    fn destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>> {
        let _ = session_id;
        Box::pin(ready(Ok(())))
    }

    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), SessionError>> {
        let _ = session_id;
        let _ = ttl;
        Box::pin(ready(Ok(())))
    }
}
