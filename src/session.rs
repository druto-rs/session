//! Active session representation with typed accessors, flash message handling, and fixation defense.

use std::collections::HashMap;

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    error::SessionError,
    id::SessionId,
    record::{SessionRecord, current_unix_timestamp},
};

/// Lifecycle state of an active session during request processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Newly created session because no valid session cookie was supplied.
    Fresh,
    /// Session loaded from storage with no in-request mutations.
    Clean,
    /// Session attributes or flash data were modified during the request.
    Modified,
    /// Session identifier was rotated during the request (e.g. after authentication).
    Regenerated,
    /// Session was explicitly invalidated (e.g. during logout).
    Destroyed,
}

/// An active request session holding persistent state and transient flash messages.
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    previous_id: Option<SessionId>,
    state: SessionState,
    data: HashMap<String, Value>,
    flash_messages: HashMap<String, Value>,
    response_flash: HashMap<String, Value>,
    created_at: u64,
    expires_at: u64,
}

impl Session {
    /// Constructs a fresh, empty session.
    #[must_use]
    pub fn new_fresh(id: SessionId, lifetime_seconds: u64) -> Self {
        let created_at = current_unix_timestamp();
        let expires_at = created_at.saturating_add(lifetime_seconds);

        Self {
            id,
            previous_id: None,
            state: SessionState::Fresh,
            data: HashMap::new(),
            flash_messages: HashMap::new(),
            response_flash: HashMap::new(),
            created_at,
            expires_at,
        }
    }

    /// Constructs an active session from a previously stored record.
    #[must_use]
    pub fn from_record(id: SessionId, record: SessionRecord) -> Self {
        Self {
            id,
            previous_id: None,
            state: SessionState::Clean,
            data: record.data,
            flash_messages: record.flash,
            response_flash: HashMap::new(),
            created_at: record.created_at,
            expires_at: record.expires_at,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the prior session identifier if the session was regenerated.
    #[must_use]
    pub fn previous_id(&self) -> Option<&SessionId> {
        self.previous_id.as_ref()
    }

    /// Returns the current lifecycle state of the session.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns true if this session was minted fresh during the current request.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.state == SessionState::Fresh
    }

    /// Returns true if this session was loaded and remained unmodified.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.state == SessionState::Clean
    }

    /// Returns true if session attributes or flash data changed during the request.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.state == SessionState::Modified
    }

    /// Returns true if the session identifier was rotated during the request.
    #[must_use]
    pub fn is_regenerated(&self) -> bool {
        self.state == SessionState::Regenerated
    }

    /// Returns true if the session was explicitly invalidated.
    #[must_use]
    pub fn is_destroyed(&self) -> bool {
        self.state == SessionState::Destroyed
    }

    /// Returns the creation Unix timestamp in seconds.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the expiration Unix timestamp in seconds.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Sets a new expiration Unix timestamp in seconds.
    pub fn set_expires_at(&mut self, expires_at: u64) {
        self.expires_at = expires_at;
    }

    /// Retrieves and deserializes a value from the session attributes.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Deserialization`] if the stored JSON value cannot be converted into `T`.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, SessionError> {
        match self.data.get(key) {
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|err| {
                    SessionError::Deserialization(format!(
                        "failed to deserialize key '{key}': {err}"
                    ))
                }),
            None => Ok(None),
        }
    }

    /// Retrieves an unparsed JSON value reference from the session attributes.
    #[must_use]
    pub fn get_value(&self, key: &str) -> Option<&Value> {
        self.data.get(key)
    }

    /// Serializes and stores a value under the specified session key.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Serialization`] if the value cannot be serialized into JSON.
    pub fn put<T: Serialize>(
        &mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<(), SessionError> {
        let serialized = serde_json::to_value(value).map_err(|err| {
            SessionError::Serialization(format!("failed to serialize session value: {err}"))
        })?;

        self.put_value(key, serialized);
        Ok(())
    }

    /// Stores an existing JSON value under the specified session key.
    pub fn put_value(&mut self, key: impl Into<String>, value: Value) {
        self.data.insert(key.into(), value);
        self.mark_modified();
    }

    /// Returns true if the session contains the specified key.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Returns an immutable reference to all session key-value attributes.
    #[must_use]
    pub fn all(&self) -> &HashMap<String, Value> {
        &self.data
    }

    /// Removes a key from the session attributes and returns its value if present.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let removed = self.data.remove(key);
        if removed.is_some() {
            self.mark_modified();
        }
        removed
    }

    /// Removes a key from the session attributes and deserializes its value.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Deserialization`] if deserialization fails.
    pub fn pull<T: DeserializeOwned>(&mut self, key: &str) -> Result<Option<T>, SessionError> {
        match self.remove(key) {
            Some(value) => serde_json::from_value(value).map(Some).map_err(|err| {
                SessionError::Deserialization(format!(
                    "failed to deserialize pulled key '{key}': {err}"
                ))
            }),
            None => Ok(None),
        }
    }

    /// Removes all session attributes.
    pub fn clear(&mut self) {
        if !self.data.is_empty() {
            self.data.clear();
            self.mark_modified();
        }
    }

    /// Rotates the session identifier while preserving all existing data and flash messages.
    ///
    /// This should be invoked following privilege escalation or authentication to prevent
    /// session fixation vulnerabilities.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Crypto`] if random number generation fails.
    pub fn regenerate(&mut self) -> Result<(), SessionError> {
        let new_id = SessionId::generate()?;

        if self.previous_id.is_none() {
            self.previous_id = Some(self.id.clone());
        }

        self.id = new_id;
        if self.state != SessionState::Destroyed {
            self.state = SessionState::Regenerated;
        }

        Ok(())
    }

    /// Completely invalidates the session, purging all state and marking it for removal.
    pub fn invalidate(&mut self) {
        self.data.clear();
        self.flash_messages.clear();
        self.response_flash.clear();
        self.state = SessionState::Destroyed;
    }

    /// Stages a flash message to be available on the immediate subsequent request.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Serialization`] if serialization fails.
    pub fn flash<T: Serialize>(
        &mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<(), SessionError> {
        let serialized = serde_json::to_value(value).map_err(|err| {
            SessionError::Serialization(format!("failed to serialize flash value: {err}"))
        })?;

        self.flash_value(key, serialized);
        Ok(())
    }

    /// Stages an existing JSON value as a flash message.
    pub fn flash_value(&mut self, key: impl Into<String>, value: Value) {
        self.response_flash.insert(key.into(), value);
        self.mark_modified();
    }

    /// Preserves all current incoming flash messages for an additional request cycle.
    pub fn reflash(&mut self) {
        if !self.flash_messages.is_empty() {
            for (key, value) in &self.flash_messages {
                self.response_flash.insert(key.clone(), value.clone());
            }
            self.mark_modified();
        }
    }

    /// Preserves only the specified keys from current incoming flash messages for another request cycle.
    pub fn keep(&mut self, keys: &[&str]) {
        let mut modified = false;
        for key in keys {
            if let Some(value) = self.flash_messages.get(*key) {
                self.response_flash
                    .insert((*key).to_string(), value.clone());
                modified = true;
            }
        }
        if modified {
            self.mark_modified();
        }
    }

    /// Retrieves and deserializes a flash message received from the preceding request.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Deserialization`] if deserialization fails.
    pub fn old<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, SessionError> {
        match self.flash_messages.get(key) {
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|err| {
                    SessionError::Deserialization(format!(
                        "failed to deserialize flash key '{key}': {err}"
                    ))
                }),
            None => Ok(None),
        }
    }

    /// Retrieves an unparsed JSON value reference of a flash message from the preceding request.
    #[must_use]
    pub fn old_value(&self, key: &str) -> Option<&Value> {
        self.flash_messages.get(key)
    }

    /// Returns a reference to all incoming flash messages from the preceding request.
    #[must_use]
    pub fn flash_messages(&self) -> &HashMap<String, Value> {
        &self.flash_messages
    }

    /// Returns a reference to all staged outgoing flash messages for the next request.
    #[must_use]
    pub fn response_flash(&self) -> &HashMap<String, Value> {
        &self.response_flash
    }

    /// Converts the active session state into a persistent session record.
    #[must_use]
    pub fn to_record(&self) -> SessionRecord {
        SessionRecord::new(
            Some(self.id.clone()),
            self.data.clone(),
            self.response_flash.clone(),
            self.created_at,
            self.expires_at,
        )
    }

    fn mark_modified(&mut self) {
        if self.state == SessionState::Clean || self.state == SessionState::Fresh {
            self.state = SessionState::Modified;
        }
    }
}
