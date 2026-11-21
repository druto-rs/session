//! Persistent representation of session data, flash messages, and validity timestamps.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::SessionError, id::SessionId};

/// Returns the current system clock time as a Unix timestamp in seconds.
#[must_use]
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// A serialized session record stored in persistent drivers or encrypted client cookies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Optional session identifier associated with this record.
    pub id: Option<SessionId>,
    /// Persistent session key-value attributes.
    pub data: HashMap<String, Value>,
    /// Flash message key-value attributes to be delivered on the next request.
    pub flash: HashMap<String, Value>,
    /// Creation Unix timestamp in seconds.
    pub created_at: u64,
    /// Expiration Unix timestamp in seconds.
    pub expires_at: u64,
}

impl SessionRecord {
    /// Constructs a new session record with explicit timestamps.
    #[must_use]
    pub fn new(
        id: Option<SessionId>,
        data: HashMap<String, Value>,
        flash: HashMap<String, Value>,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            id,
            data,
            flash,
            created_at,
            expires_at,
        }
    }

    /// Checks whether the session record has expired relative to the given Unix timestamp.
    #[must_use]
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time >= self.expires_at
    }

    /// Serializes the session record into a canonical JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Serialization`] if serialization fails.
    pub fn to_json(&self) -> Result<String, SessionError> {
        serde_json::to_string(self).map_err(|err| {
            SessionError::Serialization(format!("failed to serialize session record: {err}"))
        })
    }

    /// Deserializes a session record from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Deserialization`] if parsing fails.
    pub fn from_json(json_content: &str) -> Result<Self, SessionError> {
        serde_json::from_str(json_content).map_err(|err| {
            SessionError::Deserialization(format!("failed to deserialize session record: {err}"))
        })
    }
}
