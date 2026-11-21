//! Strongly typed, cryptographically secure session identifiers.

use std::{fmt, ops::Deref};

use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::SessionError;

/// Number of random entropy bytes used to mint a new session identifier.
pub const SESSION_ID_BYTE_LENGTH: usize = 32;

/// Length of the encoded session identifier string (43 characters).
pub const SESSION_ID_STRING_LENGTH: usize = 43;

/// A cryptographically secure, URL-safe session identifier.
///
/// Backed by 256 bits of CSPRNG entropy and encoded as unpadded URL-safe Base64.
/// Strict parsing ensures that malformed or malicious tokens are rejected before reaching storage layers.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a fresh session identifier using the system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Crypto`] if the underlying random number generator fails.
    pub fn generate() -> Result<Self, SessionError> {
        let mut entropy = [0u8; SESSION_ID_BYTE_LENGTH];
        getrandom::fill(&mut entropy).map_err(|err| {
            SessionError::Crypto(format!("failed to generate random entropy: {err}"))
        })?;

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(entropy);
        Ok(Self(encoded))
    }

    /// Parses and strictly validates a session identifier string.
    ///
    /// The string must be exactly 43 characters long and contain only valid URL-safe Base64
    /// characters (`[A-Za-z0-9_-]`).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidId`] if the input string is malformed or invalid.
    pub fn parse(candidate: &str) -> Result<Self, SessionError> {
        if candidate.len() != SESSION_ID_STRING_LENGTH {
            return Err(SessionError::InvalidId(format!(
                "expected length {SESSION_ID_STRING_LENGTH}, got {}",
                candidate.len()
            )));
        }

        let is_valid = candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');

        if !is_valid {
            return Err(SessionError::InvalidId(
                "contains invalid characters outside URL-safe alphabet".to_string(),
            ));
        }

        Ok(Self(candidate.to_string()))
    }

    /// Validates and parses a candidate session identifier string.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidId`] if the input string is malformed or invalid.
    pub fn validate(candidate: &str) -> Result<Self, SessionError> {
        Self::parse(candidate)
    }

    /// Returns a reference to the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SessionId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SessionId({})", self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
