//! Error types for session management, storage backends, and serialization.

use std::fmt;

/// Errors that can occur during session lifecycle operations, storage interactions,
/// or cryptographic operations.
#[derive(Debug)]
pub enum SessionError {
    /// An I/O error occurred during storage persistence.
    Io(std::io::Error),
    /// Failure during serialization of session or flash data.
    Serialization(String),
    /// Failure during deserialization of session or flash data.
    Deserialization(String),
    /// The provided session identifier is malformed or invalid.
    InvalidId(String),
    /// The session payload exceeded the maximum allowable size for the storage medium.
    PayloadTooLarge(usize),
    /// A cryptographic error occurred during encryption, decryption, or signing.
    Crypto(String),
    /// The requested session has expired.
    Expired,
    /// A storage backend encountered an unexpected operational failure.
    Store(String),
    /// A synchronization primitive was poisoned.
    LockPoisoned(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(formatter, "session I/O error: {err}"),
            Self::Serialization(reason) => {
                write!(formatter, "session serialization error: {reason}")
            }
            Self::Deserialization(reason) => {
                write!(formatter, "session deserialization error: {reason}")
            }
            Self::InvalidId(reason) => write!(formatter, "invalid session ID: {reason}"),
            Self::PayloadTooLarge(size) => {
                write!(
                    formatter,
                    "session payload size ({size} bytes) exceeds maximum allowable limit"
                )
            }
            Self::Crypto(reason) => write!(formatter, "session cryptographic error: {reason}"),
            Self::Expired => write!(formatter, "session has expired"),
            Self::Store(reason) => write!(formatter, "session store error: {reason}"),
            Self::LockPoisoned(reason) => write!(formatter, "session lock poisoned: {reason}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SessionError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<gopon::Error> for SessionError {
    fn from(err: gopon::Error) -> Self {
        Self::Crypto(err.to_string())
    }
}

#[cfg(feature = "redis")]
impl From<redis::RedisError> for SessionError {
    fn from(err: redis::RedisError) -> Self {
        Self::Store(err.to_string())
    }
}
