//! Multi-driver HTTP session manager, flash message storage, and session fixation defense.

pub mod config;
pub mod error;
pub mod id;
pub mod manager;
pub mod middleware;
pub mod record;
pub mod session;
pub mod store;
pub mod stores;

pub use config::{
    DEFAULT_COOKIE_NAME, DEFAULT_COOKIE_PATH, DEFAULT_SESSION_LIFETIME, SessionConfig,
    SessionConfigBuilder,
};
pub use error::SessionError;
pub use id::{SESSION_ID_BYTE_LENGTH, SESSION_ID_STRING_LENGTH, SessionId};
pub use manager::SessionManager;
pub use middleware::{SessionContext, SessionMiddleware, TestSessionContext};
pub use record::{SessionRecord, current_unix_timestamp};
pub use session::{Session, SessionState};
pub use store::{BoxFuture, SessionStore};
pub use stores::{
    CookieSessionStore, FileSessionStore, MAX_COOKIE_PAYLOAD_SIZE, MemorySessionStore,
    SESSION_COOKIE_PURPOSE,
};
#[cfg(feature = "redis")]
pub use stores::{DEFAULT_REDIS_KEY_PREFIX, RedisSessionStore};
