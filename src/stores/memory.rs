//! In-memory session store backed by thread-safe hash maps.

use std::{collections::HashMap, future::ready, sync::RwLock, time::Duration};

use crate::{
    error::SessionError,
    id::SessionId,
    record::{SessionRecord, current_unix_timestamp},
    store::{BoxFuture, SessionStore},
};

/// An in-memory session storage driver suitable for testing and development.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: RwLock<HashMap<String, SessionRecord>>,
}

impl MemorySessionStore {
    /// Constructs a new, empty in-memory session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the number of sessions currently held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::LockPoisoned`] if the internal lock was poisoned.
    pub fn count(&self) -> Result<usize, SessionError> {
        self.sessions
            .read()
            .map(|guard| guard.len())
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()))
    }

    /// Returns true if a session with the given ID exists in memory and is not expired.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::LockPoisoned`] if the internal lock was poisoned.
    pub fn contains(&self, session_id: &SessionId) -> Result<bool, SessionError> {
        let guard = self
            .sessions
            .read()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()))?;

        if let Some(record) = guard.get(session_id.as_str()) {
            Ok(!record.is_expired(current_unix_timestamp()))
        } else {
            Ok(false)
        }
    }

    /// Clears all session records from memory.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::LockPoisoned`] if the internal lock was poisoned.
    pub fn clear(&self) -> Result<(), SessionError> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()))?;
        guard.clear();
        Ok(())
    }

    /// Intentionally poisons the internal lock for testing failure pathways.
    #[doc(hidden)]
    pub fn poison_for_testing(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = self.sessions.write().unwrap();
            guard.clear();
            panic!("intentional poison for testing");
        }));
    }
}

impl SessionStore for MemorySessionStore {
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>> {
        let Some(candidate_id) = cookie_value else {
            return Box::pin(ready(Ok(None)));
        };

        if SessionId::parse(candidate_id).is_err() {
            return Box::pin(ready(Ok(None)));
        }

        let now = current_unix_timestamp();
        let read_result = self
            .sessions
            .read()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()));

        let guard = match read_result {
            Ok(guard) => guard,
            Err(err) => return Box::pin(ready(Err(err))),
        };

        if let Some(record) = guard.get(candidate_id) {
            if record.is_expired(now) {
                drop(guard);
                let _ = self.sessions.write().map(|mut write_guard| {
                    write_guard.remove(candidate_id);
                });
                Box::pin(ready(Ok(None)))
            } else {
                Box::pin(ready(Ok(Some(record.clone()))))
            }
        } else {
            Box::pin(ready(Ok(None)))
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
        persisted.expires_at = now.saturating_add(ttl.as_secs());

        let write_result = self
            .sessions
            .write()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()));

        match write_result {
            Ok(mut guard) => {
                guard.insert(session_id.as_str().to_string(), persisted);
                Box::pin(ready(Ok(session_id.as_str().to_string())))
            }
            Err(err) => Box::pin(ready(Err(err))),
        }
    }

    fn destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>> {
        let write_result = self
            .sessions
            .write()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()));

        match write_result {
            Ok(mut guard) => {
                guard.remove(session_id.as_str());
                Box::pin(ready(Ok(())))
            }
            Err(err) => Box::pin(ready(Err(err))),
        }
    }

    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), SessionError>> {
        let now = current_unix_timestamp();
        let write_result = self
            .sessions
            .write()
            .map_err(|poison| SessionError::LockPoisoned(poison.to_string()));

        match write_result {
            Ok(mut guard) => {
                if let Some(record) = guard.get_mut(session_id.as_str()) {
                    record.expires_at = now.saturating_add(ttl.as_secs());
                }
                Box::pin(ready(Ok(())))
            }
            Err(err) => Box::pin(ready(Err(err))),
        }
    }
}
