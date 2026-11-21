//! Session manager coordinating configuration, storage drivers, and cookie lifecycle.

use std::sync::Arc;

use chirkut::CookieJar;

use crate::{
    config::SessionConfig,
    error::SessionError,
    id::SessionId,
    record::current_unix_timestamp,
    session::Session,
    store::{BoxFuture, SessionStore},
};

/// High-level session manager orchestrating driver operations and cookie jar interactions.
#[derive(Clone)]
pub struct SessionManager {
    config: SessionConfig,
    store: Arc<dyn SessionStore>,
}

impl SessionManager {
    /// Constructs a new session manager with the provided configuration and storage driver.
    #[must_use]
    pub fn new(config: SessionConfig, store: Arc<dyn SessionStore>) -> Self {
        Self { config, store }
    }

    /// Returns a reference to the active session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Returns a reference to the underlying storage driver.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn SessionStore> {
        &self.store
    }

    /// Starts or restores an active session from the given cookie jar.
    ///
    /// If a valid session cookie exists and is found in storage, the existing session is restored.
    /// Otherwise, a fresh session is minted.
    pub fn start<'a>(
        &'a self,
        cookie_jar: &'a CookieJar,
    ) -> BoxFuture<'a, Result<Session, SessionError>> {
        Box::pin(async move {
            let cookie_value = cookie_jar.get_raw(&self.config.cookie_name);

            let loaded_record = self.store.load(cookie_value).await?;
            if let Some(record) = loaded_record {
                let session_id = if let Some(id) = record.id.clone() {
                    id
                } else if let Some(candidate) = cookie_value {
                    SessionId::parse(candidate).unwrap_or(SessionId::generate()?)
                } else {
                    SessionId::generate()?
                };

                let mut session = Session::from_record(session_id, record);
                if self.config.rolling {
                    let now = current_unix_timestamp();
                    session.set_expires_at(now.saturating_add(self.config.lifetime.as_secs()));
                }
                Ok(session)
            } else {
                let session_id = SessionId::generate()?;
                let session = Session::new_fresh(session_id, self.config.lifetime.as_secs());
                Ok(session)
            }
        })
    }

    /// Commits an active session's changes, persisting data to storage and staging response cookies.
    ///
    /// Handles destruction, regeneration, mutations, and rolling expiration.
    pub fn commit<'a>(
        &'a self,
        mut session: Session,
        cookie_jar: &'a mut CookieJar,
    ) -> BoxFuture<'a, Result<(), SessionError>> {
        Box::pin(async move {
            if session.is_destroyed() {
                self.store.destroy(session.id()).await?;
                let tombstone = self.config.build_tombstone()?;
                cookie_jar.set(tombstone);
                return Ok(());
            }

            if session.is_regenerated() {
                if let Some(prior_id) = session.previous_id() {
                    self.store.destroy(prior_id).await?;
                }

                if self.config.rolling {
                    let now = current_unix_timestamp();
                    session.set_expires_at(now.saturating_add(self.config.lifetime.as_secs()));
                }

                let cookie_value = self
                    .store
                    .save(session.id(), &session.to_record(), self.config.lifetime)
                    .await?;

                let cookie = self.config.build_cookie(cookie_value)?;
                cookie_jar.set(cookie);
                return Ok(());
            }

            if session.is_modified() || session.is_fresh() {
                if self.config.rolling {
                    let now = current_unix_timestamp();
                    session.set_expires_at(now.saturating_add(self.config.lifetime.as_secs()));
                }

                let cookie_value = self
                    .store
                    .save(session.id(), &session.to_record(), self.config.lifetime)
                    .await?;

                let cookie = self.config.build_cookie(cookie_value)?;
                cookie_jar.set(cookie);
                return Ok(());
            }

            // Clean (unmodified) session
            if self.config.rolling {
                self.store.touch(session.id(), self.config.lifetime).await?;
                if !self.config.expire_on_close {
                    let cookie_value = self
                        .store
                        .save(session.id(), &session.to_record(), self.config.lifetime)
                        .await?;
                    let cookie = self.config.build_cookie(cookie_value)?;
                    cookie_jar.set(cookie);
                }
            }

            Ok(())
        })
    }
}
