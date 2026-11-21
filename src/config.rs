//! Session and cookie policy configuration.

use std::time::Duration;

use chirkut::{Cookie, SameSite};

use crate::error::SessionError;

/// Default name of the session identifier cookie.
pub const DEFAULT_COOKIE_NAME: &str = "druto_session";

/// Default session validity lifetime (2 hours).
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(7200);

/// Default cookie path.
pub const DEFAULT_COOKIE_PATH: &str = "/";

/// Configuration settings controlling session lifetime and cookie delivery policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Name of the session cookie sent to the client.
    pub cookie_name: String,
    /// Validity duration of the session before it expires.
    pub lifetime: Duration,
    /// Path attribute for the session cookie.
    pub path: String,
    /// Optional domain scope for the session cookie.
    pub domain: Option<String>,
    /// Whether the session cookie must only be transmitted over HTTPS.
    pub secure: bool,
    /// Whether JavaScript access to the session cookie is strictly prohibited.
    pub http_only: bool,
    /// SameSite policy mitigating cross-site request forgery attacks.
    pub same_site: SameSite,
    /// Whether active requests continuously refresh session TTL (sliding expiration).
    pub rolling: bool,
    /// Whether the session cookie expires immediately when the browser is closed.
    pub expire_on_close: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            lifetime: DEFAULT_SESSION_LIFETIME,
            path: DEFAULT_COOKIE_PATH.to_string(),
            domain: None,
            secure: false,
            http_only: true,
            same_site: SameSite::Lax,
            rolling: true,
            expire_on_close: false,
        }
    }
}

impl SessionConfig {
    /// Creates a new configuration builder initialized with secure defaults.
    #[must_use]
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::new()
    }

    /// Constructs an active response cookie for the given session value adhering to this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Serialization`] if the cookie name or value fails validation.
    pub fn build_cookie(&self, value: impl Into<String>) -> Result<Cookie, SessionError> {
        let mut builder = Cookie::build(self.cookie_name.clone(), value)
            .path(self.path.clone())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(Some(self.same_site));

        if let Some(domain) = &self.domain {
            builder = builder.domain(domain.clone());
        }

        if !self.expire_on_close {
            builder = builder.max_age(Some(
                time::Duration::seconds(self.lifetime.as_secs() as i64),
            ));
        }

        builder.build().map_err(|err| {
            SessionError::Serialization(format!("failed to construct session cookie: {err}"))
        })
    }

    /// Constructs an immediate expiration tombstone cookie to purge the session from client browsers.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Serialization`] if cookie construction fails.
    pub fn build_tombstone(&self) -> Result<Cookie, SessionError> {
        let mut builder = Cookie::build(self.cookie_name.clone(), "")
            .path(self.path.clone())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(Some(self.same_site))
            .max_age(Some(time::Duration::ZERO));

        if let Some(domain) = &self.domain {
            builder = builder.domain(domain.clone());
        }

        builder.build().map_err(|err| {
            SessionError::Serialization(format!("failed to construct tombstone cookie: {err}"))
        })
    }
}

/// Fluent builder for [`SessionConfig`].
#[derive(Debug, Clone, Default)]
pub struct SessionConfigBuilder {
    config: SessionConfig,
}

impl SessionConfigBuilder {
    /// Constructs a builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
        }
    }

    /// Sets the cookie name.
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.config.cookie_name = name.into();
        self
    }

    /// Sets the session lifetime.
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.config.lifetime = lifetime;
        self
    }

    /// Sets the cookie path.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.config.path = path.into();
        self
    }

    /// Sets the cookie domain.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.config.domain = Some(domain.into());
        self
    }

    /// Sets whether the cookie requires HTTPS.
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.config.secure = secure;
        self
    }

    /// Sets whether JavaScript access is disabled for the cookie.
    #[must_use]
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.config.http_only = http_only;
        self
    }

    /// Sets the SameSite policy.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.config.same_site = same_site;
        self
    }

    /// Sets whether rolling sliding-window expiration is active.
    #[must_use]
    pub fn rolling(mut self, rolling: bool) -> Self {
        self.config.rolling = rolling;
        self
    }

    /// Sets whether the cookie should expire upon closing the client browser.
    #[must_use]
    pub fn expire_on_close(mut self, expire_on_close: bool) -> Self {
        self.config.expire_on_close = expire_on_close;
        self
    }

    /// Finalizes and returns the built [`SessionConfig`].
    #[must_use]
    pub fn build(self) -> SessionConfig {
        self.config
    }
}
