//! Onion pipeline middleware integrating session management with execution pipelines.

use std::sync::Arc;

use chirkut::CookieJar;
use dhap::{BoxFuture, Error as DhapError, Middleware, Next};

use crate::{error::SessionError, manager::SessionManager, session::Session};

/// Contract for context types that store session state and an HTTP cookie jar.
pub trait SessionContext: Send + 'static {
    /// Returns a mutable reference to the cookie jar.
    fn cookie_jar_mut(&mut self) -> &mut CookieJar;

    /// Returns an immutable reference to the cookie jar.
    fn cookie_jar(&self) -> &CookieJar;

    /// Sets the active session instance on the context.
    fn set_session(&mut self, session: Session);

    /// Returns a mutable reference to the active session if available.
    fn session_mut(&mut self) -> Option<&mut Session>;

    /// Returns an immutable reference to the active session if available.
    fn session(&self) -> Option<&Session>;

    /// Extracts and takes ownership of the active session from the context.
    fn take_session(&mut self) -> Option<Session>;
}

/// Asynchronous onion middleware managing session restoration, down-chain exposure, and upstream commit.
#[derive(Clone)]
pub struct SessionMiddleware {
    manager: Arc<SessionManager>,
}

impl SessionMiddleware {
    /// Constructs a new session middleware wrapping the given manager.
    #[must_use]
    pub fn new(manager: Arc<SessionManager>) -> Self {
        Self { manager }
    }

    /// Returns a reference to the wrapped session manager.
    #[must_use]
    pub fn manager(&self) -> &Arc<SessionManager> {
        &self.manager
    }
}

impl<Context, Output, Error> Middleware<Context, Output, Error> for SessionMiddleware
where
    Context: SessionContext,
    Output: Send + 'static,
    Error: From<SessionError> + Send + 'static,
{
    fn handle<'a>(
        &'a self,
        ctx: &'a mut Context,
        next: Next<Context, Output, Error>,
    ) -> BoxFuture<'a, Result<Output, DhapError<Error>>> {
        Box::pin(async move {
            let session = self
                .manager
                .start(ctx.cookie_jar())
                .await
                .map_err(Error::from)?;
            ctx.set_session(session);

            let downstream_result = next.run(ctx).await;

            if let Some(session) = ctx.take_session() {
                self.manager
                    .commit(session, ctx.cookie_jar_mut())
                    .await
                    .map_err(Error::from)?;
            }

            downstream_result
        })
    }
}

/// A lightweight context container useful for pipeline testing and verification.
#[derive(Debug, Default)]
pub struct TestSessionContext {
    /// Associated cookie jar.
    pub cookie_jar: CookieJar,
    /// Active session instance.
    pub session: Option<Session>,
}

impl TestSessionContext {
    /// Constructs a new test context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a test context with an initialized cookie jar.
    #[must_use]
    pub fn with_cookie_jar(cookie_jar: CookieJar) -> Self {
        Self {
            cookie_jar,
            session: None,
        }
    }
}

impl SessionContext for TestSessionContext {
    fn cookie_jar_mut(&mut self) -> &mut CookieJar {
        &mut self.cookie_jar
    }

    fn cookie_jar(&self) -> &CookieJar {
        &self.cookie_jar
    }

    fn set_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    fn session_mut(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    fn take_session(&mut self) -> Option<Session> {
        self.session.take()
    }
}
