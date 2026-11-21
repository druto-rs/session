//! Local filesystem session storage driver with atomic writes and automatic expiration pruning.

use std::{fs, future::ready, io::ErrorKind, path::PathBuf, time::Duration};

use crate::{
    error::SessionError,
    id::SessionId,
    record::{SessionRecord, current_unix_timestamp},
    store::{BoxFuture, SessionStore},
};

/// A local disk-backed session persistence driver storing JSON session files.
#[derive(Debug, Clone)]
pub struct FileSessionStore {
    directory: PathBuf,
}

impl FileSessionStore {
    /// Constructs a new file session store within the specified directory.
    ///
    /// Automatically creates the directory tree if it does not yet exist.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Io`] if the directory cannot be created or accessed.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, SessionError> {
        let path = directory.into();
        fs::create_dir_all(&path)?;
        Ok(Self { directory: path })
    }

    /// Returns a reference to the storage directory path.
    #[must_use]
    pub fn directory(&self) -> &PathBuf {
        &self.directory
    }

    /// Computes the absolute target file path for a given session identifier.
    #[must_use]
    pub fn session_file_path(&self, session_id: &SessionId) -> PathBuf {
        self.directory.join(format!("{}.json", session_id.as_str()))
    }

    /// Sweeps the storage directory, pruning any expired session records and stale temporary files.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Io`] if reading directory entries fails.
    pub fn clean_expired(&self) -> Result<usize, SessionError> {
        let now = current_unix_timestamp();
        let entries = fs::read_dir(&self.directory)?;
        let mut pruned_count = 0;

        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(err) => return Err(SessionError::Io(err)),
            };

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();

            if file_name.starts_with("temp_") && file_name.ends_with(".tmp") {
                let remove_result = fs::remove_file(&path);
                drop(remove_result);
                pruned_count += 1;
                continue;
            }

            if file_name.ends_with(".json") {
                let should_remove = match fs::read_to_string(&path) {
                    Ok(content) => match SessionRecord::from_json(&content) {
                        Ok(record) => record.is_expired(now),
                        Err(_) => true,
                    },
                    Err(_) => false,
                };

                if should_remove {
                    let remove_result = fs::remove_file(&path);
                    drop(remove_result);
                    pruned_count += 1;
                }
            }
        }

        Ok(pruned_count)
    }

    fn write_atomic(
        &self,
        target_path: &PathBuf,
        session_id: &SessionId,
        content: &str,
    ) -> Result<(), SessionError> {
        let random_suffix = SessionId::generate()
            .map(|id| id.as_str().to_string())
            .unwrap_or_else(|_| current_unix_timestamp().to_string());

        let temp_file_name = format!("temp_{}_{}.tmp", session_id.as_str(), random_suffix);
        let temp_path = self.directory.join(temp_file_name);

        fs::write(&temp_path, content.as_bytes())?;

        if let Err(err) = fs::rename(&temp_path, target_path) {
            drop(fs::remove_file(&temp_path));
            return Err(SessionError::Io(err));
        }

        Ok(())
    }
}

impl SessionStore for FileSessionStore {
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, SessionError>> {
        let Some(candidate_id) = cookie_value else {
            return Box::pin(ready(Ok(None)));
        };

        let session_id = match SessionId::parse(candidate_id) {
            Ok(id) => id,
            Err(_) => return Box::pin(ready(Ok(None))),
        };

        let target_path = self.session_file_path(&session_id);
        let content = match fs::read_to_string(&target_path) {
            Ok(content) => content,
            Err(err) if err.kind() == ErrorKind::NotFound => return Box::pin(ready(Ok(None))),
            Err(err) => return Box::pin(ready(Err(SessionError::Io(err)))),
        };

        let record = match SessionRecord::from_json(&content) {
            Ok(record) => record,
            Err(_) => {
                drop(fs::remove_file(&target_path));
                return Box::pin(ready(Ok(None)));
            }
        };

        let now = current_unix_timestamp();
        if record.is_expired(now) {
            drop(fs::remove_file(&target_path));
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
        persisted.expires_at = now.saturating_add(ttl.as_secs());

        let json_content = match persisted.to_json() {
            Ok(json) => json,
            Err(err) => return Box::pin(ready(Err(err))),
        };

        let target_path = self.session_file_path(session_id);
        match self.write_atomic(&target_path, session_id, &json_content) {
            Ok(()) => Box::pin(ready(Ok(session_id.as_str().to_string()))),
            Err(err) => Box::pin(ready(Err(err))),
        }
    }

    fn destroy<'a>(&'a self, session_id: &'a SessionId) -> BoxFuture<'a, Result<(), SessionError>> {
        let target_path = self.session_file_path(session_id);
        match fs::remove_file(&target_path) {
            Ok(()) => Box::pin(ready(Ok(()))),
            Err(err) if err.kind() == ErrorKind::NotFound => Box::pin(ready(Ok(()))),
            Err(err) => Box::pin(ready(Err(SessionError::Io(err)))),
        }
    }

    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), SessionError>> {
        let target_path = self.session_file_path(session_id);
        let content = match fs::read_to_string(&target_path) {
            Ok(content) => content,
            Err(err) if err.kind() == ErrorKind::NotFound => return Box::pin(ready(Ok(()))),
            Err(err) => return Box::pin(ready(Err(SessionError::Io(err)))),
        };

        let mut record = match SessionRecord::from_json(&content) {
            Ok(record) => record,
            Err(_) => return Box::pin(ready(Ok(()))),
        };

        let now = current_unix_timestamp();
        record.expires_at = now.saturating_add(ttl.as_secs());

        let json_content = match record.to_json() {
            Ok(json) => json,
            Err(err) => return Box::pin(ready(Err(err))),
        };

        match self.write_atomic(&target_path, session_id, &json_content) {
            Ok(()) => Box::pin(ready(Ok(()))),
            Err(err) => Box::pin(ready(Err(err))),
        }
    }
}
