//! Comprehensive test suite for the session crate.

use std::{
    collections::HashMap,
    fs,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    time::Duration,
};

use chirkut::{Cookie, CookieJar, SameSite};
use dhap::{Pipeline, from_terminal};
use druto_session as session;
use druto_session::{
    CookieSessionStore, FileSessionStore, MemorySessionStore, SESSION_ID_BYTE_LENGTH,
    SESSION_ID_STRING_LENGTH, Session, SessionConfig, SessionContext, SessionError, SessionId,
    SessionManager, SessionMiddleware, SessionRecord, SessionState, SessionStore,
    TestSessionContext, current_unix_timestamp,
};
use gopon::{Encrypter, Key, KeyRing};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

// --- Test Utilities (Zero-Dependency Executor) ---

fn noop_waker() -> Waker {
    fn noop_clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &NOOP_VTABLE)
    }
    fn noop_action(data: *const ()) {
        let _ = data;
    }
    static NOOP_VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_action, noop_action, noop_action);

    // SAFETY: RawWaker implementation performs no operations and maintains valid null pointer state.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_VTABLE)) }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut pinned = Pin::from(Box::new(future));
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    match pinned.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => {
            panic!("test future unexpectedly yielded Pending without an external driver")
        }
    }
}

fn create_test_encrypter() -> Arc<Encrypter> {
    let key = Key::generate().expect("key generation must succeed");
    let keyring = KeyRing::new(key);
    Arc::new(Encrypter::new(keyring))
}

// --- SessionId Tests ---

#[test]
fn test_session_id_generate_and_properties() {
    assert_eq!(SESSION_ID_BYTE_LENGTH, 32);
    let session_id = SessionId::generate().expect("session ID generation must succeed");
    assert_eq!(session_id.len(), SESSION_ID_STRING_LENGTH);
    assert_eq!(session_id.as_str().len(), 43);
    assert_eq!(format!("{session_id}").len(), 43);
    assert_eq!(
        format!("{session_id:?}"),
        format!("SessionId({})", session_id.as_str())
    );
    assert_eq!(session_id.as_ref(), session_id.as_str());

    let parsed = SessionId::parse(session_id.as_str()).expect("generated ID must parse");
    assert_eq!(session_id, parsed);
}

#[test]
fn test_session_id_uniqueness() {
    let first = SessionId::generate().expect("first ID must succeed");
    let second = SessionId::generate().expect("second ID must succeed");
    assert_ne!(first, second);
}

#[test]
fn test_session_id_parse_validation() {
    // Exact 43 character valid string
    let valid_candidate = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM012-";
    assert_eq!(valid_candidate.len(), 43);
    let parsed = SessionId::parse(valid_candidate).expect("valid candidate must parse");
    assert_eq!(parsed.as_str(), valid_candidate);

    // Too short
    let short_candidate = "abc";
    assert!(SessionId::parse(short_candidate).is_err());

    // Too long (44 characters)
    let long_candidate = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM012-X";
    assert_eq!(long_candidate.len(), 44);
    assert!(SessionId::parse(long_candidate).is_err());

    // Invalid characters: dot and slash (path traversal attempts)
    let dot_candidate = "...........................................";
    assert!(SessionId::parse(dot_candidate).is_err());

    let slash_candidate = "../../../../../../../../../../../../../../../";
    assert!(SessionId::parse(slash_candidate).is_err());

    // Invalid characters: punctuation and spaces
    let invalid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM012!";
    assert!(SessionId::parse(invalid_chars).is_err());

    let space_candidate = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM012 ";
    assert!(SessionId::parse(space_candidate).is_err());
}

#[test]
fn test_session_id_serde_roundtrip() {
    let session_id = SessionId::generate().expect("generation must succeed");
    let serialized = serde_json::to_string(&session_id).expect("must serialize");
    let deserialized: SessionId = serde_json::from_str(&serialized).expect("must deserialize");
    assert_eq!(session_id, deserialized);
}

// --- SessionError Tests ---

#[test]
fn test_session_error_display_and_source() {
    let io_err = SessionError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "disk missing",
    ));
    assert!(format!("{io_err}").contains("session I/O error: disk missing"));
    assert!(std::error::Error::source(&io_err).is_some());

    let ser_err = SessionError::Serialization("bad type".to_string());
    assert_eq!(
        format!("{ser_err}"),
        "session serialization error: bad type"
    );
    assert!(std::error::Error::source(&ser_err).is_none());

    let deser_err = SessionError::Deserialization("missing field".to_string());
    assert_eq!(
        format!("{deser_err}"),
        "session deserialization error: missing field"
    );

    let invalid_id_err = SessionError::InvalidId("bad length".to_string());
    assert_eq!(
        format!("{invalid_id_err}"),
        "invalid session ID: bad length"
    );

    let payload_err = SessionError::PayloadTooLarge(4500);
    assert!(format!("{payload_err}").contains("4500 bytes"));

    let crypto_err = SessionError::Crypto("key failure".to_string());
    assert_eq!(
        format!("{crypto_err}"),
        "session cryptographic error: key failure"
    );

    let expired_err = SessionError::Expired;
    assert_eq!(format!("{expired_err}"), "session has expired");

    let store_err = SessionError::Store("backend timeout".to_string());
    assert_eq!(
        format!("{store_err}"),
        "session store error: backend timeout"
    );

    let lock_err = SessionError::LockPoisoned("poisoned mutex".to_string());
    assert_eq!(
        format!("{lock_err}"),
        "session lock poisoned: poisoned mutex"
    );
}

#[test]
fn test_session_error_conversions() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let converted_io: SessionError = io_err.into();
    assert!(matches!(converted_io, SessionError::Io(_)));

    let json_err = serde_json::from_str::<SessionRecord>("invalid json").unwrap_err();
    let converted_json: SessionError = json_err.into();
    assert!(matches!(converted_json, SessionError::Serialization(_)));

    let crypto_err = gopon::Error::Internal("test".to_string());
    let converted_crypto: SessionError = crypto_err.into();
    assert!(matches!(converted_crypto, SessionError::Crypto(_)));
}

// --- SessionRecord Tests ---

#[test]
fn test_session_record_serialization_and_expiry() {
    let id = SessionId::generate().expect("ID generation must succeed");
    let mut data = HashMap::new();
    data.insert("user_id".to_string(), json!(42));
    data.insert("username".to_string(), json!("alice"));

    let mut flash = HashMap::new();
    flash.insert("alert".to_string(), json!("welcome"));

    let now = current_unix_timestamp();
    let record = SessionRecord::new(Some(id.clone()), data, flash, now, now + 100);

    assert!(!record.is_expired(now + 50));
    assert!(record.is_expired(now + 100));
    assert!(record.is_expired(now + 150));

    let json_repr = record.to_json().expect("record serialization must succeed");
    let restored =
        SessionRecord::from_json(&json_repr).expect("record deserialization must succeed");

    assert_eq!(record, restored);
    assert_eq!(restored.id, Some(id));
}

#[test]
fn test_session_record_invalid_json() {
    let result = SessionRecord::from_json("not valid json");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SessionError::Deserialization(_)
    ));
}

// --- Session Data & Flash Lifecycle Tests ---

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct UserProfile {
    name: String,
    role: String,
    age: u32,
}

#[test]
fn test_session_fresh_state_and_mutations() {
    let id = SessionId::generate().expect("ID must succeed");
    let mut session = Session::new_fresh(id.clone(), 3600);

    assert_eq!(session.id(), &id);
    assert!(session.is_fresh());
    assert!(!session.is_clean());
    assert!(!session.is_modified());
    assert!(!session.is_regenerated());
    assert!(!session.is_destroyed());
    assert_eq!(session.state(), SessionState::Fresh);

    // Initial read is empty
    let empty_user: Option<String> = session.get("user").expect("get must succeed");
    assert_eq!(empty_user, None);
    assert!(!session.has("user"));

    // Put typed data
    let profile = UserProfile {
        name: "Bob".to_string(),
        role: "admin".to_string(),
        age: 30,
    };
    session.put("profile", &profile).expect("put must succeed");

    assert!(session.has("profile"));
    assert_eq!(session.all().len(), 1);

    let retrieved: Option<UserProfile> = session.get("profile").expect("get must succeed");
    assert_eq!(retrieved, Some(profile));

    // Get unparsed JSON value
    let raw_val = session.get_value("profile");
    assert!(raw_val.is_some());
    assert_eq!(raw_val.unwrap()["name"], "Bob");

    // Remove
    let removed = session.remove("profile");
    assert!(removed.is_some());
    assert!(!session.has("profile"));
    assert_eq!(session.remove("non_existent"), None);

    // Pull
    session.put("token", "secret123").expect("put must succeed");
    let pulled: Option<String> = session.pull("token").expect("pull must succeed");
    assert_eq!(pulled, Some("secret123".to_string()));
    assert!(!session.has("token"));

    let pulled_none: Option<String> = session.pull("token").expect("pull none must succeed");
    assert_eq!(pulled_none, None);

    // Clear
    session.put("key1", 1).expect("put must succeed");
    session.put("key2", 2).expect("put must succeed");
    assert_eq!(session.all().len(), 2);
    session.clear();
    assert_eq!(session.all().len(), 0);
}

#[test]
fn test_session_type_mismatch_error() {
    let id = SessionId::generate().expect("ID must succeed");
    let mut session = Session::new_fresh(id, 3600);

    session
        .put("count", "not a number")
        .expect("put must succeed");

    // Expecting u32 when string is stored
    let get_result: Result<Option<u32>, SessionError> = session.get("count");
    assert!(get_result.is_err());
    assert!(matches!(
        get_result.unwrap_err(),
        SessionError::Deserialization(_)
    ));

    let pull_result: Result<Option<u32>, SessionError> = session.pull("count");
    assert!(pull_result.is_err());
}

#[test]
fn test_session_regeneration_and_invalidation() {
    let initial_id = SessionId::generate().expect("ID must succeed");
    let mut session = Session::new_fresh(initial_id.clone(), 3600);
    session.put("user_id", 100).expect("put must succeed");

    // Regenerate
    assert_eq!(session.previous_id(), None);
    session.regenerate().expect("regeneration must succeed");

    assert!(session.is_regenerated());
    assert_ne!(session.id(), &initial_id);
    assert_eq!(session.previous_id(), Some(&initial_id));
    assert_eq!(session.get::<u32>("user_id").unwrap(), Some(100));

    // Secondary regeneration retains original previous_id
    let second_id = session.id().clone();
    session
        .regenerate()
        .expect("second regeneration must succeed");
    assert_eq!(session.previous_id(), Some(&initial_id));
    assert_ne!(session.id(), &second_id);

    // Invalidate
    session.invalidate();
    assert!(session.is_destroyed());
    assert!(session.all().is_empty());
    assert!(session.flash_messages().is_empty());
    assert!(session.response_flash().is_empty());
}

#[test]
fn test_session_flash_messages_lifecycle() {
    let id = SessionId::generate().expect("ID must succeed");
    let now = current_unix_timestamp();

    // Create a record with incoming flash messages from request N
    let mut incoming_flash = HashMap::new();
    incoming_flash.insert("status".to_string(), json!("created"));
    incoming_flash.insert("message".to_string(), json!("item added"));
    incoming_flash.insert("counter".to_string(), json!(5));

    let record = SessionRecord::new(
        Some(id.clone()),
        HashMap::new(),
        incoming_flash,
        now,
        now + 3600,
    );
    let mut session = Session::from_record(id, record);

    assert!(session.is_clean());
    assert_eq!(session.flash_messages().len(), 3);
    assert_eq!(session.response_flash().len(), 0);

    // Read flash messages via old()
    let status: Option<String> = session.old("status").expect("old must succeed");
    assert_eq!(status, Some("created".to_string()));

    let counter: Option<u32> = session.old("counter").expect("old must succeed");
    assert_eq!(counter, Some(5));

    let old_raw = session.old_value("message");
    assert_eq!(old_raw, Some(&json!("item added")));

    let missing: Option<String> = session.old("missing").expect("missing must succeed");
    assert_eq!(missing, None);

    // Flash a new message for request N+2
    session
        .flash("new_alert", "all good")
        .expect("flash must succeed");
    assert!(session.is_modified());
    assert_eq!(session.response_flash().len(), 1);

    // Reflash preserves all incoming flash into response_flash
    session.reflash();
    assert_eq!(session.response_flash().len(), 4); // 3 incoming + 1 new_alert
    assert_eq!(session.response_flash()["status"], "created");

    // Convert to record and verify response_flash becomes record.flash
    let next_record = session.to_record();
    assert_eq!(next_record.flash.len(), 4);
}

#[test]
fn test_session_flash_keep() {
    let id = SessionId::generate().expect("ID must succeed");
    let now = current_unix_timestamp();

    let mut incoming_flash = HashMap::new();
    incoming_flash.insert("keep_me".to_string(), json!("stay"));
    incoming_flash.insert("discard_me".to_string(), json!("bye"));

    let record = SessionRecord::new(
        Some(id.clone()),
        HashMap::new(),
        incoming_flash,
        now,
        now + 3600,
    );
    let mut session = Session::from_record(id, record);

    session.keep(&["keep_me", "non_existent"]);

    assert_eq!(session.response_flash().len(), 1);
    assert_eq!(session.response_flash()["keep_me"], "stay");
    assert!(!session.response_flash().contains_key("discard_me"));
}

// --- SessionConfig Tests ---

#[test]
fn test_session_config_builder_and_defaults() {
    let config = SessionConfig::default();
    assert_eq!(config.cookie_name, "druto_session");
    assert_eq!(config.lifetime, Duration::from_secs(7200));
    assert_eq!(config.path, "/");
    assert_eq!(config.domain, None);
    assert!(!config.secure);
    assert!(config.http_only);
    assert_eq!(config.same_site, SameSite::Lax);
    assert!(config.rolling);
    assert!(!config.expire_on_close);

    let built = SessionConfig::builder()
        .cookie_name("custom_sess")
        .lifetime(Duration::from_secs(1800))
        .path("/app")
        .domain("example.com")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .rolling(false)
        .expire_on_close(true)
        .build();

    assert_eq!(built.cookie_name, "custom_sess");
    assert_eq!(built.lifetime, Duration::from_secs(1800));
    assert_eq!(built.path, "/app");
    assert_eq!(built.domain, Some("example.com".to_string()));
    assert!(built.secure);
    assert_eq!(built.same_site, SameSite::Strict);
    assert!(!built.rolling);
    assert!(built.expire_on_close);
}

#[test]
fn test_session_config_cookie_construction() {
    let config = SessionConfig::builder()
        .cookie_name("sess")
        .domain("sub.example.com")
        .path("/")
        .lifetime(Duration::from_secs(3600))
        .expire_on_close(false)
        .build();

    let cookie = config
        .build_cookie("token123")
        .expect("cookie build must succeed");
    assert_eq!(cookie.name(), "sess");
    assert_eq!(cookie.value(), "token123");
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.domain(), Some("sub.example.com"));
    assert!(cookie.max_age().is_some());

    let tombstone = config
        .build_tombstone()
        .expect("tombstone build must succeed");
    assert_eq!(tombstone.name(), "sess");
    assert!(tombstone.is_tombstone());
}

// --- MemorySessionStore Tests ---

#[test]
fn test_memory_session_store_roundtrip() {
    let store = MemorySessionStore::new();
    let session_id = SessionId::generate().expect("ID must succeed");

    assert_eq!(store.count().unwrap(), 0);
    assert!(!store.contains(&session_id).unwrap());

    // Load non-existent
    let loaded = block_on(store.load(Some(session_id.as_str()))).expect("load must succeed");
    assert_eq!(loaded, None);

    // Save
    let now = current_unix_timestamp();
    let mut data = HashMap::new();
    data.insert("theme".to_string(), json!("dark"));
    let record = SessionRecord::new(
        Some(session_id.clone()),
        data,
        HashMap::new(),
        now,
        now + 3600,
    );

    let saved_val = block_on(store.save(&session_id, &record, Duration::from_secs(3600)))
        .expect("save must succeed");
    assert_eq!(saved_val, session_id.as_str());

    assert_eq!(store.count().unwrap(), 1);
    assert!(store.contains(&session_id).unwrap());

    // Load existing
    let restored = block_on(store.load(Some(session_id.as_str())))
        .expect("load must succeed")
        .expect("record must exist");
    assert_eq!(restored.data["theme"], "dark");

    // Touch
    block_on(store.touch(&session_id, Duration::from_secs(7200))).expect("touch must succeed");

    // Destroy
    block_on(store.destroy(&session_id)).expect("destroy must succeed");
    assert_eq!(store.count().unwrap(), 0);
    assert!(!store.contains(&session_id).unwrap());

    // Load destroyed
    let after_destroy = block_on(store.load(Some(session_id.as_str()))).expect("load must succeed");
    assert_eq!(after_destroy, None);
}

#[test]
fn test_memory_session_store_expiration() {
    let store = MemorySessionStore::new();
    let session_id = SessionId::generate().expect("ID must succeed");

    let now = current_unix_timestamp();
    // Record that expired 10 seconds ago
    let record = SessionRecord::new(
        Some(session_id.clone()),
        HashMap::new(),
        HashMap::new(),
        now - 100,
        now - 10,
    );

    // Save with 0 duration so it expires immediately
    block_on(store.save(&session_id, &record, Duration::from_secs(0))).expect("save must succeed");

    let loaded = block_on(store.load(Some(session_id.as_str()))).expect("load must succeed");
    assert_eq!(loaded, None);
    assert_eq!(store.count().unwrap(), 0);
}

// --- FileSessionStore Tests ---

#[test]
fn test_file_session_store_lifecycle_and_atomic_writes() {
    let temp_dir =
        std::env::temp_dir().join(format!("druto_session_test_{}", current_unix_timestamp()));
    let store = FileSessionStore::new(&temp_dir).expect("file store creation must succeed");

    let session_id = SessionId::generate().expect("ID must succeed");

    // Load non-existent
    let non_existent = block_on(store.load(Some(session_id.as_str()))).expect("load must succeed");
    assert_eq!(non_existent, None);

    // Save
    let now = current_unix_timestamp();
    let mut data = HashMap::new();
    data.insert("session_key".to_string(), json!("persisted_value"));
    let record = SessionRecord::new(
        Some(session_id.clone()),
        data,
        HashMap::new(),
        now,
        now + 3600,
    );

    let returned_val = block_on(store.save(&session_id, &record, Duration::from_secs(3600)))
        .expect("save must succeed");
    assert_eq!(returned_val, session_id.as_str());

    let file_path = store.session_file_path(&session_id);
    assert!(file_path.exists());

    // Load
    let loaded = block_on(store.load(Some(session_id.as_str())))
        .expect("load must succeed")
        .expect("record must exist");
    assert_eq!(loaded.data["session_key"], "persisted_value");

    // Touch
    block_on(store.touch(&session_id, Duration::from_secs(7200))).expect("touch must succeed");

    // Destroy
    block_on(store.destroy(&session_id)).expect("destroy must succeed");
    assert!(!file_path.exists());

    let after_destroy = block_on(store.load(Some(session_id.as_str()))).expect("load must succeed");
    assert_eq!(after_destroy, None);

    // Clean up test directory
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_file_session_store_clean_expired_and_corrupt() {
    let temp_dir = std::env::temp_dir().join(format!(
        "druto_session_clean_test_{}",
        current_unix_timestamp()
    ));
    let store = FileSessionStore::new(&temp_dir).expect("store init must succeed");

    let valid_id = SessionId::generate().expect("ID must succeed");
    let expired_id = SessionId::generate().expect("ID must succeed");

    let now = current_unix_timestamp();

    // Valid record
    let valid_record = SessionRecord::new(
        Some(valid_id.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );
    block_on(store.save(&valid_id, &valid_record, Duration::from_secs(3600)))
        .expect("save must succeed");

    // Expired record
    let expired_record = SessionRecord::new(
        Some(expired_id.clone()),
        HashMap::new(),
        HashMap::new(),
        now - 100,
        now - 10,
    );
    let expired_file = store.session_file_path(&expired_id);
    fs::write(&expired_file, expired_record.to_json().unwrap()).expect("write expired file");

    // Corrupted record
    let corrupt_id = SessionId::generate().expect("ID must succeed");
    let corrupt_file = store.session_file_path(&corrupt_id);
    fs::write(&corrupt_file, "corrupt json content").expect("write corrupt file");

    // Leftover temporary file
    let stale_tmp_file = temp_dir.join("temp_some_id_123.tmp");
    fs::write(&stale_tmp_file, "stale").expect("write temp file");

    // Run clean_expired
    let pruned = store.clean_expired().expect("clean_expired must succeed");
    assert_eq!(pruned, 3); // expired + corrupt + stale temp

    assert!(store.session_file_path(&valid_id).exists());
    assert!(!expired_file.exists());
    assert!(!corrupt_file.exists());
    assert!(!stale_tmp_file.exists());

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

// --- CookieSessionStore Tests ---

#[test]
fn test_cookie_session_store_roundtrip_and_encryption() {
    let encrypter = create_test_encrypter();
    let store = CookieSessionStore::new(encrypter);
    let session_id = SessionId::generate().expect("ID must succeed");

    let now = current_unix_timestamp();
    let mut data = HashMap::new();
    data.insert("authenticated".to_string(), json!(true));
    let record = SessionRecord::new(
        Some(session_id.clone()),
        data,
        HashMap::new(),
        now,
        now + 3600,
    );

    // Save produces encrypted string prefixed with e:
    let wire_cookie = block_on(store.save(&session_id, &record, Duration::from_secs(3600)))
        .expect("save must succeed");
    assert!(wire_cookie.starts_with("e:"));
    assert_ne!(wire_cookie, session_id.as_str());

    // Load decrypts correctly
    let loaded = block_on(store.load(Some(&wire_cookie)))
        .expect("load must succeed")
        .expect("record must exist");
    assert_eq!(loaded.data["authenticated"], true);
    assert_eq!(loaded.id, Some(session_id));
}

#[test]
fn test_cookie_session_store_tamper_protection() {
    let encrypter = create_test_encrypter();
    let store = CookieSessionStore::new(encrypter);
    let session_id = SessionId::generate().expect("ID must succeed");

    let now = current_unix_timestamp();
    let record = SessionRecord::new(
        Some(session_id.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );

    let wire_cookie = block_on(store.save(&session_id, &record, Duration::from_secs(3600)))
        .expect("save must succeed");

    // Tampered cookie value
    let mut tampered = wire_cookie.clone();
    tampered.replace_range(5..8, "XYZ");

    let tampered_load =
        block_on(store.load(Some(&tampered))).expect("tamper load must return Ok(None)");
    assert_eq!(tampered_load, None);

    // Missing prefix
    let no_prefix_load =
        block_on(store.load(Some("raw_string"))).expect("no prefix must return Ok(None)");
    assert_eq!(no_prefix_load, None);
}

#[test]
fn test_cookie_session_store_payload_size_ceiling() {
    let encrypter = create_test_encrypter();
    let store = CookieSessionStore::new(encrypter).with_max_payload_size(200);

    let session_id = SessionId::generate().expect("ID must succeed");
    let now = current_unix_timestamp();

    let mut huge_data = HashMap::new();
    huge_data.insert("large".to_string(), json!("A".repeat(500)));
    let record = SessionRecord::new(
        Some(session_id.clone()),
        huge_data,
        HashMap::new(),
        now,
        now + 3600,
    );

    let result = block_on(store.save(&session_id, &record, Duration::from_secs(3600)));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SessionError::PayloadTooLarge(_)
    ));
}

// --- SessionManager & Middleware Pipeline Tests ---

#[test]
fn test_session_manager_start_and_commit_lifecycle() {
    let config = SessionConfig::default();
    let store = Arc::new(MemorySessionStore::new());
    let manager = SessionManager::new(config.clone(), store.clone());

    let mut cookie_jar = CookieJar::new();

    // Start with empty cookie jar creates fresh session
    let session = block_on(manager.start(&cookie_jar)).expect("start must succeed");
    assert!(session.is_fresh());

    let session_id = session.id().clone();
    let mut active_session = session;
    active_session.put("counter", 1).expect("put must succeed");

    // Commit modified session sets response cookie
    block_on(manager.commit(active_session, &mut cookie_jar)).expect("commit must succeed");

    assert!(cookie_jar.has(&config.cookie_name));
    let staged_cookie_value = cookie_jar
        .get_raw(&config.cookie_name)
        .expect("cookie must exist");
    assert_eq!(staged_cookie_value, session_id.as_str());

    // Subsequent start restores existing session
    let restored = block_on(manager.start(&cookie_jar)).expect("second start must succeed");
    assert!(restored.is_clean());
    assert_eq!(restored.id(), &session_id);
    assert_eq!(restored.get::<u32>("counter").unwrap(), Some(1));
}

#[test]
fn test_pipeline_middleware_end_to_end_flash_and_fixation() {
    let config = SessionConfig::default();
    let store = Arc::new(MemorySessionStore::new());
    let manager = Arc::new(SessionManager::new(config.clone(), store.clone()));
    let session_middleware = SessionMiddleware::new(manager);

    let pipeline =
        Pipeline::<TestSessionContext, String, SessionError>::new().pipe(session_middleware);

    // --- Request 1: Fresh user, writes session attribute and flashes a message ---
    let mut context1 = TestSessionContext::new();
    let result1 = block_on(pipeline.run(
        &mut context1,
        from_terminal(|ctx: &mut TestSessionContext| {
            Box::pin(async move {
                let session = ctx.session_mut().expect("session must be injected");
                session.put("username", "alice")?;
                session.flash("flash_notice", "welcome new user")?;
                Ok("request 1 completed".to_string())
            })
        }),
    ))
    .expect("pipeline 1 must succeed");
    assert_eq!(result1, "request 1 completed");

    // Extract cookie from Request 1
    let session_cookie1 = context1
        .cookie_jar
        .get_raw(&config.cookie_name)
        .expect("cookie must exist");
    let session_id1 = session_cookie1.to_string();

    // --- Request 2: Restores session, reads flash message, updates data ---
    let mut jar2 = CookieJar::new();
    jar2.set(
        Cookie::build(config.cookie_name.clone(), session_id1.clone())
            .build()
            .unwrap(),
    );
    let mut context2 = TestSessionContext::with_cookie_jar(jar2);

    let result2 = block_on(pipeline.run(
        &mut context2,
        from_terminal(|ctx: &mut TestSessionContext| {
            Box::pin(async move {
                let session = ctx.session_mut().expect("session must exist");
                assert_eq!(session.get::<String>("username")?.unwrap(), "alice");

                // Flash message from Request 1 is available
                let notice: Option<String> = session.old("flash_notice")?;
                assert_eq!(notice, Some("welcome new user".to_string()));

                // Stage another flash message
                session.flash("action_alert", "profile updated")?;

                Ok("request 2 completed".to_string())
            })
        }),
    ))
    .expect("pipeline 2 must succeed");
    assert_eq!(result2, "request 2 completed");

    // --- Request 3: Verifies Request 1 flash message was automatically purged, Request 2 flash exists ---
    let mut jar3 = CookieJar::new();
    jar3.set(
        Cookie::build(config.cookie_name.clone(), session_id1.clone())
            .build()
            .unwrap(),
    );
    let mut context3 = TestSessionContext::with_cookie_jar(jar3);

    let result3 = block_on(pipeline.run(
        &mut context3,
        from_terminal(|ctx: &mut TestSessionContext| {
            Box::pin(async move {
                let session = ctx.session_mut().expect("session must exist");

                // Request 1 flash is gone (purged on N+2)
                assert_eq!(session.old::<String>("flash_notice")?, None);

                // Request 2 flash is present
                assert_eq!(
                    session.old::<String>("action_alert")?,
                    Some("profile updated".to_string())
                );

                // User logs in: regenerate session ID to defend against fixation attacks
                session.regenerate()?;

                Ok("request 3 completed".to_string())
            })
        }),
    ))
    .expect("pipeline 3 must succeed");
    assert_eq!(result3, "request 3 completed");

    // Session ID must have rotated in Request 3
    let session_cookie3 = context3
        .cookie_jar
        .get_raw(&config.cookie_name)
        .expect("cookie must exist");
    let session_id3 = session_cookie3.to_string();
    assert_ne!(session_id3, session_id1);

    // Old session ID 1 must be destroyed in the persistent store
    assert!(
        !store
            .contains(&SessionId::parse(&session_id1).unwrap())
            .unwrap()
    );
    // New session ID 3 must exist in the persistent store
    assert!(
        store
            .contains(&SessionId::parse(&session_id3).unwrap())
            .unwrap()
    );

    // --- Request 4: User logs out: invalidate session ---
    let mut jar4 = CookieJar::new();
    jar4.set(
        Cookie::build(config.cookie_name.clone(), session_id3.clone())
            .build()
            .unwrap(),
    );
    let mut context4 = TestSessionContext::with_cookie_jar(jar4);

    let result4 = block_on(pipeline.run(
        &mut context4,
        from_terminal(|ctx: &mut TestSessionContext| {
            Box::pin(async move {
                let session = ctx.session_mut().expect("session must exist");
                assert_eq!(session.get::<String>("username")?.unwrap(), "alice");

                session.invalidate();
                Ok("logout completed".to_string())
            })
        }),
    ))
    .expect("pipeline 4 must succeed");
    assert_eq!(result4, "logout completed");

    // Verify session ID 3 was destroyed in store
    assert!(
        !store
            .contains(&SessionId::parse(&session_id3).unwrap())
            .unwrap()
    );

    // Verify tombstone cookie was emitted
    let staged_cookie = context4
        .cookie_jar
        .get_staged(&config.cookie_name)
        .expect("cookie must be staged");
    assert!(staged_cookie.is_tombstone());
}

#[test]
fn test_config_builder_full_coverage() {
    let config = SessionConfig::builder()
        .cookie_name("session_custom")
        .lifetime(Duration::from_secs(3600))
        .path("/admin")
        .domain("sub.example.com")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .rolling(true)
        .expire_on_close(true)
        .build();

    let tombstone_with_domain = config
        .build_tombstone()
        .expect("tombstone build must succeed");
    assert_eq!(tombstone_with_domain.domain(), Some("sub.example.com"));
    assert_eq!(tombstone_with_domain.path(), Some("/admin"));
    assert!(tombstone_with_domain.is_tombstone());
}

#[test]
fn test_session_accessors_and_direct_value_methods() {
    let id = SessionId::generate().expect("ID must succeed");
    let mut session = Session::new_fresh(id, 3600);

    let created_at = session.created_at();
    assert!(created_at > 0);
    let expires_at = session.expires_at();
    assert!(expires_at > created_at);

    session.set_expires_at(expires_at + 500);
    assert_eq!(session.expires_at(), expires_at + 500);

    // Direct put_value and flash_value
    session.put_value("raw_key", json!({"nested": true}));
    assert_eq!(session.get_value("raw_key").unwrap()["nested"], true);

    session.flash_value("raw_flash", json!([1, 2, 3]));
    assert_eq!(session.response_flash()["raw_flash"], json!([1, 2, 3]));

    // Reflash on empty incoming flash does not mutate
    let clean_session = Session::new_fresh(SessionId::generate().unwrap(), 3600);
    let mut empty_flash_sess = clean_session;
    empty_flash_sess.reflash();
    assert!(empty_flash_sess.response_flash().is_empty());

    // Keep on non-matching keys
    empty_flash_sess.keep(&["non_existent_key"]);
    assert!(empty_flash_sess.response_flash().is_empty());

    // Regenerate on destroyed session remains destroyed
    empty_flash_sess.invalidate();
    assert!(empty_flash_sess.is_destroyed());
    empty_flash_sess
        .regenerate()
        .expect("regenerate on destroyed must succeed");
    assert!(empty_flash_sess.is_destroyed());
}

#[test]
fn test_manager_accessors_and_clean_rolling_variations() {
    let config_rolling = SessionConfig::builder()
        .cookie_name("sess_roll")
        .rolling(true)
        .expire_on_close(false)
        .build();

    let store = Arc::new(MemorySessionStore::new());
    let manager = SessionManager::new(config_rolling.clone(), store.clone());

    assert_eq!(manager.config().cookie_name, "sess_roll");
    assert!(Arc::ptr_eq(
        manager.store(),
        &(store.clone() as Arc<dyn SessionStore>)
    ));

    // Clean session with rolling=true and expire_on_close=false
    let mut jar = CookieJar::new();
    let id = SessionId::generate().unwrap();
    let now = current_unix_timestamp();
    let record = SessionRecord::new(
        Some(id.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );
    block_on(store.save(&id, &record, Duration::from_secs(3600))).unwrap();

    jar.set(Cookie::build("sess_roll", id.as_str()).build().unwrap());

    let clean_sess = block_on(manager.start(&jar)).unwrap();
    assert!(clean_sess.is_clean());

    block_on(manager.commit(clean_sess, &mut jar)).unwrap();
    assert!(jar.has("sess_roll"));

    // Clean session with rolling=false does not touch or re-stage cookie
    let config_non_rolling = SessionConfig::builder()
        .cookie_name("sess_noroll")
        .rolling(false)
        .build();

    let manager_non_rolling = SessionManager::new(config_non_rolling, store.clone());
    let mut jar_non_rolling = CookieJar::new();
    let id2 = SessionId::generate().unwrap();
    let record2 = SessionRecord::new(
        Some(id2.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );
    block_on(store.save(&id2, &record2, Duration::from_secs(3600))).unwrap();
    jar_non_rolling.set(Cookie::build("sess_noroll", id2.as_str()).build().unwrap());

    let clean_sess2 = block_on(manager_non_rolling.start(&jar_non_rolling)).unwrap();
    block_on(manager_non_rolling.commit(clean_sess2, &mut jar_non_rolling)).unwrap();

    // Clean session with rolling=true and expire_on_close=true touches but does not re-stage cookie
    let config_expire_on_close = SessionConfig::builder()
        .cookie_name("sess_close")
        .rolling(true)
        .expire_on_close(true)
        .build();

    let manager_expire_on_close = SessionManager::new(config_expire_on_close, store.clone());
    let mut jar_close = CookieJar::new();
    let id3 = SessionId::generate().unwrap();
    let record3 = SessionRecord::new(
        Some(id3.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );
    block_on(store.save(&id3, &record3, Duration::from_secs(3600))).unwrap();
    jar_close.set(Cookie::build("sess_close", id3.as_str()).build().unwrap());

    let clean_sess3 = block_on(manager_expire_on_close.start(&jar_close)).unwrap();
    block_on(manager_expire_on_close.commit(clean_sess3, &mut jar_close)).unwrap();
}

#[test]
fn test_middleware_accessors_and_consumed_session() {
    let config = SessionConfig::default();
    let store = Arc::new(MemorySessionStore::new());
    let manager = Arc::new(SessionManager::new(config.clone(), store.clone()));
    let session_middleware = SessionMiddleware::new(manager.clone());

    assert_eq!(
        session_middleware.manager().config().cookie_name,
        "druto_session"
    );

    let pipeline =
        Pipeline::<TestSessionContext, String, SessionError>::new().pipe(session_middleware);

    let mut context = TestSessionContext::new();

    // Terminal handler consumes session early with take_session
    let terminal = from_terminal(|ctx: &mut TestSessionContext| {
        Box::pin(async move {
            let session = ctx.take_session().expect("must have session");
            assert!(session.is_fresh());
            assert!(ctx.session().is_none());
            Ok("consumed".to_string())
        })
    });

    let res = block_on(pipeline.run(&mut context, terminal)).unwrap();
    assert_eq!(res, "consumed");
}

#[test]
fn test_memory_store_edge_cases() {
    let store = MemorySessionStore::new();
    let id = SessionId::generate().unwrap();

    // contains on non-existent
    assert!(!store.contains(&id).unwrap());

    // load on invalid id format
    assert_eq!(block_on(store.load(Some("bad_id"))).unwrap(), None);

    // clear on populated store
    let now = current_unix_timestamp();
    let record = SessionRecord::new(
        Some(id.clone()),
        HashMap::new(),
        HashMap::new(),
        now,
        now + 3600,
    );
    block_on(store.save(&id, &record, Duration::from_secs(3600))).unwrap();
    assert_eq!(store.count().unwrap(), 1);

    store.clear().unwrap();
    assert_eq!(store.count().unwrap(), 0);

    // touch on non-existent
    block_on(store.touch(&id, Duration::from_secs(3600))).unwrap();
}

#[test]
fn test_file_store_edge_cases() {
    let temp_dir = std::env::temp_dir().join(format!(
        "druto_file_edge_cases_{}",
        current_unix_timestamp()
    ));
    let store = FileSessionStore::new(&temp_dir).unwrap();

    assert_eq!(store.directory(), &temp_dir);

    // load with None
    assert_eq!(block_on(store.load(None)).unwrap(), None);

    // load with invalid session id format
    assert_eq!(block_on(store.load(Some("invalid!"))).unwrap(), None);

    // touch non-existent file
    let id = SessionId::generate().unwrap();
    block_on(store.touch(&id, Duration::from_secs(3600))).unwrap();

    // touch corrupt file
    let corrupt_file = store.session_file_path(&id);
    fs::write(&corrupt_file, "corrupt content").unwrap();
    block_on(store.touch(&id, Duration::from_secs(3600))).unwrap();

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cookie_store_edge_cases() {
    let encrypter = create_test_encrypter();
    let store = CookieSessionStore::new(encrypter.clone());

    assert_eq!(store.max_payload_size(), 3800);

    let id = SessionId::generate().unwrap();

    // destroy and touch methods
    assert!(block_on(store.destroy(&id)).is_ok());
    assert!(block_on(store.touch(&id, Duration::from_secs(3600))).is_ok());

    // load with None
    assert_eq!(block_on(store.load(None)).unwrap(), None);

    // load with expired record inside cookie
    let now = current_unix_timestamp();
    let expired_record = SessionRecord::new(
        Some(id.clone()),
        HashMap::new(),
        HashMap::new(),
        now - 100,
        now - 10,
    );
    let expired_json = expired_record.to_json().unwrap();
    let encrypted = encrypter
        .encrypt_string_with_purpose(&expired_json, "session:cookie")
        .unwrap();
    let wire_cookie = format!("e:{}", encrypted);

    let loaded = block_on(store.load(Some(&wire_cookie))).unwrap();
    assert_eq!(loaded, None);
}

#[test]
fn test_config_error_and_expire_on_close_cookie() {
    let config_expire_on_close = SessionConfig::builder()
        .cookie_name("session_id")
        .expire_on_close(true)
        .build();

    let cookie = config_expire_on_close.build_cookie("val123").unwrap();
    assert!(cookie.max_age().is_none());

    // Invalid cookie name with control character or invalid token triggers error
    let invalid_config = SessionConfig::builder()
        .cookie_name("bad name with spaces")
        .build();

    let cookie_err = invalid_config.build_cookie("val");
    assert!(cookie_err.is_err());
    assert!(matches!(
        cookie_err.unwrap_err(),
        SessionError::Serialization(_)
    ));

    let tombstone_err = invalid_config.build_tombstone();
    assert!(tombstone_err.is_err());
    assert!(matches!(
        tombstone_err.unwrap_err(),
        SessionError::Serialization(_)
    ));
}

#[test]
fn test_manager_start_record_id_fallbacks() {
    let config = SessionConfig::default();
    let store = Arc::new(MemorySessionStore::new());
    let manager = SessionManager::new(config.clone(), store.clone());

    let now = current_unix_timestamp();
    // Record without ID
    let record_no_id = SessionRecord::new(None, HashMap::new(), HashMap::new(), now, now + 3600);

    let valid_id = SessionId::generate().unwrap();
    block_on(store.save(&valid_id, &record_no_id, Duration::from_secs(3600))).unwrap();

    // Candidate cookie matches valid_id
    let mut jar = CookieJar::new();
    jar.set(
        Cookie::build(config.cookie_name.clone(), valid_id.as_str())
            .build()
            .unwrap(),
    );
    let sess = block_on(manager.start(&jar)).unwrap();
    assert_eq!(sess.id(), &valid_id);

    // Candidate cookie is invalid format -> generates fresh ID
    let mut jar_invalid = CookieJar::new();
    jar_invalid.set(
        Cookie::build(config.cookie_name.clone(), "bad_cookie")
            .build()
            .unwrap(),
    );
    let sess_fresh = block_on(manager.start(&jar_invalid)).unwrap();
    assert!(sess_fresh.is_fresh());
}

#[test]
fn test_session_old_type_mismatch() {
    let id = SessionId::generate().unwrap();
    let now = current_unix_timestamp();
    let mut flash = HashMap::new();
    flash.insert("number".to_string(), json!("not_a_number"));

    let record = SessionRecord::new(Some(id.clone()), HashMap::new(), flash, now, now + 3600);
    let session = Session::from_record(id, record);

    let old_err: Result<Option<u32>, SessionError> = session.old("number");
    assert!(old_err.is_err());
    assert!(matches!(
        old_err.unwrap_err(),
        SessionError::Deserialization(_)
    ));
}

#[test]
fn test_file_store_load_expired_and_corrupt() {
    let temp_dir =
        std::env::temp_dir().join(format!("druto_file_load_test_{}", current_unix_timestamp()));
    let store = FileSessionStore::new(&temp_dir).unwrap();

    let id_expired = SessionId::generate().unwrap();
    let now = current_unix_timestamp();
    let expired_record = SessionRecord::new(
        Some(id_expired.clone()),
        HashMap::new(),
        HashMap::new(),
        now - 100,
        now - 10,
    );
    let file_expired = store.session_file_path(&id_expired);
    fs::write(&file_expired, expired_record.to_json().unwrap()).unwrap();

    // Loading expired file deletes it and returns None
    assert_eq!(
        block_on(store.load(Some(id_expired.as_str()))).unwrap(),
        None
    );
    assert!(!file_expired.exists());

    // Loading corrupt file deletes it and returns None
    let id_corrupt = SessionId::generate().unwrap();
    let file_corrupt = store.session_file_path(&id_corrupt);
    fs::write(&file_corrupt, "corrupt json").unwrap();
    assert_eq!(
        block_on(store.load(Some(id_corrupt.as_str()))).unwrap(),
        None
    );
    assert!(!file_corrupt.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

struct FailingSerializer;

impl Serialize for FailingSerializer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let _ = serializer;
        Err(serde::ser::Error::custom("forced serialization failure"))
    }
}

struct AnonymousRecordStore;

impl SessionStore for AnonymousRecordStore {
    fn load<'a>(
        &'a self,
        cookie_value: Option<&'a str>,
    ) -> session::BoxFuture<'a, Result<Option<SessionRecord>, SessionError>> {
        let _ = cookie_value;
        let now = current_unix_timestamp();
        let record = SessionRecord::new(None, HashMap::new(), HashMap::new(), now, now + 3600);
        Box::pin(std::future::ready(Ok(Some(record))))
    }

    fn save<'a>(
        &'a self,
        session_id: &'a SessionId,
        record: &'a SessionRecord,
        ttl: Duration,
    ) -> session::BoxFuture<'a, Result<String, SessionError>> {
        let _ = (record, ttl);
        Box::pin(std::future::ready(Ok(session_id.as_str().to_string())))
    }

    fn destroy<'a>(
        &'a self,
        session_id: &'a SessionId,
    ) -> session::BoxFuture<'a, Result<(), SessionError>> {
        let _ = session_id;
        Box::pin(std::future::ready(Ok(())))
    }

    fn touch<'a>(
        &'a self,
        session_id: &'a SessionId,
        ttl: Duration,
    ) -> session::BoxFuture<'a, Result<(), SessionError>> {
        let _ = (session_id, ttl);
        Box::pin(std::future::ready(Ok(())))
    }
}

#[test]
fn test_session_id_deref_and_hash() {
    let id = SessionId::generate().expect("session ID");
    assert_eq!(&*id, id.as_str());

    let mut set = std::collections::HashSet::new();
    set.insert(id.clone());
    assert!(set.contains(&id));
}

#[test]
fn test_session_serialization_failure_and_clear_modified() {
    let mut session = Session::new_fresh(SessionId::generate().unwrap(), 3600);
    assert!(matches!(
        session.put("bad", FailingSerializer),
        Err(SessionError::Serialization(_))
    ));
    assert!(matches!(
        session.flash("bad", FailingSerializer),
        Err(SessionError::Serialization(_))
    ));

    let id = SessionId::generate().unwrap();
    let mut data = HashMap::new();
    data.insert("key".to_string(), json!("val"));
    let record = SessionRecord::new(Some(id.clone()), data, HashMap::new(), 100, 200);
    let mut clean_session = Session::from_record(id, record);
    assert!(clean_session.is_clean());
    clean_session.clear();
    assert!(clean_session.is_modified());
    assert!(clean_session.all().is_empty());

    let mut empty_session = Session::new_fresh(SessionId::generate().unwrap(), 3600);
    empty_session.clear();
    assert!(empty_session.all().is_empty());
}

#[test]
fn test_cookie_store_malformed_decrypted_payload_and_none_id() {
    let encrypter = create_test_encrypter();
    let store = CookieSessionStore::new(encrypter.clone());

    let encrypted_bad_json = encrypter
        .encrypt_string_with_purpose(
            "not a valid session record json",
            session::SESSION_COOKIE_PURPOSE,
        )
        .unwrap();
    let wire = format!("e:{encrypted_bad_json}");
    let res = block_on(store.load(Some(&wire))).unwrap();
    assert_eq!(res, None);

    let id = SessionId::generate().unwrap();
    let record_no_id = SessionRecord::new(None, HashMap::new(), HashMap::new(), 100, 200);
    let save_res = block_on(store.save(&id, &record_no_id, Duration::from_secs(3600)));
    assert!(save_res.is_ok());
}

#[test]
fn test_file_store_directory_and_permission_edge_cases() {
    let temp_dir =
        std::env::temp_dir().join(format!("druto_file_dir_edge_{}", current_unix_timestamp()));
    let store = FileSessionStore::new(&temp_dir).unwrap();

    let sub_dir = temp_dir.join("subfolder");
    fs::create_dir(&sub_dir).unwrap();
    let pruned = store.clean_expired().unwrap();
    assert_eq!(pruned, 0);

    let dir_session_id = SessionId::generate().unwrap();
    let dir_path = store.session_file_path(&dir_session_id);
    fs::create_dir(&dir_path).unwrap();

    let load_dir_err = block_on(store.load(Some(dir_session_id.as_str())));
    assert!(matches!(load_dir_err, Err(SessionError::Io(_))));

    let destroy_dir_err = block_on(store.destroy(&dir_session_id));
    assert!(matches!(destroy_dir_err, Err(SessionError::Io(_))));

    let touch_dir_err = block_on(store.touch(&dir_session_id, Duration::from_secs(60)));
    assert!(matches!(touch_dir_err, Err(SessionError::Io(_))));
    fs::remove_dir(&dir_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unreadable_file = temp_dir.join("unreadable.json");
        fs::write(&unreadable_file, "data").unwrap();
        fs::set_permissions(&unreadable_file, fs::Permissions::from_mode(0o000)).unwrap();
        let _ = store.clean_expired();
        fs::set_permissions(&unreadable_file, fs::Permissions::from_mode(0o600)).unwrap();
        let _ = fs::remove_file(&unreadable_file);

        let ro_dir = temp_dir.join("ro_dir");
        fs::create_dir(&ro_dir).unwrap();
        let ro_store = FileSessionStore::new(&ro_dir).unwrap();
        let ro_id = SessionId::generate().unwrap();
        let ro_record = SessionRecord::new(
            Some(ro_id.clone()),
            HashMap::new(),
            HashMap::new(),
            100,
            200,
        );
        let valid_file = ro_store.session_file_path(&ro_id);
        fs::write(&valid_file, ro_record.to_json().unwrap()).unwrap();

        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500)).unwrap();
        let save_ro_err = block_on(ro_store.save(&ro_id, &ro_record, Duration::from_secs(60)));
        assert!(matches!(save_ro_err, Err(SessionError::Io(_))));

        let touch_ro_err = block_on(ro_store.touch(&ro_id, Duration::from_secs(60)));
        assert!(matches!(touch_ro_err, Err(SessionError::Io(_))));

        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&ro_dir);
    }

    let rename_fail_id = SessionId::generate().unwrap();
    let rename_fail_path = store.session_file_path(&rename_fail_id);
    fs::create_dir(&rename_fail_path).unwrap();
    fs::write(rename_fail_path.join("child.txt"), "blocking file").unwrap();
    let rename_fail_record = SessionRecord::new(
        Some(rename_fail_id.clone()),
        HashMap::new(),
        HashMap::new(),
        100,
        200,
    );
    let rename_fail_err = block_on(store.save(
        &rename_fail_id,
        &rename_fail_record,
        Duration::from_secs(60),
    ));
    assert!(matches!(rename_fail_err, Err(SessionError::Io(_))));
    fs::remove_file(rename_fail_path.join("child.txt")).unwrap();
    fs::remove_dir(&rename_fail_path).unwrap();

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_memory_store_poisoning_paths() {
    let store = MemorySessionStore::new();
    let session_id = SessionId::generate().expect("session ID");
    let record = SessionRecord::new(
        Some(session_id.clone()),
        HashMap::new(),
        HashMap::new(),
        100,
        200,
    );

    let save_result = block_on(store.save(&session_id, &record, Duration::from_secs(60)));
    assert!(save_result.is_ok());

    store.poison_for_testing();

    assert!(matches!(store.count(), Err(SessionError::LockPoisoned(_))));
    assert!(matches!(
        store.contains(&session_id),
        Err(SessionError::LockPoisoned(_))
    ));
    assert!(matches!(store.clear(), Err(SessionError::LockPoisoned(_))));

    let load_result = block_on(store.load(Some(session_id.as_str())));
    assert!(matches!(load_result, Err(SessionError::LockPoisoned(_))));

    let save_err = block_on(store.save(&session_id, &record, Duration::from_secs(60)));
    assert!(matches!(save_err, Err(SessionError::LockPoisoned(_))));

    let destroy_err = block_on(store.destroy(&session_id));
    assert!(matches!(destroy_err, Err(SessionError::LockPoisoned(_))));

    let touch_err = block_on(store.touch(&session_id, Duration::from_secs(60)));
    assert!(matches!(touch_err, Err(SessionError::LockPoisoned(_))));
}

#[test]
fn test_manager_anonymous_record_fallbacks_and_non_rolling_commit() {
    let config = SessionConfig::builder().rolling(false).build();
    let store = Arc::new(AnonymousRecordStore);
    let manager = SessionManager::new(config.clone(), store);

    let empty_jar = CookieJar::new();
    let session1 = block_on(manager.start(&empty_jar)).unwrap();
    assert_eq!(session1.id().len(), 43);

    let mut bad_jar = CookieJar::new();
    bad_jar.set(
        Cookie::build(config.cookie_name.clone(), "bad_cookie_value")
            .build()
            .unwrap(),
    );
    let session2 = block_on(manager.start(&bad_jar)).unwrap();
    assert_eq!(session2.id().len(), 43);

    let mut session_regen = Session::new_fresh(SessionId::generate().unwrap(), 3600);
    session_regen.regenerate().unwrap();
    let mut commit_jar = CookieJar::new();
    block_on(manager.commit(session_regen, &mut commit_jar)).unwrap();
    assert!(commit_jar.has(&config.cookie_name));

    let mut session_mod = Session::new_fresh(SessionId::generate().unwrap(), 3600);
    session_mod.put("k", "v").unwrap();
    let mut commit_jar2 = CookieJar::new();
    block_on(manager.commit(session_mod, &mut commit_jar2)).unwrap();
    assert!(commit_jar2.has(&config.cookie_name));
}

// --- Property-Based Fuzzing Tests ---

proptest! {
    #[test]
    fn prop_session_id_parse_arbitrary_strings(candidate in "\\PC{1,100}") {
        let is_valid_candidate = candidate.len() == 43 &&
            candidate.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

        let parse_result = SessionId::parse(&candidate);
        if is_valid_candidate {
            let parsed = parse_result.expect("valid candidate must parse");
            prop_assert_eq!(parsed.as_str(), candidate.as_str());
        } else {
            prop_assert!(parse_result.is_err());
        }
    }

    #[test]
    fn prop_session_record_json_roundtrip(
        key in "[a-z]{1,10}",
        value in any::<i64>(),
        created_at in any::<u64>(),
        lifetime in 1u64..100000u64,
    ) {
        let id = SessionId::generate().expect("ID must generate");
        let mut data = HashMap::new();
        data.insert(key.clone(), json!(value));

        let record = SessionRecord::new(Some(id.clone()), data, HashMap::new(), created_at, created_at + lifetime);
        let serialized = record.to_json().expect("record serialize");
        let restored = SessionRecord::from_json(&serialized).expect("record deserialize");

        prop_assert_eq!(&record.id, &restored.id);
        prop_assert_eq!(&record.data[&key], &restored.data[&key]);
        prop_assert_eq!(record.created_at, restored.created_at);
        prop_assert_eq!(record.expires_at, restored.expires_at);
    }
}

// ============================================================================
// RedisSessionStore Driver Tests
// ============================================================================

#[cfg(feature = "redis")]
mod redis_store_tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use chirkut::{Cookie, CookieJar};
    use dhap::{Pipeline, from_terminal};
    use druto_session::{
        DEFAULT_REDIS_KEY_PREFIX, RedisSessionStore, SessionConfig, SessionContext, SessionError,
        SessionId, SessionManager, SessionMiddleware, SessionRecord, SessionStore,
        TestSessionContext, current_unix_timestamp,
    };
    use redis::{RedisCommands, RedisFake};
    use serde_json::json;

    use super::block_on;

    #[test]
    fn test_redis_session_store_construction_and_prefixes() {
        let fake_redis = Arc::new(RedisFake::new());
        let default_store = RedisSessionStore::new(fake_redis.clone());

        assert_eq!(default_store.prefix(), DEFAULT_REDIS_KEY_PREFIX);
        assert_eq!(
            default_store.format_key("test_session_id"),
            format!("{DEFAULT_REDIS_KEY_PREFIX}test_session_id")
        );
        assert!(Arc::ptr_eq(default_store.client(), &fake_redis));

        let custom_store =
            RedisSessionStore::with_prefix(fake_redis.clone(), "custom:app:sessions:");
        assert_eq!(custom_store.prefix(), "custom:app:sessions:");
        assert_eq!(
            custom_store.format_key("xyz123"),
            "custom:app:sessions:xyz123"
        );
    }

    #[test]
    fn test_redis_session_store_full_lifecycle_roundtrip() {
        let fake_redis = Arc::new(RedisFake::new());
        let store = RedisSessionStore::new(fake_redis.clone());

        let session_id = SessionId::generate().expect("session ID generation must succeed");
        let now = current_unix_timestamp();

        let mut data = HashMap::new();
        data.insert("user_id".to_string(), json!(1001));
        data.insert("role".to_string(), json!("administrator"));

        let mut flash = HashMap::new();
        flash.insert("welcome".to_string(), json!("welcome to your dashboard"));

        let record = SessionRecord::new(
            Some(session_id.clone()),
            data.clone(),
            flash.clone(),
            now,
            now.saturating_add(3600),
        );

        // 1. Initial load for non-existent session yields None
        let initial_load = block_on(store.load(Some(session_id.as_str())))
            .expect("initial load operation must succeed");
        assert!(initial_load.is_none());

        // 2. Save session record into Redis store
        let saved_token = block_on(store.save(&session_id, &record, Duration::from_secs(3600)))
            .expect("save operation must succeed");
        assert_eq!(saved_token, session_id.as_str());

        // Verify key exists in underlying RedisFake
        let redis_key = store.format_key(session_id.as_str());
        let stored_json = block_on(fake_redis.get(&redis_key))
            .expect("fake redis get must succeed")
            .expect("key must exist in fake redis");
        assert!(stored_json.contains("administrator"));

        // 3. Load session record from Redis store
        let loaded = block_on(store.load(Some(session_id.as_str())))
            .expect("load operation must succeed")
            .expect("record must exist");
        assert_eq!(loaded.id, Some(session_id.clone()));
        assert_eq!(loaded.data.get("user_id"), Some(&json!(1001)));
        assert_eq!(loaded.data.get("role"), Some(&json!("administrator")));
        assert_eq!(
            loaded.flash.get("welcome"),
            Some(&json!("welcome to your dashboard"))
        );

        // 4. Touch session to slide TTL window
        block_on(store.touch(&session_id, Duration::from_secs(7200)))
            .expect("touch operation must succeed");
        let ttl = block_on(fake_redis.ttl(&redis_key)).expect("ttl check must succeed");
        assert!(ttl > 3600 && ttl <= 7200);

        // 5. Destroy session record
        block_on(store.destroy(&session_id)).expect("destroy operation must succeed");

        // 6. Post-destroy load returns None
        let post_destroy = block_on(store.load(Some(session_id.as_str())))
            .expect("post destroy load must succeed");
        assert!(post_destroy.is_none());
        assert!(!block_on(fake_redis.exists(&redis_key)).expect("exists check must succeed"));
    }

    #[test]
    fn test_redis_session_store_expired_key_and_invalid_tokens() {
        let fake_redis = Arc::new(RedisFake::new());
        let store = RedisSessionStore::new(fake_redis.clone());

        // Missing cookie value returns Ok(None)
        let none_load = block_on(store.load(None)).expect("load with None must succeed");
        assert!(none_load.is_none());

        // Malformed session tokens return Ok(None) without querying backend
        let invalid_short =
            block_on(store.load(Some("short"))).expect("invalid token load must succeed");
        assert!(invalid_short.is_none());

        let invalid_chars =
            block_on(store.load(Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM012!@#")))
                .expect("invalid characters load must succeed");
        assert!(invalid_chars.is_none());

        // Key expiration handling
        let session_id = SessionId::generate().expect("session ID generation must succeed");
        let now = current_unix_timestamp();
        let record = SessionRecord::new(
            Some(session_id.clone()),
            HashMap::new(),
            HashMap::new(),
            now,
            now.saturating_add(60),
        );

        block_on(store.save(&session_id, &record, Duration::from_secs(60)))
            .expect("save must succeed");
        let redis_key = store.format_key(session_id.as_str());

        // Expire key explicitly in RedisFake
        block_on(fake_redis.expire(&redis_key, 0)).expect("fake redis expire must succeed");

        // Load must return Ok(None) for expired key
        let expired_load = block_on(store.load(Some(session_id.as_str())))
            .expect("load on expired key must succeed");
        assert!(expired_load.is_none());
    }

    #[test]
    fn test_redis_session_store_middleware_integration() {
        let fake_redis = Arc::new(RedisFake::new());
        let store = Arc::new(RedisSessionStore::new(fake_redis.clone()));
        let config = SessionConfig::default();
        let manager = Arc::new(SessionManager::new(config.clone(), store.clone()));
        let middleware = SessionMiddleware::new(manager);

        let pipeline = Pipeline::<TestSessionContext, String, SessionError>::new().pipe(middleware);

        // --- Request 1: Fresh session, set attributes and flash message ---
        let mut context1 = TestSessionContext::new();
        let outcome1 = block_on(pipeline.run(
            &mut context1,
            from_terminal(|context: &mut TestSessionContext| {
                Box::pin(async move {
                    let session = context.session_mut().expect("session must be attached");
                    session.put("account_id", "acc_9876")?;
                    session.flash("flash_status", "operation_successful")?;
                    Ok("request 1 completed".to_string())
                })
            }),
        ))
        .expect("pipeline 1 must succeed");
        assert_eq!(outcome1, "request 1 completed");

        let cookie_raw = context1
            .cookie_jar
            .get_raw(&config.cookie_name)
            .expect("session cookie must be staged");
        let session_id_string = cookie_raw.to_string();

        // Verify key exists in RedisFake
        let redis_key = store.format_key(&session_id_string);
        assert!(block_on(fake_redis.exists(&redis_key)).expect("exists check must succeed"));

        // --- Request 2: Existing session, retrieve data and flash message ---
        let mut jar2 = CookieJar::new();
        jar2.set(
            Cookie::build(config.cookie_name.clone(), session_id_string.clone())
                .build()
                .unwrap(),
        );
        let mut context2 = TestSessionContext::with_cookie_jar(jar2);

        let outcome2 = block_on(pipeline.run(
            &mut context2,
            from_terminal(|context: &mut TestSessionContext| {
                Box::pin(async move {
                    let session = context.session_mut().expect("session must be attached");
                    let account_id: Option<String> = session.get("account_id")?;
                    assert_eq!(account_id, Some("acc_9876".to_string()));

                    let flash_status: Option<String> = session.old("flash_status")?;
                    assert_eq!(flash_status, Some("operation_successful".to_string()));

                    // Add next flash message
                    session.flash("second_flash", "next_stage")?;
                    Ok("request 2 completed".to_string())
                })
            }),
        ))
        .expect("pipeline 2 must succeed");
        assert_eq!(outcome2, "request 2 completed");

        // --- Request 3: Third request verifies flash lifecycle and invalidation ---
        let mut jar3 = CookieJar::new();
        jar3.set(
            Cookie::build(config.cookie_name.clone(), session_id_string.clone())
                .build()
                .unwrap(),
        );
        let mut context3 = TestSessionContext::with_cookie_jar(jar3);

        let outcome3 = block_on(pipeline.run(
            &mut context3,
            from_terminal(|context: &mut TestSessionContext| {
                Box::pin(async move {
                    let session = context.session_mut().expect("session must be attached");
                    // Prior flash message from request 1 is purged
                    let purged_flash: Option<String> = session.old("flash_status")?;
                    assert_eq!(purged_flash, None);

                    // Flash from request 2 is available
                    let active_flash: Option<String> = session.old("second_flash")?;
                    assert_eq!(active_flash, Some("next_stage".to_string()));

                    // Invalidate session on logout
                    session.invalidate();
                    Ok("request 3 completed".to_string())
                })
            }),
        ))
        .expect("pipeline 3 must succeed");
        assert_eq!(outcome3, "request 3 completed");

        // Confirm session destroyed in RedisFake after invalidate
        assert!(!block_on(fake_redis.exists(&redis_key)).expect("exists check must succeed"));
    }

    #[test]
    fn test_session_id_and_record_edge_cases() {
        use std::ops::Deref;

        let session_id = SessionId::generate().expect("generation failed");
        assert_eq!(session_id.as_str(), session_id.deref());
        assert_eq!(session_id.as_ref(), session_id.as_str());

        let debug_str = format!("{session_id:?}");
        assert!(debug_str.contains("SessionId("));

        let validated =
            SessionId::validate(session_id.as_str()).expect("validation should succeed");
        assert_eq!(validated, session_id);

        // Invalid length
        let err_short = SessionId::parse("too_short").unwrap_err();
        assert!(
            matches!(err_short, SessionError::InvalidId(ref msg) if msg.contains("expected length 43"))
        );

        // Invalid character in 43-character string
        let invalid_chars = "012345678901234567890123456789012345678901!";
        let err_char = SessionId::parse(invalid_chars).unwrap_err();
        assert!(
            matches!(err_char, SessionError::InvalidId(ref msg) if msg.contains("invalid characters"))
        );

        // SessionRecord deserialization failure
        let deser_err = SessionRecord::from_json("{invalid json").unwrap_err();
        assert!(matches!(deser_err, SessionError::Deserialization(_)));
    }
}
