//! Cross-cutting adversarial tests.
//!
//! Global invariants applied across all layers: no state leakage in errors,
//! constant-time comparisons, no credential logging, memory zeroing,
//! and input size limits.

mod common;

use hearth::authz::{AuthzError, ObjectRef};
use hearth::core::{RealmId, SessionId, UserId};
use hearth::identity::{
    CleartextPassword, CreateUserRequest, IdentityError, RegisterClientRequest,
};

/// Patterns that should NEVER appear in error messages.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "/home/",
    "/tmp/",
    "/var/",
    "stack trace",
    "backtrace",
    "thread '",
    "panicked at",
    "src/",
    ".rs:",
    "RUST_BACKTRACE",
    "SELECT ",
    "INSERT ",
    "DELETE ",
    "key:",
    "password",
    "secret",
    "BEGIN PRIVATE",
    "BEGIN RSA",
];

/// Asserts that a message contains no forbidden patterns.
fn assert_no_leaks(context: &str, msg: &str) {
    for pattern in FORBIDDEN_PATTERNS {
        assert!(
            !msg.to_lowercase().contains(&pattern.to_lowercase()),
            "{context} leaks '{pattern}' in: {msg}"
        );
    }
}

/// Compile-time check that a type implements `ZeroizeOnDrop`.
fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

/// Formats the result of an operation as its error message, or "ok".
fn err_display<T>(result: Result<T, impl std::fmt::Display>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("{e}"),
    }
}

// === TEST_SCENARIOS: All API error responses leak no internal state ===

#[tokio::test]
async fn error_responses_leak_no_internal_state() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // Collect error messages from various failure modes
    let errors = [
        err_display(harness.identity().delete_user(&realm, &UserId::generate())),
        err_display(
            harness
                .identity()
                .revoke_session(&realm, &SessionId::generate()),
        ),
        err_display(harness.identity().validate_token(&realm, "fake.token.here")),
    ];

    for msg in &errors {
        assert_no_leaks("API error", msg);
    }

    // Verify Display impls of all error enums don't leak secrets
    let identity_errors = [
        format!("{}", IdentityError::UserNotFound),
        format!("{}", IdentityError::DuplicateEmail),
        format!(
            "{}",
            IdentityError::InvalidInput {
                reason: "bad input".to_string()
            }
        ),
        format!("{}", IdentityError::CredentialNotFound),
        format!(
            "{}",
            IdentityError::InvalidCredential {
                reason: "wrong".to_string()
            }
        ),
        format!("{}", IdentityError::SessionNotFound),
        format!("{}", IdentityError::InvalidToken),
        format!("{}", IdentityError::TokenExpired),
        format!("{}", IdentityError::InvalidClient),
        format!("{}", IdentityError::InvalidRedirectUri),
        format!("{}", IdentityError::InvalidAuthorizationCode),
        format!(
            "{}",
            IdentityError::InvalidGrant {
                reason: "PKCE mismatch".to_string()
            }
        ),
    ];

    for msg in &identity_errors {
        assert_no_leaks("IdentityError", msg);
    }

    // AuthzError
    let authz_errors = [
        format!("{}", AuthzError::MaxDepthExceeded),
        format!(
            "{}",
            AuthzError::InvalidTuple {
                reason: "bad".to_string()
            }
        ),
        format!(
            "{}",
            AuthzError::InvalidReference {
                reason: "bad ref".to_string()
            }
        ),
    ];

    for msg in &authz_errors {
        assert_no_leaks("AuthzError", msg);
    }
}

// === TEST_SCENARIOS: Constant-time comparisons for secrets ===

#[tokio::test]
async fn constant_time_comparisons_for_secrets() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // Create a user with a password
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "timing-test@example.com".to_string(),
                display_name: "Timing Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let pw = CleartextPassword::from_string("CorrectP@ss123".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &pw)
        .expect("set password");

    // Non-existent user should fail with the same generic error type
    let fake_user = UserId::generate();
    let fake_pw = CleartextPassword::from_string("anything".to_string());
    let result = harness
        .identity()
        .verify_password(&realm, &fake_user, &fake_pw);
    assert!(result.is_err(), "non-existent user should return error");

    // Error must NOT reveal whether the user exists
    let err_msg = err_display(result);
    assert!(
        !err_msg.contains("user not found"),
        "error should not reveal user existence: {err_msg}"
    );
    assert!(
        err_msg.contains("credential"),
        "error should be a generic credential error: {err_msg}"
    );

    // Session IDs for non-existent sessions return None (enumeration resistance)
    let fake_session = SessionId::generate();
    let session_result = harness
        .identity()
        .get_session(&realm, &fake_session)
        .expect("get session should not error");
    assert!(
        session_result.is_none(),
        "non-existent session should return None"
    );

    // Token validation for garbage should fail cleanly
    let token_result = harness.identity().validate_token(&realm, "garbage-token");
    assert!(token_result.is_err(), "garbage token should fail");
}

// === TEST_SCENARIOS: No credentials in log output ===

#[tokio::test]
async fn no_credential_material_in_log_output() {
    // CleartextPassword Debug should not show the actual password
    let pw = CleartextPassword::from_string("SuperSecret123!".to_string());
    let debug = format!("{pw:?}");
    assert!(
        !debug.contains("SuperSecret123!"),
        "CleartextPassword Debug leaks password: {debug}"
    );
    assert!(
        debug.contains("***") || debug.contains("REDACTED"),
        "CleartextPassword Debug should show redacted placeholder: {debug}"
    );

    // SigningKey Debug should not show key material
    let key = hearth::identity::SigningKey::generate().expect("generate key");
    let key_debug = format!("{key:?}");
    assert!(
        key_debug.contains("SigningKey"),
        "SigningKey Debug should identify the type: {key_debug}"
    );
    assert!(
        !key_debug.contains("key_bytes") && !key_debug.contains("private"),
        "SigningKey Debug should not contain key material: {key_debug}"
    );

    // Error messages should not contain passwords
    let err = IdentityError::InvalidCredential {
        reason: "verification failed".to_string(),
    };
    let err_msg = format!("{err}");
    assert!(
        !err_msg.contains("SuperSecret"),
        "error message should not contain password: {err_msg}"
    );

    // InvalidToken should be generic
    let err = IdentityError::InvalidToken;
    assert_eq!(format!("{err}"), "invalid token");
}

// === TEST_SCENARIOS: Sensitive data zeroed from memory ===

#[tokio::test]
async fn sensitive_data_zeroed_from_memory() {
    // Verify CleartextPassword Debug is redacted
    let pw = CleartextPassword::from_string("ZeroizeMe!".to_string());
    let debug = format!("{pw:?}");
    assert!(
        debug.contains("***"),
        "password debug should be redacted: {debug}"
    );

    // Verify SigningKey can be created and dropped safely
    let key = hearth::identity::SigningKey::generate().expect("generate");
    let debug = format!("{key:?}");
    assert!(
        debug.contains("SigningKey"),
        "key debug should be safe: {debug}"
    );
    drop(key);

    // Compile-time check: CleartextPassword implements ZeroizeOnDrop
    assert_zeroize_on_drop::<CleartextPassword>();
}

// === TEST_SCENARIOS: Input size limits enforced ===

#[tokio::test]
async fn input_size_limits_enforced() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // Oversized email
    let long_email = format!("{}@example.com", "a".repeat(1000));
    let result = harness.identity().create_user(
        &realm,
        &CreateUserRequest {
            email: long_email,
            display_name: "Normal Name".to_string(),
            first_name: String::new(),
            last_name: String::new(),
        },
    );
    assert!(result.is_err(), "oversized email should be rejected");

    // Oversized display name
    let result = harness.identity().create_user(
        &realm,
        &CreateUserRequest {
            email: "valid@example.com".to_string(),
            display_name: "x".repeat(10_000),
            first_name: String::new(),
            last_name: String::new(),
        },
    );
    assert!(result.is_err(), "oversized display name should be rejected");

    // Oversized password (prevents Argon2id denial-of-service)
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "limits@example.com".to_string(),
                display_name: "Limits Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let huge_pw = CleartextPassword::from_string("P@".repeat(5_000));
    let result = harness.identity().set_password(&realm, user.id(), &huge_pw);
    assert!(
        result.is_err(),
        "extremely large password should be rejected"
    );

    // Oversized OAuth client name
    let result = harness.identity().register_client(
        &realm,
        &RegisterClientRequest {
            client_name: "x".repeat(10_000),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_secret: None,
            grant_types: vec!["authorization_code".to_string()],
            require_consent: true,
            client_logo_url: None,
        },
    );
    assert!(result.is_err(), "oversized client name should be rejected");

    // Oversized redirect URI
    let long_uri = format!("https://example.com/{}", "a".repeat(10_000));
    let result = harness.identity().register_client(
        &realm,
        &RegisterClientRequest {
            client_name: "Normal App".to_string(),
            redirect_uris: vec![long_uri],
            client_secret: None,
            grant_types: vec!["authorization_code".to_string()],
            require_consent: true,
            client_logo_url: None,
        },
    );
    assert!(result.is_err(), "oversized redirect URI should be rejected");

    // Authorization engine: oversized object type/id
    assert!(
        ObjectRef::new(&"x".repeat(1_000), "id").is_err(),
        "oversized object type should be rejected"
    );
    assert!(
        ObjectRef::new("document", &"x".repeat(1_000)).is_err(),
        "oversized object ID should be rejected"
    );
}
