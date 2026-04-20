//! Integration tests for TOTP / MFA (Step 23).
//!
//! Black box tests via `TestHarness` — exercises MFA enrollment, TOTP
//! verification, recovery codes, and disable flow through the public
//! `IdentityEngine` trait.

mod common;

use hearth::core::TenantId;
use hearth::identity::{CleartextPassword, CreateTenantRequest, CreateUserRequest, User};

/// Helper: creates a real tenant with a signing key.
fn create_tenant(harness: &common::TestHarness) -> TenantId {
    let tenant = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("mfa-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create tenant");
    tenant.id().clone()
}

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, tenant: &TenantId) -> User {
    harness
        .identity()
        .create_user(
            tenant,
            &CreateUserRequest {
                email: format!("mfa-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "MFA Test User".to_string(),
            },
        )
        .expect("create user")
}

/// Computes a TOTP code from a base32 secret at the current time.
///
/// Uses the same algorithm as the engine — `compute_totp` is a pure function
/// so we can call it directly from the test.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    // Inline TOTP computation (matches engine's implementation)
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let otp = binary % 1_000_000;
    format!("{otp:06}")
}

// ===== Scenario D1: MFA enrollment flow =====
//
// create tenant → user → password → enroll_totp → compute code from secret →
// verify_totp_enrollment → mfa_enabled true → verify_totp succeeds → create session

#[tokio::test]
async fn mfa_enrollment_full_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = create_tenant(&harness);
    let user = create_user(&harness, &tenant);

    // Set password
    let pw = CleartextPassword::from_string("test-password-123!".to_string());
    harness
        .identity()
        .set_password(&tenant, user.id(), &pw)
        .expect("set password");

    // MFA should not be enabled yet
    assert!(
        !harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should not be enabled before enrollment"
    );

    // Enroll TOTP
    let enrollment = harness
        .identity()
        .enroll_totp(&tenant, user.id())
        .expect("enroll_totp");

    // Validate enrollment response
    assert!(
        !enrollment.secret_base32.is_empty(),
        "secret should be present"
    );
    assert!(
        enrollment.provisioning_uri.starts_with("otpauth://totp/"),
        "URI should be otpauth: {}",
        enrollment.provisioning_uri
    );
    assert_eq!(
        enrollment.recovery_codes.len(),
        8,
        "should have 8 recovery codes"
    );

    // MFA still not enabled (pending verification)
    assert!(
        !harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should not be enabled before verification"
    );

    // Compute TOTP code from the enrollment secret
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);

    // Verify enrollment (activates MFA)
    harness
        .identity()
        .verify_totp_enrollment(&tenant, user.id(), &code)
        .expect("verify_totp_enrollment");

    // MFA now enabled
    assert!(
        harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should be enabled after verification"
    );

    // Verify TOTP code succeeds (use a fresh code since time may have advanced)
    let now_secs2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code2 = compute_totp_code(&enrollment.secret_base32, now_secs2);
    // Note: this may fail if the step matches the enrollment step (replay protection).
    // We advance by attempting with a code from 30s later if needed.
    let verify_result = harness.identity().verify_totp(&tenant, user.id(), &code2);
    if verify_result.is_err() {
        // Replay protection kicked in — try code for next step
        let code3 = compute_totp_code(&enrollment.secret_base32, now_secs2 + 30);
        harness
            .identity()
            .verify_totp(&tenant, user.id(), &code3)
            .expect("verify_totp with next step");
    }

    // Can still create a session (MFA does not block session creation)
    let session = harness
        .identity()
        .create_session(
            &tenant,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    assert!(
        harness
            .identity()
            .get_session(&tenant, session.id())
            .expect("get session")
            .is_some(),
        "session should be valid"
    );
}

// ===== Scenario D2: Recovery code flow =====
//
// enroll TOTP → verify_recovery_code succeeds → same code again fails →
// disable_mfa → re-enroll succeeds

#[tokio::test]
async fn mfa_recovery_code_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = create_tenant(&harness);
    let user = create_user(&harness, &tenant);

    // Enroll and activate TOTP
    let enrollment = harness
        .identity()
        .enroll_totp(&tenant, user.id())
        .expect("enroll_totp");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(&tenant, user.id(), &code)
        .expect("verify enrollment");

    // Use first recovery code
    let recovery_code = &enrollment.recovery_codes.as_slice()[0];
    harness
        .identity()
        .verify_recovery_code(&tenant, user.id(), recovery_code)
        .expect("verify_recovery_code first use");

    // Same recovery code should fail (single-use)
    let err = harness
        .identity()
        .verify_recovery_code(&tenant, user.id(), recovery_code)
        .expect_err("recovery code should be consumed");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidMfaCode),
        "should be InvalidMfaCode, got: {err:?}"
    );

    // Disable MFA
    harness
        .identity()
        .disable_mfa(&tenant, user.id())
        .expect("disable_mfa");

    assert!(
        !harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should be disabled"
    );

    // Re-enroll should succeed
    let enrollment2 = harness
        .identity()
        .enroll_totp(&tenant, user.id())
        .expect("re-enroll after disable");
    assert_ne!(
        enrollment.secret_base32, enrollment2.secret_base32,
        "new enrollment should have a different secret"
    );
}

// ===== Scenario D3: MFA disable flow =====
//
// enroll + verify TOTP → disable_mfa → mfa_enabled false → auth without MFA

#[tokio::test]
async fn mfa_disable_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = create_tenant(&harness);
    let user = create_user(&harness, &tenant);

    // Set password
    let pw = CleartextPassword::from_string("disable-test-pw!".to_string());
    harness
        .identity()
        .set_password(&tenant, user.id(), &pw)
        .expect("set password");

    // Enroll and activate TOTP
    let enrollment = harness
        .identity()
        .enroll_totp(&tenant, user.id())
        .expect("enroll_totp");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(&tenant, user.id(), &code)
        .expect("verify enrollment");

    assert!(
        harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should be enabled"
    );

    // Disable MFA
    harness
        .identity()
        .disable_mfa(&tenant, user.id())
        .expect("disable_mfa");

    assert!(
        !harness
            .identity()
            .mfa_enabled(&tenant, user.id())
            .expect("mfa_enabled"),
        "MFA should be disabled after disable_mfa"
    );

    // Password still works normally (no MFA needed)
    let pw2 = CleartextPassword::from_string("disable-test-pw!".to_string());
    let verified = harness
        .identity()
        .verify_password(&tenant, user.id(), &pw2)
        .expect("verify_password");
    assert!(verified, "password should still verify after MFA disable");

    // Trying to verify TOTP should fail (MFA not enabled)
    let err = harness
        .identity()
        .verify_totp(&tenant, user.id(), "123456")
        .expect_err("verify_totp should fail");
    assert!(
        matches!(err, hearth::identity::IdentityError::MfaNotEnabled),
        "should be MfaNotEnabled, got: {err:?}"
    );

    // Trying to disable again should fail
    let err = harness
        .identity()
        .disable_mfa(&tenant, user.id())
        .expect_err("disable_mfa should fail");
    assert!(
        matches!(err, hearth::identity::IdentityError::MfaNotEnabled),
        "should be MfaNotEnabled, got: {err:?}"
    );
}
