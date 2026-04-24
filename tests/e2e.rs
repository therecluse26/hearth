//! End-to-end integration tests spanning all layers.
//!
//! These tests exercise full user journeys through the public API,
//! verifying that all layers (storage, identity, authorization, tokens,
//! OIDC) work together correctly.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CleartextPassword, CodeChallengeMethod, CreateUserRequest,
    RegisterClientRequest, TokenExchangeRequest,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;

// === TEST_SCENARIOS: Developer on-ramp ===
// start server → create realm → create app → complete OIDC login

#[tokio::test]
async fn developer_onramp_realm_app_oidc_login() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    // 1. Create a realm (just generate an ID — no separate realm CRUD yet)
    let realm = RealmId::generate();

    // 2. Create a user (the developer)
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "dev@startup.io".to_string(),
                display_name: "Developer".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // 3. Set a password for the user
    let password = CleartextPassword::from_string("s3cureP@ssw0rd!".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &password)
        .expect("set password");

    // 4. Register an OAuth client (the app)
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "My SaaS App".to_string(),
                redirect_uris: vec!["https://app.startup.io/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
            },
        )
        .expect("register client");

    // 5. Verify password (simulating authentication)
    let verified = harness
        .identity()
        .verify_password(&realm, user.id(), &password)
        .expect("verify password");
    assert!(verified, "correct password should verify");

    // 6. Complete OIDC authorization code flow with PKCE
    let rng = ring::rand::SystemRandom::new();
    let mut verifier_bytes = [0u8; 32];
    rng.fill(&mut verifier_bytes).expect("fill random");
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let digest = ring::digest::digest(&ring::digest::SHA256, code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest.as_ref());

    let auth_response = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.startup.io/callback".to_string(),
                scope: "openid".to_string(),
                state: "onramp-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(code_challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
            },
        )
        .expect("authorize");

    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.startup.io/callback".to_string(),
                code_verifier: Some(code_verifier),
            },
        )
        .expect("exchange code");

    // 7. Verify the tokens are valid
    let claims = harness
        .identity()
        .validate_token(&realm, token_response.access_token())
        .expect("validate token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.tid, realm.to_string());

    // 8. JWKS can verify the token externally
    let jwks = harness.identity().jwks();
    assert!(!jwks.keys.is_empty(), "JWKS should have at least one key");
}

// === TEST_SCENARIOS: User lifecycle ===
// register → authenticate → receive session → validate token

#[tokio::test]
async fn user_lifecycle_register_authenticate_session_token() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // 1. Register: create user
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // 2. Set password
    let password = CleartextPassword::from_string("MyP@ssw0rd123".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &password)
        .expect("set password");

    // 3. Authenticate: verify password
    let verified = harness
        .identity()
        .verify_password(&realm, user.id(), &password)
        .expect("verify");
    assert!(verified);

    // Wrong password should fail
    let wrong = CleartextPassword::from_string("WrongPassword".to_string());
    let wrong_result = harness
        .identity()
        .verify_password(&realm, user.id(), &wrong)
        .expect("verify wrong");
    assert!(!wrong_result, "wrong password should not verify");

    // 4. Receive session
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    assert_eq!(session.user_id(), user.id());

    // 5. Issue tokens from session
    let tokens = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // 6. Validate token
    let claims = harness
        .identity()
        .validate_token(&realm, tokens.access_token())
        .expect("validate");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.sid, session.id().to_string());
    assert_eq!(claims.tid, realm.to_string());

    // 7. Token refresh works
    let refreshed = harness
        .identity()
        .refresh_tokens(&realm, tokens.refresh_token())
        .expect("refresh");
    let refreshed_claims = harness
        .identity()
        .validate_token(&realm, refreshed.access_token())
        .expect("validate refreshed");
    assert_eq!(refreshed_claims.sub, user.id().to_string());
}

// === TEST_SCENARIOS: Auth + RBAC ===
// authenticate → create role + assign → resolve permissions → authorized action succeeds

#[tokio::test]
async fn auth_plus_rbac_permission_grant_and_check() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // 1. Create and authenticate user
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bob@example.com".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let password = CleartextPassword::from_string("BobsP@ss123".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &password)
        .expect("set password");

    let verified = harness
        .identity()
        .verify_password(&realm, user.id(), &password)
        .expect("verify");
    assert!(verified);

    // 2. Create session and tokens
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // 3. Validate token to confirm identity
    let claims = harness
        .identity()
        .validate_token(&realm, tokens.access_token())
        .expect("validate");
    assert_eq!(claims.sub, user.id().to_string());

    // 4. Create a role that carries `docs.edit` and assign it to the user.
    let doc_perm = hearth::rbac::Permission::new("docs.edit").expect("valid perm");
    let role = harness
        .rbac()
        .create_role(
            &realm,
            &hearth::rbac::CreateRoleRequest {
                name: "doc-owner".to_string(),
                description: None,
                permissions: vec![doc_perm.clone()],
                parent_roles: Vec::new(),
            },
        )
        .expect("create role");
    harness
        .rbac()
        .assign_role(
            &realm,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user.id().clone()),
                role_id: role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    // 5. Resolve — should carry docs.edit.
    let resolved = harness
        .rbac()
        .resolve_permissions(user.id(), &realm, None, None)
        .expect("resolve");
    assert!(
        resolved.permissions.contains(&doc_perm),
        "user should have docs.edit permission"
    );

    // 6. Non-granted permission should NOT be present.
    assert!(
        !resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        "user should NOT carry hearth.admin"
    );

    // 7. list_role_members should include the user.
    let members = harness
        .rbac()
        .list_role_members(&realm, &role.id, None, 10)
        .expect("list members");
    assert!(
        members
            .items
            .iter()
            .any(|s| matches!(s, hearth::rbac::RoleSubject::User(u) if u == user.id())),
        "list_role_members should include the user"
    );
}

// === TEST_SCENARIOS: Cascading invalidation ===
// delete user → sessions invalidated → token validation fails

#[tokio::test]
async fn cascading_invalidation_delete_user_invalidates_everything() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    // 1. Create user with credentials, session, and tokens
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "charlie@example.com".to_string(),
                display_name: "Charlie".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let password = CleartextPassword::from_string("Ch@rlieP@ss!".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &password)
        .expect("set password");

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    let tokens = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Verify everything works before deletion
    let claims = harness
        .identity()
        .validate_token(&realm, tokens.access_token())
        .expect("validate pre-delete");
    assert_eq!(claims.sub, user.id().to_string());

    let session_valid = harness
        .identity()
        .get_session(&realm, session.id())
        .expect("get session pre-delete");
    assert!(session_valid.is_some(), "session should exist pre-delete");

    // 2. Delete the user
    harness
        .identity()
        .delete_user(&realm, user.id())
        .expect("delete user");

    // 3. Verify user is gone
    let user_gone = harness
        .identity()
        .get_user(&realm, user.id())
        .expect("get deleted user");
    assert!(user_gone.is_none(), "user should be gone after deletion");

    // 4. Session should be invalidated
    let session_gone = harness
        .identity()
        .get_session(&realm, session.id())
        .expect("get session post-delete");
    assert!(
        session_gone.is_none(),
        "session should be invalidated after user deletion"
    );

    // 5. Token validation should fail (session is gone)
    let token_result = harness
        .identity()
        .validate_token(&realm, tokens.access_token());
    assert!(
        token_result.is_err(),
        "token validation should fail after user deletion"
    );

    // 6. Password verification should fail
    let cred_result = harness
        .identity()
        .verify_password(&realm, user.id(), &password);
    assert!(
        cred_result.is_err(),
        "credential verification should fail after user deletion"
    );
}
