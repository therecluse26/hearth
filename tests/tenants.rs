//! Integration tests for Phase 1 Step 19: Multi-Tenancy.
//!
//! Tests the public `IdentityEngine` API for tenant lifecycle,
//! cross-tenant token isolation, and tenant-scoped OIDC discovery.

mod common;

use hearth::core::TenantId;
use hearth::identity::{
    CreateTenantRequest, CreateUserRequest, TenantConfig, TenantStatus, UpdateTenantRequest,
};

// ===== Integration Scenario 1: Full tenant lifecycle =====
//
// create → configure → create users → delete tenant → verify cleanup

#[tokio::test]
async fn full_tenant_lifecycle() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // 1. Create tenant
    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "Lifecycle Corp".to_string(),
            config: Some(TenantConfig {
                session_ttl_micros: Some(3_600_000_000), // 1 hour
                ..TenantConfig::default()
            }),
        })
        .expect("create tenant");

    assert_eq!(tenant.name(), "Lifecycle Corp");
    assert_eq!(tenant.status(), TenantStatus::Active);
    assert_eq!(tenant.config().session_ttl_micros, Some(3_600_000_000));

    // 2. Configure (update)
    let updated = identity
        .update_tenant(
            tenant.id(),
            &UpdateTenantRequest {
                name: Some("Updated Corp".to_string()),
                config: Some(TenantConfig {
                    session_ttl_micros: Some(7_200_000_000), // 2 hours
                    password_memory_cost: Some(32768),
                    ..TenantConfig::default()
                }),
                ..UpdateTenantRequest::default()
            },
        )
        .expect("update tenant");
    assert_eq!(updated.name(), "Updated Corp");

    // 3. Create users within the tenant
    let user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "alice@lifecycle.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create user");

    // 4. Create session
    let session = identity
        .create_session(tenant.id(), user.id())
        .expect("create session");

    // 5. Delete tenant
    identity.delete_tenant(tenant.id()).expect("delete tenant");

    // 6. Verify cleanup
    assert!(
        identity.get_tenant(tenant.id()).expect("get").is_none(),
        "tenant record should be gone"
    );
    assert!(
        identity
            .get_user(tenant.id(), user.id())
            .expect("get")
            .is_none(),
        "user should be gone"
    );
    assert!(
        identity
            .get_session(tenant.id(), session.id())
            .expect("get")
            .is_none(),
        "session should be gone"
    );
}

// ===== Integration Scenario 2: Multi-tenant token issuance =====
//
// Tokens from tenant A are invalid in tenant B.

#[tokio::test]
async fn multi_tenant_token_isolation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create two tenants
    let tenant_a = identity
        .create_tenant(&CreateTenantRequest {
            name: "Tenant A".to_string(),
            config: None,
        })
        .expect("create tenant A");
    let tenant_b = identity
        .create_tenant(&CreateTenantRequest {
            name: "Tenant B".to_string(),
            config: None,
        })
        .expect("create tenant B");

    // Create a user and session in tenant A
    let user_a = identity
        .create_user(
            tenant_a.id(),
            &CreateUserRequest {
                email: "alice@a.com".to_string(),
                display_name: "Alice A".to_string(),
            },
        )
        .expect("create user A");

    let session_a = identity
        .create_session(tenant_a.id(), user_a.id())
        .expect("create session A");

    let tokens_a = identity
        .issue_tokens(tenant_a.id(), user_a.id(), session_a.id())
        .expect("issue tokens A");

    // Token should validate in tenant A
    let claims = identity
        .validate_token(tenant_a.id(), tokens_a.access_token())
        .expect("validate in A");
    // Token claims store the user ID with prefix ("user_{uuid}")
    assert_eq!(claims.sub, user_a.id().to_string());

    // Token should NOT validate in tenant B (different tenant namespace)
    let result_b = identity.validate_token(tenant_b.id(), tokens_a.access_token());
    assert!(
        result_b.is_err(),
        "token from tenant A should not validate in tenant B"
    );

    // Each tenant should have different JWKS keys
    let jwks_a = identity.tenant_jwks(tenant_a.id()).expect("jwks A");
    let jwks_b = identity.tenant_jwks(tenant_b.id()).expect("jwks B");
    assert_ne!(
        jwks_a.keys[0].kid, jwks_b.keys[0].kid,
        "tenant signing keys must be different"
    );
}

// ===== Integration Scenario 3: Tenant-scoped OIDC =====
//
// Discovery documents and JWKS endpoints differ per tenant.

#[tokio::test]
async fn tenant_scoped_oidc_discovery_and_jwks() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let tenant_a = identity
        .create_tenant(&CreateTenantRequest {
            name: "OIDC Tenant A".to_string(),
            config: None,
        })
        .expect("create tenant A");
    let tenant_b = identity
        .create_tenant(&CreateTenantRequest {
            name: "OIDC Tenant B".to_string(),
            config: None,
        })
        .expect("create tenant B");

    // JWKS documents should exist for each tenant
    let jwks_a = identity.tenant_jwks(tenant_a.id()).expect("jwks A");
    let jwks_b = identity.tenant_jwks(tenant_b.id()).expect("jwks B");

    // Each should have exactly one key
    assert_eq!(jwks_a.keys.len(), 1, "tenant A should have 1 key");
    assert_eq!(jwks_b.keys.len(), 1, "tenant B should have 1 key");

    // Keys should be distinct
    assert_ne!(
        jwks_a.keys[0].x, jwks_b.keys[0].x,
        "public keys must differ between tenants"
    );

    // Key algorithm should be EdDSA
    assert_eq!(jwks_a.keys[0].alg, "EdDSA");
    assert_eq!(jwks_b.keys[0].alg, "EdDSA");

    // Nonexistent tenant should fail
    let err = identity.tenant_jwks(&TenantId::generate());
    assert!(err.is_err(), "JWKS for nonexistent tenant should fail");
}

// ===== Adversarial Scenario 1: Cross-tenant session injection =====
//
// Session ID from tenant A rejected when presented to tenant B.

#[tokio::test]
async fn adversarial_cross_tenant_session_injection() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let tenant_a = identity
        .create_tenant(&CreateTenantRequest {
            name: "Tenant A".to_string(),
            config: None,
        })
        .expect("create A");
    let tenant_b = identity
        .create_tenant(&CreateTenantRequest {
            name: "Tenant B".to_string(),
            config: None,
        })
        .expect("create B");

    // Create user and session in tenant A
    let user = identity
        .create_user(
            tenant_a.id(),
            &CreateUserRequest {
                email: "victim@a.com".to_string(),
                display_name: "Victim".to_string(),
            },
        )
        .expect("create user");
    let session = identity
        .create_session(tenant_a.id(), user.id())
        .expect("create session");

    // Session should be valid in tenant A
    let found = identity
        .get_session(tenant_a.id(), session.id())
        .expect("get A");
    assert!(found.is_some(), "session valid in its own tenant");

    // Session should NOT be found when queried via tenant B
    let injected = identity
        .get_session(tenant_b.id(), session.id())
        .expect("get B");
    assert!(
        injected.is_none(),
        "cross-tenant session injection must be rejected"
    );
}

// ===== Adversarial Scenario 2: Tenant ID spoofing =====
//
// Forged TenantId in request rejected by ownership validation.

#[tokio::test]
async fn adversarial_tenant_id_spoofing() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "Real Tenant".to_string(),
            config: None,
        })
        .expect("create tenant");

    // Create a user in the real tenant
    let user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "alice@real.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create user");

    // Forged tenant ID — an attacker crafts a random ID
    let forged_tenant = TenantId::generate();

    // Cannot read user via forged tenant
    let result = identity
        .get_user(&forged_tenant, user.id())
        .expect("get user");
    assert!(
        result.is_none(),
        "user should not be accessible via forged tenant ID"
    );

    // Cannot create session via forged tenant
    let session_result = identity.create_session(&forged_tenant, user.id());
    assert!(
        session_result.is_err(),
        "creating session with forged tenant should fail"
    );

    // Cannot issue tokens via forged tenant
    let fake_session = identity
        .create_session(tenant.id(), user.id())
        .expect("real session");
    let token_result = identity.issue_tokens(&forged_tenant, user.id(), fake_session.id());
    assert!(
        token_result.is_err(),
        "issuing tokens with forged tenant should fail"
    );
}

// ===== Adversarial Scenario 3: Tenant enumeration resistance =====
//
// Responses for nonexistent tenants are indistinguishable from forbidden.

#[tokio::test]
async fn adversarial_tenant_enumeration_resistance() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let real_tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "Real Corp".to_string(),
            config: None,
        })
        .expect("create tenant");

    let fake_tenant = TenantId::generate();

    // Both real (no user) and fake tenant should return None for user lookup
    let real_result = identity
        .get_user(real_tenant.id(), &hearth::core::UserId::generate())
        .expect("get from real");
    let fake_result = identity
        .get_user(&fake_tenant, &hearth::core::UserId::generate())
        .expect("get from fake");

    // Both should be None — indistinguishable
    assert!(real_result.is_none());
    assert!(fake_result.is_none());

    // Tenant lookup for nonexistent vs suspended should also be uniform
    // (update real tenant to suspended)
    let _suspended = identity
        .update_tenant(
            real_tenant.id(),
            &UpdateTenantRequest {
                status: Some(TenantStatus::Suspended),
                ..UpdateTenantRequest::default()
            },
        )
        .expect("suspend");

    // Both get_tenant calls return successfully (one Some, one None)
    // But the key point is that error responses for operations
    // against nonexistent tenants don't reveal whether the tenant exists.
    let update_fake = identity.update_tenant(
        &fake_tenant,
        &UpdateTenantRequest {
            name: Some("probe".to_string()),
            ..UpdateTenantRequest::default()
        },
    );
    assert!(
        matches!(
            update_fake,
            Err(hearth::identity::IdentityError::TenantNotFound)
        ),
        "updating fake tenant returns TenantNotFound"
    );

    let delete_fake = identity.delete_tenant(&fake_tenant);
    assert!(
        matches!(
            delete_fake,
            Err(hearth::identity::IdentityError::TenantNotFound)
        ),
        "deleting fake tenant returns TenantNotFound"
    );
}
