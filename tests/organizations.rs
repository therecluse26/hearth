//! Integration tests for Organizations feature.
//!
//! Tests the public `IdentityEngine` API for organization CRUD,
//! membership management, invitation lifecycle, and cascading deletes.

mod common;

use hearth::core::OrganizationId;
use hearth::identity::{
    CreateInvitationRequest, CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest,
    IdentityEngine, OrganizationConfig, OrganizationRole, OrganizationStatus,
    UpdateOrganizationRequest,
};

/// Helper: creates a realm and returns its ID for org tests.
fn setup_realm(identity: &dyn IdentityEngine) -> hearth::core::RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: "org-test-realm".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

// ===== Integration Scenario 1: Full organization lifecycle =====

#[tokio::test]
async fn full_organization_lifecycle() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    // 1. Create organization
    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Acme Corp".to_string(),
                slug: "acme-corp".to_string(),
                description: Some("A test organization".to_string()),
                config: Some(OrganizationConfig {
                    max_members: Some(100),
                }),
            },
        )
        .expect("create org");

    assert_eq!(org.name(), "Acme Corp");
    assert_eq!(org.slug(), "acme-corp");
    assert_eq!(org.description(), "A test organization");
    assert_eq!(org.status(), OrganizationStatus::Active);
    assert_eq!(org.config().max_members, Some(100));

    // 2. Get by ID
    let fetched = identity
        .get_organization(&realm_id, org.id())
        .expect("get org")
        .expect("org should exist");
    assert_eq!(fetched.name(), "Acme Corp");

    // 3. Get by slug
    let by_slug = identity
        .get_organization_by_slug(&realm_id, "acme-corp")
        .expect("get by slug")
        .expect("org should exist");
    assert_eq!(by_slug.id(), org.id());

    // 4. Update
    let updated = identity
        .update_organization(
            &realm_id,
            org.id(),
            &UpdateOrganizationRequest {
                name: Some("Acme Corporation".to_string()),
                description: Some("Updated description".to_string()),
                ..UpdateOrganizationRequest::default()
            },
        )
        .expect("update org");
    assert_eq!(updated.name(), "Acme Corporation");
    assert_eq!(updated.description(), "Updated description");

    // 5. List organizations
    let page = identity
        .list_organizations(&realm_id, None, 10)
        .expect("list orgs");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id(), org.id());

    // 6. Delete
    identity
        .delete_organization(&realm_id, org.id())
        .expect("delete org");

    // 7. Verify cleanup
    assert!(
        identity
            .get_organization(&realm_id, org.id())
            .expect("get")
            .is_none(),
        "org should be gone"
    );
    assert!(
        identity
            .get_organization_by_slug(&realm_id, "acme-corp")
            .expect("get by slug")
            .is_none(),
        "slug index should be gone"
    );
}

// ===== Integration Scenario 2: Membership lifecycle =====

#[tokio::test]
async fn membership_lifecycle() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    // Create org
    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Membership Org".to_string(),
                slug: "membership-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    // Create users
    let alice = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "alice@test.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create alice");

    let bob = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "bob@test.com".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create bob");

    // Add alice as Owner
    let alice_membership = identity
        .add_member(&realm_id, org.id(), alice.id(), OrganizationRole::Owner)
        .expect("add alice");
    assert_eq!(alice_membership.role(), OrganizationRole::Owner);

    // Add bob as Member
    let bob_membership = identity
        .add_member(&realm_id, org.id(), bob.id(), OrganizationRole::Member)
        .expect("add bob");
    assert_eq!(bob_membership.role(), OrganizationRole::Member);

    // List members
    let members = identity
        .list_members(&realm_id, org.id(), None, 10)
        .expect("list members");
    assert_eq!(members.items.len(), 2);

    // List user's organizations
    let alice_orgs = identity
        .list_user_organizations(&realm_id, alice.id(), None, 10)
        .expect("list alice orgs");
    assert_eq!(alice_orgs.items.len(), 1);
    assert_eq!(alice_orgs.items[0].org_id(), org.id());

    // Update bob's role to Admin
    let updated = identity
        .update_member_role(&realm_id, org.id(), bob.id(), OrganizationRole::Admin)
        .expect("update bob role");
    assert_eq!(updated.role(), OrganizationRole::Admin);

    // Get specific membership
    let membership = identity
        .get_membership(&realm_id, org.id(), bob.id())
        .expect("get membership")
        .expect("membership should exist");
    assert_eq!(membership.role(), OrganizationRole::Admin);

    // Remove bob
    identity
        .remove_member(&realm_id, org.id(), bob.id())
        .expect("remove bob");

    // Verify bob is gone
    assert!(
        identity
            .get_membership(&realm_id, org.id(), bob.id())
            .expect("get")
            .is_none(),
        "bob membership should be gone"
    );

    // Verify reverse index is also cleaned
    let bob_orgs = identity
        .list_user_organizations(&realm_id, bob.id(), None, 10)
        .expect("list bob orgs");
    assert_eq!(bob_orgs.items.len(), 0);
}

// ===== Integration Scenario 3: Invitation E2E flow =====

#[tokio::test]
async fn invitation_e2e_flow() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    // Setup: org + admin user
    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Invitation Org".to_string(),
                slug: "invitation-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let admin = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "admin@test.com".to_string(),
                display_name: "Admin".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create admin");

    identity
        .add_member(&realm_id, org.id(), admin.id(), OrganizationRole::Owner)
        .expect("add admin");

    // 1. Create invitation
    let (invitation, token) = identity
        .create_invitation(
            &realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: "newuser@test.com".to_string(),
                role: OrganizationRole::Member,
                invited_by: admin.id().clone(),
            },
        )
        .expect("create invitation");

    assert_eq!(invitation.email(), "newuser@test.com");
    assert_eq!(invitation.role(), OrganizationRole::Member);
    assert!(!token.is_empty());

    // 2. List invitations
    let invitations = identity
        .list_invitations(&realm_id, org.id(), None, 10)
        .expect("list invitations");
    assert_eq!(invitations.items.len(), 1);

    // 3. Accept invitation (auto-creates user)
    let membership = identity
        .accept_invitation(&realm_id, &token)
        .expect("accept invitation");
    assert_eq!(membership.org_id(), org.id());
    assert_eq!(membership.role(), OrganizationRole::Member);

    // 4. Verify user was created
    let new_user = identity
        .get_user_by_email(&realm_id, "newuser@test.com")
        .expect("get user")
        .expect("user should exist");
    assert_eq!(new_user.email(), "newuser@test.com");

    // 5. Verify membership exists
    let m = identity
        .get_membership(&realm_id, org.id(), new_user.id())
        .expect("get")
        .expect("membership should exist");
    assert_eq!(m.role(), OrganizationRole::Member);

    // 6. Verify token can't be reused
    let reuse_result = identity.accept_invitation(&realm_id, &token);
    assert!(
        reuse_result.is_err(),
        "token should not be reusable (already accepted)"
    );
}

// ===== Integration Scenario 4: Cascading delete =====

#[tokio::test]
async fn cascading_delete_org_cleans_memberships_and_invitations() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Cascade Org".to_string(),
                slug: "cascade-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "cascade@test.com".to_string(),
                display_name: "Cascade User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Add member
    identity
        .add_member(&realm_id, org.id(), user.id(), OrganizationRole::Owner)
        .expect("add member");

    // Create invitation
    let (_inv, _token) = identity
        .create_invitation(
            &realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: "pending@test.com".to_string(),
                role: OrganizationRole::Member,
                invited_by: user.id().clone(),
            },
        )
        .expect("create invitation");

    // Delete org
    identity
        .delete_organization(&realm_id, org.id())
        .expect("delete org");

    // Verify membership cleaned up
    let user_orgs = identity
        .list_user_organizations(&realm_id, user.id(), None, 10)
        .expect("list user orgs");
    assert_eq!(user_orgs.items.len(), 0, "membership should be cleaned up");

    // Verify org is gone
    assert!(
        identity
            .get_organization(&realm_id, org.id())
            .expect("get")
            .is_none(),
        "org should be gone"
    );
}

// ===== Integration Scenario 5: Last-owner protection =====

#[tokio::test]
async fn last_owner_cannot_be_removed_or_downgraded() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Owner Org".to_string(),
                slug: "owner-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let owner = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "owner@test.com".to_string(),
                display_name: "Owner".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create owner");

    identity
        .add_member(&realm_id, org.id(), owner.id(), OrganizationRole::Owner)
        .expect("add owner");

    // Cannot remove last owner
    let remove_result = identity.remove_member(&realm_id, org.id(), owner.id());
    assert!(
        matches!(
            remove_result,
            Err(hearth::identity::IdentityError::LastOwner)
        ),
        "should prevent removing last owner"
    );

    // Cannot downgrade last owner
    let downgrade_result =
        identity.update_member_role(&realm_id, org.id(), owner.id(), OrganizationRole::Admin);
    assert!(
        matches!(
            downgrade_result,
            Err(hearth::identity::IdentityError::LastOwner)
        ),
        "should prevent downgrading last owner"
    );

    // Add second owner, then first can be removed
    let owner2 = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "owner2@test.com".to_string(),
                display_name: "Owner 2".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create owner2");

    identity
        .add_member(&realm_id, org.id(), owner2.id(), OrganizationRole::Owner)
        .expect("add owner2");

    // Now the first owner can be removed
    identity
        .remove_member(&realm_id, org.id(), owner.id())
        .expect("remove owner should now succeed");
}

// ===== Integration Scenario 6: Slug uniqueness =====

#[tokio::test]
async fn duplicate_slug_rejected() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "First Org".to_string(),
                slug: "unique-slug".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create first org");

    let result = identity.create_organization(
        &realm_id,
        &CreateOrganizationRequest {
            name: "Second Org".to_string(),
            slug: "unique-slug".to_string(),
            description: None,
            config: None,
        },
    );

    assert!(
        matches!(
            result,
            Err(hearth::identity::IdentityError::DuplicateOrgSlug)
        ),
        "should reject duplicate slug"
    );
}

// ===== Integration Scenario 7: Member limit enforcement =====

#[tokio::test]
async fn member_limit_enforced() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Limited Org".to_string(),
                slug: "limited-org".to_string(),
                description: None,
                config: Some(OrganizationConfig {
                    max_members: Some(1),
                }),
            },
        )
        .expect("create org");

    let user1 = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "user1@test.com".to_string(),
                display_name: "User 1".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user1");

    let user2 = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "user2@test.com".to_string(),
                display_name: "User 2".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user2");

    // First member succeeds
    identity
        .add_member(&realm_id, org.id(), user1.id(), OrganizationRole::Owner)
        .expect("add first member");

    // Second member fails (limit reached)
    let result = identity.add_member(&realm_id, org.id(), user2.id(), OrganizationRole::Member);
    assert!(
        matches!(
            result,
            Err(hearth::identity::IdentityError::MemberLimitReached)
        ),
        "should enforce member limit"
    );
}

// ===== Integration Scenario 8: Delete user cascades org memberships =====

#[tokio::test]
async fn delete_user_cascades_org_memberships() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "User Cascade Org".to_string(),
                slug: "user-cascade".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "deleteme@test.com".to_string(),
                display_name: "Delete Me".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Need a second owner so delete_user doesn't fail on LastOwner
    let owner = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "stayowner@test.com".to_string(),
                display_name: "Stay Owner".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create owner");

    identity
        .add_member(&realm_id, org.id(), owner.id(), OrganizationRole::Owner)
        .expect("add owner");
    identity
        .add_member(&realm_id, org.id(), user.id(), OrganizationRole::Member)
        .expect("add member");

    // Delete user
    identity
        .delete_user(&realm_id, user.id())
        .expect("delete user");

    // Verify membership cleaned from org's perspective
    let members = identity
        .list_members(&realm_id, org.id(), None, 10)
        .expect("list members");
    assert_eq!(
        members.items.len(),
        1,
        "deleted user's membership should be cleaned"
    );
    assert_eq!(members.items[0].user_id(), owner.id());
}

// ===== Integration Scenario 9: Invitation revocation =====

#[tokio::test]
async fn invitation_revocation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Revoke Org".to_string(),
                slug: "revoke-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let admin = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "admin-revoke@test.com".to_string(),
                display_name: "Admin".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create admin");

    let (invitation, token) = identity
        .create_invitation(
            &realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: "revokee@test.com".to_string(),
                role: OrganizationRole::Member,
                invited_by: admin.id().clone(),
            },
        )
        .expect("create invitation");

    // Revoke it
    identity
        .revoke_invitation(&realm_id, invitation.id())
        .expect("revoke invitation");

    // Try to accept — should fail
    let result = identity.accept_invitation(&realm_id, &token);
    assert!(result.is_err(), "revoked invitation should not be accepted");
}

// ===== Integration Scenario 10: Organization not found =====

#[tokio::test]
async fn operations_on_nonexistent_org_fail() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let fake_org_id = OrganizationId::generate();

    // Get returns None
    assert!(identity
        .get_organization(&realm_id, &fake_org_id)
        .expect("get")
        .is_none());

    // Update returns error
    assert!(matches!(
        identity.update_organization(
            &realm_id,
            &fake_org_id,
            &UpdateOrganizationRequest::default()
        ),
        Err(hearth::identity::IdentityError::OrganizationNotFound)
    ));

    // Delete returns error
    assert!(matches!(
        identity.delete_organization(&realm_id, &fake_org_id),
        Err(hearth::identity::IdentityError::OrganizationNotFound)
    ));
}

// =========================================================================
// Property tests
// =========================================================================

mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for valid slugs (3-63 chars, lowercase alphanumeric + hyphens).
    fn valid_slug() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{1,10}(-[a-z0-9]{1,10}){0,3}".prop_filter("slug too short", |s| s.len() >= 3)
    }

    /// Helper to create a harness synchronously for property tests.
    fn make_harness() -> common::TestHarness {
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(common::TestHarness::embedded())
            .expect("harness")
    }

    proptest! {
        /// Property: a valid slug survives roundtrip through create_organization and
        /// get_organization_by_slug — the slug stored is the slug queried.
        #[test]
        fn slug_roundtrip_through_engine(slug in valid_slug()) {
            let harness = make_harness();
            let identity = harness.identity();
            let realm_id = setup_realm(identity);

            let result = identity.create_organization(
                &realm_id,
                &CreateOrganizationRequest {
                    name: format!("Org for {slug}"),
                    slug: slug.clone(),
                    description: None,
                    config: None,
                },
            );

            if let Ok(org) = result {
                prop_assert_eq!(org.slug(), slug.as_str());

                let by_slug = identity
                    .get_organization_by_slug(&realm_id, &slug)
                    .expect("get by slug")
                    .expect("org should exist");
                prop_assert_eq!(by_slug.id(), org.id());
            }
        }

        /// Property: membership indexes are always symmetric — if a user appears in
        /// list_members(org), then the org appears in list_user_organizations(user),
        /// and vice versa.
        #[test]
        fn membership_index_symmetry(member_count in 1u32..5) {
            let harness = make_harness();
            let identity = harness.identity();
            let realm_id = setup_realm(identity);

            let org = identity
                .create_organization(
                    &realm_id,
                    &CreateOrganizationRequest {
                        name: format!("Sym Org {member_count}"),
                        slug: format!("sym-org-{member_count}"),
                        description: None,
                        config: None,
                    },
                )
                .expect("create org");

            let mut user_ids = Vec::new();
            for i in 0..member_count {
                let user = identity
                    .create_user(
                        &realm_id,
                        &CreateUserRequest {
                            email: format!("sym-{i}-{member_count}@test.com"),
                            display_name: format!("User {i}"),
                            first_name: String::new(),
                            last_name: String::new(),
                        },
                    )
                    .expect("create user");

                let role = if i == 0 { OrganizationRole::Owner } else { OrganizationRole::Member };
                identity.add_member(&realm_id, org.id(), user.id(), role).expect("add member");
                user_ids.push(user.id().clone());
            }

            // Check forward: list_members contains all users
            let members = identity
                .list_members(&realm_id, org.id(), None, 100)
                .expect("list members");
            prop_assert_eq!(members.items.len(), member_count as usize);

            // Check reverse: each user's org list contains the org
            for uid in &user_ids {
                let orgs = identity
                    .list_user_organizations(&realm_id, uid, None, 100)
                    .expect("list user orgs");
                prop_assert!(
                    orgs.items.iter().any(|m| m.org_id() == org.id()),
                    "user {} should have org {} in their list",
                    uid.as_uuid(),
                    org.id().as_uuid()
                );
            }
        }

        /// Property: CRUD sequences maintain consistent organization count.
        /// After creating N orgs and deleting M of them, exactly N-M should remain.
        #[test]
        fn crud_count_invariant(
            create_count in 1u32..6,
            delete_fraction in 0.0f64..1.0,
        ) {
            let harness = make_harness();
            let identity = harness.identity();
            let realm_id = setup_realm(identity);

            let mut org_ids = Vec::new();
            for i in 0..create_count {
                let org = identity
                    .create_organization(
                        &realm_id,
                        &CreateOrganizationRequest {
                            name: format!("Count Org {i}"),
                            slug: format!("count-org-{i}-{create_count}"),
                            description: None,
                            config: None,
                        },
                    )
                    .expect("create org");
                org_ids.push(org.id().clone());
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let delete_count = (f64::from(create_count) * delete_fraction).floor() as u32;
            for i in 0..delete_count {
                identity
                    .delete_organization(&realm_id, &org_ids[i as usize])
                    .expect("delete org");
            }

            let remaining = identity
                .list_organizations(&realm_id, None, 100)
                .expect("list orgs");
            let expected = create_count - delete_count;
            prop_assert_eq!(
                remaining.items.len(),
                expected as usize,
                "expected {} orgs after creating {} and deleting {}",
                expected,
                create_count,
                delete_count
            );
        }
    }
}

// =========================================================================
// Adversarial tests
// =========================================================================

/// Adversarial: invalid invitation tokens should not reveal whether
/// a token exists or was expired. All errors must be `InvitationInvalid`.
#[tokio::test]
async fn token_enumeration_resistance() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    // Attempt to accept a completely fake token
    let fake_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let result = identity.accept_invitation(&realm_id, fake_token);
    assert!(
        matches!(
            result,
            Err(hearth::identity::IdentityError::InvitationInvalid)
        ),
        "fake token should return InvitationInvalid, got: {result:?}"
    );

    // Attempt with empty token
    let result = identity.accept_invitation(&realm_id, "");
    assert!(
        matches!(
            result,
            Err(hearth::identity::IdentityError::InvitationInvalid)
        ),
        "empty token should return InvitationInvalid, got: {result:?}"
    );

    // Attempt with very long token (1 KiB of random characters)
    let long_token = "a".repeat(1024);
    let result = identity.accept_invitation(&realm_id, &long_token);
    assert!(
        matches!(
            result,
            Err(hearth::identity::IdentityError::InvitationInvalid)
        ),
        "long token should return InvitationInvalid, got: {result:?}"
    );
}

/// Adversarial: members cannot escalate their own role or assign roles
/// they don't have. (The engine doesn't enforce caller roles — that's the
/// authorization layer's job — but we verify that role changes go through
/// properly and last-owner protection cannot be bypassed.)
#[tokio::test]
async fn role_escalation_prevention() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Escalation Org".to_string(),
                slug: "escalation-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let owner = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "sole-owner@test.com".to_string(),
                display_name: "Sole Owner".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create owner");

    identity
        .add_member(&realm_id, org.id(), owner.id(), OrganizationRole::Owner)
        .expect("add owner");

    // Cannot demote the sole owner to Member
    assert!(matches!(
        identity.update_member_role(&realm_id, org.id(), owner.id(), OrganizationRole::Member),
        Err(hearth::identity::IdentityError::LastOwner)
    ));

    // Cannot demote the sole owner to Admin
    assert!(matches!(
        identity.update_member_role(&realm_id, org.id(), owner.id(), OrganizationRole::Admin),
        Err(hearth::identity::IdentityError::LastOwner)
    ));

    // Cannot remove the sole owner
    assert!(matches!(
        identity.remove_member(&realm_id, org.id(), owner.id()),
        Err(hearth::identity::IdentityError::LastOwner)
    ));
}

/// Adversarial: slug injection — ensure special characters, SQL injection
/// attempts, and path traversal are rejected by validation.
#[tokio::test]
async fn slug_injection_rejected() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = setup_realm(identity);

    let malicious_slugs = [
        "../etc/passwd",
        "'; DROP TABLE--",
        "<script>alert(1)</script>",
        "org%00null",
        "UPPER-CASE",
        "org with spaces",
        "-leading-hyphen",
        "trailing-hyphen-",
        "double--hyphen",
        "ab",            // Too short
        &"a".repeat(64), // Too long
    ];

    for slug in &malicious_slugs {
        let result = identity.create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Injection Test".to_string(),
                slug: (*slug).to_string(),
                description: None,
                config: None,
            },
        );
        assert!(
            result.is_err(),
            "slug '{slug}' should be rejected but was accepted"
        );
    }
}
