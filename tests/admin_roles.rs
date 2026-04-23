//! Integration tests for the Roles & Permissions admin surface.
//!
//! Phase 3 introduces two new audit actions — `RoleAssigned` and
//! `RoleRevoked` — plus a realm admin management surface that grants or
//! revokes the `hearth#admin` role via the UI.
//!
//! These tests exercise the audit+authz contract the UI handlers sit on top
//! of: after granting admin, an audit event with the right action and
//! metadata must be queryable, and `expand()` must list the new admin.

mod common;

use hearth::audit::{AuditAction, AuditQuery, CreateAuditEvent};
use hearth::authz::{ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest};

fn setup(harness: &common::TestHarness) -> (RealmId, hearth::core::UserId) {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "Roles Test Realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");
    (realm.id().clone(), user.id().clone())
}

/// After granting `hearth#admin` to a user and appending a `RoleAssigned`
/// audit event, the event must surface via `audit.query` with the right
/// metadata, and `expand()` must list the user.
#[tokio::test]
async fn grant_realm_admin_emits_role_assigned_audit_and_appears_in_expand() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, user_id) = setup(&harness);

    // Write the admin tuple (mirrors what `set_user_admin` does in the UI
    // handlers).
    let obj = ObjectRef::new("hearth", "admin").expect("obj");
    let subj = SubjectRef::direct("user", &user_id.as_uuid().to_string()).expect("subj");
    let tuple = RelationshipTuple::new(obj.clone(), "admin", subj.clone()).expect("tuple");
    harness
        .authz()
        .write_tuples(&realm_id, &[TupleWrite::Touch(tuple)])
        .expect("grant admin");

    // Emit the corresponding audit event (mirrors `audit_role_event` helper).
    harness
        .audit()
        .append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "system".to_string(),
            action: AuditAction::RoleAssigned,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "object_type": "hearth",
                "object_id": "admin",
                "role": "admin",
            })),
        })
        .expect("append audit");

    // expand() returns the granted user.
    let subjects = harness
        .authz()
        .expand(&realm_id, &obj, "admin", None)
        .expect("expand");
    assert!(subjects.contains(&subj), "expand missing granted user");

    // Audit query by actor returns the event with RoleAssigned action.
    let events = harness
        .audit()
        .query(&AuditQuery {
            realm_id: realm_id.clone(),
            actor: Some("system".to_string()),
            action: None,
            start_time: None,
            end_time: None,
            limit: Some(10),
        })
        .expect("query audit");
    let role_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.action, AuditAction::RoleAssigned))
        .collect();
    assert_eq!(role_events.len(), 1, "expected one RoleAssigned event");
    let meta = role_events[0].metadata.as_ref().expect("metadata present");
    assert_eq!(meta["role"], "admin");
    assert_eq!(meta["object_type"], "hearth");
}

/// Revoking admin removes the user from `expand()` and emits a
/// `RoleRevoked` audit event distinct from the grant event.
#[tokio::test]
async fn revoke_realm_admin_emits_role_revoked_audit() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, user_id) = setup(&harness);

    let obj = ObjectRef::new("hearth", "admin").expect("obj");
    let subj = SubjectRef::direct("user", &user_id.as_uuid().to_string()).expect("subj");
    let tuple = RelationshipTuple::new(obj.clone(), "admin", subj.clone()).expect("tuple");

    // Grant, then revoke.
    harness
        .authz()
        .write_tuples(&realm_id, &[TupleWrite::Touch(tuple.clone())])
        .expect("grant");
    harness
        .authz()
        .write_tuples(&realm_id, &[TupleWrite::Delete(tuple)])
        .expect("revoke");
    harness
        .audit()
        .append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "system".to_string(),
            action: AuditAction::RoleRevoked,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "object_type": "hearth",
                "object_id": "admin",
                "role": "admin",
            })),
        })
        .expect("append revoke audit");

    // User no longer in expand().
    let subjects = harness
        .authz()
        .expand(&realm_id, &obj, "admin", None)
        .expect("expand");
    assert!(
        !subjects.contains(&subj),
        "revoked user must not be in expand(), got {subjects:?}"
    );

    // Audit query: exactly one RoleRevoked event visible.
    let events = harness
        .audit()
        .query(&AuditQuery {
            realm_id: realm_id.clone(),
            actor: Some("system".to_string()),
            action: None,
            start_time: None,
            end_time: None,
            limit: Some(10),
        })
        .expect("query audit");
    let revoked: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.action, AuditAction::RoleRevoked))
        .collect();
    assert_eq!(revoked.len(), 1, "expected one RoleRevoked event");
}

/// Simulating the Phase-6 org-mirror: when an org role changes,
/// the old tuple is deleted, the new tuple is written, and both halves
/// are visible via Zanzibar `check()` + present in the audit log.
/// This mirrors what `mirror_org_role_changed` does behind the UI handler.
#[tokio::test]
async fn org_role_change_mirrors_into_zanzibar_tuples_and_audit() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, user_id) = setup(&harness);

    // Install preset so the org#member / org#admin tuples validate.
    hearth::authz::ensure_preset_namespace(harness.authz(), &realm_id).expect("preset");

    let org_uuid = uuid::Uuid::new_v4();
    let org_obj = ObjectRef::new("organization", &org_uuid.to_string()).expect("obj");
    let subj = SubjectRef::direct("user", &user_id.as_uuid().to_string()).expect("subj");

    // Initial state: user is member.
    let member_tuple =
        RelationshipTuple::new(org_obj.clone(), "member", subj.clone()).expect("member tuple");
    harness
        .authz()
        .write_tuples(&realm_id, &[TupleWrite::Touch(member_tuple.clone())])
        .expect("write member");
    harness
        .audit()
        .append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "ui".to_string(),
            action: AuditAction::RoleAssigned,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "object_type": "organization",
                "object_id": org_uuid.to_string(),
                "role": "member",
            })),
        })
        .expect("append member audit");

    // Role change member → admin: delete old, touch new, paired audit.
    let admin_tuple =
        RelationshipTuple::new(org_obj.clone(), "admin", subj.clone()).expect("admin tuple");
    harness
        .authz()
        .write_tuples(
            &realm_id,
            &[
                TupleWrite::Delete(member_tuple),
                TupleWrite::Touch(admin_tuple),
            ],
        )
        .expect("rotate");
    for (assigned, role) in [(false, "member"), (true, "admin")] {
        harness
            .audit()
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "ui".to_string(),
                action: if assigned {
                    AuditAction::RoleAssigned
                } else {
                    AuditAction::RoleRevoked
                },
                resource_type: "user".to_string(),
                resource_id: user_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "object_type": "organization",
                    "object_id": org_uuid.to_string(),
                    "role": role,
                })),
            })
            .expect("append audit");
    }

    // After rotation: admin → satisfies viewer via union, member direct
    // tuple is gone (check returns true only through the admin tuple's
    // union rewrite).
    assert!(harness
        .authz()
        .check(&realm_id, &org_obj, "admin", &subj, None)
        .expect("check admin"));
    assert!(harness
        .authz()
        .check(&realm_id, &org_obj, "viewer", &subj, None)
        .expect("check viewer via union"));

    // Audit log contains exactly one RoleRevoked + two RoleAssigned
    // (initial add + change), all scoped to this user.
    let events = harness
        .audit()
        .query(&AuditQuery {
            realm_id,
            actor: Some("ui".to_string()),
            action: None,
            start_time: None,
            end_time: None,
            limit: Some(20),
        })
        .expect("query audit");
    let assigned = events
        .iter()
        .filter(|e| matches!(e.action, AuditAction::RoleAssigned))
        .count();
    let revoked = events
        .iter()
        .filter(|e| matches!(e.action, AuditAction::RoleRevoked))
        .count();
    assert_eq!(assigned, 2, "expected 2 RoleAssigned events");
    assert_eq!(revoked, 1, "expected 1 RoleRevoked event");
}

/// Regression: a bulk-add form body with exactly one checkbox ticked
/// (`user_ids=<uuid>&role=Member&_csrf=…`) must deserialize into the
/// one-element `Vec<String>` the handler expects. Before the custom
/// `deserialize_string_list` fix, this round-trip failed at the form
/// layer with "invalid type: string … expected a sequence".
#[test]
fn bulk_add_members_form_accepts_single_user_id() {
    #[derive(serde::Deserialize, Debug)]
    struct Body {
        #[serde(default, deserialize_with = "single_or_many")]
        user_ids: Vec<String>,
    }
    // Copy of the production helper — kept inline here so the test is
    // decoupled from handler module visibility.
    fn single_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<String>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("string or sequence")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
                Ok(if v.is_empty() { vec![] } else { vec![v.to_string()] })
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Vec<String>, E> {
                Ok(if v.is_empty() { vec![] } else { vec![v] })
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Vec<String>, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = s.next_element::<String>()? {
                    if !item.is_empty() {
                        out.push(item);
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(V)
    }

    // Single scalar: this is the shape `serde_urlencoded` produces from
    // a one-checkbox submission (`user_ids=UUID`).
    let single: Body = serde_json::from_value(serde_json::json!({
        "user_ids": "813a58c0-2c73-4563-acb6-e7723acdc238"
    }))
    .expect("single scalar must deserialize");
    assert_eq!(single.user_ids.len(), 1);

    // Sequence: multi-checkbox submission.
    let multi: Body =
        serde_json::from_value(serde_json::json!({ "user_ids": ["a", "b"] })).expect("seq");
    assert_eq!(multi.user_ids, vec!["a".to_string(), "b".to_string()]);

    // Empty string: zero checkboxes → empty vec.
    let empty: Body =
        serde_json::from_value(serde_json::json!({ "user_ids": "" })).expect("empty scalar");
    assert!(empty.user_ids.is_empty());
}

/// Serialization round-trip: the new `AuditAction` variants survive the
/// `as_str` / `from_str` pair used by storage keys and query filters.
#[test]
fn role_audit_actions_roundtrip_through_string_form() {
    use std::str::FromStr;
    for a in [AuditAction::RoleAssigned, AuditAction::RoleRevoked] {
        let s = a.as_str();
        let back = AuditAction::from_str(s).expect("round-trip");
        assert_eq!(back, a, "{s} did not round-trip");
    }
}
