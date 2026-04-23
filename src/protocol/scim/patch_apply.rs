//! SCIM 2.0 PATCH apply logic (RFC 7644 §3.5.2).
//!
//! Phase 1 supports the flat subset real IdPs emit:
//! - `op: replace` / `op: add` on simple paths: `active`, `displayName`,
//!   `name.givenName`, `name.familyName`, `emails`, `externalId`.
//! - `op: remove` on `externalId` (clears the index).
//! - PATCH without a `path` (root replacement with a JSON object) is
//!   unwound into per-attribute replaces.
//!
//! Bracketed filter paths like `emails[type eq "work"].value` are
//! rejected with `invalidPath`. This matches the narrow scope Okta and
//! Azure AD actually send.

use crate::protocol::scim::error::ScimError;
use crate::protocol::scim::types::{PatchOp, ScimEmail, ScimName, ScimUser};

/// Applies a list of PATCH operations to a `ScimUser` in place. Returns
/// the first error on failure (ops are not transactional at this layer —
/// callers that need atomicity should validate the full op list first).
pub fn apply_user_patch(u: &mut ScimUser, ops: &[PatchOp]) -> Result<(), ScimError> {
    for op in ops {
        apply_one_user(u, op)?;
    }
    Ok(())
}

fn apply_one_user(u: &mut ScimUser, op: &PatchOp) -> Result<(), ScimError> {
    let verb = op.op.to_ascii_lowercase();
    if verb != "add" && verb != "replace" && verb != "remove" {
        return Err(ScimError::invalid_syntax(format!(
            "unsupported PATCH op '{}'",
            op.op
        )));
    }

    match op.path.as_deref() {
        None => {
            // No path: operand must be a JSON object; its entries are
            // handled as individual sets.
            if verb == "remove" {
                return Err(ScimError::invalid_syntax(
                    "PATCH remove requires a path",
                ));
            }
            let Some(serde_json::Value::Object(map)) = op.value.clone() else {
                return Err(ScimError::invalid_syntax(
                    "PATCH without path requires a JSON object value",
                ));
            };
            for (k, v) in map {
                set_user_attr(u, &k, Some(v))?;
            }
            Ok(())
        }
        Some(path) if !path.contains('[') => {
            let value = op.value.clone();
            match verb.as_str() {
                "remove" => set_user_attr(u, path, None),
                _ => set_user_attr(u, path, value),
            }
        }
        Some(_) => Err(ScimError::invalid_path(
            "bracketed PATCH paths are not supported",
        )),
    }
}

fn set_user_attr(u: &mut ScimUser, path: &str, value: Option<serde_json::Value>) -> Result<(), ScimError> {
    match path.to_ascii_lowercase().as_str() {
        "active" => {
            u.active = value
                .as_ref()
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| ScimError::invalid_value("active must be boolean"))?;
        }
        "displayname" => match value {
            Some(serde_json::Value::String(s)) => u.display_name = Some(s),
            Some(serde_json::Value::Null) | None => u.display_name = None,
            _ => return Err(ScimError::invalid_value("displayName must be string")),
        },
        "externalid" => match value {
            Some(serde_json::Value::String(s)) => u.external_id = Some(s),
            Some(serde_json::Value::Null) | None => u.external_id = None,
            _ => return Err(ScimError::invalid_value("externalId must be string")),
        },
        "username" => match value {
            Some(serde_json::Value::String(s)) => u.user_name = s,
            _ => return Err(ScimError::invalid_value("userName must be string")),
        },
        "name" => match value {
            Some(v) => {
                let n: ScimName = serde_json::from_value(v)
                    .map_err(|e| ScimError::invalid_value(format!("name: {e}")))?;
                u.name = Some(n);
            }
            None => u.name = None,
        },
        "name.givenname" => {
            let n = u.name.get_or_insert_with(ScimName::default);
            match value {
                Some(serde_json::Value::String(s)) => n.given_name = Some(s),
                Some(serde_json::Value::Null) | None => n.given_name = None,
                _ => return Err(ScimError::invalid_value("name.givenName must be string")),
            }
        }
        "name.familyname" => {
            let n = u.name.get_or_insert_with(ScimName::default);
            match value {
                Some(serde_json::Value::String(s)) => n.family_name = Some(s),
                Some(serde_json::Value::Null) | None => n.family_name = None,
                _ => return Err(ScimError::invalid_value("name.familyName must be string")),
            }
        }
        "emails" => match value {
            Some(v) => {
                let emails: Vec<ScimEmail> = serde_json::from_value(v)
                    .map_err(|e| ScimError::invalid_value(format!("emails: {e}")))?;
                u.emails = emails;
            }
            None => u.emails.clear(),
        },
        other => {
            return Err(ScimError::invalid_path(format!(
                "unsupported PATCH target '{other}'"
            )));
        }
    }
    Ok(())
}

/// Operations applied to a `ScimGroup`. Simpler than users — the only
/// attributes Okta PATCHes in practice are `displayName`, `externalId`,
/// and `members`.
pub fn apply_group_patch(
    g: &mut crate::protocol::scim::types::ScimGroup,
    ops: &[PatchOp],
) -> Result<(), ScimError> {
    use crate::protocol::scim::types::ScimMember;
    for op in ops {
        let verb = op.op.to_ascii_lowercase();
        if verb != "add" && verb != "replace" && verb != "remove" {
            return Err(ScimError::invalid_syntax(format!(
                "unsupported PATCH op '{}'",
                op.op
            )));
        }
        let path = op.path.as_deref();
        if path.map_or(false, |p| p.contains('[')) {
            return Err(ScimError::invalid_path(
                "bracketed PATCH paths are not supported",
            ));
        }
        match path.map(str::to_ascii_lowercase).as_deref() {
            Some("displayname") => match op.value.clone() {
                Some(serde_json::Value::String(s)) => g.display_name = s,
                _ => return Err(ScimError::invalid_value("displayName must be string")),
            },
            Some("externalid") => match op.value.clone() {
                Some(serde_json::Value::String(s)) => g.external_id = Some(s),
                Some(serde_json::Value::Null) | None => g.external_id = None,
                _ => return Err(ScimError::invalid_value("externalId must be string")),
            },
            Some("members") => {
                let members: Vec<ScimMember> = match op.value.clone() {
                    Some(v) => serde_json::from_value(v)
                        .map_err(|e| ScimError::invalid_value(format!("members: {e}")))?,
                    None => Vec::new(),
                };
                match verb.as_str() {
                    "replace" => g.members = members,
                    "add" => g.members.extend(members),
                    "remove" => {
                        if members.is_empty() {
                            g.members.clear();
                        } else {
                            let drop: std::collections::HashSet<_> =
                                members.iter().map(|m| m.value.clone()).collect();
                            g.members.retain(|m| !drop.contains(&m.value));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            None => {
                let Some(serde_json::Value::Object(map)) = op.value.clone() else {
                    return Err(ScimError::invalid_syntax(
                        "PATCH without path requires object value",
                    ));
                };
                for (k, v) in map {
                    apply_group_patch(
                        g,
                        &[PatchOp {
                            op: "replace".to_string(),
                            path: Some(k),
                            value: Some(v),
                        }],
                    )?;
                }
            }
            Some(other) => {
                return Err(ScimError::invalid_path(format!(
                    "unsupported group PATCH target '{other}'"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::scim::types::{ScimEmail, ScimName, ScimUser};
    use serde_json::json;

    fn sample_user() -> ScimUser {
        ScimUser {
            schemas: vec![],
            id: None,
            external_id: Some("okta-1".to_string()),
            user_name: "alice@example.com".to_string(),
            display_name: Some("Alice".to_string()),
            name: Some(ScimName {
                formatted: None,
                given_name: Some("Alice".to_string()),
                family_name: Some("Example".to_string()),
            }),
            emails: vec![ScimEmail {
                value: "alice@example.com".to_string(),
                primary: Some(true),
                r#type: None,
            }],
            active: true,
            meta: None,
        }
    }

    #[test]
    fn replace_active_flips_to_disabled() {
        let mut u = sample_user();
        let op = PatchOp {
            op: "replace".to_string(),
            path: Some("active".to_string()),
            value: Some(json!(false)),
        };
        apply_user_patch(&mut u, &[op]).expect("apply");
        assert!(!u.active);
    }

    #[test]
    fn replace_name_familyname_updates_nested() {
        let mut u = sample_user();
        let op = PatchOp {
            op: "replace".to_string(),
            path: Some("name.familyName".to_string()),
            value: Some(json!("Smith")),
        };
        apply_user_patch(&mut u, &[op]).expect("apply");
        assert_eq!(u.name.unwrap().family_name.as_deref(), Some("Smith"));
    }

    #[test]
    fn remove_external_id_clears() {
        let mut u = sample_user();
        let op = PatchOp {
            op: "remove".to_string(),
            path: Some("externalId".to_string()),
            value: None,
        };
        apply_user_patch(&mut u, &[op]).expect("apply");
        assert!(u.external_id.is_none());
    }

    #[test]
    fn bracketed_path_rejected() {
        let mut u = sample_user();
        let op = PatchOp {
            op: "replace".to_string(),
            path: Some("emails[type eq \"work\"].value".to_string()),
            value: Some(json!("x@y.z")),
        };
        let err = apply_user_patch(&mut u, &[op]).expect_err("reject");
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn root_replace_unfolds_into_attributes() {
        let mut u = sample_user();
        let op = PatchOp {
            op: "replace".to_string(),
            path: None,
            value: Some(json!({"active": false, "displayName": "Ali"})),
        };
        apply_user_patch(&mut u, &[op]).expect("apply");
        assert!(!u.active);
        assert_eq!(u.display_name.as_deref(), Some("Ali"));
    }
}
