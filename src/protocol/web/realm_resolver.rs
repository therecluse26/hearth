//! Resolves which realm a pre-auth `/ui/*` request belongs to.
//!
//! Under Hearth's explicit-realm-routing model (see gap: realm routing),
//! every pre-auth page — login, register, forgot/reset-password, verify-
//! email, accept-invitation, device approval, MFA challenge — must settle
//! on exactly one realm before touching the identity engine.
//!
//! The resolution precedence is:
//!
//! 1. **URL path** — if the request came in under `/ui/realms/<name>/...`,
//!    the name is authoritative. Unknown names yield [`Resolved::NotFound`]
//!    and callers should return HTTP 404 (not 400: "this URL doesn't
//!    exist" is the honest answer; 400 would leak routing shape).
//!
//! 2. **Single-realm shortcut** — if storage contains exactly one realm,
//!    we use it regardless of `default_realm_name`. Zero-config single-
//!    realm deployments "just work".
//!
//! 3. **Declared default** — on multi-realm deployments, if
//!    `WebState::default_realm_name` is set *and* the named realm exists,
//!    use it.
//!
//! 4. **No default, multi-realm** — return [`Resolved::MustChoose`] with
//!    the list of active realms. GET handlers render the picker template;
//!    POST handlers return 400.
//!
//! The session-cookie case is out of scope here — authenticated handlers
//! read the realm directly from `UiSession::realm_id` and never need this
//! resolver.

use crate::identity::Realm;

use super::WebState;

/// Outcome of a realm-resolution attempt.
///
/// Size-difference lint suppressed: `Resolved::Realm` dominates the
/// common path and boxing it would add an indirection on every pre-auth
/// request; `MustChoose` is rare (multi-realm, no default).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Resolved {
    /// The realm was resolved unambiguously. Most common case.
    Realm(Realm),
    /// An explicit `/ui/realms/<name>/...` path was used, but that realm
    /// does not exist. Callers return 404.
    NotFound,
    /// Multi-realm deployment with no `default_realm` configured and no
    /// explicit path segment. Callers either render a picker (GET) or
    /// return 400 (POST).
    MustChoose(Vec<Realm>),
    /// Storage returned an error. Callers return 500.
    Storage,
}

/// Rejects realm names that contain characters which shouldn't appear in
/// a URL path segment. Applied before any storage lookup so we never
/// route on attacker-controlled junk.
fn is_sane_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| !(c == '/' || c == '\\' || c.is_whitespace() || c.is_control()))
}

/// Attempts to resolve the realm for a pre-auth request.
///
/// `path_realm` is the optional `<name>` extracted from a
/// `/ui/realms/<name>/...` path. When `None`, the resolver falls back
/// to the sole-realm / default / picker chain described in the module
/// docs.
#[must_use]
pub fn resolve(state: &WebState, path_realm: Option<&str>) -> Resolved {
    // Rule 1: URL path wins.
    if let Some(name) = path_realm {
        if !is_sane_name(name) {
            return Resolved::NotFound;
        }
        return match state.identity.get_realm_by_name(name) {
            Ok(Some(realm)) => Resolved::Realm(realm),
            Ok(None) => Resolved::NotFound,
            Err(e) => {
                tracing::warn!(error = %e, realm_name = %name, "resolve: get_realm_by_name failed");
                Resolved::Storage
            }
        };
    }

    // For rules 2-4 we need the realm inventory. Cap at 2 is enough to
    // distinguish "exactly one" from "more than one"; the picker case
    // loads the full set separately when needed.
    let inventory = match state.identity.list_realms(None, 2) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::warn!(error = %e, "resolve: list_realms failed");
            return Resolved::Storage;
        }
    };

    // Rule 2: sole-realm shortcut.
    if inventory.len() == 1 {
        return Resolved::Realm(inventory.into_iter().next().expect("len == 1"));
    }

    // Rule 3: declared default (multi-realm only).
    if let Some(name) = state.default_realm_name.as_deref() {
        return match state.identity.get_realm_by_name(name) {
            Ok(Some(realm)) => Resolved::Realm(realm),
            Ok(None) => {
                // Config validation at startup should have caught this,
                // but the realm could have been deleted since. Fall back
                // to the picker rather than 500.
                tracing::warn!(
                    realm_name = %name,
                    "resolve: default_realm_name points to nonexistent realm"
                );
                fetch_picker(state)
            }
            Err(e) => {
                tracing::warn!(error = %e, "resolve: default realm lookup failed");
                Resolved::Storage
            }
        };
    }

    // Rule 4: no default, multi-realm — picker.
    fetch_picker(state)
}

/// Loads a larger page of realms for the "choose a realm" picker.
fn fetch_picker(state: &WebState) -> Resolved {
    match state.identity.list_realms(None, 100) {
        Ok(page) => Resolved::MustChoose(page.items),
        Err(e) => {
            tracing::warn!(error = %e, "resolve: picker list_realms failed");
            Resolved::Storage
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sane_name_accepts_normal_names() {
        assert!(is_sane_name("default"));
        assert!(is_sane_name("acme-corp"));
        assert!(is_sane_name("Realm_42"));
    }

    #[test]
    fn is_sane_name_rejects_path_traversal_and_control() {
        assert!(!is_sane_name(""));
        assert!(!is_sane_name("a/b"));
        assert!(!is_sane_name("a\\b"));
        assert!(!is_sane_name("has space"));
        assert!(!is_sane_name("tab\there"));
        assert!(!is_sane_name("new\nline"));
    }

    #[test]
    fn is_sane_name_caps_length() {
        assert!(is_sane_name(&"a".repeat(128)));
        assert!(!is_sane_name(&"a".repeat(129)));
    }
}
