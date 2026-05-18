//! Config snapshot persistence and typed diff computation.
//!
//! # Snapshot
//!
//! [`ConfigSnapshot`] captures the subset of [`Config`] that can produce
//! data-layer consequences. Secrets (SMTP passwords, API keys) are replaced
//! with a short SHA-256 fingerprint before serialisation so the stored bytes
//! never contain plaintext credentials.
//!
//! The snapshot is serialised to canonical JSON (BTreeMap → sorted keys) and
//! written to the WAL under `config:snapshot:v1` in the system realm. On the
//! next startup the stored snapshot is loaded and compared against the live
//! `Config` to produce a [`Vec<ConfigDiff>`].
//!
//! # Diff
//!
//! [`ConfigDiff`] is `#[non_exhaustive]` so adding a new variant in a future
//! phase is a compile error for any `match` that doesn't cover it — the
//! compile-time exhaustiveness guarantee the spec requires.
//!
//! Phase A: all [`apply_diff`] handlers are no-ops that emit `trace!` events.
//! Actual handlers are added in subsequent phases.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Config, EmailTransport};

// ── Snapshot ──────────────────────────────────────────────────────────────────

/// A fingerprint of a secret value.
///
/// The plaintext is never stored; only the first 16 hex characters of the
/// SHA-256 hash are kept — sufficient for detecting changes without exposing
/// the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFingerprint {
    /// Truncated SHA-256 hex of the secret value (first 16 hex chars = 64 bits).
    pub hash: String,
}

impl SecretFingerprint {
    /// Compute a fingerprint from a plaintext secret.
    #[must_use]
    pub fn of(value: &str) -> Self {
        let digest = Sha256::digest(value.as_bytes());
        let hex = hex::encode(digest);
        Self {
            hash: hex[..16].to_string(),
        }
    }
}

/// Snapshot of the token-issuance settings at the time the snapshot was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenSnapshot {
    /// Resolved `iss` claim value (from `token.issuer` or `oidc.issuer`).
    pub issuer: Option<String>,
    /// Resolved `aud` claim value.
    pub audience: Option<String>,
}

/// Snapshot of a single YAML-declared realm.
///
/// Phase A recorded presence only. Phase C adds settings and structural
/// inventories so that within-realm changes are detected between restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmSnapshot {
    /// Whether the realm was explicitly listed in the `realms:` YAML map.
    pub present: bool,
    /// SHA-256 fingerprint (first 16 hex chars) of the realm's settings block
    /// (session TTL, MFA policy, theme, token TTLs). Changing any setting
    /// produces a different fingerprint and emits `RealmSettingsChanged`.
    #[serde(default)]
    pub settings_hash: String,
    /// Sorted set of organization slugs declared in this realm's YAML.
    #[serde(default)]
    pub org_slugs: BTreeSet<String>,
    /// Sorted set of application YAML keys declared in this realm's YAML.
    #[serde(default)]
    pub app_keys: BTreeSet<String>,
    /// Sorted set of role names declared in this realm's YAML.
    #[serde(default)]
    pub role_names: BTreeSet<String>,
    /// Sorted set of group names declared in this realm's YAML.
    #[serde(default)]
    pub group_names: BTreeSet<String>,
    /// Whether `rotate_signing_key: true` was set in this realm's YAML at
    /// snapshot time. Written as `true` when the flag is set in YAML, and
    /// explicitly cleared to `false` after the rotation is applied — so a
    /// subsequent restart with the flag still in YAML does not re-rotate.
    #[serde(default)]
    pub rotate_signing_key: bool,
}

impl RealmSnapshot {
    /// Build a [`RealmSnapshot`] from a YAML realm config entry.
    #[must_use]
    pub fn from_yaml(name: &str, yaml: &crate::config::RealmYamlConfig) -> Self {
        // Settings fingerprint: hash all the fields that drive RealmSettingsChanged.
        // Changing any one of these emits the diff; exact field values are NOT stored.
        let settings_input = format!(
            "realm={name}\
             session_ttl={}\
             mfa_required={}\
             theme={}\
             access_token_ttl={}\
             refresh_token_ttl={}",
            yaml.session_ttl.as_deref().unwrap_or(""),
            yaml.auth
                .as_ref()
                .and_then(|a| a.mfa_required)
                .map_or("", |b| if b { "true" } else { "false" }),
            yaml.web
                .as_ref()
                .and_then(|w| w.theme.as_deref())
                .unwrap_or(""),
            yaml.auth
                .as_ref()
                .and_then(|a| a.token.as_ref())
                .and_then(|t| t.access_token_ttl.as_deref())
                .unwrap_or(""),
            yaml.auth
                .as_ref()
                .and_then(|a| a.token.as_ref())
                .and_then(|t| t.refresh_token_ttl.as_deref())
                .unwrap_or(""),
        );
        let digest = Sha256::digest(settings_input.as_bytes());
        let settings_hash = hex::encode(digest)[..16].to_string();

        let org_slugs = yaml
            .organizations
            .as_ref()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        // `applications` and `oauth_clients` are aliases; merge both.
        let app_keys = {
            let mut keys = BTreeSet::new();
            if let Some(m) = yaml.applications.as_ref() {
                keys.extend(m.keys().cloned());
            }
            if let Some(m) = yaml.oauth_clients.as_ref() {
                keys.extend(m.keys().cloned());
            }
            keys
        };

        let role_names = yaml
            .roles
            .as_ref()
            .map(|v| v.iter().map(|r| r.name.clone()).collect())
            .unwrap_or_default();

        let group_names = yaml
            .groups
            .as_ref()
            .map(|v| v.iter().map(|g| g.name.clone()).collect())
            .unwrap_or_default();

        Self {
            present: true,
            settings_hash,
            org_slugs,
            app_keys,
            role_names,
            group_names,
            rotate_signing_key: yaml.rotate_signing_key.unwrap_or(false),
        }
    }
}

/// An immutable snapshot of the applied configuration, with secrets scrubbed.
///
/// Serialised to canonical JSON (sorted BTreeMap keys) and written atomically
/// to the WAL under the system realm on each successful startup. Loaded on the
/// next startup and compared to the current [`Config`] to compute a
/// [`Vec<ConfigDiff>`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// Schema version. Always `1` for this format.
    pub version: u8,
    /// RFC 3339 timestamp when this snapshot was captured.
    pub captured_at: String,
    /// OIDC issuer URL (`oidc.issuer`).
    pub oidc_issuer: Option<String>,
    /// Token issuance settings.
    pub token: TokenSnapshot,
    /// Email transport label (e.g. `"log"`, `"smtp"`, `"sendgrid"`).
    pub email_transport: String,
    /// SMTP password fingerprint, if the transport is SMTP and a password is set.
    pub smtp_password_fingerprint: Option<SecretFingerprint>,
    /// Storage data directory path at the time of snapshot.
    pub storage_data_dir: String,
    /// Realm keys present in the `realms:` YAML map when this snapshot was taken.
    ///
    /// `None` means the `realms:` section was absent (backward-compat mode).
    pub realms: Option<BTreeMap<String, RealmSnapshot>>,
}

fn email_transport_label(t: EmailTransport) -> &'static str {
    match t {
        EmailTransport::Log => "log",
        EmailTransport::Smtp => "smtp",
        EmailTransport::Sendgrid => "sendgrid",
        EmailTransport::Postmark => "postmark",
        EmailTransport::Mailgun => "mailgun",
        EmailTransport::Mailtrap => "mailtrap",
        EmailTransport::Mailcatcher => "mailcatcher",
    }
}

impl ConfigSnapshot {
    /// Build a [`ConfigSnapshot`] from the live config, scrubbing secrets.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let smtp_password_fingerprint = config
            .email
            .smtp
            .as_ref()
            .and_then(|s| s.password.as_deref())
            .map(SecretFingerprint::of);

        let realms = config.realms.as_ref().map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), RealmSnapshot::from_yaml(k, v)))
                .collect::<BTreeMap<_, _>>()
        });

        // RFC 3339 timestamp using only std (time crate is present but we keep
        // the snapshot simple — wall-clock seconds precision is enough).
        let captured_at = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Build a minimal RFC 3339 string without pulling in a full date library.
            // We only need this for human readability in the stored JSON; the
            // diff engine never parses it back.
            format_unix_secs_as_rfc3339(secs)
        };

        Self {
            version: 1,
            captured_at,
            oidc_issuer: config.oidc.issuer.clone(),
            token: TokenSnapshot {
                issuer: config.token.issuer.clone(),
                audience: config.token.audience.clone(),
            },
            email_transport: email_transport_label(config.email.transport).to_string(),
            smtp_password_fingerprint,
            storage_data_dir: config.storage.data_dir.clone(),
            realms,
        }
    }

    /// Serialise to canonical JSON (BTreeMap guarantees sorted keys).
    ///
    /// # Errors
    ///
    /// Returns an error if serde_json serialisation fails (should never happen
    /// for a well-formed snapshot, but callers must handle it).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialise from stored JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid JSON or don't match
    /// the expected snapshot schema.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Minimal RFC 3339 formatter for a Unix timestamp (UTC, seconds precision).
#[allow(clippy::many_single_char_names)]
pub(crate) fn format_unix_secs_as_rfc3339(secs: u64) -> String {
    // Days-since-epoch → calendar date via the Gregorian proleptic algorithm
    // (https://howardhinnant.github.io/date_algorithms.html). Single-letter
    // variable names match the published algorithm verbatim — renaming them
    // would make it harder to verify correctness against the reference.
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3_600;
    let min = (time_of_day % 3_600) / 60;
    let sec = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

// ── Diff ──────────────────────────────────────────────────────────────────────

/// A typed change between two successive configurations that can produce a
/// data-layer consequence.
///
/// `#[non_exhaustive]` ensures that adding a new variant in a future phase
/// is a compile error for any `match` that doesn't cover it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigDiff {
    /// A new realm key appeared in the `realms:` YAML map.
    RealmAdded(String),
    /// A realm key was removed from the `realms:` YAML map.
    RealmRemoved(String),
    /// The global email transport type changed (e.g. `"log"` → `"smtp"`).
    EmailTransportChanged {
        /// Previous transport label.
        old: String,
        /// New transport label.
        new: String,
    },
    /// The SMTP password fingerprint changed (transport stays SMTP, but
    /// credentials were rotated).
    SmtpPasswordRotated,
    /// The `token.issuer` value changed. Existing access tokens signed with
    /// the old issuer will fail `iss` validation.
    TokenIssuerChanged {
        /// Previous issuer value (`None` means it was absent, defaulting to
        /// `oidc.issuer`).
        old: Option<String>,
        /// New issuer value.
        new: Option<String>,
    },
    /// The `token.audience` value changed.
    TokenAudienceChanged {
        /// Previous audience.
        old: Option<String>,
        /// New audience.
        new: Option<String>,
    },
    /// The `oidc.issuer` value changed. Affects OIDC Discovery metadata and
    /// ID token `iss` claims.
    OidcIssuerChanged {
        /// Previous issuer URL.
        old: Option<String>,
        /// New issuer URL.
        new: Option<String>,
    },
    /// The storage `data_dir` path changed between startups. This is almost
    /// certainly a misconfiguration — the node will see an empty database.
    StorageDataDirChanged {
        /// Path recorded in the previous snapshot.
        old: String,
        /// Path in the current config.
        new: String,
    },
    /// A realm's settings changed (session TTL, MFA policy, theme, token TTLs).
    ///
    /// Handled by `reconcile_realms` → `update_realm`. No cross-realm data
    /// migration is required; enforcement happens at login time.
    RealmSettingsChanged {
        /// Name of the realm whose settings changed.
        realm: String,
    },
    /// A new organization slug appeared in a realm's YAML block.
    OrgAdded {
        /// Realm name (YAML key).
        realm: String,
        /// Organization slug (YAML key).
        slug: String,
    },
    /// An organization slug was removed from a realm's YAML block.
    OrgRemoved {
        /// Realm name (YAML key).
        realm: String,
        /// Organization slug that is no longer declared.
        slug: String,
    },
    /// A new application key appeared in a realm's YAML block.
    ApplicationAdded {
        /// Realm name (YAML key).
        realm: String,
        /// Application YAML key.
        key: String,
    },
    /// An application key was removed from a realm's YAML block.
    ApplicationRemoved {
        /// Realm name (YAML key).
        realm: String,
        /// Application YAML key that is no longer declared.
        key: String,
    },
    /// A new role name appeared in a realm's YAML block.
    RoleAdded {
        /// Realm name (YAML key).
        realm: String,
        /// Role name.
        name: String,
    },
    /// A role name was removed from a realm's YAML block.
    RoleRemoved {
        /// Realm name (YAML key).
        realm: String,
        /// Role name that is no longer declared.
        name: String,
    },
    /// A new group name appeared in a realm's YAML block.
    GroupAdded {
        /// Realm name (YAML key).
        realm: String,
        /// Group name.
        name: String,
    },
    /// A group name was removed from a realm's YAML block.
    GroupRemoved {
        /// Realm name (YAML key).
        realm: String,
        /// Group name that is no longer declared.
        name: String,
    },
    /// `rotate_signing_key: true` was newly set for a realm.
    ///
    /// Handled by generating a new Ed25519 key, storing the old key as a
    /// retiring key, and serving both in JWKS for the configured grace period.
    /// The flag is auto-cleared from the snapshot after the rotation is applied
    /// so that subsequent restarts with the flag still in YAML do not re-rotate.
    RealmSigningKeyRotationRequested {
        /// Realm name (YAML key).
        realm: String,
    },
}

/// Compare a previous [`ConfigSnapshot`] against the current [`Config`] and
/// return the list of data-layer-significant changes.
///
/// When there is no previous snapshot (first startup), pass
/// `&ConfigSnapshot::from_config(&Config::default())` to treat all realms as
/// newly added — the caller in `main.rs` should use
/// [`ConfigSnapshot::from_config`] only on the *old* snapshot when loading
/// from storage; for first-run it passes an empty baseline.
///
/// Returns an empty `Vec` when the config is identical to the snapshot
/// (idempotent — no diff means no action needed).
#[must_use]
pub fn compute_diff(old: &ConfigSnapshot, new: &Config) -> Vec<ConfigDiff> {
    let new_snap = ConfigSnapshot::from_config(new);
    let mut diffs = Vec::new();

    // Realm membership changes.
    match (&old.realms, &new_snap.realms) {
        (Some(prev), Some(curr)) => {
            for name in curr.keys() {
                if !prev.contains_key(name) {
                    diffs.push(ConfigDiff::RealmAdded(name.clone()));
                }
            }
            for name in prev.keys() {
                if !curr.contains_key(name) {
                    diffs.push(ConfigDiff::RealmRemoved(name.clone()));
                }
            }
        }
        (None, Some(curr)) => {
            // Transitioned from implicit-mode to declarative mode.
            for name in curr.keys() {
                diffs.push(ConfigDiff::RealmAdded(name.clone()));
            }
        }
        (Some(prev), None) => {
            // Transitioned from declarative mode back to implicit (unusual).
            for name in prev.keys() {
                diffs.push(ConfigDiff::RealmRemoved(name.clone()));
            }
        }
        (None, None) => {}
    }

    // Email transport.
    if old.email_transport != new_snap.email_transport {
        diffs.push(ConfigDiff::EmailTransportChanged {
            old: old.email_transport.clone(),
            new: new_snap.email_transport.clone(),
        });
    }

    // SMTP password rotation (only meaningful when transport stays SMTP).
    if old.email_transport == "smtp"
        && new_snap.email_transport == "smtp"
        && old.smtp_password_fingerprint != new_snap.smtp_password_fingerprint
    {
        diffs.push(ConfigDiff::SmtpPasswordRotated);
    }

    // Token issuer.
    if old.token.issuer != new_snap.token.issuer {
        diffs.push(ConfigDiff::TokenIssuerChanged {
            old: old.token.issuer.clone(),
            new: new_snap.token.issuer.clone(),
        });
    }

    // Token audience.
    if old.token.audience != new_snap.token.audience {
        diffs.push(ConfigDiff::TokenAudienceChanged {
            old: old.token.audience.clone(),
            new: new_snap.token.audience.clone(),
        });
    }

    // OIDC issuer.
    if old.oidc_issuer != new_snap.oidc_issuer {
        diffs.push(ConfigDiff::OidcIssuerChanged {
            old: old.oidc_issuer.clone(),
            new: new_snap.oidc_issuer.clone(),
        });
    }

    // Storage data dir — almost certainly operator error, but we track it.
    if old.storage_data_dir != new_snap.storage_data_dir
        && !old.storage_data_dir.is_empty()
        && !new_snap.storage_data_dir.is_empty()
    {
        diffs.push(ConfigDiff::StorageDataDirChanged {
            old: old.storage_data_dir.clone(),
            new: new_snap.storage_data_dir.clone(),
        });
    }

    // Within-realm changes: only for realms present in BOTH snapshots.
    // Added/removed realms are already covered by RealmAdded/RealmRemoved above.
    if let (Some(old_realms), Some(new_realms)) = (&old.realms, &new_snap.realms) {
        for (realm_name, new_rs) in new_realms {
            let Some(old_rs) = old_realms.get(realm_name) else {
                continue;
            };

            // Settings fingerprint changed?
            if old_rs.settings_hash != new_rs.settings_hash {
                diffs.push(ConfigDiff::RealmSettingsChanged {
                    realm: realm_name.clone(),
                });
            }

            // Organization slug changes.
            for slug in new_rs.org_slugs.difference(&old_rs.org_slugs) {
                diffs.push(ConfigDiff::OrgAdded {
                    realm: realm_name.clone(),
                    slug: slug.clone(),
                });
            }
            for slug in old_rs.org_slugs.difference(&new_rs.org_slugs) {
                diffs.push(ConfigDiff::OrgRemoved {
                    realm: realm_name.clone(),
                    slug: slug.clone(),
                });
            }

            // Application key changes.
            for key in new_rs.app_keys.difference(&old_rs.app_keys) {
                diffs.push(ConfigDiff::ApplicationAdded {
                    realm: realm_name.clone(),
                    key: key.clone(),
                });
            }
            for key in old_rs.app_keys.difference(&new_rs.app_keys) {
                diffs.push(ConfigDiff::ApplicationRemoved {
                    realm: realm_name.clone(),
                    key: key.clone(),
                });
            }

            // Role name changes.
            for name in new_rs.role_names.difference(&old_rs.role_names) {
                diffs.push(ConfigDiff::RoleAdded {
                    realm: realm_name.clone(),
                    name: name.clone(),
                });
            }
            for name in old_rs.role_names.difference(&new_rs.role_names) {
                diffs.push(ConfigDiff::RoleRemoved {
                    realm: realm_name.clone(),
                    name: name.clone(),
                });
            }

            // Group name changes.
            for name in new_rs.group_names.difference(&old_rs.group_names) {
                diffs.push(ConfigDiff::GroupAdded {
                    realm: realm_name.clone(),
                    name: name.clone(),
                });
            }
            for name in old_rs.group_names.difference(&new_rs.group_names) {
                diffs.push(ConfigDiff::GroupRemoved {
                    realm: realm_name.clone(),
                    name: name.clone(),
                });
            }

            // Signing key rotation trigger: emit only when the flag transitions
            // false → true. Once handled, the caller clears it in the saved
            // snapshot so a second restart with the flag still in YAML is a no-op.
            if !old_rs.rotate_signing_key && new_rs.rotate_signing_key {
                diffs.push(ConfigDiff::RealmSigningKeyRotationRequested {
                    realm: realm_name.clone(),
                });
            }
        }
    }

    diffs
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn base_config() -> Config {
        let mut c = Config::default();
        c.oidc.issuer = Some("https://auth.example.com".to_string());
        c.token.issuer = Some("https://auth.example.com".to_string());
        c.token.audience = Some("myapp".to_string());
        c.storage.data_dir = "/data/hearth".to_string();
        c
    }

    #[test]
    fn snapshot_round_trip() {
        let config = base_config();
        let snap = ConfigSnapshot::from_config(&config);
        let json = snap.to_canonical_json().expect("serialise");
        let restored = ConfigSnapshot::from_json(&json).expect("deserialise");
        assert_eq!(snap, restored);
    }

    #[test]
    fn empty_diff_when_config_unchanged() {
        let config = base_config();
        let snap = ConfigSnapshot::from_config(&config);
        let diffs = compute_diff(&snap, &config);
        assert!(diffs.is_empty(), "expected no diffs, got: {diffs:?}");
    }

    #[test]
    fn diff_detects_realm_added() {
        let config = base_config();
        let old_snap = ConfigSnapshot::from_config(&config);

        let mut new_config = base_config();
        let mut realms = std::collections::HashMap::new();
        realms.insert(
            "production".to_string(),
            crate::config::RealmYamlConfig::default(),
        );
        new_config.realms = Some(realms);

        let diffs = compute_diff(&old_snap, &new_config);
        assert_eq!(diffs.len(), 1);
        assert!(matches!(&diffs[0], ConfigDiff::RealmAdded(n) if n == "production"));
    }

    #[test]
    fn diff_detects_realm_removed() {
        let mut old_config = base_config();
        let mut realms = std::collections::HashMap::new();
        realms.insert(
            "staging".to_string(),
            crate::config::RealmYamlConfig::default(),
        );
        old_config.realms = Some(realms);
        let old_snap = ConfigSnapshot::from_config(&old_config);

        let new_config = base_config(); // no realms map
        let diffs = compute_diff(&old_snap, &new_config);
        assert_eq!(diffs.len(), 1);
        assert!(matches!(&diffs[0], ConfigDiff::RealmRemoved(n) if n == "staging"));
    }

    #[test]
    fn diff_detects_oidc_issuer_change() {
        let config = base_config();
        let old_snap = ConfigSnapshot::from_config(&config);

        let mut new_config = base_config();
        new_config.oidc.issuer = Some("https://new-auth.example.com".to_string());

        let diffs = compute_diff(&old_snap, &new_config);
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, ConfigDiff::OidcIssuerChanged { .. })),
            "expected OidcIssuerChanged, got: {diffs:?}"
        );
    }

    #[test]
    fn diff_detects_token_issuer_change() {
        let config = base_config();
        let old_snap = ConfigSnapshot::from_config(&config);

        let mut new_config = base_config();
        new_config.token.issuer = Some("https://tokens.example.com".to_string());

        let diffs = compute_diff(&old_snap, &new_config);
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, ConfigDiff::TokenIssuerChanged { .. })),
            "expected TokenIssuerChanged, got: {diffs:?}"
        );
    }

    #[test]
    fn diff_detects_email_transport_change() {
        let config = base_config();
        let old_snap = ConfigSnapshot::from_config(&config);

        let mut new_config = base_config();
        new_config.email.transport = EmailTransport::Smtp;

        let diffs = compute_diff(&old_snap, &new_config);
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, ConfigDiff::EmailTransportChanged { .. })),
            "expected EmailTransportChanged, got: {diffs:?}"
        );
    }

    #[test]
    fn secret_fingerprint_stable_and_truncated() {
        let fp = SecretFingerprint::of("supersecret");
        assert_eq!(fp.hash.len(), 16, "fingerprint must be 16 hex chars");
        assert_eq!(
            fp,
            SecretFingerprint::of("supersecret"),
            "stable across calls"
        );
    }

    #[test]
    fn secret_fingerprint_differs_for_different_values() {
        let fp1 = SecretFingerprint::of("password1");
        let fp2 = SecretFingerprint::of("password2");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn rfc3339_formatter_smoke() {
        // Unix epoch should format as 1970-01-01T00:00:00Z
        let s = format_unix_secs_as_rfc3339(0);
        assert_eq!(s, "1970-01-01T00:00:00Z");

        // 2024-01-15T12:34:56Z = 1_705_322_096 seconds
        // Verification: 19737 days * 86400 + 45296 (12h34m56s) = 1_705_322_096
        let s = format_unix_secs_as_rfc3339(1_705_322_096);
        assert_eq!(s, "2024-01-15T12:34:56Z");
    }

    #[test]
    fn snapshot_version_is_one() {
        let snap = ConfigSnapshot::from_config(&base_config());
        assert_eq!(snap.version, 1);
    }

    #[test]
    fn snapshot_data_dir_matches_config() {
        let config = base_config();
        let snap = ConfigSnapshot::from_config(&config);
        assert_eq!(snap.storage_data_dir, "/data/hearth");
    }
}
