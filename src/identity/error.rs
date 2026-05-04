//! Identity engine error types.

use std::fmt;

/// Errors originating from the identity engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
    /// The requested realm was not found.
    RealmNotFound,
    /// The realm is suspended; operations are denied.
    RealmSuspended,
    /// A realm with the given name already exists.
    DuplicateRealmName,
    /// The requested user was not found.
    UserNotFound,
    /// A user with the given email already exists in this realm.
    DuplicateEmail,
    /// The input failed validation.
    InvalidInput {
        /// Description of what was invalid.
        reason: String,
    },
    /// No credential found for this user.
    CredentialNotFound,
    /// The provided credential was invalid (e.g., wrong password).
    InvalidCredential {
        /// Description of why the credential was invalid.
        reason: String,
    },
    /// The requested session was not found, expired, or revoked.
    ///
    /// Intentionally conflates not-found, expired, and revoked for
    /// enumeration resistance — callers cannot distinguish the three.
    SessionNotFound,
    /// The token is invalid (malformed, bad signature, unsupported algorithm).
    ///
    /// Intentionally vague to prevent information leakage about why
    /// validation failed.
    InvalidToken,
    /// The token has expired.
    TokenExpired,
    /// A cryptographic signing or key generation error.
    SigningError {
        /// Description of the signing failure (no secrets).
        reason: String,
    },
    /// The OAuth client was not found or is invalid.
    InvalidClient,
    /// The redirect URI does not match any registered URI for the client.
    InvalidRedirectUri,
    /// The authorization code is not found, expired, already used, or invalid.
    InvalidAuthorizationCode,
    /// A generic OAuth error for code exchange failures (e.g., PKCE mismatch).
    InvalidGrant {
        /// Description of why the grant was invalid.
        reason: String,
    },
    /// The client secret is invalid.
    ///
    /// Intentionally vague — does not distinguish wrong vs. expired
    /// for enumeration resistance.
    InvalidClientSecret,
    /// The device authorization is still pending user action.
    AuthorizationPending,
    /// The device is polling too frequently; must slow down.
    SlowDown,
    /// The device authorization code has expired.
    DeviceCodeExpired,
    /// The device authorization was denied by the user.
    DeviceCodeDenied,
    /// The token has been revoked (grant family revoked).
    TokenRevoked,
    /// The requested grant type is not supported for this client.
    UnsupportedGrantType,
    /// Password authentication succeeded but MFA verification is required.
    MfaRequired,
    /// The TOTP code or recovery code is invalid.
    InvalidMfaCode,
    /// MFA is not enabled for this user.
    MfaNotEnabled,
    /// MFA is already enabled; disable it before re-enrolling.
    MfaAlreadyEnabled,
    /// A `WebAuthn` registration ceremony failed.
    WebAuthnRegistrationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// A `WebAuthn` authentication ceremony failed.
    WebAuthnAuthenticationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// The requested `WebAuthn` credential was not found.
    WebAuthnCredentialNotFound,
    /// The attestation provided during registration is invalid or unsupported.
    InvalidAttestation {
        /// Description of the attestation failure.
        reason: String,
    },
    /// The assertion provided during authentication is invalid.
    InvalidAssertion {
        /// Description of the assertion failure.
        reason: String,
    },
    /// The caller is not authorized to perform this operation.
    ///
    /// Used for admin API access control. Intentionally vague to
    /// prevent information leakage about what resources exist.
    Unauthorized,
    /// The requested OAuth client was not found.
    ClientNotFound,
    /// The magic link token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    MagicLinkTokenInvalid,
    /// The email-verification token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    VerificationTokenInvalid,
    /// The password-reset token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    PasswordResetTokenInvalid,
    /// The user account has not yet verified their email address.
    ///
    /// Returned by `create_session` when a user in `PendingVerification`
    /// status attempts to log in. Callers should direct the user to the
    /// email-verification flow.
    UserNotVerified,
    /// Too many failed credential attempts; the account is temporarily locked.
    ///
    /// Intentionally vague to avoid leaking lockout state to attackers.
    RateLimited,
    /// The requested organization was not found.
    OrganizationNotFound,
    /// An organization with the given slug already exists in this realm.
    DuplicateOrgSlug,
    /// The organization is suspended; operations are denied.
    OrganizationSuspended,
    /// The user is already a member of this organization.
    AlreadyMember,
    /// The user is not a member of this organization.
    NotAMember,
    /// Cannot remove the last owner of an organization.
    LastOwner,
    /// The organization has reached its maximum member count.
    MemberLimitReached,
    /// The invitation is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    InvitationInvalid,
    /// An invitation for this email already exists for this organization.
    DuplicateInvitation,
    /// An operation targeted the reserved system realm, which only
    /// accepts writes from Hearth itself. The admin realm is not a
    /// place for application users, OAuth clients, organizations, or
    /// operator-created realms.
    SystemRealmProtected {
        /// The operation that was attempted (e.g. `"create_realm"`).
        /// Static strings to keep the error cheap and greppable.
        operation: &'static str,
    },
    /// Self-service registration is disabled for this realm.
    RegistrationDisabled,
    /// Self-service registration is enabled but the email's domain is not
    /// in the realm's allow-list.
    RegistrationDomainNotAllowed {
        /// The domain that was rejected.
        domain: String,
    },
    /// Self-service registration is enabled in invite-only mode and the
    /// caller did not present a valid invitation token.
    RegistrationRequiresInvitation,
    /// The OAuth client requires user consent and no sufficient consent
    /// record exists. Returned by `authorize_with_consent` when the caller
    /// must route the user through the consent prompt, or by the OIDC
    /// `prompt=none` branch when silent issuance cannot proceed without
    /// interaction.
    ConsentRequired,
    /// The pending-authorization ticket was not found. The ticket may
    /// have been consumed already, may belong to a different user, or
    /// may never have existed.
    ConsentTicketNotFound,
    /// The pending-authorization ticket has expired. The user must restart
    /// the authorization flow from the client.
    ConsentTicketExpired,
    /// The user attempted to approve a scope that was not present in the
    /// original authorization request. Prevents clients from widening the
    /// granted scope set through tampered form submissions.
    ConsentScopeNotRequested,
    /// No consent record exists for the requested `(user, client)` pair.
    ConsentNotFound,
    /// The referenced external IdP connector is not registered in this
    /// realm. Returned by `/ui/federation/begin` when `idp=...` names
    /// a connector that never existed or has been deleted.
    FederationUnknownConnector,
    /// The federation `state` parameter returned by the upstream IdP
    /// does not correspond to any known in-flight login. Intentionally
    /// conflates not-found, expired, and single-use-consumed for
    /// enumeration resistance and replay protection.
    FederationInvalidState,
    /// The upstream Identity Provider returned an error or unexpected
    /// response during token exchange, userinfo fetch, or JWKS lookup.
    /// Message is sanitized — never contains client secrets or raw
    /// upstream bodies.
    FederationUpstreamError {
        /// Connector the error originated from (e.g. `"google"`,
        /// `"github"`, `"oidc"`). Never contains PII.
        provider: String,
        /// Sanitized human-readable description. Safe to surface to end
        /// users and logs.
        reason: String,
    },
    /// Verification of an upstream ID token failed (bad issuer,
    /// audience, signature, nonce, or lifetime). Intentionally vague
    /// to avoid leaking which check failed to a tampering client.
    FederationTokenVerificationFailed,
    /// The upstream IdP returned `email_verified: false` for an
    /// operation that requires verified email (e.g., auto-linking to an
    /// existing user under `link_existing_accounts: auto`). The flow
    /// falls through to JIT provisioning rather than silently linking.
    FederationEmailNotVerified,
    /// The external login landed on an existing local user under
    /// `link_existing_accounts: confirm`. The caller MUST redirect the
    /// browser to `/ui/federation/confirm-link?ticket={ticket}` so the
    /// user can authenticate locally before the link is persisted.
    FederationLinkConfirmationRequired {
        /// Opaque single-use ticket bound to the target user and the
        /// pending external identity. 10-minute TTL.
        ticket: String,
    },
    /// The user has no linked external identity for this connector;
    /// returned from `unlink_external_identity` on a miss and from
    /// `find_user_by_external_identity` wrappers that require a hit.
    FederationNotLinked,
    /// The external identity is already linked — either to this user
    /// (duplicate `link`) or to a different user in the realm
    /// (conflict). Hearth refuses to re-home a link without an explicit
    /// unlink from the current owner.
    FederationAlreadyLinked,
    /// SAML XML parsing failed. Generic by design — never leaks parser
    /// internals (XXE vectors, entity expansion attempts) to the caller.
    SamlParse {
        /// Short sanitized description. Safe to log and return.
        reason: String,
    },
    /// SAML XML-DSIG signature verification failed. Covers:
    /// missing `<Signature>`, invalid digest, invalid signature value,
    /// wrong signing cert, signature-wrapping attack. Intentionally
    /// conflated — the caller MUST NOT learn which check failed.
    SamlSignature,
    /// A SAML assertion's `NotBefore`/`NotOnOrAfter` bounds place it
    /// outside the clock-skew tolerance window.
    SamlExpired,
    /// A SAML assertion with this ID has already been consumed for this
    /// IdP. Replay attack (or a confused client retrying a consumed
    /// assertion). Rejected.
    SamlReplay,
    /// A SAML assertion's `AudienceRestriction` list does not include
    /// this SP's entity ID.
    SamlAudienceMismatch,
    /// A SAML `<Response>` or `<LogoutRequest>` names an issuer that does
    /// not match the expected IdP / SP entity ID.
    SamlIssuerMismatch,
    /// A SAML `<Response>` names a `Destination` that does not match this
    /// SP's ACS URL. Defense against cookie-less CSRF.
    SamlDestinationMismatch,
    /// A SAML XML-DSIG element uses an algorithm not supported by Hearth
    /// (SHA-1 digests, RSA-SHA1 signatures, inclusive C14N). Algorithm
    /// downgrade is rejected by design.
    SamlUnsupportedAlgorithm,
    /// Fetching SAML IdP metadata from the configured URL failed.
    SamlMetadataFetch {
        /// Sanitized reason — never contains full URL or upstream body.
        reason: String,
    },
    /// A SAML `<AuthnRequest>` referenced an SP entity ID that is not
    /// registered for this realm.
    SamlUnknownSp,
    /// A SAML callback referenced an IdP that is not registered for
    /// this realm.
    SamlUnknownIdp,
    /// A SAML `<AuthnRequest>` failed validation (malformed, bad signature
    /// when required, missing required attributes).
    SamlInvalidAuthnRequest {
        /// Short sanitized description.
        reason: String,
    },
    /// The supplied SCIM `externalId` is already associated with a
    /// different user (or organization) in this realm.
    DuplicateScimExternalId,
    /// YAML-authored realm configuration failed registry validation.
    ///
    /// Emitted at startup or SIGHUP reload when `to_realm_config` detects
    /// invalid permission names, malformed scope bundle names, undeclared
    /// permission references, role parent cycles, or Tier 1 claim targets.
    /// All violations are collected and returned together so operators can
    /// fix them in a single pass.
    ConfigInvalid {
        /// Name of the realm whose config failed validation.
        realm_name: String,
        /// Every validation error found in the registry.
        errors: Vec<crate::rbac::RegistryError>,
    },
    /// An error from the underlying storage layer.
    Storage(Box<dyn std::error::Error + Send + Sync>),
    /// Serialization or deserialization failed.
    Serialization {
        /// Description of the serialization failure.
        reason: String,
    },
    /// An internal engine-layer failure that does not map to any more
    /// specific variant. Used e.g. when RBAC resolution reports an
    /// unexpected error during token issuance.
    Internal {
        /// Sanitized description of what went wrong.
        reason: String,
    },
    /// Token issuance aborted because the resolved claim set exceeds a
    /// configured size bound from `AUTHORIZATION.md § 2.6`.
    TokenTooLarge {
        /// Name of the specific limit that was exceeded.
        limit: String,
        /// Configured maximum for this limit.
        limit_value: usize,
        /// The size actually produced at resolve time.
        actual: usize,
    },
    /// A user attribute key or value failed validation.
    ///
    /// Covers: empty key, key exceeds 64 chars, key contains invalid
    /// characters, value exceeds 1 KiB, or total map exceeds 16 KiB.
    InvalidAttribute {
        /// Description of what was invalid.
        reason: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RealmNotFound => write!(f, "realm not found"),
            Self::RealmSuspended => write!(f, "realm is suspended"),
            Self::DuplicateRealmName => write!(f, "a realm with this name already exists"),
            Self::UserNotFound => write!(f, "user not found"),
            Self::DuplicateEmail => write!(f, "a user with this email already exists"),
            Self::InvalidInput { reason } => write!(f, "invalid input: {reason}"),
            Self::CredentialNotFound => write!(f, "no credential found for this user"),
            Self::InvalidCredential { reason } => {
                write!(f, "invalid credential: {reason}")
            }
            Self::SessionNotFound => write!(f, "session not found"),
            Self::InvalidToken => write!(f, "invalid token"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::SigningError { reason } => write!(f, "signing error: {reason}"),
            Self::InvalidClient => write!(f, "invalid client"),
            Self::InvalidRedirectUri => write!(f, "invalid redirect URI"),
            Self::InvalidAuthorizationCode => write!(f, "invalid authorization code"),
            Self::InvalidGrant { reason } => write!(f, "invalid grant: {reason}"),
            Self::InvalidClientSecret => write!(f, "invalid client secret"),
            Self::AuthorizationPending => write!(f, "authorization pending"),
            Self::SlowDown => write!(f, "polling too frequently"),
            Self::DeviceCodeExpired => write!(f, "device code expired"),
            Self::DeviceCodeDenied => write!(f, "device authorization denied"),
            Self::TokenRevoked => write!(f, "token has been revoked"),
            Self::UnsupportedGrantType => write!(f, "unsupported grant type"),
            Self::MfaRequired => write!(f, "MFA verification required"),
            Self::InvalidMfaCode => write!(f, "invalid MFA code"),
            Self::MfaNotEnabled => write!(f, "MFA is not enabled for this user"),
            Self::MfaAlreadyEnabled => write!(f, "MFA is already enabled"),
            Self::WebAuthnRegistrationFailed { reason } => {
                write!(f, "WebAuthn registration failed: {reason}")
            }
            Self::WebAuthnAuthenticationFailed { reason } => {
                write!(f, "WebAuthn authentication failed: {reason}")
            }
            Self::WebAuthnCredentialNotFound => write!(f, "WebAuthn credential not found"),
            Self::InvalidAttestation { reason } => {
                write!(f, "invalid attestation: {reason}")
            }
            Self::InvalidAssertion { reason } => {
                write!(f, "invalid assertion: {reason}")
            }
            Self::Unauthorized => write!(f, "forbidden"),
            Self::ClientNotFound => write!(f, "client not found"),
            Self::MagicLinkTokenInvalid => write!(f, "invalid or expired magic link"),
            Self::VerificationTokenInvalid => write!(f, "invalid or expired verification link"),
            Self::PasswordResetTokenInvalid => {
                write!(f, "invalid or expired password reset link")
            }
            Self::UserNotVerified => write!(f, "user email not verified"),
            Self::RateLimited => write!(f, "too many failed attempts"),
            Self::OrganizationNotFound => write!(f, "organization not found"),
            Self::DuplicateOrgSlug => {
                write!(f, "an organization with this slug already exists")
            }
            Self::OrganizationSuspended => write!(f, "organization is suspended"),
            Self::AlreadyMember => write!(f, "user is already a member of this organization"),
            Self::NotAMember => write!(f, "user is not a member of this organization"),
            Self::LastOwner => write!(f, "cannot remove the last owner of an organization"),
            Self::MemberLimitReached => write!(f, "organization member limit reached"),
            Self::InvitationInvalid => write!(f, "invalid or expired invitation"),
            Self::DuplicateInvitation => {
                write!(f, "an invitation for this email already exists")
            }
            Self::SystemRealmProtected { operation } => write!(
                f,
                "operation not permitted on the system realm: {operation}"
            ),
            Self::RegistrationDisabled => write!(f, "self-service registration is disabled"),
            Self::RegistrationDomainNotAllowed { domain } => write!(
                f,
                "email domain is not permitted for self-service registration: {domain}"
            ),
            Self::RegistrationRequiresInvitation => {
                write!(f, "self-service registration requires a valid invitation")
            }
            Self::ConsentRequired => write!(f, "user consent is required"),
            Self::ConsentTicketNotFound => write!(f, "consent ticket not found"),
            Self::ConsentTicketExpired => write!(f, "consent ticket expired"),
            Self::ConsentScopeNotRequested => {
                write!(f, "approved scope was not in the original request")
            }
            Self::ConsentNotFound => write!(f, "no consent record for this client"),
            Self::FederationUnknownConnector => write!(f, "unknown federation connector"),
            Self::FederationInvalidState => write!(f, "invalid federation state"),
            Self::FederationUpstreamError { provider, reason } => {
                write!(f, "federation upstream error ({provider}): {reason}")
            }
            Self::FederationTokenVerificationFailed => {
                write!(f, "federation token verification failed")
            }
            Self::FederationEmailNotVerified => {
                write!(f, "upstream email is not verified")
            }
            Self::FederationLinkConfirmationRequired { .. } => {
                write!(f, "federation login requires confirm-to-link")
            }
            Self::FederationNotLinked => write!(f, "external identity is not linked"),
            Self::FederationAlreadyLinked => write!(f, "external identity is already linked"),
            Self::DuplicateScimExternalId => {
                write!(f, "SCIM externalId is already associated with another user")
            }
            Self::SamlParse { reason } => write!(f, "SAML parse error: {reason}"),
            Self::SamlSignature => write!(f, "SAML signature verification failed"),
            Self::SamlExpired => write!(f, "SAML assertion expired or not yet valid"),
            Self::SamlReplay => write!(f, "SAML assertion replay detected"),
            Self::SamlAudienceMismatch => write!(f, "SAML audience mismatch"),
            Self::SamlIssuerMismatch => write!(f, "SAML issuer mismatch"),
            Self::SamlDestinationMismatch => write!(f, "SAML destination mismatch"),
            Self::SamlUnsupportedAlgorithm => write!(f, "SAML unsupported algorithm"),
            Self::SamlMetadataFetch { reason } => {
                write!(f, "SAML metadata fetch failed: {reason}")
            }
            Self::SamlUnknownSp => write!(f, "unknown SAML service provider"),
            Self::SamlUnknownIdp => write!(f, "unknown SAML identity provider"),
            Self::SamlInvalidAuthnRequest { reason } => {
                write!(f, "invalid SAML AuthnRequest: {reason}")
            }
            Self::ConfigInvalid { realm_name, errors } => write!(
                f,
                "realm '{realm_name}' config is invalid ({} error(s)): {}",
                errors.len(),
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
            Self::Internal { reason } => write!(f, "internal error: {reason}"),
            Self::TokenTooLarge {
                limit,
                limit_value,
                actual,
            } => write!(
                f,
                "resolved claim set exceeds size limit {limit} ({actual} > {limit_value})"
            ),
            Self::InvalidAttribute { reason } => write!(f, "invalid attribute: {reason}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::RealmNotFound
            | Self::RealmSuspended
            | Self::DuplicateRealmName
            | Self::UserNotFound
            | Self::DuplicateEmail
            | Self::InvalidInput { .. }
            | Self::CredentialNotFound
            | Self::InvalidCredential { .. }
            | Self::SessionNotFound
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::SigningError { .. }
            | Self::InvalidClient
            | Self::InvalidRedirectUri
            | Self::InvalidAuthorizationCode
            | Self::InvalidGrant { .. }
            | Self::InvalidClientSecret
            | Self::AuthorizationPending
            | Self::SlowDown
            | Self::DeviceCodeExpired
            | Self::DeviceCodeDenied
            | Self::TokenRevoked
            | Self::UnsupportedGrantType
            | Self::MfaRequired
            | Self::InvalidMfaCode
            | Self::MfaNotEnabled
            | Self::MfaAlreadyEnabled
            | Self::WebAuthnRegistrationFailed { .. }
            | Self::WebAuthnAuthenticationFailed { .. }
            | Self::WebAuthnCredentialNotFound
            | Self::InvalidAttestation { .. }
            | Self::InvalidAssertion { .. }
            | Self::Unauthorized
            | Self::ClientNotFound
            | Self::MagicLinkTokenInvalid
            | Self::VerificationTokenInvalid
            | Self::PasswordResetTokenInvalid
            | Self::UserNotVerified
            | Self::RateLimited
            | Self::OrganizationNotFound
            | Self::DuplicateOrgSlug
            | Self::OrganizationSuspended
            | Self::AlreadyMember
            | Self::NotAMember
            | Self::LastOwner
            | Self::MemberLimitReached
            | Self::InvitationInvalid
            | Self::DuplicateInvitation
            | Self::RegistrationDisabled
            | Self::RegistrationDomainNotAllowed { .. }
            | Self::RegistrationRequiresInvitation
            | Self::ConsentRequired
            | Self::ConsentTicketNotFound
            | Self::ConsentTicketExpired
            | Self::ConsentScopeNotRequested
            | Self::ConsentNotFound
            | Self::FederationUnknownConnector
            | Self::FederationInvalidState
            | Self::FederationUpstreamError { .. }
            | Self::FederationTokenVerificationFailed
            | Self::FederationEmailNotVerified
            | Self::FederationLinkConfirmationRequired { .. }
            | Self::FederationNotLinked
            | Self::FederationAlreadyLinked
            | Self::SamlParse { .. }
            | Self::SamlSignature
            | Self::SamlExpired
            | Self::SamlReplay
            | Self::SamlAudienceMismatch
            | Self::SamlIssuerMismatch
            | Self::SamlDestinationMismatch
            | Self::SamlUnsupportedAlgorithm
            | Self::SamlMetadataFetch { .. }
            | Self::SamlUnknownSp
            | Self::SamlUnknownIdp
            | Self::SamlInvalidAuthnRequest { .. }
            | Self::SystemRealmProtected { .. }
            | Self::DuplicateScimExternalId
            | Self::ConfigInvalid { .. }
            | Self::Serialization { .. }
            | Self::Internal { .. }
            | Self::TokenTooLarge { .. }
            | Self::InvalidAttribute { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_realm_not_found() {
        let err = IdentityError::RealmNotFound;
        let display = format!("{err}");
        assert!(display.contains("realm not found"), "got: {display}");
    }

    #[test]
    fn display_realm_suspended() {
        let err = IdentityError::RealmSuspended;
        let display = format!("{err}");
        assert!(display.contains("suspended"), "got: {display}");
    }

    #[test]
    fn display_duplicate_realm_name() {
        let err = IdentityError::DuplicateRealmName;
        let display = format!("{err}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_user_not_found() {
        let err = IdentityError::UserNotFound;
        let display = format!("{err}");
        assert!(display.contains("user not found"), "got: {display}");
    }

    #[test]
    fn display_duplicate_email() {
        let err = IdentityError::DuplicateEmail;
        let display = format!("{err}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_invalid_input() {
        let err = IdentityError::InvalidInput {
            reason: "email missing @".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid input"), "got: {display}");
        assert!(display.contains("email missing @"), "got: {display}");
    }

    #[test]
    fn display_storage() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = IdentityError::Storage(Box::new(io_err));
        let display = format!("{err}");
        assert!(display.contains("storage error"), "got: {display}");
        assert!(display.contains("file missing"), "got: {display}");
    }

    #[test]
    fn display_serialization() {
        let err = IdentityError::Serialization {
            reason: "invalid JSON".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("serialization error"), "got: {display}");
        assert!(display.contains("invalid JSON"), "got: {display}");
    }

    #[test]
    fn implements_error_trait() {
        let err = IdentityError::UserNotFound;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn source_storage_has_inner() {
        let io_err = std::io::Error::other("disk full");
        let err = IdentityError::Storage(Box::new(io_err));
        assert!(err.source().is_some(), "Storage variant should have source");
    }

    #[test]
    fn display_credential_not_found() {
        let err = IdentityError::CredentialNotFound;
        let display = format!("{err}");
        assert!(display.contains("no credential found"), "got: {display}");
    }

    #[test]
    fn display_invalid_credential() {
        let err = IdentityError::InvalidCredential {
            reason: "wrong password".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid credential"), "got: {display}");
        assert!(display.contains("wrong password"), "got: {display}");
    }

    #[test]
    fn display_session_not_found() {
        let err = IdentityError::SessionNotFound;
        let display = format!("{err}");
        assert!(display.contains("session not found"), "got: {display}");
    }

    #[test]
    fn display_invalid_token() {
        let err = IdentityError::InvalidToken;
        let display = format!("{err}");
        assert!(display.contains("invalid token"), "got: {display}");
    }

    #[test]
    fn display_token_expired() {
        let err = IdentityError::TokenExpired;
        let display = format!("{err}");
        assert!(display.contains("token expired"), "got: {display}");
    }

    #[test]
    fn display_signing_error() {
        let err = IdentityError::SigningError {
            reason: "key generation failed".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("signing error"), "got: {display}");
        assert!(display.contains("key generation failed"), "got: {display}");
    }

    #[test]
    fn display_invalid_client() {
        let err = IdentityError::InvalidClient;
        let display = format!("{err}");
        assert!(display.contains("invalid client"), "got: {display}");
    }

    #[test]
    fn display_invalid_redirect_uri() {
        let err = IdentityError::InvalidRedirectUri;
        let display = format!("{err}");
        assert!(display.contains("invalid redirect URI"), "got: {display}");
    }

    #[test]
    fn display_invalid_authorization_code() {
        let err = IdentityError::InvalidAuthorizationCode;
        let display = format!("{err}");
        assert!(
            display.contains("invalid authorization code"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_grant() {
        let err = IdentityError::InvalidGrant {
            reason: "PKCE mismatch".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid grant"), "got: {display}");
        assert!(display.contains("PKCE mismatch"), "got: {display}");
    }

    #[test]
    fn display_invalid_client_secret() {
        let err = IdentityError::InvalidClientSecret;
        let display = format!("{err}");
        assert!(display.contains("invalid client secret"), "got: {display}");
    }

    #[test]
    fn display_authorization_pending() {
        let err = IdentityError::AuthorizationPending;
        let display = format!("{err}");
        assert!(display.contains("authorization pending"), "got: {display}");
    }

    #[test]
    fn display_slow_down() {
        let err = IdentityError::SlowDown;
        let display = format!("{err}");
        assert!(display.contains("polling too frequently"), "got: {display}");
    }

    #[test]
    fn display_device_code_expired() {
        let err = IdentityError::DeviceCodeExpired;
        let display = format!("{err}");
        assert!(display.contains("device code expired"), "got: {display}");
    }

    #[test]
    fn display_device_code_denied() {
        let err = IdentityError::DeviceCodeDenied;
        let display = format!("{err}");
        assert!(display.contains("denied"), "got: {display}");
    }

    #[test]
    fn display_token_revoked() {
        let err = IdentityError::TokenRevoked;
        let display = format!("{err}");
        assert!(display.contains("revoked"), "got: {display}");
    }

    #[test]
    fn display_unsupported_grant_type() {
        let err = IdentityError::UnsupportedGrantType;
        let display = format!("{err}");
        assert!(display.contains("unsupported grant type"), "got: {display}");
    }

    #[test]
    fn display_mfa_required() {
        let err = IdentityError::MfaRequired;
        let display = format!("{err}");
        assert!(
            display.contains("MFA verification required"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_mfa_code() {
        let err = IdentityError::InvalidMfaCode;
        let display = format!("{err}");
        assert!(display.contains("invalid MFA code"), "got: {display}");
    }

    #[test]
    fn display_mfa_not_enabled() {
        let err = IdentityError::MfaNotEnabled;
        let display = format!("{err}");
        assert!(display.contains("not enabled"), "got: {display}");
    }

    #[test]
    fn display_mfa_already_enabled() {
        let err = IdentityError::MfaAlreadyEnabled;
        let display = format!("{err}");
        assert!(display.contains("already enabled"), "got: {display}");
    }

    #[test]
    fn display_webauthn_registration_failed() {
        let err = IdentityError::WebAuthnRegistrationFailed {
            reason: "challenge mismatch".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn registration failed"),
            "got: {display}"
        );
        assert!(display.contains("challenge mismatch"), "got: {display}");
    }

    #[test]
    fn display_webauthn_authentication_failed() {
        let err = IdentityError::WebAuthnAuthenticationFailed {
            reason: "signature invalid".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn authentication failed"),
            "got: {display}"
        );
    }

    #[test]
    fn display_webauthn_credential_not_found() {
        let err = IdentityError::WebAuthnCredentialNotFound;
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn credential not found"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_attestation() {
        let err = IdentityError::InvalidAttestation {
            reason: "unsupported format".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid attestation"), "got: {display}");
    }

    #[test]
    fn display_invalid_assertion() {
        let err = IdentityError::InvalidAssertion {
            reason: "counter replay".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid assertion"), "got: {display}");
    }

    #[test]
    fn display_unauthorized() {
        let err = IdentityError::Unauthorized;
        let display = format!("{err}");
        assert!(display.contains("forbidden"), "got: {display}");
    }

    #[test]
    fn display_client_not_found() {
        let err = IdentityError::ClientNotFound;
        let display = format!("{err}");
        assert!(display.contains("client not found"), "got: {display}");
    }

    #[test]
    fn display_magic_link_token_invalid() {
        let err = IdentityError::MagicLinkTokenInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired magic link"),
            "got: {display}"
        );
    }

    #[test]
    fn display_verification_token_invalid() {
        let err = IdentityError::VerificationTokenInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired verification link"),
            "got: {display}"
        );
    }

    #[test]
    fn display_password_reset_token_invalid() {
        let err = IdentityError::PasswordResetTokenInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired password reset link"),
            "got: {display}"
        );
    }

    #[test]
    fn display_user_not_verified() {
        let err = IdentityError::UserNotVerified;
        let display = format!("{err}");
        assert!(display.contains("not verified"), "got: {display}");
    }

    #[test]
    fn display_organization_not_found() {
        let err = IdentityError::OrganizationNotFound;
        let display = format!("{err}");
        assert!(display.contains("organization not found"), "got: {display}");
    }

    #[test]
    fn display_duplicate_org_slug() {
        let err = IdentityError::DuplicateOrgSlug;
        let display = format!("{err}");
        assert!(display.contains("slug already exists"), "got: {display}");
    }

    #[test]
    fn display_organization_suspended() {
        let err = IdentityError::OrganizationSuspended;
        let display = format!("{err}");
        assert!(display.contains("suspended"), "got: {display}");
    }

    #[test]
    fn display_already_member() {
        let err = IdentityError::AlreadyMember;
        let display = format!("{err}");
        assert!(display.contains("already a member"), "got: {display}");
    }

    #[test]
    fn display_not_a_member() {
        let err = IdentityError::NotAMember;
        let display = format!("{err}");
        assert!(display.contains("not a member"), "got: {display}");
    }

    #[test]
    fn display_last_owner() {
        let err = IdentityError::LastOwner;
        let display = format!("{err}");
        assert!(display.contains("last owner"), "got: {display}");
    }

    #[test]
    fn display_member_limit_reached() {
        let err = IdentityError::MemberLimitReached;
        let display = format!("{err}");
        assert!(display.contains("member limit"), "got: {display}");
    }

    #[test]
    fn display_invitation_invalid() {
        let err = IdentityError::InvitationInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired invitation"),
            "got: {display}"
        );
    }

    #[test]
    fn display_duplicate_invitation() {
        let err = IdentityError::DuplicateInvitation;
        let display = format!("{err}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_consent_variants() {
        assert!(format!("{}", IdentityError::ConsentRequired).contains("consent is required"));
        assert!(format!("{}", IdentityError::ConsentTicketNotFound).contains("ticket not found"));
        assert!(format!("{}", IdentityError::ConsentTicketExpired).contains("expired"));
        assert!(format!("{}", IdentityError::ConsentScopeNotRequested)
            .contains("not in the original request"));
        assert!(format!("{}", IdentityError::ConsentNotFound).contains("no consent record"));
    }

    #[test]
    fn display_federation_variants() {
        assert!(format!("{}", IdentityError::FederationUnknownConnector)
            .contains("unknown federation connector"));
        assert!(format!("{}", IdentityError::FederationInvalidState)
            .contains("invalid federation state"));
        assert!(format!(
            "{}",
            IdentityError::FederationUpstreamError {
                provider: "google".to_string(),
                reason: "bad response".to_string(),
            }
        )
        .contains("google"));
        assert!(format!(
            "{}",
            IdentityError::FederationUpstreamError {
                provider: "google".to_string(),
                reason: "bad response".to_string(),
            }
        )
        .contains("bad response"));
        assert!(
            format!("{}", IdentityError::FederationTokenVerificationFailed)
                .contains("token verification failed")
        );
        assert!(format!("{}", IdentityError::FederationEmailNotVerified)
            .contains("email is not verified"));
        assert!(format!(
            "{}",
            IdentityError::FederationLinkConfirmationRequired {
                ticket: "abc".to_string()
            }
        )
        .contains("confirm-to-link"));
        assert!(format!("{}", IdentityError::FederationNotLinked)
            .contains("external identity is not linked"));
        assert!(format!("{}", IdentityError::FederationAlreadyLinked).contains("already linked"));
    }

    #[test]
    fn federation_errors_have_no_source() {
        assert!(IdentityError::FederationUnknownConnector.source().is_none());
        assert!(IdentityError::FederationInvalidState.source().is_none());
        assert!((IdentityError::FederationUpstreamError {
            provider: "x".to_string(),
            reason: "y".to_string(),
        })
        .source()
        .is_none());
        assert!(IdentityError::FederationTokenVerificationFailed
            .source()
            .is_none());
        assert!(IdentityError::FederationEmailNotVerified.source().is_none());
        assert!((IdentityError::FederationLinkConfirmationRequired {
            ticket: "t".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::FederationNotLinked.source().is_none());
        assert!(IdentityError::FederationAlreadyLinked.source().is_none());
    }

    #[test]
    fn federation_upstream_error_sanitizes_reason_field() {
        // Regression guard: `FederationUpstreamError.reason` is a free
        // string. Callers MUST NOT stuff raw HTTP bodies, client secrets,
        // or upstream stack traces into it. The test below just asserts
        // the Display format is stable; actual sanitization is enforced
        // at callsites (connector impls).
        let err = IdentityError::FederationUpstreamError {
            provider: "github".to_string(),
            reason: "upstream returned 500".to_string(),
        };
        let display = format!("{err}");
        assert!(display.starts_with("federation upstream error (github):"));
    }

    #[test]
    fn source_others_none() {
        assert!(IdentityError::RealmNotFound.source().is_none());
        assert!(IdentityError::RealmSuspended.source().is_none());
        assert!(IdentityError::DuplicateRealmName.source().is_none());
        assert!(IdentityError::UserNotFound.source().is_none());
        assert!(IdentityError::DuplicateEmail.source().is_none());
        assert!(IdentityError::CredentialNotFound.source().is_none());
        assert!(IdentityError::SessionNotFound.source().is_none());
        assert!(IdentityError::InvalidToken.source().is_none());
        assert!(IdentityError::TokenExpired.source().is_none());
        assert!(IdentityError::InvalidClient.source().is_none());
        assert!(IdentityError::InvalidRedirectUri.source().is_none());
        assert!(IdentityError::InvalidAuthorizationCode.source().is_none());
        assert!(IdentityError::InvalidClientSecret.source().is_none());
        assert!(IdentityError::AuthorizationPending.source().is_none());
        assert!(IdentityError::SlowDown.source().is_none());
        assert!(IdentityError::DeviceCodeExpired.source().is_none());
        assert!(IdentityError::DeviceCodeDenied.source().is_none());
        assert!(IdentityError::TokenRevoked.source().is_none());
        assert!(IdentityError::UnsupportedGrantType.source().is_none());
        assert!((IdentityError::InvalidInput {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidCredential {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::SigningError {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidGrant {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::MfaRequired.source().is_none());
        assert!(IdentityError::InvalidMfaCode.source().is_none());
        assert!(IdentityError::MfaNotEnabled.source().is_none());
        assert!(IdentityError::MfaAlreadyEnabled.source().is_none());
        assert!((IdentityError::WebAuthnRegistrationFailed {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::WebAuthnAuthenticationFailed {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::WebAuthnCredentialNotFound.source().is_none());
        assert!((IdentityError::InvalidAttestation {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidAssertion {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::Unauthorized.source().is_none());
        assert!(IdentityError::ClientNotFound.source().is_none());
        assert!(IdentityError::MagicLinkTokenInvalid.source().is_none());
        assert!(IdentityError::VerificationTokenInvalid.source().is_none());
        assert!(IdentityError::PasswordResetTokenInvalid.source().is_none());
        assert!(IdentityError::UserNotVerified.source().is_none());
        assert!(IdentityError::RateLimited.source().is_none());
        assert!(IdentityError::OrganizationNotFound.source().is_none());
        assert!(IdentityError::DuplicateOrgSlug.source().is_none());
        assert!(IdentityError::OrganizationSuspended.source().is_none());
        assert!(IdentityError::AlreadyMember.source().is_none());
        assert!(IdentityError::NotAMember.source().is_none());
        assert!(IdentityError::LastOwner.source().is_none());
        assert!(IdentityError::MemberLimitReached.source().is_none());
        assert!(IdentityError::InvitationInvalid.source().is_none());
        assert!(IdentityError::DuplicateInvitation.source().is_none());
        assert!((IdentityError::Serialization {
            reason: "x".to_string()
        })
        .source()
        .is_none());
    }
}
