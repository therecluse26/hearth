//! Stable machine-readable error codes for REST API responses.
//!
//! Each constant maps to a specific client-visible error condition. Codes are
//! additive — new codes can be added without breaking existing clients. 5xx
//! (server-side) errors intentionally produce `None` to avoid leaking internals.
//!
//! # Wire format
//! ```json
//! { "error": "token expired", "error_code": "HEARTH_TOKEN_EXPIRED" }
//! { "error": "internal error", "error_code": null }
//! ```

// ── Token errors ──────────────────────────────────────────────────────────────

/// JWT or session token has expired.
pub const TOKEN_EXPIRED: &str = "HEARTH_TOKEN_EXPIRED";
/// Token has been explicitly revoked.
pub const TOKEN_REVOKED: &str = "HEARTH_TOKEN_REVOKED";
/// Malformed token or bad signature.
pub const TOKEN_INVALID: &str = "HEARTH_TOKEN_INVALID";
/// Resolved claim set exceeds a configured size bound.
pub const TOKEN_TOO_LARGE: &str = "HEARTH_TOKEN_TOO_LARGE";

// ── Authentication / credential errors ───────────────────────────────────────

/// The presented credential (password, secret) is wrong.
pub const INVALID_CREDENTIAL: &str = "HEARTH_INVALID_CREDENTIAL";
/// The OAuth client is not recognized or misconfigured.
pub const INVALID_CLIENT: &str = "HEARTH_INVALID_CLIENT";
/// The authorization grant (auth code or device code) is invalid, expired, or consumed.
pub const INVALID_GRANT: &str = "HEARTH_INVALID_GRANT";
/// The redirect URI does not match any registered URI.
pub const INVALID_REDIRECT_URI: &str = "HEARTH_INVALID_REDIRECT_URI";
/// The requested grant type is not supported for this client.
pub const UNSUPPORTED_GRANT_TYPE: &str = "HEARTH_UNSUPPORTED_GRANT_TYPE";

// ── MFA ───────────────────────────────────────────────────────────────────────

/// Authentication requires an MFA step before a session can be issued.
pub const MFA_REQUIRED: &str = "HEARTH_MFA_REQUIRED";
/// The TOTP or recovery code presented is incorrect.
pub const MFA_INVALID_CODE: &str = "HEARTH_MFA_INVALID_CODE";
/// MFA is not enrolled for this user.
pub const MFA_NOT_ENABLED: &str = "HEARTH_MFA_NOT_ENABLED";
/// MFA is already enrolled; disable before re-enrolling.
pub const MFA_ALREADY_ENABLED: &str = "HEARTH_MFA_ALREADY_ENABLED";

// ── WebAuthn / Passkeys ───────────────────────────────────────────────────────

/// WebAuthn registration ceremony failed.
pub const WEBAUTHN_REGISTRATION_FAILED: &str = "HEARTH_WEBAUTHN_REGISTRATION_FAILED";
/// WebAuthn authentication ceremony failed.
pub const WEBAUTHN_AUTHENTICATION_FAILED: &str = "HEARTH_WEBAUTHN_AUTHENTICATION_FAILED";
/// The referenced WebAuthn credential does not exist.
pub const WEBAUTHN_CREDENTIAL_NOT_FOUND: &str = "HEARTH_WEBAUTHN_CREDENTIAL_NOT_FOUND";
/// Attestation provided during registration is invalid or unsupported.
pub const INVALID_ATTESTATION: &str = "HEARTH_INVALID_ATTESTATION";
/// Assertion provided during authentication is invalid.
pub const INVALID_ASSERTION: &str = "HEARTH_INVALID_ASSERTION";

// ── Device authorization flow ─────────────────────────────────────────────────

/// Device authorization is waiting for the user to approve via the browser.
pub const AUTHORIZATION_PENDING: &str = "HEARTH_AUTHORIZATION_PENDING";
/// Device is polling too frequently; must back off.
pub const SLOW_DOWN: &str = "HEARTH_SLOW_DOWN";
/// Device authorization code has expired.
pub const DEVICE_CODE_EXPIRED: &str = "HEARTH_DEVICE_CODE_EXPIRED";
/// Device authorization was denied by the user.
pub const DEVICE_CODE_DENIED: &str = "HEARTH_DEVICE_CODE_DENIED";

// ── Rate limiting / account lockout ───────────────────────────────────────────

/// Request rate limit exceeded or account temporarily locked after failed attempts.
pub const RATE_LIMITED: &str = "HEARTH_RATE_LIMITED";

// ── Account state ─────────────────────────────────────────────────────────────

/// Email address not yet verified.
pub const EMAIL_UNVERIFIED: &str = "HEARTH_EMAIL_UNVERIFIED";
/// Password has expired and must be reset before logging in.
pub const PASSWORD_EXPIRED: &str = "HEARTH_PASSWORD_EXPIRED";
/// New password matches a previously used password.
pub const PASSWORD_REUSED: &str = "HEARTH_PASSWORD_REUSED";
/// Authentication method is not permitted by realm policy.
pub const AUTH_METHOD_NOT_ALLOWED: &str = "HEARTH_AUTH_METHOD_NOT_ALLOWED";

// ── Resource not found ────────────────────────────────────────────────────────

/// Generic not-found (user, client, or resource does not exist).
pub const NOT_FOUND: &str = "HEARTH_NOT_FOUND";
/// Session not found, expired, or revoked.
pub const SESSION_NOT_FOUND: &str = "HEARTH_SESSION_NOT_FOUND";

// ── Realm ──────────────────────────────────────────────────────────────────────

/// The realm is suspended; operations are denied.
pub const REALM_SUSPENDED: &str = "HEARTH_REALM_SUSPENDED";

// ── Input validation ──────────────────────────────────────────────────────────

/// Request input failed validation.
pub const INVALID_INPUT: &str = "HEARTH_INVALID_INPUT";

// ── Conflict / duplicate ──────────────────────────────────────────────────────

/// A user with this email already exists.
pub const DUPLICATE_EMAIL: &str = "HEARTH_DUPLICATE_EMAIL";
/// A realm with this name already exists.
pub const DUPLICATE_REALM_NAME: &str = "HEARTH_DUPLICATE_REALM_NAME";

// ── Organizations ──────────────────────────────────────────────────────────────

/// Organization not found.
pub const ORG_NOT_FOUND: &str = "HEARTH_ORG_NOT_FOUND";
/// Organization is suspended.
pub const ORG_SUSPENDED: &str = "HEARTH_ORG_SUSPENDED";
/// User is already a member of this organization.
pub const ORG_ALREADY_MEMBER: &str = "HEARTH_ORG_ALREADY_MEMBER";
/// User is not a member of this organization.
pub const ORG_NOT_MEMBER: &str = "HEARTH_ORG_NOT_MEMBER";
/// Cannot remove the last owner of an organization.
pub const ORG_LAST_OWNER: &str = "HEARTH_ORG_LAST_OWNER";
/// Organization has reached its maximum member count.
pub const ORG_MEMBER_LIMIT: &str = "HEARTH_ORG_MEMBER_LIMIT";
/// An organization with this slug already exists.
pub const ORG_DUPLICATE_SLUG: &str = "HEARTH_ORG_DUPLICATE_SLUG";

// ── Invitations ────────────────────────────────────────────────────────────────

/// Invitation is invalid, expired, or already used.
pub const INVITATION_INVALID: &str = "HEARTH_INVITATION_INVALID";
/// An invitation for this email already exists.
pub const INVITATION_DUPLICATE: &str = "HEARTH_INVITATION_DUPLICATE";

// ── Self-service registration ──────────────────────────────────────────────────

/// Self-service registration is disabled for this realm.
pub const REGISTRATION_DISABLED: &str = "HEARTH_REGISTRATION_DISABLED";
/// Email domain is not on the realm's allow-list.
pub const REGISTRATION_DOMAIN_NOT_ALLOWED: &str = "HEARTH_REGISTRATION_DOMAIN_NOT_ALLOWED";
/// Registration requires a valid invitation token.
pub const REGISTRATION_REQUIRES_INVITATION: &str = "HEARTH_REGISTRATION_REQUIRES_INVITATION";

// ── Passwordless / magic-link ──────────────────────────────────────────────────

/// Magic link token is invalid, expired, or already used.
pub const MAGIC_LINK_INVALID: &str = "HEARTH_MAGIC_LINK_INVALID";
/// Email-verification token is invalid, expired, or already used.
pub const VERIFICATION_TOKEN_INVALID: &str = "HEARTH_VERIFICATION_TOKEN_INVALID";
/// Password-reset token is invalid, expired, or already used.
pub const PASSWORD_RESET_TOKEN_INVALID: &str = "HEARTH_PASSWORD_RESET_TOKEN_INVALID";

// ── Consent ────────────────────────────────────────────────────────────────────

/// User consent is required before issuing tokens.
pub const CONSENT_REQUIRED: &str = "HEARTH_CONSENT_REQUIRED";
/// Consent ticket is invalid or expired.
pub const CONSENT_TICKET_INVALID: &str = "HEARTH_CONSENT_TICKET_INVALID";
/// Approved scope was not in the original authorization request.
pub const CONSENT_SCOPE_NOT_REQUESTED: &str = "HEARTH_CONSENT_SCOPE_NOT_REQUESTED";
/// No consent record exists for this client.
pub const CONSENT_NOT_FOUND: &str = "HEARTH_CONSENT_NOT_FOUND";

// ── Federation ─────────────────────────────────────────────────────────────────

/// Named federation connector is not registered for this realm.
pub const FEDERATION_UNKNOWN_CONNECTOR: &str = "HEARTH_FEDERATION_UNKNOWN_CONNECTOR";
/// Federation state parameter is invalid or expired.
pub const FEDERATION_INVALID_STATE: &str = "HEARTH_FEDERATION_INVALID_STATE";
/// Upstream IdP returned an error during token exchange or userinfo fetch.
pub const FEDERATION_UPSTREAM_ERROR: &str = "HEARTH_FEDERATION_UPSTREAM_ERROR";
/// Upstream ID token failed signature or claims verification.
pub const FEDERATION_TOKEN_VERIFICATION_FAILED: &str =
    "HEARTH_FEDERATION_TOKEN_VERIFICATION_FAILED";
/// Upstream IdP returned `email_verified: false`.
pub const FEDERATION_EMAIL_NOT_VERIFIED: &str = "HEARTH_FEDERATION_EMAIL_NOT_VERIFIED";
/// Federation login requires the user to confirm linking an existing account.
pub const FEDERATION_LINK_CONFIRMATION_REQUIRED: &str =
    "HEARTH_FEDERATION_LINK_CONFIRMATION_REQUIRED";
/// User has no linked external identity for this connector.
pub const FEDERATION_NOT_LINKED: &str = "HEARTH_FEDERATION_NOT_LINKED";
/// External identity is already linked (to this or another user).
pub const FEDERATION_ALREADY_LINKED: &str = "HEARTH_FEDERATION_ALREADY_LINKED";

// ── SAML ───────────────────────────────────────────────────────────────────────

/// SAML message is invalid (parse, signature, replay, audience, or destination check).
pub const SAML_INVALID: &str = "HEARTH_SAML_INVALID";
/// Fetching SAML IdP metadata failed.
pub const SAML_METADATA_FETCH_FAILED: &str = "HEARTH_SAML_METADATA_FETCH_FAILED";
/// SAML entity (SP or IdP) is not registered for this realm.
pub const SAML_ENTITY_NOT_FOUND: &str = "HEARTH_SAML_ENTITY_NOT_FOUND";

// ── SCIM ───────────────────────────────────────────────────────────────────────

/// SCIM `externalId` is already associated with a different resource.
pub const DUPLICATE_SCIM_EXTERNAL_ID: &str = "HEARTH_DUPLICATE_SCIM_EXTERNAL_ID";

// ── Access control ─────────────────────────────────────────────────────────────

/// Caller is not authorized to perform this operation.
pub const FORBIDDEN: &str = "HEARTH_FORBIDDEN";
/// Operation is not permitted on the system realm.
pub const SYSTEM_REALM_PROTECTED: &str = "HEARTH_SYSTEM_REALM_PROTECTED";

// ── Mapping ────────────────────────────────────────────────────────────────────

/// Maps an [`crate::identity::IdentityError`] variant to a stable error code.
///
/// Returns `None` for server-side (5xx) errors to avoid leaking internal detail.
pub(crate) fn for_identity_error(err: &crate::identity::IdentityError) -> Option<&'static str> {
    use crate::identity::IdentityError;

    match err {
        IdentityError::TokenExpired => Some(TOKEN_EXPIRED),
        IdentityError::TokenRevoked => Some(TOKEN_REVOKED),
        IdentityError::InvalidToken => Some(TOKEN_INVALID),
        IdentityError::TokenTooLarge { .. } => Some(TOKEN_TOO_LARGE),

        IdentityError::InvalidCredential { .. } => Some(INVALID_CREDENTIAL),
        IdentityError::CredentialNotFound => Some(INVALID_CREDENTIAL),
        IdentityError::InvalidClient | IdentityError::InvalidClientSecret => Some(INVALID_CLIENT),
        IdentityError::InvalidAuthorizationCode | IdentityError::InvalidGrant { .. } => {
            Some(INVALID_GRANT)
        }
        IdentityError::DeviceCodeExpired => Some(DEVICE_CODE_EXPIRED),
        IdentityError::InvalidRedirectUri => Some(INVALID_REDIRECT_URI),
        IdentityError::UnsupportedGrantType => Some(UNSUPPORTED_GRANT_TYPE),

        IdentityError::MfaRequired => Some(MFA_REQUIRED),
        IdentityError::InvalidMfaCode => Some(MFA_INVALID_CODE),
        IdentityError::MfaNotEnabled => Some(MFA_NOT_ENABLED),
        IdentityError::MfaAlreadyEnabled => Some(MFA_ALREADY_ENABLED),

        IdentityError::WebAuthnRegistrationFailed { .. } => Some(WEBAUTHN_REGISTRATION_FAILED),
        IdentityError::WebAuthnAuthenticationFailed { .. } => Some(WEBAUTHN_AUTHENTICATION_FAILED),
        IdentityError::WebAuthnCredentialNotFound => Some(WEBAUTHN_CREDENTIAL_NOT_FOUND),
        IdentityError::InvalidAttestation { .. } => Some(INVALID_ATTESTATION),
        IdentityError::InvalidAssertion { .. } => Some(INVALID_ASSERTION),

        IdentityError::AuthorizationPending => Some(AUTHORIZATION_PENDING),
        IdentityError::SlowDown => Some(SLOW_DOWN),
        IdentityError::DeviceCodeDenied => Some(DEVICE_CODE_DENIED),

        IdentityError::RateLimited => Some(RATE_LIMITED),

        IdentityError::UserNotVerified => Some(EMAIL_UNVERIFIED),
        IdentityError::PasswordExpired => Some(PASSWORD_EXPIRED),
        IdentityError::PasswordReused => Some(PASSWORD_REUSED),
        IdentityError::AuthMethodNotAllowed { .. } => Some(AUTH_METHOD_NOT_ALLOWED),

        IdentityError::RealmNotFound
        | IdentityError::UserNotFound
        | IdentityError::ClientNotFound
        | IdentityError::WebhookNotFound
        | IdentityError::ConsentNotFound => Some(NOT_FOUND),
        IdentityError::SessionNotFound => Some(SESSION_NOT_FOUND),

        IdentityError::RealmSuspended => Some(REALM_SUSPENDED),

        IdentityError::InvalidInput { .. } | IdentityError::InvalidAttribute { .. } => {
            Some(INVALID_INPUT)
        }

        IdentityError::DuplicateEmail => Some(DUPLICATE_EMAIL),
        IdentityError::DuplicateRealmName => Some(DUPLICATE_REALM_NAME),

        IdentityError::OrganizationNotFound => Some(ORG_NOT_FOUND),
        IdentityError::OrganizationSuspended => Some(ORG_SUSPENDED),
        IdentityError::AlreadyMember => Some(ORG_ALREADY_MEMBER),
        IdentityError::NotAMember => Some(ORG_NOT_MEMBER),
        IdentityError::LastOwner => Some(ORG_LAST_OWNER),
        IdentityError::MemberLimitReached => Some(ORG_MEMBER_LIMIT),
        IdentityError::DuplicateOrgSlug => Some(ORG_DUPLICATE_SLUG),

        IdentityError::InvitationInvalid => Some(INVITATION_INVALID),
        IdentityError::DuplicateInvitation => Some(INVITATION_DUPLICATE),

        IdentityError::RegistrationDisabled => Some(REGISTRATION_DISABLED),
        IdentityError::RegistrationDomainNotAllowed { .. } => Some(REGISTRATION_DOMAIN_NOT_ALLOWED),
        IdentityError::RegistrationRequiresInvitation => Some(REGISTRATION_REQUIRES_INVITATION),

        IdentityError::MagicLinkTokenInvalid => Some(MAGIC_LINK_INVALID),
        IdentityError::VerificationTokenInvalid => Some(VERIFICATION_TOKEN_INVALID),
        IdentityError::PasswordResetTokenInvalid => Some(PASSWORD_RESET_TOKEN_INVALID),

        IdentityError::ConsentRequired => Some(CONSENT_REQUIRED),
        IdentityError::ConsentTicketNotFound | IdentityError::ConsentTicketExpired => {
            Some(CONSENT_TICKET_INVALID)
        }
        IdentityError::ConsentScopeNotRequested => Some(CONSENT_SCOPE_NOT_REQUESTED),

        IdentityError::FederationUnknownConnector => Some(FEDERATION_UNKNOWN_CONNECTOR),
        IdentityError::FederationInvalidState => Some(FEDERATION_INVALID_STATE),
        IdentityError::FederationUpstreamError { .. } => Some(FEDERATION_UPSTREAM_ERROR),
        IdentityError::FederationTokenVerificationFailed => {
            Some(FEDERATION_TOKEN_VERIFICATION_FAILED)
        }
        IdentityError::FederationEmailNotVerified => Some(FEDERATION_EMAIL_NOT_VERIFIED),
        IdentityError::FederationLinkConfirmationRequired { .. } => {
            Some(FEDERATION_LINK_CONFIRMATION_REQUIRED)
        }
        IdentityError::FederationNotLinked => Some(FEDERATION_NOT_LINKED),
        IdentityError::FederationAlreadyLinked => Some(FEDERATION_ALREADY_LINKED),

        IdentityError::SamlParse { .. }
        | IdentityError::SamlSignature
        | IdentityError::SamlExpired
        | IdentityError::SamlReplay
        | IdentityError::SamlAudienceMismatch
        | IdentityError::SamlIssuerMismatch
        | IdentityError::SamlDestinationMismatch
        | IdentityError::SamlUnsupportedAlgorithm
        | IdentityError::SamlInvalidAuthnRequest { .. } => Some(SAML_INVALID),
        IdentityError::SamlMetadataFetch { .. } => Some(SAML_METADATA_FETCH_FAILED),
        IdentityError::SamlUnknownSp | IdentityError::SamlUnknownIdp => Some(SAML_ENTITY_NOT_FOUND),

        IdentityError::DuplicateScimExternalId => Some(DUPLICATE_SCIM_EXTERNAL_ID),

        IdentityError::Unauthorized => Some(FORBIDDEN),
        IdentityError::SystemRealmProtected { .. } => Some(SYSTEM_REALM_PROTECTED),

        // 5xx — do not leak internal detail
        IdentityError::SigningError { .. }
        | IdentityError::Storage(_)
        | IdentityError::Serialization { .. }
        | IdentityError::Internal { .. }
        | IdentityError::ConfigInvalid { .. }
        | IdentityError::AuditFailure { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityError;

    #[test]
    fn token_expired_maps_to_token_expired() {
        assert_eq!(
            for_identity_error(&IdentityError::TokenExpired),
            Some(TOKEN_EXPIRED)
        );
    }

    #[test]
    fn token_revoked_maps_to_token_revoked() {
        assert_eq!(
            for_identity_error(&IdentityError::TokenRevoked),
            Some(TOKEN_REVOKED)
        );
    }

    #[test]
    fn invalid_token_maps_to_token_invalid() {
        assert_eq!(
            for_identity_error(&IdentityError::InvalidToken),
            Some(TOKEN_INVALID)
        );
    }

    #[test]
    fn mfa_required_maps_to_mfa_required() {
        assert_eq!(
            for_identity_error(&IdentityError::MfaRequired),
            Some(MFA_REQUIRED)
        );
    }

    #[test]
    fn invalid_grant_maps_to_invalid_grant() {
        assert_eq!(
            for_identity_error(&IdentityError::InvalidGrant {
                reason: "pkce mismatch".to_string()
            }),
            Some(INVALID_GRANT)
        );
        assert_eq!(
            for_identity_error(&IdentityError::InvalidAuthorizationCode),
            Some(INVALID_GRANT)
        );
        assert_eq!(
            for_identity_error(&IdentityError::DeviceCodeExpired),
            Some(DEVICE_CODE_EXPIRED)
        );
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        assert_eq!(
            for_identity_error(&IdentityError::RateLimited),
            Some(RATE_LIMITED)
        );
    }

    #[test]
    fn realm_suspended_maps_to_realm_suspended() {
        assert_eq!(
            for_identity_error(&IdentityError::RealmSuspended),
            Some(REALM_SUSPENDED)
        );
    }

    #[test]
    fn account_locked_maps_to_rate_limited() {
        // RateLimited covers both rate-limit and temporary account lockout
        assert_eq!(
            for_identity_error(&IdentityError::RateLimited),
            Some(RATE_LIMITED)
        );
    }

    #[test]
    fn email_unverified_maps_to_email_unverified() {
        assert_eq!(
            for_identity_error(&IdentityError::UserNotVerified),
            Some(EMAIL_UNVERIFIED)
        );
    }

    #[test]
    fn server_errors_return_none() {
        // 5xx errors must not expose internal codes
        assert_eq!(
            for_identity_error(&IdentityError::Storage(Box::new(std::io::Error::other(
                "disk full"
            )))),
            None
        );
        assert_eq!(
            for_identity_error(&IdentityError::Internal {
                reason: "unexpected state".to_string()
            }),
            None
        );
        assert_eq!(
            for_identity_error(&IdentityError::SigningError {
                reason: "key gen failed".to_string()
            }),
            None
        );
        assert_eq!(
            for_identity_error(&IdentityError::Serialization {
                reason: "bad json".to_string()
            }),
            None
        );
        assert_eq!(
            for_identity_error(&IdentityError::AuditFailure {
                action: "delete_user".to_string(),
                reason: "storage".to_string()
            }),
            None
        );
    }

    #[test]
    fn org_errors_map_correctly() {
        assert_eq!(
            for_identity_error(&IdentityError::OrganizationNotFound),
            Some(ORG_NOT_FOUND)
        );
        assert_eq!(
            for_identity_error(&IdentityError::LastOwner),
            Some(ORG_LAST_OWNER)
        );
        assert_eq!(
            for_identity_error(&IdentityError::MemberLimitReached),
            Some(ORG_MEMBER_LIMIT)
        );
    }

    #[test]
    fn saml_variants_map_to_saml_invalid() {
        assert_eq!(
            for_identity_error(&IdentityError::SamlSignature),
            Some(SAML_INVALID)
        );
        assert_eq!(
            for_identity_error(&IdentityError::SamlReplay),
            Some(SAML_INVALID)
        );
        assert_eq!(
            for_identity_error(&IdentityError::SamlExpired),
            Some(SAML_INVALID)
        );
        assert_eq!(
            for_identity_error(&IdentityError::SamlUnknownSp),
            Some(SAML_ENTITY_NOT_FOUND)
        );
    }

    #[test]
    fn federation_errors_map_correctly() {
        assert_eq!(
            for_identity_error(&IdentityError::FederationUnknownConnector),
            Some(FEDERATION_UNKNOWN_CONNECTOR)
        );
        assert_eq!(
            for_identity_error(&IdentityError::FederationUpstreamError {
                provider: "google".to_string(),
                reason: "500".to_string()
            }),
            Some(FEDERATION_UPSTREAM_ERROR)
        );
        assert_eq!(
            for_identity_error(&IdentityError::FederationLinkConfirmationRequired {
                ticket: "t".to_string()
            }),
            Some(FEDERATION_LINK_CONFIRMATION_REQUIRED)
        );
    }

    #[test]
    fn all_codes_start_with_hearth_prefix() {
        let codes: &[&str] = &[
            TOKEN_EXPIRED,
            TOKEN_REVOKED,
            TOKEN_INVALID,
            TOKEN_TOO_LARGE,
            INVALID_CREDENTIAL,
            INVALID_CLIENT,
            INVALID_GRANT,
            INVALID_REDIRECT_URI,
            UNSUPPORTED_GRANT_TYPE,
            MFA_REQUIRED,
            MFA_INVALID_CODE,
            MFA_NOT_ENABLED,
            MFA_ALREADY_ENABLED,
            WEBAUTHN_REGISTRATION_FAILED,
            WEBAUTHN_AUTHENTICATION_FAILED,
            WEBAUTHN_CREDENTIAL_NOT_FOUND,
            INVALID_ATTESTATION,
            INVALID_ASSERTION,
            AUTHORIZATION_PENDING,
            SLOW_DOWN,
            DEVICE_CODE_EXPIRED,
            DEVICE_CODE_DENIED,
            RATE_LIMITED,
            EMAIL_UNVERIFIED,
            PASSWORD_EXPIRED,
            PASSWORD_REUSED,
            AUTH_METHOD_NOT_ALLOWED,
            NOT_FOUND,
            SESSION_NOT_FOUND,
            REALM_SUSPENDED,
            INVALID_INPUT,
            DUPLICATE_EMAIL,
            DUPLICATE_REALM_NAME,
            ORG_NOT_FOUND,
            ORG_SUSPENDED,
            ORG_ALREADY_MEMBER,
            ORG_NOT_MEMBER,
            ORG_LAST_OWNER,
            ORG_MEMBER_LIMIT,
            ORG_DUPLICATE_SLUG,
            INVITATION_INVALID,
            INVITATION_DUPLICATE,
            REGISTRATION_DISABLED,
            REGISTRATION_DOMAIN_NOT_ALLOWED,
            REGISTRATION_REQUIRES_INVITATION,
            MAGIC_LINK_INVALID,
            VERIFICATION_TOKEN_INVALID,
            PASSWORD_RESET_TOKEN_INVALID,
            CONSENT_REQUIRED,
            CONSENT_TICKET_INVALID,
            CONSENT_SCOPE_NOT_REQUESTED,
            CONSENT_NOT_FOUND,
            FEDERATION_UNKNOWN_CONNECTOR,
            FEDERATION_INVALID_STATE,
            FEDERATION_UPSTREAM_ERROR,
            FEDERATION_TOKEN_VERIFICATION_FAILED,
            FEDERATION_EMAIL_NOT_VERIFIED,
            FEDERATION_LINK_CONFIRMATION_REQUIRED,
            FEDERATION_NOT_LINKED,
            FEDERATION_ALREADY_LINKED,
            SAML_INVALID,
            SAML_METADATA_FETCH_FAILED,
            SAML_ENTITY_NOT_FOUND,
            DUPLICATE_SCIM_EXTERNAL_ID,
            FORBIDDEN,
            SYSTEM_REALM_PROTECTED,
        ];
        for code in codes {
            assert!(
                code.starts_with("HEARTH_"),
                "code {code:?} must start with HEARTH_"
            );
        }
    }
}
