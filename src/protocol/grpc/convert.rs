//! Shared helpers for gRPC service implementations.
//!
//! Domain-error → `tonic::Status` mapping, realm-id extraction, and other
//! glue that would otherwise be duplicated across service impls.

use tonic::metadata::MetadataMap;
use tonic::{Code, Status};

use crate::core::RealmId;
use crate::identity::IdentityError;
use crate::rbac::RbacError;

/// Metadata key carrying the target realm for admin calls.
pub const REALM_ID_META_KEY: &str = "x-realm-id";

/// Maps an [`IdentityError`] to a [`tonic::Status`] following the same
/// policy as the REST surface in `src/protocol/http.rs`.
///
/// The caller is expected to have already logged the error at `debug` or
/// higher where appropriate — the produced `Status` message is safe to
/// surface to untrusted clients (no secrets, no internals).
#[must_use]
pub fn identity_to_status(err: IdentityError) -> Status {
    let (code, msg) = match &err {
        IdentityError::RealmNotFound
        | IdentityError::UserNotFound
        | IdentityError::SessionNotFound
        | IdentityError::CredentialNotFound
        | IdentityError::ClientNotFound
        | IdentityError::OrganizationNotFound
        | IdentityError::WebAuthnCredentialNotFound
        | IdentityError::ConsentNotFound
        | IdentityError::FederationNotLinked => (Code::NotFound, err.to_string()),
        IdentityError::DuplicateEmail
        | IdentityError::DuplicateRealmName
        | IdentityError::DuplicateOrgSlug
        | IdentityError::DuplicateInvitation
        | IdentityError::MfaAlreadyEnabled
        | IdentityError::AlreadyMember
        | IdentityError::FederationAlreadyLinked
        | IdentityError::DuplicateScimExternalId => (Code::AlreadyExists, err.to_string()),
        IdentityError::InvalidToken
        | IdentityError::TokenExpired
        | IdentityError::InvalidCredential { .. }
        | IdentityError::InvalidClient
        | IdentityError::InvalidClientSecret => (Code::Unauthenticated, err.to_string()),
        IdentityError::Unauthorized
        | IdentityError::SystemRealmProtected { .. }
        | IdentityError::RealmSuspended
        | IdentityError::OrganizationSuspended
        | IdentityError::RegistrationDisabled
        | IdentityError::RegistrationDomainNotAllowed { .. }
        | IdentityError::RegistrationRequiresInvitation
        | IdentityError::ConsentRequired
        | IdentityError::LastOwner
        | IdentityError::NotAMember
        | IdentityError::UserNotVerified
        | IdentityError::AuthMethodNotAllowed { .. } => (Code::PermissionDenied, err.to_string()),
        IdentityError::InvalidInput { .. }
        | IdentityError::InvalidAttribute { .. }
        | IdentityError::InvalidRedirectUri
        | IdentityError::InvalidAuthorizationCode
        | IdentityError::InvalidGrant { .. }
        | IdentityError::UnsupportedGrantType
        | IdentityError::InvalidMfaCode
        | IdentityError::MfaNotEnabled
        | IdentityError::MagicLinkTokenInvalid
        | IdentityError::VerificationTokenInvalid
        | IdentityError::PasswordResetTokenInvalid
        | IdentityError::InvitationInvalid
        | IdentityError::ConsentTicketNotFound
        | IdentityError::ConsentTicketExpired
        | IdentityError::ConsentScopeNotRequested
        | IdentityError::FederationUnknownConnector
        | IdentityError::FederationInvalidState
        | IdentityError::FederationTokenVerificationFailed
        | IdentityError::FederationEmailNotVerified
        | IdentityError::FederationLinkConfirmationRequired { .. }
        | IdentityError::WebAuthnRegistrationFailed { .. }
        | IdentityError::WebAuthnAuthenticationFailed { .. }
        | IdentityError::InvalidAttestation { .. }
        | IdentityError::InvalidAssertion { .. }
        | IdentityError::SamlParse { .. }
        | IdentityError::SamlSignature
        | IdentityError::SamlExpired
        | IdentityError::SamlReplay
        | IdentityError::SamlAudienceMismatch
        | IdentityError::SamlIssuerMismatch
        | IdentityError::SamlDestinationMismatch
        | IdentityError::SamlUnsupportedAlgorithm
        | IdentityError::SamlInvalidAuthnRequest { .. } => (Code::InvalidArgument, err.to_string()),
        IdentityError::SamlUnknownSp | IdentityError::SamlUnknownIdp => {
            (Code::NotFound, err.to_string())
        }
        IdentityError::MfaRequired
        | IdentityError::AuthorizationPending
        | IdentityError::SlowDown
        | IdentityError::DeviceCodeExpired
        | IdentityError::DeviceCodeDenied
        | IdentityError::TokenRevoked
        | IdentityError::PasswordExpired
        | IdentityError::PasswordReused => (Code::FailedPrecondition, err.to_string()),
        IdentityError::RateLimited
        | IdentityError::MemberLimitReached
        | IdentityError::TokenTooLarge { .. } => (Code::ResourceExhausted, err.to_string()),
        IdentityError::Storage(_)
        | IdentityError::Serialization { .. }
        | IdentityError::SigningError { .. }
        | IdentityError::FederationUpstreamError { .. }
        | IdentityError::SamlMetadataFetch { .. }
        | IdentityError::ConfigInvalid { .. }
        | IdentityError::AuditFailure { .. }
        | IdentityError::Internal { .. } => {
            tracing::error!(error = %err, "internal gRPC error");
            (Code::Internal, "internal error".to_string())
        }
    };
    Status::new(code, msg)
}

/// Maps an [`RbacError`] to a [`tonic::Status`].
#[must_use]
pub fn rbac_to_status(err: RbacError) -> Status {
    match err {
        RbacError::RoleNotFound | RbacError::GroupNotFound | RbacError::AssignmentNotFound => {
            Status::new(Code::NotFound, err.to_string())
        }
        RbacError::DuplicateRoleName | RbacError::DuplicateGroupSlug => {
            Status::new(Code::AlreadyExists, err.to_string())
        }
        RbacError::InvalidPermission { .. }
        | RbacError::InvalidRoleName { .. }
        | RbacError::InvalidGroupSlug { .. } => Status::new(Code::InvalidArgument, err.to_string()),
        RbacError::CycleDetected { .. } => Status::new(Code::FailedPrecondition, err.to_string()),
        RbacError::DepthExceeded { .. }
        | RbacError::BreadthExceeded { .. }
        | RbacError::TokenSizeExceeded { .. } => {
            Status::new(Code::ResourceExhausted, err.to_string())
        }
        RbacError::ReservedNamespace { .. } => Status::new(Code::PermissionDenied, err.to_string()),
        RbacError::InvalidScope { .. } => Status::new(Code::InvalidArgument, err.to_string()),
        RbacError::Storage(e) => {
            tracing::error!(error = %e, "rbac storage error");
            Status::new(Code::Internal, "internal error")
        }
        RbacError::Serialization { .. } => {
            tracing::error!(error = %err, "rbac serialization error");
            Status::new(Code::Internal, "internal error")
        }
    }
}

/// Parses a UUID-string realm id from request metadata.
///
/// The admin interceptor calls this; returns `UNAUTHENTICATED` for missing,
/// `INVALID_ARGUMENT` for malformed input.
pub fn extract_realm_id(md: &MetadataMap) -> Result<RealmId, Status> {
    let raw = md
        .get(REALM_ID_META_KEY)
        .ok_or_else(|| Status::unauthenticated(format!("missing {REALM_ID_META_KEY} metadata")))?
        .to_str()
        .map_err(|_| {
            Status::invalid_argument(format!("{REALM_ID_META_KEY} metadata is not valid ASCII"))
        })?;
    let uuid = raw
        .parse::<uuid::Uuid>()
        .map_err(|_| Status::invalid_argument("realm id is not a valid UUID"))?;
    Ok(RealmId::new(uuid))
}

/// Metadata key carrying the OAuth client ID for protected RPC calls.
pub const CLIENT_ID_META_KEY: &str = "x-hearth-client-id";

/// Metadata key carrying the OAuth client secret for protected RPC calls.
pub const CLIENT_SECRET_META_KEY: &str = "x-hearth-client-secret";

/// Extracts and verifies OAuth client credentials from gRPC request metadata.
///
/// Reads `x-hearth-client-id` and optional `x-hearth-client-secret` metadata
/// values and delegates to the identity engine for verification. Confidential
/// clients require the secret; public clients are accepted with ID alone.
/// Returns `UNAUTHENTICATED` for any auth failure.
pub fn verify_grpc_client_auth(
    md: &MetadataMap,
    realm_id: &RealmId,
    identity: &dyn crate::identity::IdentityEngine,
) -> Result<(), Status> {
    let raw_id = md
        .get(CLIENT_ID_META_KEY)
        .ok_or_else(|| Status::unauthenticated("missing x-hearth-client-id metadata"))?
        .to_str()
        .map_err(|_| Status::invalid_argument("x-hearth-client-id is not valid ASCII"))?;

    let uuid = raw_id
        .parse::<uuid::Uuid>()
        .map_err(|_| Status::unauthenticated("invalid client credentials"))?;
    let client_id = crate::core::ClientId::new(uuid);

    let secret = md.get(CLIENT_SECRET_META_KEY).and_then(|v| v.to_str().ok());

    identity
        .authenticate_client(realm_id, &client_id, secret)
        .map_err(|_| Status::unauthenticated("invalid client credentials"))
}
