//! SAML 2.0 support.
//!
//! Hearth acts both as a SAML **Service Provider** (consuming assertions
//! from external IdPs such as Okta, AD FS, PingFederate) and as a SAML
//! **Identity Provider** (issuing assertions to external SPs). Phase 1
//! ships:
//!
//! - SP-initiated SSO (SP and IdP sides).
//! - IdP-initiated SSO.
//! - Single Logout (SLO) for both roles.
//! - Metadata generation + parsing.
//!
//! The implementation intentionally locks the algorithm suite to
//! **exclusive C14N 1.0 + SHA-256 digests + RSA-SHA256 signatures**.
//! SHA-1 digests and RSA-SHA1 signatures are rejected — algorithm
//! downgrade is a common SAML attack vector, and every IdP that matters
//! in 2026 supports RSA-SHA256.
//!
//! Each submodule is narrow and independently testable:
//!
//! - [`xml`] — minimal quick-xml helpers shared by parse/build paths.
//! - [`c14n`] — exclusive XML canonicalization (subset).
//! - [`signature`] — XML-DSIG sign + verify over canonicalized input.
//! - [`metadata`] — `<EntityDescriptor>` generation + parsing.
//! - [`authn_request`] — `<AuthnRequest>` build + parse.
//! - [`response`] — `<Response>` + `<Assertion>` build, parse, validate.
//! - [`logout`] — `<LogoutRequest>` + `<LogoutResponse>`.
//! - [`binding`] — HTTP-Redirect and HTTP-POST helpers.
//! - [`sp`] — SP-side orchestration (begin login, ACS, SLO).
//! - [`idp`] — IdP-side orchestration (receive AuthnRequest, issue
//!   Response, IdP-initiated SSO, SLO).

pub mod authn_request;
pub mod binding;
pub mod c14n;
pub mod idp;
pub mod logout;
pub mod metadata;
pub mod response;
pub mod signature;
pub mod sp;
pub mod types;
pub mod xml;

pub use authn_request::{build_authn_request_xml, parse_authn_request, AuthnRequest};
pub use binding::{
    build_post_form_html, build_redirect_url, decode_redirect_request, parse_post_form_saml,
};
pub use idp::{SamlIdpOutcome, SamlIdpService};
pub use logout::{
    build_logout_request_xml, build_logout_response_xml, parse_logout_request,
    parse_logout_response, BuildLogoutRequestParams, BuildLogoutResponseParams, LogoutRequest,
    LogoutResponse,
};
pub use metadata::{
    build_idp_metadata, build_sp_metadata, parse_idp_metadata, IdpMetadataParams,
    ParsedIdpMetadata, SpMetadataParams,
};
pub use response::{
    build_response_xml, extract_and_validate_assertion, parse_response, Assertion, ResponseBuilder,
    SamlResponse,
};
pub use signature::{sign_element, verify_signed_element, SignedElement};
pub use sp::{SamlSpOutcome, SamlSpService};
pub use types::{
    AttributeMap, SamlIdpConfig, SamlNameIdFormat, SamlServiceProvider, SamlSessionRegistration,
    SamlStateBag,
};
