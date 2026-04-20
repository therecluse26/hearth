//! OAuth/OIDC type conversions: domain <-> proto wire types.

use crate::core::{ClientId, UserId};
use crate::identity::{self as domain, CodeChallengeMethod};
use crate::protocol::proto::identity::v1 as pb;

// ==================== OAuthClient ====================

impl From<&domain::OAuthClient> for pb::OAuthClient {
    fn from(c: &domain::OAuthClient) -> Self {
        Self {
            client_id: c.client_id().as_uuid().to_string(),
            client_name: c.client_name().to_string(),
            redirect_uris: c.redirect_uris().to_vec(),
            created_at: c.created_at().as_micros(),
            is_confidential: c.is_confidential(),
            grant_types: c.grant_types().to_vec(),
        }
    }
}

/// Converts a domain `Page<OAuthClient>` to a proto `OAuthClientPage`.
pub(crate) fn client_page_to_proto(
    page: &domain::Page<domain::OAuthClient>,
) -> pb::OAuthClientPage {
    pb::OAuthClientPage {
        items: page.items.iter().map(pb::OAuthClient::from).collect(),
        next_cursor: page.next_cursor.clone(),
    }
}

// ==================== RegisterClientRequest ====================

impl From<pb::RegisterClientRequest> for domain::RegisterClientRequest {
    fn from(r: pb::RegisterClientRequest) -> Self {
        Self {
            client_name: r.client_name,
            redirect_uris: r.redirect_uris,
            client_secret: r.client_secret,
            grant_types: if r.grant_types.is_empty() {
                vec!["authorization_code".to_string()]
            } else {
                r.grant_types
            },
        }
    }
}

// ==================== UpdateClientRequest ====================

impl From<pb::UpdateClientRequest> for domain::UpdateClientRequest {
    fn from(r: pb::UpdateClientRequest) -> Self {
        Self {
            client_name: r.client_name,
            redirect_uris: if r.redirect_uris.is_empty() {
                None
            } else {
                Some(r.redirect_uris)
            },
            grant_types: if r.grant_types.is_empty() {
                None
            } else {
                Some(r.grant_types)
            },
        }
    }
}

// ==================== AuthorizationRequest ====================

/// Converts a proto `AuthorizationRequest` to a domain `AuthorizationRequest`.
///
/// `code_challenge_method` is validated here: only "S256" is accepted.
/// Returns `Err(String)` if the method is unsupported.
pub(crate) fn proto_authorize_to_domain(
    r: pb::AuthorizationRequest,
) -> Result<domain::AuthorizationRequest, String> {
    let code_challenge_method = match r.code_challenge_method.as_deref() {
        Some("S256") => Some(CodeChallengeMethod::S256),
        Some(other) => return Err(format!("unsupported code_challenge_method: {other}")),
        None => None,
    };

    Ok(domain::AuthorizationRequest {
        client_id: ClientId::new(
            uuid::Uuid::parse_str(&r.client_id)
                .map_err(|_| "invalid client_id UUID".to_string())?,
        ),
        redirect_uri: r.redirect_uri,
        scope: r.scope,
        state: r.state,
        response_type: r.response_type,
        user_id: UserId::new(
            uuid::Uuid::parse_str(&r.user_id).map_err(|_| "invalid user_id UUID".to_string())?,
        ),
        code_challenge: r.code_challenge,
        code_challenge_method,
        nonce: r.nonce,
    })
}

// ==================== AuthorizationResponse ====================

impl From<&domain::AuthorizationResponse> for pb::AuthorizationResponse {
    fn from(r: &domain::AuthorizationResponse) -> Self {
        Self {
            code: r.code().to_string(),
            state: r.state().to_string(),
        }
    }
}

// ==================== TokenExchangeRequest ====================

/// Converts a proto `TokenExchangeRequest` to a domain `TokenExchangeRequest`.
pub(crate) fn proto_token_exchange_to_domain(
    r: &pb::TokenExchangeRequest,
) -> Result<domain::TokenExchangeRequest, String> {
    Ok(domain::TokenExchangeRequest {
        client_id: ClientId::new(
            uuid::Uuid::parse_str(&r.client_id)
                .map_err(|_| "invalid client_id UUID".to_string())?,
        ),
        code: r.code.clone(),
        redirect_uri: r.redirect_uri.clone(),
        code_verifier: r.code_verifier.clone(),
    })
}

// ==================== OidcTokenResponse ====================

impl From<&domain::OidcTokenResponse> for pb::OidcTokenResponse {
    fn from(r: &domain::OidcTokenResponse) -> Self {
        Self {
            access_token: r.access_token().to_string(),
            id_token: r.id_token().to_string(),
            token_type: r.token_type().to_string(),
            expires_in: r.expires_in(),
            refresh_token: r.refresh_token().to_string(),
        }
    }
}

// ==================== ClientCredentialsRequest ====================

/// Converts a proto `ClientCredentialsRequest` to domain.
pub(crate) fn proto_client_creds_to_domain(
    r: &pb::ClientCredentialsRequest,
) -> Result<domain::ClientCredentialsRequest, String> {
    Ok(domain::ClientCredentialsRequest {
        client_id: ClientId::new(
            uuid::Uuid::parse_str(&r.client_id)
                .map_err(|_| "invalid client_id UUID".to_string())?,
        ),
        client_secret: r.client_secret.clone(),
        scope: r.scope.clone(),
    })
}

// ==================== ClientCredentialsResponse ====================

impl From<&domain::ClientCredentialsResponse> for pb::ClientCredentialsResponse {
    fn from(r: &domain::ClientCredentialsResponse) -> Self {
        Self {
            access_token: r.access_token().to_string(),
            token_type: r.token_type().to_string(),
            expires_in: r.expires_in(),
            scope: r.scope().map(String::from),
        }
    }
}

// ==================== DeviceAuthorizationResponse ====================

impl From<&domain::DeviceAuthorizationResponse> for pb::DeviceAuthorizationResponse {
    fn from(r: &domain::DeviceAuthorizationResponse) -> Self {
        Self {
            device_code: r.device_code.clone(),
            user_code: r.user_code.clone(),
            verification_uri: r.verification_uri.clone(),
            expires_in: r.expires_in,
            interval: r.interval,
        }
    }
}

// ==================== TokenRevocationRequest ====================

impl From<pb::TokenRevocationRequest> for domain::TokenRevocationRequest {
    fn from(r: pb::TokenRevocationRequest) -> Self {
        Self {
            token: r.token,
            token_type_hint: r.token_type_hint,
        }
    }
}

// ==================== TokenIntrospectionRequest ====================

impl From<pb::TokenIntrospectionRequest> for domain::TokenIntrospectionRequest {
    fn from(r: pb::TokenIntrospectionRequest) -> Self {
        Self {
            token: r.token,
            token_type_hint: r.token_type_hint,
        }
    }
}

// ==================== IntrospectionResponse ====================

impl From<&domain::IntrospectionResponse> for pb::IntrospectionResponse {
    fn from(r: &domain::IntrospectionResponse) -> Self {
        Self {
            active: r.active,
            scope: r.scope.clone(),
            client_id: r.client_id.clone(),
            sub: r.sub.clone(),
            exp: r.exp,
            iat: r.iat,
            token_type: r.token_type.clone(),
            iss: r.iss.clone(),
            aud: r.aud.clone(),
        }
    }
}

// ==================== UserInfoResponse ====================

impl From<&domain::UserInfoResponse> for pb::UserInfoResponse {
    fn from(r: &domain::UserInfoResponse) -> Self {
        Self {
            sub: r.sub.clone(),
            email: r.email.clone(),
            email_verified: r.email_verified,
            name: r.name.clone(),
        }
    }
}

// ==================== OidcDiscoveryDocument ====================

impl From<&domain::OidcDiscoveryDocument> for pb::OidcDiscoveryDocument {
    fn from(d: &domain::OidcDiscoveryDocument) -> Self {
        Self {
            issuer: d.issuer.clone(),
            authorization_endpoint: d.authorization_endpoint.clone(),
            token_endpoint: d.token_endpoint.clone(),
            jwks_uri: d.jwks_uri.clone(),
            userinfo_endpoint: d.userinfo_endpoint.clone(),
            response_types_supported: d.response_types_supported.clone(),
            response_modes_supported: d.response_modes_supported.clone(),
            subject_types_supported: d.subject_types_supported.clone(),
            id_token_signing_alg_values_supported: d.id_token_signing_alg_values_supported.clone(),
            scopes_supported: d.scopes_supported.clone(),
            claims_supported: d.claims_supported.clone(),
            token_endpoint_auth_methods_supported: d.token_endpoint_auth_methods_supported.clone(),
            code_challenge_methods_supported: d.code_challenge_methods_supported.clone(),
            grant_types_supported: d.grant_types_supported.clone(),
            registration_endpoint: d.registration_endpoint.clone(),
            device_authorization_endpoint: d.device_authorization_endpoint.clone(),
            revocation_endpoint: d.revocation_endpoint.clone(),
            introspection_endpoint: d.introspection_endpoint.clone(),
        }
    }
}

// ==================== JwksDocument ====================

impl From<&domain::Jwk> for pb::JsonWebKey {
    fn from(j: &domain::Jwk) -> Self {
        Self {
            kty: j.kty.clone(),
            crv: j.crv.clone(),
            x: j.x.clone(),
            kid: j.kid.clone(),
            r#use: j.use_.clone(),
            alg: j.alg.clone(),
        }
    }
}

impl From<&domain::JwksDocument> for pb::JwksDocument {
    fn from(d: &domain::JwksDocument) -> Self {
        Self {
            keys: d.keys.iter().map(pb::JsonWebKey::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    #[test]
    fn oauth_client_to_proto() {
        let client = domain::OAuthClient::new(
            ClientId::generate(),
            "Test App".to_string(),
            vec!["https://app.example.com/callback".to_string()],
            Timestamp::from_micros(1_000_000),
        );
        let proto = pb::OAuthClient::from(&client);
        assert_eq!(proto.client_id, client.client_id().as_uuid().to_string());
        assert_eq!(proto.client_name, "Test App");
        assert_eq!(
            proto.redirect_uris,
            vec!["https://app.example.com/callback"]
        );
        assert!(!proto.is_confidential);
    }

    #[test]
    fn register_client_request_conversion() {
        let proto = pb::RegisterClientRequest {
            client_name: "My App".to_string(),
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            client_secret: Some("secret123".to_string()),
            grant_types: vec![],
        };
        let domain = domain::RegisterClientRequest::from(proto);
        assert_eq!(domain.client_name, "My App");
        assert_eq!(domain.client_secret.as_deref(), Some("secret123"));
        assert_eq!(domain.grant_types, vec!["authorization_code"]);
    }

    #[test]
    fn token_response_conversion() {
        let resp = domain::OidcTokenResponse::new(
            "access".to_string(),
            "id".to_string(),
            "Bearer".to_string(),
            900,
            "refresh".to_string(),
        );
        let proto = pb::OidcTokenResponse::from(&resp);
        assert_eq!(proto.access_token, "access");
        assert_eq!(proto.id_token, "id");
        assert_eq!(proto.token_type, "Bearer");
        assert_eq!(proto.expires_in, 900);
        assert_eq!(proto.refresh_token, "refresh");
    }
}
