//! HearthClient — OAuth flows, RBAC predicates, and WebAuthn.

use reqwest::header;
use serde_json::Value;

use crate::error::HearthError;
use crate::types::*;

/// Client for Hearth OAuth flows, userinfo, and RBAC predicates.
///
/// RBAC predicate methods decode the JWT locally — no network call needed.
pub struct HearthClient {
    base_url: String,
    realm_id: String,
    http: reqwest::Client,
}

impl HearthClient {
    pub fn new(base_url: impl Into<String>, realm_id: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let realm_id = realm_id.into();
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = header::HeaderMap::new();
                h.insert(
                    "X-Realm-ID",
                    header::HeaderValue::from_str(&realm_id).expect("valid realm id"),
                );
                h
            })
            .build()
            .expect("reqwest client");
        Self {
            base_url,
            realm_id,
            http,
        }
    }

    // ------------------------------------------------------------------
    // Static bootstrap (dev-only)
    // ------------------------------------------------------------------

    pub async fn bootstrap(base_url: &str) -> Result<BootstrapResponse, HearthError> {
        let url = format!("{}/admin/bootstrap", base_url.trim_end_matches('/'));
        let resp = reqwest::Client::new().post(&url).send().await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // OAuth flows
    // ------------------------------------------------------------------

    pub async fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        resource: Option<&str>,
    ) -> Result<AuthorizeResponse, HearthError> {
        let mut params = vec![
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", scope),
            ("state", state),
        ];
        if let Some(r) = resource {
            params.push(("resource", r));
        }
        let resp = self
            .http
            .get(format!("{}/authorize", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, HearthError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(cv) = code_verifier {
            form.push(("code_verifier", cv));
        }
        let resp = self
            .http
            .post(format!("{}/token", self.base_url))
            .form(&form)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn refresh_tokens(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, HearthError> {
        let resp = self
            .http
            .post(format!("{}/token", self.base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn register_client(
        &self,
        req: &RegisterClientRequest,
    ) -> Result<OAuthClient, HearthError> {
        let resp = self
            .http
            .post(format!("{}/clients", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Protected endpoints
    // ------------------------------------------------------------------

    pub async fn userinfo(
        &self,
        access_token: &str,
    ) -> Result<UserInfoResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/userinfo", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn permissions(
        &self,
        access_token: &str,
    ) -> Result<MePermissionsResponse, HearthError> {
        let resp = self
            .http
            .get(format!("{}/v1/me/permissions", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn jwks(&self) -> Result<JwksDocument, HearthError> {
        let resp = self
            .http
            .get(format!("{}/.well-known/jwks.json", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn discovery(&self) -> Result<Value, HearthError> {
        let resp = self
            .http
            .get(format!(
                "{}/.well-known/openid-configuration",
                self.base_url
            ))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // RBAC predicates (local, no network call)
    // ------------------------------------------------------------------

    pub fn has_permission(token: &str, permission: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let perms: Vec<String> = claims
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(perms.iter().any(|p| p == permission))
    }

    pub fn has_role(token: &str, role: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let roles: Vec<String> = claims
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(roles.iter().any(|r| r == role))
    }

    pub fn in_group(token: &str, group_slug: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        let groups: Vec<String> = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(groups.iter().any(|g| g == group_slug))
    }

    pub fn in_org(token: &str, org_id: &str) -> Result<bool, HearthError> {
        let claims = Self::decode_claims(token)?;
        Ok(claims.get("oid").and_then(|v| v.as_str()) == Some(org_id))
    }

    fn decode_claims(token: &str) -> Result<Value, HearthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Err(HearthError::Other("invalid JWT format".into()));
        }
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| HearthError::Other(format!("base64 decode: {e}")))?;
        let claims: Value = serde_json::from_slice(&payload)?;
        Ok(claims)
    }

    // ------------------------------------------------------------------
    // WebAuthn
    // ------------------------------------------------------------------

    pub async fn webauthn_register_begin(
        &self,
        access_token: &str,
        rp_id: &str,
        discoverable: bool,
    ) -> Result<Value, HearthError> {
        let resp = self
            .http
            .post(format!("{}/webauthn/register/begin", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "rp_id": rp_id,
                "discoverable": discoverable,
            }))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_register_complete(
        &self,
        access_token: &str,
        client_data_json: &str,
        attestation_object: &str,
        origin: &str,
        discoverable: bool,
    ) -> Result<Value, HearthError> {
        let resp = self
            .http
            .post(format!("{}/webauthn/register/complete", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({
                "client_data_json": client_data_json,
                "attestation_object": attestation_object,
                "origin": origin,
                "discoverable": discoverable,
            }))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_auth_begin(
        &self,
        rp_id: &str,
        user_id: Option<&str>,
    ) -> Result<Value, HearthError> {
        let mut body = serde_json::json!({ "rp_id": rp_id });
        if let Some(uid) = user_id {
            body["user_id"] = serde_json::Value::String(uid.to_string());
        }
        let resp = self
            .http
            .post(format!("{}/webauthn/auth/begin", self.base_url))
            .json(&body)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn webauthn_auth_complete(
        &self,
        credential_id: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
        origin: &str,
        user_handle: Option<&str>,
    ) -> Result<Value, HearthError> {
        let mut body = serde_json::json!({
            "credential_id": credential_id,
            "client_data_json": client_data_json,
            "authenticator_data": authenticator_data,
            "signature": signature,
            "origin": origin,
        });
        if let Some(uh) = user_handle {
            body["user_handle"] = serde_json::Value::String(uh.to_string());
        }
        let resp = self
            .http
            .post(format!("{}/webauthn/auth/complete", self.base_url))
            .json(&body)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn check(resp: &reqwest::Response) -> Result<(), HearthError> {
        let status = resp.status().as_u16();
        if status < 400 {
            return Ok(());
        }
        Err(HearthError::Api {
            status,
            message: format!("{}", resp.status()),
            details: None,
        })
    }
}
