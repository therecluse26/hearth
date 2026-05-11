//! AdminClient — user and realm CRUD operations.

use crate::error::HearthError;
use crate::types::*;

/// Client for Hearth admin operations (user and realm CRUD).
///
/// Requires an admin access token obtained via `/admin/bootstrap`.
pub struct AdminClient {
    base_url: String,
    realm_id: String,
    http: reqwest::Client,
}

impl AdminClient {
    pub fn new(
        base_url: impl Into<String>,
        admin_token: impl Into<String>,
        realm_id: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let realm_id = realm_id.into();
        let admin_token = admin_token.into();
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    "X-Realm-ID",
                    reqwest::header::HeaderValue::from_str(&realm_id).expect("valid realm id"),
                );
                h.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {admin_token}"))
                        .expect("valid token"),
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
    // Users
    // ------------------------------------------------------------------

    pub async fn create_user(&self, req: &CreateUserRequest) -> Result<User, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/users", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn list_users(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PageResponse<User>, HearthError> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .http
            .get(format!("{}/admin/users", self.base_url))
            .query(&params)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn get_user(&self, user_id: &str) -> Result<User, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/users/{user_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        req: &UpdateUserRequest,
    ) -> Result<User, HearthError> {
        let resp = self
            .http
            .put(format!("{}/admin/users/{user_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/users/{user_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Realms
    // ------------------------------------------------------------------

    pub async fn create_realm(&self, req: &CreateRealmRequest) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .post(format!("{}/admin/realms", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn list_realms(&self) -> Result<Vec<Realm>, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/realms", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        let val: serde_json::Value = resp.json().await?;
        if let Some(items) = val.get("items").and_then(|i| i.as_array()) {
            Ok(serde_json::from_value(serde_json::Value::Array(items.clone()))?)
        } else {
            Ok(serde_json::from_value(val)?)
        }
    }

    pub async fn get_realm(&self, realm_id: &str) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .get(format!("{}/admin/realms/{realm_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn update_realm(
        &self,
        realm_id: &str,
        req: &UpdateRealmRequest,
    ) -> Result<Realm, HearthError> {
        let resp = self
            .http
            .put(format!("{}/admin/realms/{realm_id}", self.base_url))
            .json(req)
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(resp.json().await?)
    }

    pub async fn delete_realm(&self, realm_id: &str) -> Result<(), HearthError> {
        let resp = self
            .http
            .delete(format!("{}/admin/realms/{realm_id}", self.base_url))
            .send()
            .await?;
        Self::check(&resp)?;
        Ok(())
    }

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
