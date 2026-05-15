//! Embedded webhook engine: CRUD for subscriptions and delivery log writes.

use std::sync::Arc;

use crate::core::{Clock, RealmId, WebhookDeliveryId, WebhookId};
use crate::storage::StorageEngine;

use super::error::WebhookError;
use super::keys;
use super::types::{
    CreateWebhookRequest, DeliveryQuery, DeliveryStatus, UpdateWebhookRequest, WebhookDelivery,
    WebhookQuery, WebhookSubscription, MIN_SECRET_LEN,
};
use super::WebhookEngine;

/// Storage-backed webhook engine.
pub struct EmbeddedWebhookEngine {
    storage: Arc<dyn StorageEngine>,
    clock: Arc<dyn Clock>,
}

impl EmbeddedWebhookEngine {
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }
}

impl WebhookEngine for EmbeddedWebhookEngine {
    fn create(&self, req: &CreateWebhookRequest) -> Result<WebhookSubscription, WebhookError> {
        if req.secret.len() < MIN_SECRET_LEN {
            return Err(WebhookError::SecretTooShort);
        }
        validate_url(&req.url)?;

        let now = self.clock.now();
        let sub = WebhookSubscription {
            id: WebhookId::generate(),
            realm_id: req.realm_id.clone(),
            url: req.url.clone(),
            secret: req.secret.clone(),
            enabled: req.enabled,
            event_filters: req.event_filters.clone(),
            created_at: now,
            updated_at: now,
        };

        let key = keys::sub_key(&sub.id);
        let value = serde_json::to_vec(&sub).map_err(|e| WebhookError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage.put(&req.realm_id, &key, &value)?;
        Ok(sub)
    }

    fn get(&self, realm_id: &RealmId, id: &WebhookId) -> Result<WebhookSubscription, WebhookError> {
        let key = keys::sub_key(id);
        match self.storage.get(realm_id, &key)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| WebhookError::Serialization {
                    reason: e.to_string(),
                })
            }
            None => Err(WebhookError::NotFound { id: id.clone() }),
        }
    }

    fn update(
        &self,
        realm_id: &RealmId,
        id: &WebhookId,
        req: &UpdateWebhookRequest,
    ) -> Result<WebhookSubscription, WebhookError> {
        let mut sub = self.get(realm_id, id)?;

        if let Some(url) = &req.url {
            validate_url(url)?;
            sub.url = url.clone();
        }
        if let Some(secret) = &req.secret {
            if secret.len() < MIN_SECRET_LEN {
                return Err(WebhookError::SecretTooShort);
            }
            sub.secret = secret.clone();
        }
        if let Some(enabled) = req.enabled {
            sub.enabled = enabled;
        }
        if let Some(filters) = &req.event_filters {
            sub.event_filters = filters.clone();
        }
        sub.updated_at = self.clock.now();

        let key = keys::sub_key(id);
        let value = serde_json::to_vec(&sub).map_err(|e| WebhookError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage.put(realm_id, &key, &value)?;
        Ok(sub)
    }

    fn delete(&self, realm_id: &RealmId, id: &WebhookId) -> Result<(), WebhookError> {
        let key = keys::sub_key(id);
        // Verify it exists first so callers get a clear NotFound.
        self.get(realm_id, id)?;
        self.storage.delete(realm_id, &key)?;
        Ok(())
    }

    fn list(&self, query: &WebhookQuery) -> Result<Vec<WebhookSubscription>, WebhookError> {
        let prefix = keys::sub_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(&query.realm_id, &prefix, &end)?;

        let mut subs = Vec::with_capacity(entries.len());
        for entry in entries {
            let sub: WebhookSubscription =
                serde_json::from_slice(&entry.value).map_err(|e| WebhookError::Serialization {
                    reason: e.to_string(),
                })?;
            if !query.enabled_only || sub.enabled {
                subs.push(sub);
            }
        }
        Ok(subs)
    }

    fn record_delivery(&self, delivery: &WebhookDelivery) -> Result<(), WebhookError> {
        let key = keys::dlv_key(&delivery.webhook_id, delivery.attempted_at, &delivery.id);
        let value = serde_json::to_vec(delivery).map_err(|e| WebhookError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage.put(&delivery.realm_id, &key, &value)?;
        Ok(())
    }

    fn list_deliveries(&self, query: &DeliveryQuery) -> Result<Vec<WebhookDelivery>, WebhookError> {
        let (prefix, end) = match &query.webhook_id {
            Some(wid) => {
                let p = keys::dlv_scan_prefix_for_webhook(wid);
                let e = keys::prefix_end(&p);
                (p, e)
            }
            None => {
                let p = keys::dlv_scan_prefix();
                let e = keys::prefix_end(&p);
                (p, e)
            }
        };

        let entries = self.storage.scan(&query.realm_id, &prefix, &end)?;
        // Default to 1000 to avoid unbounded allocations when no limit is supplied.
        let limit = query.limit.unwrap_or(1_000);

        let mut deliveries = Vec::with_capacity(entries.len().min(limit));
        for entry in entries.into_iter().rev().take(limit) {
            let d: WebhookDelivery =
                serde_json::from_slice(&entry.value).map_err(|e| WebhookError::Serialization {
                    reason: e.to_string(),
                })?;
            deliveries.push(d);
        }
        Ok(deliveries)
    }
}

/// Creates a new delivery record with status Success for internal use.
pub(crate) fn make_delivery(
    webhook_id: WebhookId,
    realm_id: RealmId,
    event_id: crate::core::AuditEventId,
    attempt: u32,
    status: DeliveryStatus,
    response_status: Option<u16>,
    error_message: Option<String>,
    attempted_at: crate::core::Timestamp,
) -> WebhookDelivery {
    WebhookDelivery {
        id: WebhookDeliveryId::generate(),
        webhook_id,
        realm_id,
        event_id,
        attempt,
        status,
        response_status,
        error_message,
        attempted_at,
    }
}

fn validate_url(url: &str) -> Result<(), WebhookError> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(WebhookError::InvalidUrl {
            reason: "URL must begin with http:// or https://".to_string(),
        });
    }
    if url.len() > 2048 {
        return Err(WebhookError::InvalidUrl {
            reason: "URL exceeds 2048 characters".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditAction;
    use crate::core::{FakeClock, Timestamp};
    use crate::storage::EmbeddedStorageEngine;
    use std::sync::Arc;

    fn make_engine() -> EmbeddedWebhookEngine {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = crate::storage::StorageConfig::dev(temp_dir.path().to_path_buf());
        // Leak the temp_dir so the storage files outlive this function.
        std::mem::forget(temp_dir);
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        EmbeddedWebhookEngine::new(storage, clock)
    }

    #[test]
    fn create_and_get_webhook() {
        let engine = make_engine();
        let realm = RealmId::generate();
        let req = CreateWebhookRequest {
            realm_id: realm.clone(),
            url: "https://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![AuditAction::UserCreated],
        };
        let sub = engine.create(&req).expect("create");
        assert_eq!(sub.url, "https://example.com/hook");
        assert!(sub.enabled);
        assert_eq!(sub.event_filters, vec![AuditAction::UserCreated]);

        let fetched = engine.get(&realm, &sub.id).expect("get");
        assert_eq!(fetched, sub);
    }

    #[test]
    fn create_rejects_short_secret() {
        let engine = make_engine();
        let realm = RealmId::generate();
        let req = CreateWebhookRequest {
            realm_id: realm,
            url: "https://example.com/hook".to_string(),
            secret: "short".to_string(),
            enabled: true,
            event_filters: vec![],
        };
        assert!(matches!(
            engine.create(&req),
            Err(WebhookError::SecretTooShort)
        ));
    }

    #[test]
    fn create_rejects_bad_url() {
        let engine = make_engine();
        let realm = RealmId::generate();
        let req = CreateWebhookRequest {
            realm_id: realm,
            url: "ftp://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![],
        };
        assert!(matches!(
            engine.create(&req),
            Err(WebhookError::InvalidUrl { .. })
        ));
    }

    #[test]
    fn update_webhook() {
        let engine = make_engine();
        let realm = RealmId::generate();
        let req = CreateWebhookRequest {
            realm_id: realm.clone(),
            url: "https://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![],
        };
        let sub = engine.create(&req).expect("create");
        let update = UpdateWebhookRequest {
            enabled: Some(false),
            ..Default::default()
        };
        let updated = engine.update(&realm, &sub.id, &update).expect("update");
        assert!(!updated.enabled);
    }

    #[test]
    fn delete_webhook() {
        let engine = make_engine();
        let realm = RealmId::generate();
        let req = CreateWebhookRequest {
            realm_id: realm.clone(),
            url: "https://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![],
        };
        let sub = engine.create(&req).expect("create");
        engine.delete(&realm, &sub.id).expect("delete");
        assert!(matches!(
            engine.get(&realm, &sub.id),
            Err(WebhookError::NotFound { .. })
        ));
    }

    #[test]
    fn list_webhooks() {
        let engine = make_engine();
        let realm = RealmId::generate();
        for i in 0..3 {
            let req = CreateWebhookRequest {
                realm_id: realm.clone(),
                url: format!("https://example.com/hook{i}"),
                secret: "super-secret-key-16+".to_string(),
                enabled: i % 2 == 0,
                event_filters: vec![],
            };
            engine.create(&req).expect("create");
        }
        let all = engine
            .list(&WebhookQuery {
                realm_id: realm.clone(),
                enabled_only: false,
            })
            .expect("list");
        assert_eq!(all.len(), 3);

        let active = engine
            .list(&WebhookQuery {
                realm_id: realm,
                enabled_only: true,
            })
            .expect("list enabled");
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn subscription_matches_filters() {
        let sub = WebhookSubscription {
            id: WebhookId::generate(),
            realm_id: RealmId::generate(),
            url: "https://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![AuditAction::UserCreated],
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        };
        assert!(sub.matches(&AuditAction::UserCreated));
        assert!(!sub.matches(&AuditAction::UserDeleted));
    }

    #[test]
    fn subscription_empty_filter_matches_all() {
        let sub = WebhookSubscription {
            id: WebhookId::generate(),
            realm_id: RealmId::generate(),
            url: "https://example.com/hook".to_string(),
            secret: "super-secret-key-16+".to_string(),
            enabled: true,
            event_filters: vec![],
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        };
        assert!(sub.matches(&AuditAction::UserCreated));
        assert!(sub.matches(&AuditAction::UserDeleted));
        assert!(sub.matches(&AuditAction::RealmDeleted));
    }
}
