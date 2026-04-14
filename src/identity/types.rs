//! Identity domain types: users, requests, and status.

use serde::{Deserialize, Serialize};

use crate::core::{SessionId, Timestamp, UserId};

/// The lifecycle status of a user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserStatus {
    /// Account is active and can authenticate.
    Active,
    /// Account is disabled by an administrator.
    Disabled,
    /// Account is awaiting email verification.
    PendingVerification,
}

/// A user record within a tenant.
///
/// Fields are private; access via accessor methods. Email is always stored
/// normalized (lowercase, trimmed, NFC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    id: UserId,
    email: String,
    display_name: String,
    status: UserStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl User {
    /// Creates a new user. Used internally by the identity engine.
    pub(crate) fn new(
        id: UserId,
        email: String,
        display_name: String,
        status: UserStatus,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            email,
            display_name,
            status,
            created_at,
            updated_at,
        }
    }

    /// Returns the user's unique identifier.
    pub fn id(&self) -> &UserId {
        &self.id
    }

    /// Returns the user's normalized email address.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the user's display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the user's account status.
    pub fn status(&self) -> UserStatus {
        self.status
    }

    /// Returns when the user was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the user was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the email. Used internally during user updates.
    pub(crate) fn set_email(&mut self, email: String) {
        self.email = email;
    }

    /// Updates the display name. Used internally during user updates.
    pub(crate) fn set_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
    }

    /// Updates the status. Used internally during user updates.
    pub(crate) fn set_status(&mut self, status: UserStatus) {
        self.status = status;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// An authentication session bound to a user.
///
/// Sessions have a configurable TTL and can be refreshed or revoked.
/// Fields are private; access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    created_at: Timestamp,
    expires_at: Timestamp,
    last_refreshed_at: Timestamp,
    revoked: bool,
}

impl Session {
    /// Creates a new session. Used internally by the identity engine.
    pub(crate) fn new(
        id: SessionId,
        user_id: UserId,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_refreshed_at: created_at,
            revoked: false,
        }
    }

    /// Returns the session's unique identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the ID of the user this session belongs to.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns when the session was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the session expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns when the session was last refreshed (UTC microseconds).
    pub fn last_refreshed_at(&self) -> Timestamp {
        self.last_refreshed_at
    }

    /// Returns whether the session is valid (not expired and not revoked).
    pub(crate) fn is_valid(&self, now: Timestamp) -> bool {
        !self.revoked && now < self.expires_at
    }

    /// Marks the session as revoked.
    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Refreshes the session by extending the TTL.
    pub(crate) fn refresh(&mut self, now: Timestamp, ttl_micros: i64) {
        self.expires_at = now.add_micros(ttl_micros);
        self.last_refreshed_at = now;
    }
}

/// Request to create a new user.
#[derive(Clone, Debug)]
pub struct CreateUserRequest {
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized).
    pub display_name: String,
}

/// Request to update an existing user.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateUserRequest {
    /// New email address (will be normalized).
    pub email: Option<String>,
    /// New display name (will be trimmed and NFC-normalized).
    pub display_name: Option<String>,
    /// New account status.
    pub status: Option<UserStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    #[test]
    fn user_accessors() {
        let id = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            id.clone(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            UserStatus::Active,
            now,
            now,
        );

        assert_eq!(user.id(), &id);
        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), now);
        assert_eq!(user.updated_at(), now);
    }

    #[test]
    fn user_serde_round_trip() {
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            UserStatus::PendingVerification,
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }

    #[test]
    fn user_status_serde_round_trip() {
        for status in [
            UserStatus::Active,
            UserStatus::Disabled,
            UserStatus::PendingVerification,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: UserStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn user_mutators() {
        let mut user = User::new(
            UserId::generate(),
            "old@example.com".to_string(),
            "Old Name".to_string(),
            UserStatus::Active,
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        user.set_email("new@example.com".to_string());
        user.set_display_name("New Name".to_string());
        user.set_status(UserStatus::Disabled);
        user.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(user.email(), "new@example.com");
        assert_eq!(user.display_name(), "New Name");
        assert_eq!(user.status(), UserStatus::Disabled);
        assert_eq!(user.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn update_request_default_is_all_none() {
        let req = UpdateUserRequest::default();
        assert!(req.email.is_none());
        assert!(req.display_name.is_none());
        assert!(req.status.is_none());
    }
}
