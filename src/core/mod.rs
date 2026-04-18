//! Core types and traits shared across all Hearth layers.
//!
//! Contains only types and traits — no logic, no state, no I/O.

mod error;
mod time;
mod types;

pub use error::CoreError;
pub use time::{Clock, FakeClock, SystemClock, Timestamp};
pub use types::{
    AuditEventId, ClientId, InvitationId, OrganizationId, SessionId, TenantId, UserId,
};
