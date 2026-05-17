//! Admin handlers for migration history and orphaned-realm recovery.

use super::*;
use crate::identity::reconcile::{MigrationHistoryRecord, OrphanRecord};

// ---------------------------------------------------------------------------
// View types
// ---------------------------------------------------------------------------

/// A single row on the migration history page.
pub struct MigrationRow {
    /// Source realm slug.
    pub source_slug: String,
    /// Destination realm slug.
    pub destination_slug: String,
    /// `"move"` or `"copy"`.
    pub kind: &'static str,
    /// Users migrated count.
    pub users_migrated: u64,
    /// Users skipped count (non-zero only on `CompletedWithSkips`).
    pub users_skipped: u64,
    /// Human-readable completion timestamp.
    pub completed_at: String,
    /// CSS token classes for the status badge.
    pub badge_class: String,
    /// Human-readable status label.
    pub status_label: String,
    /// Audit link for this source slug (pre-filtered query string).
    pub audit_filter: String,
}

impl MigrationRow {
    fn from_record(r: &MigrationHistoryRecord) -> Self {
        Self {
            source_slug: r.source_slug.clone(),
            destination_slug: r.destination_slug.clone(),
            kind: if r.move_semantics { "move" } else { "copy" },
            users_migrated: r.users_migrated,
            users_skipped: r.users_skipped,
            completed_at: r.completed_at.clone(),
            badge_class: r.status.badge_class().to_string(),
            status_label: r.status.label().to_string(),
            audit_filter: format!("action=MigrationCompleted&q={}", r.source_slug),
        }
    }
}

/// An orphan row shown on the migrations page.
pub struct OrphanRow {
    /// Realm slug.
    pub realm_slug: String,
    /// When the orphan was first detected.
    pub detected_at: String,
    /// Number of users at detection time.
    pub user_count: u64,
    /// Number of orgs at detection time.
    pub org_count: u64,
    /// Pre-filled YAML snippet the operator can paste into `hearth.yaml`.
    pub yaml_snippet: String,
}

impl OrphanRow {
    fn from_record(r: &OrphanRecord) -> Self {
        let yaml_snippet = format!(
            "# Add this block to an existing destination realm entry in hearth.yaml:\n  migrate_from: {}\n",
            r.realm_slug
        );
        Self {
            realm_slug: r.realm_slug.clone(),
            detected_at: r.detected_at.clone(),
            user_count: r.user_count,
            org_count: r.org_count,
            yaml_snippet,
        }
    }
}

// ---------------------------------------------------------------------------
// Migration list page
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/migrations/list.html")]
struct MigrationsListTemplate {
    migrations: Vec<MigrationRow>,
    orphans: Vec<OrphanRow>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/migrations`.
pub async fn admin_migrations_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    let migrations: Vec<MigrationRow> = state
        .migration_records
        .iter()
        .map(MigrationRow::from_record)
        .collect();

    let orphans: Vec<OrphanRow> = state
        .orphaned_realms
        .iter()
        .map(OrphanRow::from_record)
        .collect();

    render(&MigrationsListTemplate {
        migrations,
        orphans,
        chrome: true,
        active: "migrations",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Orphan resolve form
// ---------------------------------------------------------------------------

/// Form fields for the orphan resolve action.
#[derive(Debug, Deserialize)]
pub struct OrphanResolveForm {
    /// CSRF token (double-submit pattern).
    pub csrf: String,
    /// The orphan realm slug being resolved.
    pub slug: String,
    /// Destination realm slug (empty means "discard").
    pub destination: Option<String>,
}

/// HTMX partial rendered into `#yaml-result-{n}` after form submit.
#[derive(Template)]
#[template(path = "ui/admin/migrations/_orphan_yaml.html")]
struct OrphanYamlTemplate {
    slug: String,
    destination: Option<String>,
    yaml_migrate: String,
    yaml_discard: String,
}

/// `POST /ui/admin/migrations/orphans/resolve` — returns an HTMX fragment.
///
/// Does NOT mutate storage. Generates a YAML snippet the operator can paste
/// into `hearth.yaml` and apply on next restart.
pub async fn admin_migrations_orphan_resolve(
    State(_state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<OrphanResolveForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let destination = form.destination.filter(|d| !d.is_empty());

    let yaml_migrate = if let Some(dest) = destination.as_deref() {
        format!("realms:\n  {dest}:\n    migrate_from: {}\n", form.slug)
    } else {
        String::new()
    };

    let yaml_discard = format!("realms:\n  {}:\n    archive_drop: true\n", form.slug);

    render(&OrphanYamlTemplate {
        slug: form.slug,
        destination,
        yaml_migrate,
        yaml_discard,
    })
}
