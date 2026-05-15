# Organizations Guide

**Audience:** developers and operators building B2B SaaS products where end customers are companies, teams, or tenants that each need their own membership, roles, and access boundaries within a shared realm.

An **Organization** in Hearth is a B2B customer grouping inside a realm. Users can belong to multiple organizations within the same realm, and RBAC role assignments can be scoped to a specific organization so that a user's permissions differ depending on which org context they are acting in.

## Organizations vs Realms

| | Realm | Organization |
|-|-------|-------------|
| Purpose | Top-level tenant / product boundary | Customer account within a product |
| Isolation | Complete (storage, signing keys, sessions) | Logical (shared realm storage) |
| Users | Each user belongs to exactly one realm | Users may belong to many orgs in the same realm |
| Typical mapping | One realm per product / environment | One org per customer company |

Use realms to separate completely independent products or environments. Use organizations when one product serves multiple customer companies under the same identity database.

## Organization roles

Every member has exactly one **organization role**:

| Role | Capabilities |
|------|-------------|
| `Owner` | Full control: delete org, manage members and their roles, manage settings. An org must always have at least one owner. |
| `Admin` | Manage members and settings; cannot delete the org. |
| `Member` | Basic membership; access to org resources. |

In addition, members may have **additional RBAC roles** scoped to the organization (see [RBAC: org-scoped assignments](rbac.md#5-assign-a-role-to-a-user-or-group)).

## Declaring organizations in config

Organizations listed under `realms.<name>.organizations:` in `hearth.yaml` are reconciled at startup — created if absent, updated if changed.

```yaml
realms:
  my-realm:
    organizations:
      acme-corp:
        name: "Acme Corp"
        description: "Acme account"
        config:
          max_members: 50
      beta-customer:
        name: "Beta Customer"
```

The YAML key (`acme-corp`) becomes the URL-safe slug. `max_members` is optional; omit it for unlimited membership. Members and invitations are runtime-only and cannot be seeded from YAML.

## Managing organizations via the Admin UI

All organization lifecycle operations are available in the Admin console at `/ui/admin/`. Select a realm from the sidebar, then choose **Organizations**.

### Create an organization

Navigate to **Organizations → New** and fill in the name, slug, and optional description. Slugs must be unique within the realm. See [Slug constraints](#slug-constraints) for the full rule set.

### Manage members

Open an organization's detail page and use the **Members** panel to:

- Add existing realm users as owners, admins, or members.
- Change a member's role.
- Remove a member.

An organization must always have at least one owner. Removing the last owner is rejected.

### Invite users by email

From the organization detail page, click **Invite Member** and enter an email address and desired role. Hearth generates a secure invitation token (SHA-256 hashed before storage, plaintext returned only once) and sends an invitation email if email delivery is configured.

- Invitations expire after 7 days.
- Pending invitations can be revoked or resent from the **Invitations** panel.
- When a user accepts an invitation, Hearth finds or creates the user account for that email address and adds them to the organization.
- Inviting an email address that already has a pending invitation for the same org returns a `DuplicateInvitation` error.
- An expired, already-accepted, or non-existent invitation token all return the same `InvitationInvalid` error (enumeration resistance — callers cannot distinguish the three cases).

## Org-scoped RBAC

When a user belongs to an organization, you can assign RBAC roles that are valid only within that org's context. Org-scoped assignments are invisible in tokens that lack the matching `oid` claim.

### Assign a role scoped to an organization

```bash
HEARTH_ADMIN="Authorization: Bearer <admin-token>"
REALM="X-Realm-ID: <realm-uuid>"

curl -X POST http://127.0.0.1:8420/admin/users/<user-id>/roles \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "<role-id>",
    "scope": {"type": "org", "org_id": "org_<uuid>"}
  }'
```

The `org_id` value is the full `org_`-prefixed organization ID (e.g., `org_550e8400-e29b-41d4-a716-446655440000`).

### Inspect org-scoped permissions for a user

The `GET /v1/me/permissions` endpoint resolves a user's effective roles, groups, and permissions and accepts an `org_id` query parameter to include org-scoped assignments:

```bash
curl "http://127.0.0.1:8420/v1/me/permissions?org_id=<org-uuid>" \
  -H "Authorization: Bearer <access-token>" \
  -H "$REALM"
```

For the admin debug view:

```bash
curl "http://127.0.0.1:8420/admin/users/<user-id>/effective-permissions?org_id=<org-uuid>" \
  -H "$HEARTH_ADMIN" -H "$REALM"
```

See [AUTHORIZATION.md §2.4](../specs/AUTHORIZATION.md) for the full org-scoped permission resolution algorithm and the `oid` JWT claim specification.

## Listing an organization's members

Use the Admin UI: open the organization's detail page and select the **Members** tab. The member list shows each user's organization role and any additional RBAC roles scoped to the org.

## Slug constraints

Slugs are the URL-safe identifier for an organization within a realm. The validation rules (`src/identity/validation.rs`) are:

| Rule | Constraint |
|------|-----------|
| Length | 3–63 characters |
| Characters | Lowercase ASCII alphanumeric and hyphens only |
| First/last character | Must be alphanumeric (not a hyphen) |
| Consecutive hyphens | Forbidden (`acme--corp` is rejected) |
| Uppercase | Rejected (`Acme-Corp` is rejected) |
| Underscores | Rejected (`acme_corp` is rejected) |

Slugs must also be unique within the realm. Once set, a slug cannot be changed via the Admin UI (changing it would break any external URLs that use it).

## Organization configuration

| Field | Default | Description |
|-------|---------|-------------|
| `max_members` | unlimited | Maximum number of active members. Invitation acceptance fails when the limit would be exceeded. |

## Cascading deletes

Deleting an organization removes:

- All membership records (both forward and reverse indexes).
- All pending, accepted, and revoked invitations (primary record, token index, email dedup index, and list index entries).
- The org slug index.
- The SCIM `externalId` mapping for the org (forward and reverse indexes), if the org was provisioned via SCIM.

Users themselves are **not** deleted — they remain in the realm. Realm-scoped role assignments for those users are also unaffected; only org-scoped RBAC assignments targeting this org are removed.

## Webhook events

The following webhook event types are emitted for organization lifecycle changes:

| Event | Trigger |
|-------|---------|
| `org_created` | Organization created |
| `org_updated` | Organization name, description, or config changed |
| `org_deleted` | Organization deleted |

Subscribe to these events via the [Webhooks guide](webhooks.md).
