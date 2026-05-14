# Client-scoped roles

**Audience:** Hearth operators migrating from Keycloak, or anyone who wants per-OAuth-client role visibility on a single Hearth realm.

**Related normative specs:**
- [`AUTHORIZATION.md`](../specs/AUTHORIZATION.md) — RBAC model, role/permission grammar, scope semantics.
- [`AUTHZ_EXPANSION.md`](../specs/AUTHZ_EXPANSION.md) — `ClaimProfile`, release gates, layered evaluation.
- [`CONFIGURATION.md`](../specs/CONFIGURATION.md) — `realms.<id>.claims.mappings` YAML schema.

This guide is non-normative. Where it disagrees with the specs above, the specs win.

---

## TL;DR

Hearth has no first-class client-role namespace. To deliver one client a subset of realm roles in its access token:

1. Name the roles with a per-client prefix (e.g., `my-app.admin`, `my-app.viewer`).
2. Add a `role_subset` claim mapping to the realm's `claims.mappings`, gated on `allowed_clients`.
3. Other clients fall through to the default `roles` mapping (which emits **all** realm roles assigned to the user).

```yaml
realms:
  prod:
    claims:
      mappings:
        - claim: roles
          source:
            source: role_subset
            prefix: "my-app."
          allowed_clients: ["my-app"]
          include_in_access_token: true
          include_in_id_token: false
          include_in_userinfo: false
```

Verified with `hearth config validate <file>`; see [§6](#6-verifying-your-configuration).

The full recipe, behavior breakdown, Keycloak-importer gap, and known limitations are below.

> **Note on the nested `source:` shape.** Some shorthand examples in the spec docs ([`AUTHZ_EXPANSION.md`](../specs/AUTHZ_EXPANSION.md), [`CONFIGURATION.md`](../specs/CONFIGURATION.md)) show the source variant flattened onto the mapping (`source: role_subset, prefix: "..."`). The current implementation rejects that form — `ClaimMapping.source` deserializes as a nested `ClaimSource` value with `source` as its discriminator. Use the nested shape above. The spec docs need a follow-up correction; this guide reflects what `hearth config validate` accepts today.

---

## 1. Concept

In Keycloak, every OAuth client carries its own role namespace. The `admin` role on client `my-app` and the `admin` role on client `other-app` are distinct entities: each is scoped to its own client, and a user's token for `my-app` carries only `my-app`'s view of the role set.

Hearth intentionally does **not** model client-scoped roles as a first-class primitive. Roles live at the realm tier (with optional org-scope narrowing — see [AUTHORIZATION.md §2.4](../specs/AUTHORIZATION.md)). Every role is a single, realm-unique name.

To still deliver "client A sees one role vocabulary, client B sees another," Hearth operators compose two existing primitives:

- **Naming convention.** Roles intended for a specific client are prefixed with that client's slug.
- **Claim profile mapping.** The realm's `ClaimProfile` declares a per-client `role_subset` override on the `roles` claim, gated by `allowed_clients` so the override only applies when that client requests a token.

The result is functionally equivalent to Keycloak's client-role view in the `roles` claim, without introducing a second role-namespace concept in the data model. The trade-off is that the realm-wide role list still contains all the prefixed names — there is no per-client isolation at the admin-UI tier (see [§5 Known limitations](#5-known-limitations)).

---

## 2. Naming convention

Pick a prefix per client and apply it consistently. Recommended shape:

```
<client-slug>.<role-name>
```

Examples:

| Client slug   | Role names                                       |
| ------------- | ------------------------------------------------ |
| `my-app`      | `my-app.admin`, `my-app.editor`, `my-app.viewer` |
| `billing`     | `billing.read`, `billing.write`                  |
| `partner-api` | `partner-api.support`, `partner-api.readonly`    |

Constraints worth knowing:

- Role names are validated as `[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*` (see [AUTHORIZATION.md §2.5](../specs/AUTHORIZATION.md) for the permission grammar; role names follow a similar shape).
- `.` is a readability separator, **not** a hierarchical operator. `my-app.admin` does not implicitly grant `my-app.admin.users` or anything else.
- The prefix is operator-defined. The matcher in [§3](#3-claimprofile-recipe-yaml) does a literal `starts_with` check — leading-dot is conventional, not required.

Keep one prefix per logical application. Avoid overlapping prefixes (e.g., `my-app.` and `my-app-admin.`), because `starts_with("my-app.")` will match both and that almost certainly is not what you wanted.

---

## 3. ClaimProfile recipe (YAML)

Append the override to `realms.<realm>.claims.mappings`. The default profile is always present as a fallback layer (see [AUTHZ_EXPANSION.md §"Evaluation and merge model"](../specs/AUTHZ_EXPANSION.md)), so this single entry is enough — you do **not** need to redeclare the built-in `roles` mapping for other clients.

```yaml
realms:
  prod:
    rbac:
      roles:
        - name: my-app.admin
          scope_kind: realm
          permissions: [my-app.docs.read, my-app.docs.write]
          description: "Full admin for the my-app client"
        - name: my-app.viewer
          scope_kind: realm
          permissions: [my-app.docs.read]
          description: "Read-only access for the my-app client"

    oauth_clients:
      my-app:
        name: "My App"
        slug: my-app                # used by allowed_clients below
        trust_level: first_party    # tighter default; see §3 note on third-party clients
        redirect_uris:
          - https://my-app.example.com/oauth/callback
        grant_types: [authorization_code]
        declared_scopes: [openid, profile]

    claims:
      mappings:
        - claim: roles
          source:
            source: role_subset
            prefix: "my-app."
          allowed_clients: ["my-app"]
          include_in_access_token: true
          include_in_id_token: false
          include_in_userinfo: false
          # Optional release gates (omit unless you need them):
          # first_party_only: false
          # required_scopes: [openid]
```

The `source` block carries the variant discriminator (`source: role_subset`) plus that variant's payload fields (`prefix:`). Other variants follow the same shape — see the [Source variants](#source-variants) table below.

**About `first_party_only` on the override.** The example above does not set `first_party_only`, so it defaults to `false` (see [`ClaimMapping`](../../src/identity/claims_config.rs) defaults). That means if the gated client `my-app` were registered as third-party, the override would still emit. The default `roles` mapping in the built-in profile is `first_party_only: true`, so without an override third-party clients receive no `roles` claim by default. If you want to preserve that posture for clients **other than** the gated one, you don't need to do anything — the override is gated by `allowed_clients`, so non-allowed clients fall back to the default. If you want to additionally restrict the override to first-party clients, set `first_party_only: true` on the override.

### What this does, claim by claim

When user `alice` (assigned `my-app.admin` and `internal.observer`) authenticates against client `my-app`:

| Token target   | Claim     | Mapping that wins              | Value emitted                  |
| -------------- | --------- | ------------------------------ | ------------------------------ |
| Access token   | `roles`   | YAML override (gate passes)    | `["my-app.admin"]`             |
| ID token       | `roles`   | Default (override has `include_in_id_token: false`) | `["my-app.admin", "internal.observer"]` |
| `/userinfo`    | `roles`   | Default (override has `include_in_userinfo: false`) | omitted (default is `first_party_only` only) |

When the same user authenticates against a different first-party client `internal-tools`:

| Token target   | Claim     | Mapping that wins                                   | Value emitted                           |
| -------------- | --------- | --------------------------------------------------- | --------------------------------------- |
| Access token   | `roles`   | Default (override gate fails: client slug ≠ my-app) | `["my-app.admin", "internal.observer"]` |

If you want `internal-tools` to also see a filtered view, add a second mapping with `prefix: "internal."` and `allowed_clients: ["internal-tools"]` — they evaluate independently per (claim, target) tuple.

### Source variants

The full set of `source.source` discriminators (see [`ClaimSource`](../../src/identity/claims_config.rs)):

| `source.source`            | Extra payload                     | Output                                                              |
| -------------------------- | --------------------------------- | ------------------------------------------------------------------- |
| `roles_from_assignments`   | —                                 | Array of all role names assigned to the user                        |
| `groups_from_memberships`  | —                                 | Array of group names                                                |
| `effective_permissions`    | —                                 | Array of resolved permission strings                                |
| `org_context`              | —                                 | The `oid` string for this token, or omitted                         |
| `canonical_user_field`     | `field: <closed enum>`            | OIDC profile field off `User` (e.g., `email`, `family_name`)        |
| `user_attribute`           | `attribute: <key>`                | Value of `User.attributes[<key>]`, or omitted if absent             |
| `role_subset`              | `prefix: <string>`                | Array of role names that `starts_with(prefix)` — **unstripped**     |
| `constant`                 | `value: <JSON value>`             | The literal JSON value                                              |
| `omit`                     | —                                 | Emits nothing (use to suppress a default mapping for a target)      |

### Filter behavior, exactly

The `RoleSubset` source **filters** the user's effective role list by `starts_with(prefix)` and emits matches **unchanged**. It does NOT strip the prefix.

Source: [`src/identity/claims_config.rs:151-160`](../../src/identity/claims_config.rs).

So in the example above, the access token's `roles` claim is `["my-app.admin"]`, not `["admin"]`. If your client code wants to compare against `"admin"` rather than `"my-app.admin"`, strip the prefix on the client side or post-process with a custom mapper in a follow-up release.

### Slug ≠ client_id

`allowed_clients` matches the OAuth client's **slug** (a stable, realm-unique handle declared in YAML), not its `client_id` UUID. The slug is the `slug:` field on the `oauth_clients` entry. Hearth resolves the slug to a `ClientId` at YAML load and compares the resolved id at evaluation time — see [`src/identity/claims_config.rs:124`](../../src/identity/claims_config.rs).

**Managed clients only.** Dynamic-client-registration (DCR) slugs are auto-generated and ephemeral; the config validator rejects DCR slugs in `allowed_clients` at load time. If you need to gate on a runtime-registered client, file a feature request — the current model expects allowlists to be admin-authored.

---

## 4. Keycloak migration: client roles are dropped

The Keycloak realm-export importer at [`src/identity/migration/keycloak.rs`](../../src/identity/migration/keycloak.rs) imports **realm roles only**. Client roles, composite-role parent links, groups, and required-actions are silently skipped (see the comment at `keycloak.rs:265`).

What this means in practice for an operator carrying a Keycloak export across:

1. **Re-create client roles as prefixed realm roles** in Hearth YAML (or via the admin API) before importing assignments. A Keycloak client role `admin` on client `my-app` becomes a Hearth realm role `my-app.admin`.
2. **Re-assign users to the renamed roles.** The importer reconstructs only assignments to roles that exist in the Keycloak `roles.realm` block; client-role assignments are dropped on the floor.
3. **Add the `role_subset` claim mapping** described in [§3](#3-claimprofile-recipe-yaml) so the client sees the filtered view in its access tokens.

Worked example. Keycloak realm export contains:

```jsonc
{
  "clients": [{ "clientId": "my-app", "enabled": true }],
  "roles": {
    "realm": [{ "name": "internal.observer" }],
    "client": {
      "my-app": [{ "name": "admin" }, { "name": "viewer" }]
    }
  },
  "users": [
    {
      "username": "alice",
      "realmRoles": ["internal.observer"],
      "clientRoles": { "my-app": ["admin"] }  // <-- dropped on import
    }
  ]
}
```

After running `hearth migrate keycloak`, Hearth has:

- realm role `internal.observer`
- user `alice` assigned `internal.observer`
- **No** trace of `my-app.admin`, `my-app.viewer`, or alice's `admin` assignment.

To complete the migration manually:

1. Create realm roles `my-app.admin` and `my-app.viewer` in Hearth.
2. Re-assign alice to `my-app.admin`.
3. Add the `role_subset` mapping for `my-app` per [§3](#3-claimprofile-recipe-yaml).

The importer's `MigrationReport.warnings` currently does NOT call out dropped client-role assignments. Operators are responsible for diffing the Keycloak export against the Hearth realm after import. A follow-up enhancement to surface a warning per dropped client-role assignment is tracked separately.

---

## 5. Known limitations

These are intentional trade-offs of the convention-based approach. None of them block the recipe from working, but operators should know about them.

1. **Role names appear in the realm-wide role list.** The admin UI's role browser shows every realm role, including all prefixed names. There is no per-client filter in the UI. If you have a dozen apps each with five prefixed roles, the realm role list shows sixty entries.

2. **No name-collision protection across prefixes.** Nothing in Hearth enforces "all `my-app.*` roles must be admin-authored together" or prevents a typo like `my-app-admin` from coexisting with `my-app.admin`. Treat naming as an operator discipline, not a guardrail.

3. **`RoleSubset` does not strip the prefix.** The receiving app must either tolerate the prefix in its `roles` claim or strip it client-side. Hearth has no built-in "strip prefix before emit" source today.

4. **No client-scoped permission grammar.** A permission like `my-app.docs.write` is still a flat string in Hearth's vocabulary. Two apps that want disjoint permission namespaces must apply the same prefix discipline at the permission tier — Hearth will not stop them from accidentally sharing names.

5. **Effective-roles resolution still walks the whole realm.** Adding many prefixed roles to a realm increases the per-issue resolution cost slightly. This is a constant factor — within the depth bounds in [AUTHORIZATION.md](../specs/AUTHORIZATION.md) — but worth noting for realms with thousands of roles.

6. **First-class client-scoped roles are tracked as a post-1.0 enhancement.** If operator feedback indicates the convention-based pattern is too painful, Hearth may add a `RoleScopeKind::Client` variant in a follow-up. Until then, the recipe above is the supported path.

---

## 6. Verifying your configuration

After editing `hearth.yaml`:

```bash
# Validates YAML schema and registry constraints, exits non-zero on error.
hearth config validate ./hearth.yaml

# Hot-reload the running server (or restart) so the new claim profile takes effect.
hearth config reload
```

End-to-end check with a real token:

```bash
# 1. Issue a token through the my-app OAuth flow (or use the dev bootstrap).
# 2. Decode the access token's payload:
TOKEN=$(... your access token ...)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.roles'
# Expected: only roles starting with "my-app."
```

If the `roles` claim contains roles outside your prefix, the override's release gates probably failed. Common causes:

- Slug mismatch: `allowed_clients: ["my-app"]` but the client's `slug:` is `MyApp` or empty.
- Client is third-party and you forgot to set `first_party_only: false`. The default profile gates `roles` on `first_party_only: true`; an override that fails its gates falls back to the default, which then also rejects third-party clients.
- Required scope missing: if you added `required_scopes`, the **granted** scope set (post-resolution, not requested) must include at least one entry.

The release-gate logic is covered by the unit tests at [`tests/claims_config.rs`](../../tests/claims_config.rs); read those for ground truth on edge cases.
