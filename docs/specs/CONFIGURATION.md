# Configuration Reference

Hearth is configured via a single YAML file. Every field is optional — an empty file (`{}`) is a valid, production-safe configuration with sensible defaults.

## File Location & Loading

Hearth looks for configuration in this order:

1. `--config` / `-c` CLI flag: `hearth serve -c /etc/hearth/config.yaml`
2. `HEARTH_CONFIG` environment variable: `HEARTH_CONFIG=/etc/hearth/config.yaml hearth serve`
3. `hearth.yaml` in the current working directory (auto-detected)

If no config file is found, all defaults apply.

## Environment Variable Expansion

Any string value in the YAML supports `${VAR_NAME}` substitution:

```yaml
email:
  smtp:
    password: "${SMTP_PASSWORD}"

realms:
  prod:
    applications:
      api:
        client_secret: "${API_CLIENT_SECRET}"
```

A referenced variable that is **not set** is a **startup error** — there is no silent fallback. This prevents accidental deployment with missing secrets.

## Duration Format

Duration fields accept human-readable strings with a single suffix:

| Suffix | Unit    | Example  | Equivalent         |
|--------|---------|----------|--------------------|
| `s`    | seconds | `"30s"`  | 30 seconds         |
| `m`    | minutes | `"15m"`  | 15 minutes         |
| `h`    | hours   | `"24h"`  | 24 hours           |
| `d`    | days    | `"7d"`   | 7 days             |

No spaces between the number and suffix. Fractional values are not supported — use a smaller unit instead (e.g. `"90s"` not `"1.5m"`).

---

## Top-Level Sections

### `server`

Network binding and TLS configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_address` | string | `"127.0.0.1"` | IP address to bind the HTTP(S) listener to. Use `"0.0.0.0"` for all interfaces. |
| `port` | integer | `8420` | TCP port for the main listener. |
| `tls_cert_path` | string | — | Path to a PEM-encoded TLS certificate. If set, `tls_key_path` MUST also be set. |
| `tls_key_path` | string | — | Path to the PEM-encoded private key for the TLS certificate. |
| `tls_client_ca_path` | string | — | Path to a CA certificate for client certificate verification (mTLS). |
| `tls_require_client_cert` | bool | `false` | When `true`, all connections must present a valid client certificate signed by `tls_client_ca_path`. |

When TLS is enabled, Hearth also spawns an HTTP → HTTPS redirect listener on `port - 1` (or port 80 when `port: 443`). Send `SIGHUP` to hot-reload the certificate and key without downtime.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"
```

### `storage`

Embedded storage engine tuning. These control WAL, memtable, and hot tier behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `data_dir` | string | `"./data"` | Directory for WAL files, SSTs, and metadata. Created if it does not exist. |
| `wal_max_size_bytes` | integer | `268435456` (256 MiB) | WAL file rotation threshold. |
| `memtable_flush_bytes` | integer | `67108864` (64 MiB) | Memtable size threshold before flushing to an SST file. |
| `hot_tier_capacity` | integer | auto | When set, uses this exact number of hot tier entries. When omitted, auto-sizes from system memory (or `hot_tier_max_memory` if set). |
| `hot_tier_max_memory` | integer | none | Maximum bytes to allocate for the hot tier. Overrides system memory detection during auto-sizing. Ignored when `hot_tier_capacity` is explicitly set. |
| `fsync` | bool | `true` | Whether to `fsync` WAL writes. **MUST be `true` in production.** Dev mode disables this for faster iteration. |

```yaml
storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true
  # Option A: explicit entry count
  hot_tier_capacity: 500000
  # Option B: memory budget (triggers auto-sizing, ignored when capacity is set)
  hot_tier_max_memory: 4294967296  # 4 GiB
```

### `cluster`

Multi-node Raft consensus configuration. **Omit this section entirely for single-node deployments** — when absent, Hearth runs in single-node mode with no clustering overhead, no extra port, and no Raft log.

When present, Hearth starts a Raft engine and participates in peer-to-peer log replication over mTLS-secured gRPC. All three TLS certificate fields are required — plaintext peer connections are unconditionally rejected.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `node_id` | integer | — | **Required.** This node's numeric ID. Must be unique across the cluster. Typically `1`, `2`, `3`, … |
| `peer_address` | string | `"127.0.0.1:8421"` | `host:port` this node listens on for inbound Raft RPCs from peers. Use a routable address in production (not loopback). |
| `peers` | list | `[]` | Known cluster peers. Each entry has `id` (integer) and `address` (string `host:port`). List all nodes except this one. |
| `tls_cert_path` | path | — | **Required.** Path to this node's PEM certificate (presented to peers during mTLS). |
| `tls_key_path` | path | — | **Required.** Path to this node's PEM private key. |
| `tls_ca_cert_path` | path | — | **Required.** Path to the CA certificate used to verify peer certificates. All nodes must share the same CA. |
| `read_lag_threshold_ms` | integer | `500` | Maximum follower replication lag in milliseconds before reads are refused. When exceeded, the caller receives a redirect to the leader's address. |

```yaml
cluster:
  node_id: 1
  peer_address: "10.0.0.1:8421"
  peers:
    - id: 2
      address: "10.0.0.2:8421"
    - id: 3
      address: "10.0.0.3:8421"
  tls_cert_path: "/etc/hearth/certs/node1.crt"
  tls_key_path:  "/etc/hearth/certs/node1.key"
  tls_ca_cert_path: "/etc/hearth/certs/ca.crt"
  read_lag_threshold_ms: 500   # optional — omit to use the default
```

**Write routing:** Writes that arrive on a follower return an error with the leader's address. Your load balancer or client should retry the write against that address. Writes go through Raft and are only acknowledged after quorum commit.

**Read routing:** Follower reads are served locally when replication lag is below `read_lag_threshold_ms`. When lag is exceeded, reads also return the leader's address for redirect.

**Bootstrap:** On first cluster startup, call the bootstrap API on the designated bootstrap node once all peers are reachable. See the [Clustering guide](../guides/clustering.md) for the step-by-step sequence.

**NTP requirement:** Hearth embeds `leader_timestamp` (wall-clock microseconds) in every Raft log entry to produce stable, monotonic timestamps across nodes. **NTP-synchronized clocks are a hard operational requirement for cluster mode.** Clock skew above 1 second will cause a startup warning; skew above several seconds will produce incorrect ordering of concurrent writes.

> **See also:** [Clustering guide](../guides/clustering.md) for bootstrap, quorum, cert generation, graceful shutdown, and backup strategy.

### `metrics`

Prometheus metrics endpoint configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Expose the `GET /metrics` Prometheus scrape endpoint. Set to `false` when metrics are collected via a sidecar agent instead of a direct scrape. |

```yaml
metrics:
  enabled: true
```

The `/metrics` endpoint returns metrics in Prometheus text exposition format (`text/plain; version=0.0.4`). It includes the following metric families:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hearth_http_request_duration_seconds` | histogram | `method`, `route`, `status` | HTTP request latency |
| `hearth_auth_attempts_total` | counter | `realm`, `outcome` | Authentication attempts by outcome (`success`/`failure`) |
| `hearth_tokens_issued_total` | counter | `realm`, `grant_type` | Tokens issued by OAuth 2.0 grant type |
| `hearth_active_sessions` | gauge | — | Current active session count across all realms |
| `hearth_storage_operation_duration_seconds` | histogram | `operation` | Storage write/scan latency |

### `observability`

Logging and tracing configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | string | `"info"` | Tracing log level filter. One of: `trace`, `debug`, `info`, `warn`, `error`. |
| `log_format` | string | `"text"` | Output format. `"text"` for human-readable, `"json"` for structured logging. |

```yaml
observability:
  log_level: "info"
  log_format: "json"
```

### `operational`

Operational limits and timeouts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `request_timeout_secs` | integer | `30` | Maximum time in seconds for a single HTTP request. |
| `shutdown_timeout_secs` | integer | `10` | Graceful shutdown timeout in seconds. |
| `max_connections` | integer | `1024` | Maximum concurrent TCP connections. |
| `queue_depth` | integer | `4096` | Internal work queue depth. |

```yaml
operational:
  request_timeout_secs: 60
  max_connections: 2048
```

### `branding`

Global UI and email branding. Controls the product name, logo, and visual theme across the admin UI and all outbound emails.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `product_name` | string | `"Hearth"` | Shown in logo alt text, page titles, and email subjects. |
| `logo_url` | string | built-in Hearth SVG | Logo image URL. Can be a remote URL (used directly in `<img>`) or a local file path (read at startup, served at `/ui/static/custom-logo`). Supported formats: SVG, PNG, JPEG. |
| `theme` | string | `"ember"` | Named UI theme. See [Themes](#themes) below. |
| `custom_css` | string | — | Path to a CSS file appended after the named theme. Use this to override `--ht-*` CSS variables without forking a theme. Read once at startup. |

#### Themes

| Name | Type | Description |
|------|------|-------------|
| `ember` | dark | Warm charcoal with orange accents (default) |
| `ocean` | dark | Deep blue with teal accents |
| `midnight` | dark | Purple/violet dark theme |
| `forest` | dark | Green-accented dark theme |
| `cloud` | light | Clean light theme |
| `parchment` | light | Warm light theme |

```yaml
branding:
  product_name: "Acme Auth"
  logo_url: "/opt/hearth/logo.svg"
  theme: ocean
  custom_css: "/etc/hearth/brand.css"
```

### `email`

Outbound email delivery for verification emails, password resets, magic links, and invitation notifications.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `transport` | string | `"log"` | Delivery transport. One of: `log`, `smtp`, `sendgrid`, `postmark`, `mailgun`, `mailtrap`. |
| `from` | string | — | Sender address for the `From:` header. **Required** when transport is not `log`. |
| `smtp` | object | — | SMTP-specific settings. Required when `transport: smtp`. |
| `sendgrid` | object | — | SendGrid API settings. Required when `transport: sendgrid`. |
| `postmark` | object | — | Postmark API settings. Required when `transport: postmark`. |
| `mailgun` | object | — | Mailgun API settings. Required when `transport: mailgun`. |
| `mailtrap` | object | — | Mailtrap API settings. Required when `transport: mailtrap`. |
| `branding` | object | — | Global email branding defaults (accent color, support email, footer text). |
| `templates_dir` | string | — | Directory containing custom Tera email templates that override compiled defaults. |

#### `email.smtp`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | *required* | SMTP server hostname. |
| `port` | integer | *required* | SMTP port (25, 465, 587, or 1025 for a local relay). |
| `encryption` | string | `"starttls"` | Transport encryption: `none`, `starttls`, `tls`. |
| `username` | string | — | SMTP AUTH username. Must be paired with `password`. |
| `password` | string | — | SMTP AUTH password. Must be paired with `username`. |

#### `email.sendgrid`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | SendGrid API key. |

#### `email.postmark`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server_token` | string | *required* | Postmark server token. |

#### `email.mailgun`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | Mailgun API key. |
| `domain` | string | *required* | Sending domain (e.g. `mg.example.com`). |
| `region` | string | `"us"` | API region: `us` or `eu`. |

#### `email.mailtrap`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | Mailtrap API key. |
| `inbox_id` | integer | — | Inbox ID for sandbox/testing mode. When set, emails go to the sandbox API. |

#### `email.branding`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `accent_color` | string | `"#E85D04"` | Brand color used in email templates. |
| `support_email` | string | — | Support email shown in email footers. |
| `custom_footer_text` | string | — | Custom text appended to email footers. |

```yaml
email:
  transport: smtp
  from: "Hearth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
  branding:
    accent_color: "#4F46E5"
    support_email: "support@example.com"
```

### `oidc`

OIDC Discovery metadata and authorization code behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | — | The `iss` claim in ID tokens and the `issuer` in the discovery document. Must be a valid HTTPS URL. **Required in production — no safe default exists.** |
| `authorization_code_ttl` | duration | `"10m"` | How long an authorization code is valid after issuance. |
| `enforce_nonces` | bool | `true` | When `true`, authorization requests must include a unique `nonce` parameter. Disable only for legacy clients that cannot supply a nonce. |
| `require_pkce_for_confidential_clients` | bool | `true` | Require PKCE for confidential OAuth clients (RFC 9700 §2.1.1). Disable only for legacy clients that cannot supply `code_challenge`. |

```yaml
oidc:
  issuer: "https://auth.example.com"
  authorization_code_ttl: "5m"
  enforce_nonces: true
```

### `token`

JWT issuance parameters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | `oidc.issuer` | The `iss` claim value. Defaults to `oidc.issuer` when omitted. Set this only if your token issuer differs from the OIDC issuer. |
| `audience` | string | `oidc.issuer` | The `aud` claim value. Defaults to `oidc.issuer` when omitted. Override only if your resource server expects a different audience (e.g. a separate API gateway URL). |
| `access_token_ttl` | duration | `"15m"` | Access token lifetime. |
| `refresh_token_ttl` | duration | `"7d"` | Refresh token lifetime. |

```yaml
token:
  audience: "my-app"
  access_token_ttl: "30m"
  refresh_token_ttl: "14d"
```

### `auth`

Global authentication defaults. These apply to all realms unless overridden per-realm.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | `"24h"` | Default session lifetime. |
| `password_memory_cost` | integer | `65536` | Argon2id memory parameter in KiB (OWASP minimum). |
| `password_time_cost` | integer | `3` | Argon2id time parameter (iterations). |
| `mfa_required` | bool | `false` | Whether MFA is required for all users. Per-realm `auth.mfa_required` overrides. |
| `passkey_requires_mfa` | bool | `false` | Whether passkey login requires an additional TOTP challenge. Per-realm `auth.passkey_requires_mfa` overrides. |

```yaml
auth:
  session_ttl: "12h"
  password_memory_cost: 131072
  password_time_cost: 4
```

### `onboarding`

First-run setup flow configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | When `true`, the `/ui/setup` flow is available until the first admin is created. Set to `false` to permanently disable. |
| `base_url` | string | — | Public base URL for verification-email links (e.g. `https://auth.example.com`). Falls back to the request `Host` header when unset. |
| `notification_email` | string | — | Email address that receives the setup URL on first boot (requires a working email transport). |

```yaml
onboarding:
  base_url: "https://auth.example.com"
  notification_email: "ops@example.com"
```

---

## `realms` Section

The `realms` key is a map of **slug → configuration**. When present, Hearth manages realms declaratively via YAML reconciliation at startup.

### Reconciliation Behavior

| Scenario | Action |
|----------|--------|
| YAML entry not in storage | **Created** as an Active realm |
| YAML entry exists in storage | Config **updated** if changed |
| Storage realm not in YAML | **Archived** (soft-deleted) |
| `realms` key omitted entirely | No realms → auto-create `"default"`; existing realms left untouched |

Archived realms appear in the Admin UI with an "Archived" badge and can be permanently deleted from there.

### Per-Realm Fields

Each realm entry supports:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | inherits `auth.session_ttl` | Per-realm session lifetime override. |
| `password_memory_cost` | integer | inherits `auth.password_memory_cost` | Per-realm Argon2id memory cost. |
| `password_time_cost` | integer | inherits `auth.password_time_cost` | Per-realm Argon2id time cost. |
| `email` | object | — | Per-realm email branding overrides. |
| `web` | object | — | Per-realm UI theme overrides. |
| `auth` | object | — | Per-realm auth policy (MFA, password policy, rate limits, token TTLs). |
| `applications` | map | — | Declarative OAuth 2.0 client definitions. |
| `organizations` | map | — | Declarative organization definitions. |

### `realms.<name>.email`

| Field | Type | Description |
|-------|------|-------------|
| `branding.accent_color` | string | Override the email accent color for this realm. |
| `branding.support_email` | string | Override the support email shown in footers. |
| `branding.custom_footer_text` | string | Override the email footer text. |

### `realms.<name>.web`

| Field | Type | Description |
|-------|------|-------------|
| `theme` | string | Named theme override for this realm's UI sessions. |
| `custom_css` | string | Path to a CSS file for this realm's UI sessions. |

### `realms.<name>.auth`

Per-realm authentication policy. These are policy declarations stored in `RealmConfig` — enforcement happens in the identity engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mfa_required` | bool | `false` | Whether MFA is required for all users in this realm. |
| `passkey_requires_mfa` | bool | `false` | Whether passkey (WebAuthn) login still requires a TOTP challenge. Passkeys are inherently multi-factor, but regulated environments (healthcare, finance) may require an additional TOTP step. When `true` and the user has TOTP enrolled, passkey login redirects to the MFA challenge page. When `true` but the user has no TOTP enrolled, login proceeds normally. |
| `mfa_methods` | list | — | Allowed MFA methods: `"totp"`, `"webauthn"`. |
| `allowed_auth_methods` | list | — | Allowed login methods: `"password"`, `"magic_link"`, `"passkey"`. |
| `password_policy` | object | — | Password complexity requirements (see below). |
| `token` | object | — | Per-realm token TTL overrides. |
| `rate_limit` | object | — | Per-realm rate limit overrides. |

#### `realms.<name>.auth.password_policy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_length` | integer | — | Minimum password length. Must be >= 1. |
| `require_uppercase` | bool | — | Require at least one uppercase letter. |
| `require_number` | bool | — | Require at least one digit. |
| `require_special` | bool | — | Require at least one special character. |

#### `realms.<name>.auth.token`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access_token_ttl` | duration | inherits `token.access_token_ttl` | Per-realm access token lifetime. |
| `refresh_token_ttl` | duration | inherits `token.refresh_token_ttl` | Per-realm refresh token lifetime. |

#### `realms.<name>.auth.rate_limit`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_failed_logins` | integer | — | Maximum failed login attempts before lockout. |
| `lockout_duration` | duration | — | How long to lock out after exceeding max failed logins. |

### `realms.<name>.applications`

Declarative OAuth 2.0 client definitions. Keyed by a **slug** (used to derive a deterministic `client_id` via UUID v5).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Human-readable application name. |
| `redirect_uris` | list | `[]` | Allowed OAuth 2.0 redirect URIs. |
| `grant_types` | list | `["authorization_code"]` | Allowed grant types: `authorization_code`, `client_credentials`, `refresh_token`, `device_code`. |
| `confidential` | bool | `false` | Whether this is a confidential client (has a client secret). |
| `client_secret` | string | — | Client secret. Supports `${ENV_VAR}` substitution. **Required** when `confidential: true`. Hashed with Argon2id before storage. |

Reconciliation:
- New slug → client **created** with deterministic UUID
- Existing slug → `name`, `redirect_uris`, `grant_types` **updated** if changed
- Removed slug → client **archived**

```yaml
realms:
  prod:
    applications:
      dashboard:
        name: "Dashboard"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
      api-service:
        name: "API Service"
        confidential: true
        client_secret: "${API_CLIENT_SECRET}"
        grant_types:
          - client_credentials
```

### `realms.<name>.organizations`

Declarative organization definitions. Keyed by **slug**. Members and invitations are managed at runtime — not via YAML.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Human-readable organization name. |
| `description` | string | — | Optional description. |
| `config.max_members` | integer | — | Maximum number of members allowed. `null`/omitted means unlimited. |

Reconciliation:
- New slug → organization **created**
- Existing slug → `name`, `description`, `config` **updated** if changed
- Removed slug → organization left in place (not archived, since it may have runtime members)

```yaml
realms:
  prod:
    organizations:
      acme-corp:
        name: "Acme Corporation"
        description: "Enterprise customer"
        config:
          max_members: 500
      beta-testers:
        name: "Beta Testers"
```

### `realms.<name>.rbac`

Declarative role, permission, group, and scope setup for the realm's RBAC model. See [`AUTHORIZATION.md`](./AUTHORIZATION.md) for the semantic model and [`AUTHZ_EXPANSION.md`](./AUTHZ_EXPANSION.md) for the full registry, scope-bundle, and claim-profile surfaces.

**Authoring model:** permissions, roles, and scope bundles are YAML-only. The admin UI displays them read-only. Runtime data (group memberships, user role assignments, user extras, OAuth consents) is admin-UI-managed. A YAML reload hot-swaps the registry via `ArcSwap`; dangling references are handled lazily (fail-closed at resolution).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `permissions` | array of permission | `[]` | Permission definitions. See rules below. |
| `permissions[].name` | string | *required* | Permission identifier. Must contain `.`, must not contain `:`. Pattern: `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$`. ≤128 chars. Reserved namespace `hearth.*` rejected. Single-word names (e.g. `admin`) rejected — use `system.admin`. |
| `permissions[].display_name` | string | *required* | Human-readable label for admin UI and consent screens. |
| `permissions[].description` | string | — | Optional longer explanation. |
| `permissions[].category` | string | — | Optional tag for admin UI grouping. |
| `roles` | array of role | `[]` | Role definitions. |
| `roles[].name` | string | *required* | Role identifier, unique per realm. |
| `roles[].scope_kind` | `realm` \| `organization` \| `any` | `realm` | Controls where this role may be assigned. Realm-kind roles cannot be assigned at org scope and vice versa; `any` accepts either. |
| `roles[].permissions` | array of strings | `[]` | Permission names granted by this role. All must be declared in the realm's `permissions` list. |
| `roles[].parents` | array of strings | `[]` | Parent role names. Resolution unions parent permissions (composition depth capped at 10, cycle-detected). |
| `roles[].description` | string | — | Optional description for admin UI display. |
| `groups` | map of group | `{}` | Groups keyed by slug. Group memberships are runtime data (admin-UI-managed). |
| `groups.<slug>.name` | string | *required* | Human-readable name. |
| `groups.<slug>.description` | string | — | Optional description. |
| `scopes` | array of scope bundle | `[]` | OPTIONAL coarse-grained consent bundles. When a token request specifies `scope=<name>`, the user's effective permissions are intersected with the bundle's permissions (per AUTHZ_EXPANSION). A client may also request individual permission names directly as scopes without needing a bundle. |
| `scopes[].name` | string | *required* | Bundle identifier. Must contain `:`, must not contain `.`. Pattern: `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$`. ≤128 chars. Single-word names rejected. |
| `scopes[].display_name` | string | *required* | Shown on consent screens. |
| `scopes[].description` | string | — | Shown on consent screens. |
| `scopes[].permissions` | array of strings | *required* | Permission names this bundle expands to. All must be declared in the realm's `permissions` list. |
| `claims` | object | *(defaults)* | OPTIONAL override of the realm's token claim profile. Absent → default profile emits `roles`, `groups`, `permissions`, `oid` with their standard shapes. Note: under the layered profile model in [`AUTHZ_EXPANSION.md`](./AUTHZ_EXPANSION.md), `roles`, `groups`, AND `permissions` are gated `first_party_only: true` by default — third-party clients receive none of these by default. |
| `claims.mappings` | array of mapping | `[]` | Ordered list of claim mappings appended after the built-in defaults and evaluated under the **layered gate-aware fallback model** per (claim-name, token-target) tuple. NOT last-wins replacement — when a YAML override's release gates fail for a given context, evaluation falls back to the default mapping for the same (claim, target) rather than suppressing the claim entirely. See `AUTHZ_EXPANSION.md` §"Evaluation and merge model" for the authoritative rule. |
| `claims.mappings[].claim` | string | *required* | Target JWT claim name. Tier 1 claims (JWT-registered, identity, authorization, tenant-routing, OIDC flow, token-binding, client-identity, proof-of-possession, delegation-attestation, and verification-attestation claims) rejected at config load. See `AUTHZ_EXPANSION.md` §"Claim name tiers" for the full Tier 1 list. |
| `claims.mappings[].source` | enum | *required* | One of: `roles_from_assignments`, `groups_from_memberships`, `effective_permissions`, `org_context`, `canonical_user_field` (with `field` — closed enum of OIDC standard fields), `user_attribute` (with `attribute` — `User.attributes` map lookup, **disjoint from canonical**), `role_subset` (with `prefix`), `constant` (with `value`), `omit`. |
| `claims.mappings[].include_in_access_token` | bool | `true` | Whether this claim appears in access tokens. |
| `claims.mappings[].include_in_id_token` | bool | `true` | Whether this claim appears in ID tokens. |
| `claims.mappings[].include_in_userinfo` | bool | `false` | Whether this claim is emitted by the `/userinfo` endpoint. The merge model evaluates per (claim, token-target) — a YAML override gated for ID tokens does NOT suppress the default's UserInfo emission. |
| `claims.mappings[].first_party_only` | bool | `true` for Tier 3 (custom) claims; default of the overridden mapping otherwise | Release gate: emit only when `client.trust_level == FirstParty`. Tier 3 custom claims default to `true` (over-disclosure is opt-in). |
| `claims.mappings[].required_scopes` | array of strings | — | Release gate: if set, the **granted** scope set (post-resolution, not raw request) must include ≥1 of these for the claim to emit. |
| `claims.mappings[].allowed_clients` | array of strings | — | Release gate: if set, the requesting client's slug must be in this list. **Managed-client slugs only** — DCR-registered slugs are rejected at config load. |
| `protected_resources` | array of resource | `[]` | OPTIONAL RFC 8707 protected-resource registrations (e.g., MCP tool servers). Each resource owns its own scope namespace; scopes declared here are NOT realm-global and apply only when a token is issued with `aud` set to this resource's URI. See `AUTHZ_EXPANSION.md` §"Architectural Model" and `AGENT_AUTH.md` §2.5. |
| `protected_resources[].resource_uri` | string | *required* | Canonical URI of the protected resource (becomes the token `aud` claim). |
| `protected_resources[].display_name` | string | *required* | Shown on consent screens. |
| `protected_resources[].scopes` | array of scope bundle | `[]` | Resource-local scope bundles. Same shape as the realm-level `scopes` entries. Looked up only when a token request includes `resource = <this URI>`; the realm-level `scopes` block is NOT consulted under a resource. |
| `oauth_clients[].slug` | string | *required* | Realm-unique human-readable handle. Managed clients (declared in YAML) have admin-authored slugs; runtime-registered (DCR) clients have auto-generated slugs and cannot be referenced from `allowed_clients` mapper gates. |

**Example:**

```yaml
realms:
  prod:
    rbac:
      permissions:
        - { name: docs.view,       display_name: "View documents",   category: Documents }
        - { name: docs.edit,       display_name: "Edit documents",   category: Documents }
        - { name: docs.delete,     display_name: "Delete documents", category: Documents }
        - { name: billing.view,    display_name: "View billing",     category: Billing }
        - { name: billing.write,   display_name: "Manage billing",   category: Billing }
        - { name: system.admin,    display_name: "System administrator", category: System }

      roles:
        - name: docs.viewer
          scope_kind: realm
          permissions: [docs.view]
          description: "Read-only access to docs"
        - name: docs.editor
          scope_kind: realm
          permissions: [docs.view, docs.edit]
          parents: [docs.viewer]
        - name: docs.admin
          scope_kind: realm
          permissions: [docs.delete]
          parents: [docs.editor]
          description: "Full docs administration"
        - name: billing.admin
          scope_kind: organization
          permissions: [billing.view, billing.write]

      groups:
        engineering:
          name: "Engineering"
          description: "All engineers"
        leads:
          name: "Engineering Leads"

      scopes:
        # OPTIONAL — only define when you want coarse-grained consent bundling
        - name: read:docs
          display_name: "Read your documents"
          description: "View documents you own or have been shared with you."
          permissions: [docs.view]
        - name: manage:billing
          display_name: "Manage your billing"
          description: "View and update billing settings."
          permissions: [billing.view, billing.write]

    claims:
      # OPTIONAL — omit for default shape
      mappings:
        - { claim: groups,     source: omit }
        - { claim: department, source: user_attribute, attribute: dept }
```

The first user created in a realm is automatically assigned the seed `realm.admin` role (not configurable). All other role assignments happen at runtime via the admin API.

---

## Complete Example

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

observability:
  log_level: "info"
  log_format: "json"

branding:
  product_name: "Acme Auth"
  theme: ocean

email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "${SMTP_USER}"
    password: "${SMTP_PASS}"

oidc:
  issuer: "https://auth.example.com"

token:
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"

auth:
  session_ttl: "24h"

onboarding:
  base_url: "https://auth.example.com"

realms:
  customer-portal:
    session_ttl: "12h"
    web:
      theme: cloud
    auth:
      mfa_required: true
      passkey_requires_mfa: true
      mfa_methods: [totp, webauthn]
      password_policy:
        min_length: 12
        require_uppercase: true
        require_number: true
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "15m"
    applications:
      portal-app:
        name: "Customer Portal"
        redirect_uris:
          - "https://portal.example.com/callback"
        grant_types: [authorization_code, refresh_token]
    organizations:
      acme:
        name: "Acme Corp"
        config:
          max_members: 100

  internal:
    session_ttl: "8h"
    applications:
      api:
        name: "Internal API"
        confidential: true
        client_secret: "${INTERNAL_API_SECRET}"
        grant_types: [client_credentials]
```

---

## Defaults Table

Every field's default value at a glance.

| Section | Field | Default |
|---------|-------|---------|
| `server` | `bind_address` | `"127.0.0.1"` |
| `server` | `port` | `8420` |
| `server` | `tls_require_client_cert` | `false` |
| `cluster` | `peer_address` | `"127.0.0.1:8421"` |
| `cluster` | `read_lag_threshold_ms` | `500` |
| `storage` | `data_dir` | `"./data"` |
| `storage` | `wal_max_size_bytes` | `268435456` (256 MiB) |
| `storage` | `memtable_flush_bytes` | `67108864` (64 MiB) |
| `storage` | `hot_tier_capacity` | `10000` |
| `storage` | `fsync` | `true` |
| `observability` | `log_level` | `"info"` |
| `observability` | `log_format` | `"text"` |
| `operational` | `request_timeout_secs` | `30` |
| `operational` | `shutdown_timeout_secs` | `10` |
| `operational` | `max_connections` | `1024` |
| `operational` | `queue_depth` | `4096` |
| `branding` | `product_name` | `"Hearth"` |
| `branding` | `theme` | `"ember"` |
| `email` | `transport` | `"log"` |
| `email.smtp` | `encryption` | `"starttls"` |
| `email.mailgun` | `region` | `"us"` |
| `oidc` | `issuer` | required (no default) |
| `oidc` | `authorization_code_ttl` | `"10m"` |
| `oidc` | `enforce_nonces` | `true` |
| `oidc` | `require_pkce_for_confidential_clients` | `true` |
| `token` | `issuer` | same as `oidc.issuer` |
| `token` | `audience` | same as `oidc.issuer` |
| `token` | `access_token_ttl` | `"15m"` |
| `token` | `refresh_token_ttl` | `"7d"` |
| `auth` | `session_ttl` | `"24h"` |
| `auth` | `mfa_required` | `false` |
| `auth` | `passkey_requires_mfa` | `false` |
| `onboarding` | `enabled` | `true` |
