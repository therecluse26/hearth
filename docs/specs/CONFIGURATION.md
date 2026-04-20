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

tenants:
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
| `hot_tier_capacity` | integer | `10000` | Maximum number of entries cached in the in-memory hot tier. |
| `fsync` | bool | `true` | Whether to `fsync` WAL writes. **MUST be `true` in production.** Dev mode disables this for faster iteration. |

```yaml
storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true
```

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
| `port` | integer | *required* | SMTP port (25, 465, 587, or 1025 for Mailpit). |
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
| `issuer` | string | `"https://hearth.local"` | The `iss` claim in ID tokens and the `issuer` in the discovery document. Must be a valid URL. |
| `authorization_code_ttl` | duration | `"10m"` | How long an authorization code is valid after issuance. |
| `enforce_nonces` | bool | `false` | When `true`, authorization requests must include a unique `nonce` parameter. |

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
| `audience` | string | `"hearth"` | The `aud` claim value. |
| `access_token_ttl` | duration | `"15m"` | Access token lifetime. |
| `refresh_token_ttl` | duration | `"7d"` | Refresh token lifetime. |

```yaml
token:
  audience: "my-app"
  access_token_ttl: "30m"
  refresh_token_ttl: "14d"
```

### `auth`

Global authentication defaults. These apply to all tenants unless overridden per-tenant.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | `"24h"` | Default session lifetime. |
| `password_memory_cost` | integer | `65536` | Argon2id memory parameter in KiB (OWASP minimum). |
| `password_time_cost` | integer | `3` | Argon2id time parameter (iterations). |

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

## `tenants` Section

The `tenants` key is a map of **slug → configuration**. When present, Hearth manages tenants declaratively via YAML reconciliation at startup.

### Reconciliation Behavior

| Scenario | Action |
|----------|--------|
| YAML entry not in storage | **Created** as an Active tenant |
| YAML entry exists in storage | Config **updated** if changed |
| Storage tenant not in YAML | **Archived** (soft-deleted) |
| `tenants` key omitted entirely | No tenants → auto-create `"default"`; existing tenants left untouched |

Archived tenants appear in the Admin UI with an "Archived" badge and can be permanently deleted from there.

### Per-Tenant Fields

Each tenant entry supports:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | inherits `auth.session_ttl` | Per-tenant session lifetime override. |
| `password_memory_cost` | integer | inherits `auth.password_memory_cost` | Per-tenant Argon2id memory cost. |
| `password_time_cost` | integer | inherits `auth.password_time_cost` | Per-tenant Argon2id time cost. |
| `email` | object | — | Per-tenant email branding overrides. |
| `web` | object | — | Per-tenant UI theme overrides. |
| `auth` | object | — | Per-tenant auth policy (MFA, password policy, rate limits, token TTLs). |
| `applications` | map | — | Declarative OAuth 2.0 client definitions. |
| `organizations` | map | — | Declarative organization definitions. |

### `tenants.<name>.email`

| Field | Type | Description |
|-------|------|-------------|
| `branding.accent_color` | string | Override the email accent color for this tenant. |
| `branding.support_email` | string | Override the support email shown in footers. |
| `branding.custom_footer_text` | string | Override the email footer text. |

### `tenants.<name>.web`

| Field | Type | Description |
|-------|------|-------------|
| `theme` | string | Named theme override for this tenant's UI sessions. |
| `custom_css` | string | Path to a CSS file for this tenant's UI sessions. |

### `tenants.<name>.auth`

Per-tenant authentication policy. These are policy declarations stored in `TenantConfig` — enforcement happens in the identity engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mfa_required` | bool | `false` | Whether MFA is required for all users in this tenant. |
| `mfa_methods` | list | — | Allowed MFA methods: `"totp"`, `"webauthn"`. |
| `allowed_auth_methods` | list | — | Allowed login methods: `"password"`, `"magic_link"`, `"passkey"`. |
| `password_policy` | object | — | Password complexity requirements (see below). |
| `token` | object | — | Per-tenant token TTL overrides. |
| `rate_limit` | object | — | Per-tenant rate limit overrides. |

#### `tenants.<name>.auth.password_policy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_length` | integer | — | Minimum password length. Must be >= 1. |
| `require_uppercase` | bool | — | Require at least one uppercase letter. |
| `require_number` | bool | — | Require at least one digit. |
| `require_special` | bool | — | Require at least one special character. |

#### `tenants.<name>.auth.token`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access_token_ttl` | duration | inherits `token.access_token_ttl` | Per-tenant access token lifetime. |
| `refresh_token_ttl` | duration | inherits `token.refresh_token_ttl` | Per-tenant refresh token lifetime. |

#### `tenants.<name>.auth.rate_limit`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_failed_logins` | integer | — | Maximum failed login attempts before lockout. |
| `lockout_duration` | duration | — | How long to lock out after exceeding max failed logins. |

### `tenants.<name>.applications`

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
tenants:
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

### `tenants.<name>.organizations`

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
tenants:
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

tenants:
  customer-portal:
    session_ttl: "12h"
    web:
      theme: cloud
    auth:
      mfa_required: true
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
| `oidc` | `issuer` | `"https://hearth.local"` |
| `oidc` | `authorization_code_ttl` | `"10m"` |
| `oidc` | `enforce_nonces` | `false` |
| `token` | `issuer` | same as `oidc.issuer` |
| `token` | `audience` | `"hearth"` |
| `token` | `access_token_ttl` | `"15m"` |
| `token` | `refresh_token_ttl` | `"7d"` |
| `auth` | `session_ttl` | `"24h"` |
| `onboarding` | `enabled` | `true` |
