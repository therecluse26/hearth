# `hearth.yaml` Examples

This guide collects copy-paste-ready `hearth.yaml` snippets for common deployment patterns. Every
key is verified against `src/config/types.rs`. Use `${ENV_VAR_NAME}` syntax for secrets —
Hearth substitutes environment variables at startup and treats an unset variable as a fatal error.
All example URLs use `auth.example.com`.

> **Quick-start:** An empty file (`{}`) or no file at all is a valid configuration.
> Run `hearth serve --dev` in development — it enables in-memory storage and disables fsync so you
> never need a config file to get started.

---

## Quick Reference

| # | Title | Section |
|---|-------|---------|
| 1 | Zero-config / dev quickstart | [Part 1](#part-1--basics) |
| 2 | Minimal production | [Part 1](#part-1--basics) |
| 3 | Password login — basic | [Part 1](#part-1--basics) |
| 4 | Password login — strict policy | [Part 1](#part-1--basics) |
| 5 | Rate limiting + lockout | [Part 1](#part-1--basics) |
| 6 | Invite-only registration | [Part 1](#part-1--basics) |
| 7 | Magic link only | [Part 2](#part-2--passwordless) |
| 8 | Passkey / WebAuthn only | [Part 2](#part-2--passwordless) |
| 9 | Combined passwordless | [Part 2](#part-2--passwordless) |
| 10 | MFA required — TOTP | [Part 3](#part-3--mfa) |
| 11 | MFA — TOTP + WebAuthn | [Part 3](#part-3--mfa) |
| 12 | Passkey + TOTP backup | [Part 3](#part-3--mfa) |
| 13 | Google Sign In | [Part 4](#part-4--social-login--federation) |
| 14 | Google + GitHub | [Part 4](#part-4--social-login--federation) |
| 15 | Microsoft Azure AD (tenant) | [Part 4](#part-4--social-login--federation) |
| 16 | Apple Sign In | [Part 4](#part-4--social-login--federation) |
| 17 | Generic OIDC (Okta / PingFederate) | [Part 4](#part-4--social-login--federation) |
| 18 | Auto account-linking | [Part 4](#part-4--social-login--federation) |
| 19 | SMTP transport | [Part 5](#part-5--email-transports) |
| 20 | SendGrid | [Part 5](#part-5--email-transports) |
| 21 | Postmark | [Part 5](#part-5--email-transports) |
| 22 | Mailgun EU region | [Part 5](#part-5--email-transports) |
| 23 | HTTPS / TLS termination | [Part 6](#part-6--tls) |
| 24 | Mutual TLS (mTLS) | [Part 6](#part-6--tls) |
| 25 | Two realms — consumer + internal | [Part 7](#part-7--multi-tenancy) |
| 26 | Single realm with organizations (B2B) | [Part 7](#part-7--multi-tenancy) |
| 27 | Full B2B SaaS — multi-realm | [Part 7](#part-7--multi-tenancy) |
| 28 | Custom permissions + roles | [Part 8](#part-8--rbac--oauth) |
| 29 | OAuth scope bundles | [Part 8](#part-8--rbac--oauth) |
| 30 | Public OAuth client — SPA | [Part 8](#part-8--rbac--oauth) |
| 31 | Confidential OAuth client — M2M | [Part 8](#part-8--rbac--oauth) |
| 32 | First-party SSO — no consent | [Part 8](#part-8--rbac--oauth) |
| 33 | SCIM provisioning | [Part 9](#part-9--enterprise-integrations) |
| 34 | SAML SP registration | [Part 9](#part-9--enterprise-integrations) |
| 35 | Custom claim mappings | [Part 9](#part-9--enterprise-integrations) |
| 36 | Production observability | [Part 9](#part-9--enterprise-integrations) |
| 37 | Storage tuning | [Part 9](#part-9--enterprise-integrations) |
| 38 | Custom branding | [Part 10](#part-10--branding--complex-scenarios) |
| 39 | High-security / financial services | [Part 10](#part-10--branding--complex-scenarios) |
| 40 | Full enterprise kitchen sink | [Part 10](#part-10--branding--complex-scenarios) |

---

## Part 1 — Basics

### Example 1 — Zero-config / dev quickstart

**Audience:** developers running Hearth locally for the first time.

```yaml
{}
```

Start with:

```bash
hearth serve --dev
```

`--dev` enables in-memory storage (nothing is persisted), disables `fsync`, and binds to
`127.0.0.1:8420`. The bootstrap endpoint is available immediately:

```bash
curl -X POST http://127.0.0.1:8420/admin/bootstrap
```

- An empty YAML file and a missing file are treated identically — every field defaults.
- Never use `--dev` in production: data is lost on restart and fsync is off.

---

### Example 2 — Minimal production

**Audience:** operators deploying Hearth for the first time behind a TLS-terminating load balancer
or directly with TLS enabled.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 8420
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  trusted_proxies:
    - "10.0.0.0/8"          # CIDR ranges are not yet supported; list individual IPs
  trust_forwarded_proto: true

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true               # must be true — WAL durability guarantee

oidc:
  issuer: "https://auth.example.com"

token:
  audience: "my-app"
```

- `oidc.issuer` populates the `iss` claim in all JWTs and the OIDC Discovery document
  at `/.well-known/openid-configuration`. Must be reachable by clients.
- `token.audience` is the `aud` claim. Set it to match your application's expected audience.
- When TLS is enabled, Hearth spawns an HTTP→HTTPS redirect listener on `port - 1`
  (or port 80 when `port: 443`). Send `SIGHUP` to hot-reload the certificate.

---

### Example 3 — Traditional password login (basic)

**Audience:** operators wanting open registration with standard password auth and explicit Argon2id
tuning.

```yaml
auth:
  session_ttl: "24h"
  password_memory_cost: 65536  # Argon2id memory in KiB (OWASP minimum: 64 MiB = 65536)
  password_time_cost: 3        # Argon2id iterations

oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: open             # anyone may self-register
```

- `auth.*` at the top level sets global defaults inherited by all realms. Per-realm overrides
  go under `realms.<name>.auth.*`.
- `registration.mode: open` allows anyone to create an account. The default when `registration`
  is omitted is `disabled` — only admins can create users.
- Duration strings accept suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).

---

### Example 4 — Traditional password login (strict policy)

**Audience:** operators in regulated or enterprise environments that need password complexity rules
and expiry enforcement.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: open
      password_policy:
        min_length: 12
        require_uppercase: true
        require_number: true
        require_special: true
        not_username: true     # password must not equal or contain the display name
        not_email: true        # password must not equal or contain the email address
        history_depth: 12      # reject the last 12 passwords on change
        max_age_days: 90       # require reset after 90 days
```

- All `password_policy` fields are optional; omit any you don't need.
- `not_username` and `not_email` perform case-insensitive substring checks.
- `history_depth` stores Argon2id hashes of previous passwords — it does not store plaintext.
- `max_age_days` forces a password-reset flow; it does not lock the account.

---

### Example 5 — Rate limiting + lockout

**Audience:** operators hardening a public-facing login endpoint against credential-stuffing.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      rate_limit:
        max_failed_logins: 5      # failed attempts before lockout
        lockout_duration: "15m"   # locked for 15 minutes
```

- Rate limit fields live under `realms.<name>.auth.rate_limit`, not at the top level.
- Lockout is per-account (not per-IP). Combine with a WAF or reverse proxy for IP-level rate
  limiting.
- A locked account can be manually unlocked via the Admin UI or `PATCH /admin/users/{id}`.

---

### Example 6 — Closed / invite-only registration

**Audience:** operators running an internal or B2B product where user accounts must be
pre-approved.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: invite_only    # only users with a valid organization invitation may register
```

Valid `registration.mode` values:

| Value | Behavior |
|-------|----------|
| `disabled` | No self-registration; admins create users (default) |
| `open` | Anyone may register |
| `invite_only` | Must present a valid organization invitation |
| `domain_restricted` | Email must match `allowed_domains` |

For `domain_restricted`, add:

```yaml
      registration:
        mode: domain_restricted
        allowed_domains:
          - "example.com"
          - "subsidiary.example.com"
```

---

## Part 2 — Passwordless

### Example 7 — Magic link only

**Audience:** operators building consumer apps where password friction hurts conversion, or
internal tools where phishing resistance matters more than convenience.

```yaml
email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls          # none | starttls | tls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"  # used in magic-link URLs sent via email

realms:
  default:
    auth:
      allowed_auth_methods:
        - magic_link
      registration:
        mode: open
```

- `email` must be configured with a real transport; magic links cannot be delivered via the
  default `log` transport in production.
- `onboarding.base_url` (or `oidc.issuer`) is used to construct the clickable link in emails.
- Users who previously had passwords can no longer log in with them once `allowed_auth_methods`
  excludes `password`.

---

### Example 8 — Passkey / WebAuthn only

**Audience:** operators building high-assurance applications where phishing-resistant
authentication is required (FIDO2 / WebAuthn Level 2).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - passkey
      registration:
        mode: open
```

- Restricting `allowed_auth_methods` to `[passkey]` disables all other login methods for this
  realm; Hearth will reject password and magic-link login attempts with `401`.
- WebAuthn relying-party policy (user verification requirement, resident-key preference) is
  configured at runtime via the Admin API — these are not `hearth.yaml` keys.
- Passkey enrollment requires the user to complete at least one prior authentication; provision
  accounts via the admin API or an invitation flow.

---

### Example 9 — Combined passwordless (magic link + passkey)

**Audience:** operators who want a fully passwordless experience with a fallback for users whose
device does not support passkeys.

```yaml
email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - magic_link
        - passkey
      registration:
        mode: open
```

- Users are presented with both options on the login page; the UI highlights passkeys when the
  browser supports them.
- `password` is omitted from `allowed_auth_methods`, so password auth is disabled.
- Ensure `email` is configured — magic link delivery fails silently with the `log` transport.

---

## Part 3 — MFA

### Example 10 — MFA required globally (TOTP)

**Audience:** operators in security-conscious environments (SOC 2, HIPAA) who must enforce a
second factor for all users across all realms.

```yaml
auth:
  mfa_required: true       # global default — applies to every realm unless overridden

oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      mfa_methods:
        - totp             # time-based one-time password (Google Authenticator, Authy, etc.)
```

- `auth.mfa_required: true` at the top level enables MFA globally. Override per-realm with
  `realms.<name>.auth.mfa_required: false`.
- `mfa_methods` controls which second factors are accepted. When absent, all enrolled factors
  are accepted.
- Users without an enrolled factor are redirected to MFA enrollment on first login.

---

### Example 11 — MFA required (TOTP + WebAuthn)

**Audience:** operators who want users to choose their preferred second factor: TOTP app or a
hardware security key.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn         # security keys (YubiKey, etc.) used as a second factor
```

- `webauthn` as an MFA method means users authenticate with a password first, then confirm with
  a security key. This is distinct from `passkey` (which is a first-factor, passwordless flow).
- Users may enroll multiple factors; any enrolled and allowed factor satisfies the MFA gate.

---

### Example 12 — Passkey + TOTP backup

**Audience:** regulated environments (FedRAMP, PCI-DSS) that require an additional OTP challenge
even after a phishing-resistant passkey authentication.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - passkey
        - password          # keep password as fallback; remove if fully passkey-only
      passkey_requires_mfa: true   # enforce TOTP step after passkey authentication
      mfa_methods:
        - totp
```

- Passkeys are inherently multi-factor (possession + biometric). `passkey_requires_mfa: true`
  adds an explicit TOTP step on top — use only when a compliance control explicitly mandates it.
- Setting `passkey_requires_mfa: true` without configuring `mfa_methods` accepts all enrolled
  MFA factors (TOTP and WebAuthn hardware keys).

---

## Part 4 — Social Login / Federation

Federation providers are configured per-realm under `realms.<name>.federation.providers`. Each
provider entry is keyed by the operator-assigned name that appears in the login URL as
`?idp=<name>`.

### Example 13 — Google Sign In

**Audience:** operators adding Google as a social login provider for consumer or workspace apps.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm    # require local re-auth before linking (safe default)
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

- Register your OAuth app at <https://console.cloud.google.com> and set the redirect URI to
  `https://auth.example.com/v1/federation/callback`.
- `link_existing_accounts: confirm` (the default) requires the user to authenticate with their
  existing password before Hearth links the Google identity to their account.

---

### Example 14 — Google + GitHub (two providers)

**Audience:** operators who want users to choose their preferred social login method.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
        github:
          type: github
          client_id:     "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"
```

- Each provider key (`google`, `github`) becomes the `?idp=` value in the login URL and is
  shown as a button label on the login page (overridable with `display_name`).
- GitHub uses OAuth 2.0, not OIDC — Hearth handles the protocol difference automatically.

---

### Example 15 — Microsoft Azure AD (tenant-specific)

**Audience:** operators authenticating Microsoft 365 / Entra ID users from a specific tenant.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        azure:
          type: microsoft
          display_name: "Microsoft (Contoso)"
          # Pin to your tenant to prevent cross-tenant token acceptance.
          # Replace {tenant-id} with your Azure AD tenant GUID or domain.
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          client_id:     "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
```

- Without `issuer`, the `microsoft` preset accepts tokens from *any* Azure AD tenant — a
  security risk for single-tenant applications. Always set `issuer` in production.
- Azure maps the user's UPN to the `email` claim differently than standard OIDC. If email is
  not populated, add `claim_mappings: { email: "upn" }` to the provider block.

---

### Example 16 — Apple Sign In

**Audience:** operators building iOS/macOS apps or web apps that need "Sign in with Apple".

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      providers:
        apple:
          type: apple
          client_id:     "${APPLE_CLIENT_ID}"      # your App ID or Services ID
          client_secret: "${APPLE_CLIENT_SECRET}"  # JWT signed with your Apple private key
```

- Apple requires `client_secret` to be a short-lived JWT (ES256) signed with your Apple
  private key — not a static string. Generate it with the Apple developer tools and store it
  in the environment variable. It expires in at most 6 months.
- Register the redirect URI `https://auth.example.com/v1/federation/callback` in your Apple
  Services ID configuration.

---

### Example 17 — Generic OIDC connector (Okta / PingFederate)

**Audience:** operators integrating with an enterprise IdP that speaks OIDC but is not one of
the built-in presets.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        okta:
          type: oidc
          display_name: "Okta"
          # All four endpoint fields are required for type: oidc.
          issuer:                  "https://your-domain.okta.com"
          authorization_endpoint:  "https://your-domain.okta.com/oauth2/v1/authorize"
          token_endpoint:          "https://your-domain.okta.com/oauth2/v1/token"
          jwks_uri:                "https://your-domain.okta.com/oauth2/v1/keys"
          client_id:     "${OKTA_CLIENT_ID}"
          client_secret: "${OKTA_CLIENT_SECRET}"
          # Optional: override the default openid+email+profile scope set.
          scopes:
            - openid
            - email
            - profile
            - groups
```

For PingFederate, substitute Ping's well-known URLs. If the IdP uses non-standard claim names,
add a `claim_mappings` block:

```yaml
          claim_mappings:
            email: "upn"           # map Hearth's "email" field to the "upn" claim
            name:  "display_name"
```

- `type: oidc` requires all four endpoint fields (`issuer`, `authorization_endpoint`,
  `token_endpoint`, `jwks_uri`). For presets (`google`, `microsoft`, etc.) these are inferred.
- The optional `userinfo_endpoint` may be added for IdPs that return richer profile data there.

---

### Example 18 — Auto account-linking

**Audience:** operators who trust their federation providers' email verification and want a
frictionless first-login experience without a re-authentication prompt.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: auto    # link on verified email match without re-auth prompt
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

`link_existing_accounts` controls what happens when a federated email matches a local account:

| Value | Behavior |
|-------|----------|
| `disabled` | Never link — always JIT-provision a new account |
| `confirm` | Require local credential re-auth before linking (default; Keycloak-equivalent) |
| `auto` | Link immediately on verified email match — no re-auth step |

- Use `auto` only when you trust the upstream provider to verify email addresses (Google and
  Microsoft do; GitHub does not verify by default).
- `auto` removes the phishing-protection gate. A compromised upstream account can silently
  access the linked local account.

---

---

## Part 5 — Email Transports

All examples in this section assume `onboarding.base_url` is set (needed for verification links).
The `email.from` field is required for every production transport; it becomes the `From:` header.
Leave the transport unset (or set `transport: log`) in development — Hearth will write the email
content to the log instead of attempting delivery.

### Example 19 — SMTP

**Audience:** operators self-hosting email delivery via any SMTP relay (AWS SES SMTP, Postfix,
Mailpit, etc.).

```yaml
email:
  transport: smtp
  from: "Hearth Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls      # none | starttls | tls — default is starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- `encryption: starttls` (STARTTLS on port 587) is the default. Use `tls` for implicit TLS on
  port 465. Use `none` only against a local relay on a trusted network (e.g. Mailpit on `:1025`).
- `username` and `password` must either both be set or both be absent — the config validator
  enforces the pair.
- Store credentials in environment variables; never commit them to `hearth.yaml`.

---

### Example 20 — SendGrid

**Audience:** operators using the SendGrid v3 transactional email API.

```yaml
email:
  transport: sendgrid
  from: "Hearth Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- Create a restricted API key in the SendGrid dashboard with **Mail Send** permission only.
- The sending domain (`example.com` in the `from` address) must be verified in SendGrid's
  **Sender Authentication** settings, otherwise deliveries are rejected.

---

### Example 21 — Postmark

**Audience:** operators using Postmark for transactional email.

```yaml
email:
  transport: postmark
  from: "Hearth Auth <auth@example.com>"
  postmark:
    server_token: "${POSTMARK_SERVER_TOKEN}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- The field is `server_token`, not `api_key` — use the **Server API token** from your Postmark
  server dashboard, not the account-level API key.
- The sender domain must be verified in Postmark's **Sender Signatures** settings.

---

### Example 22 — Mailgun EU region

**Audience:** operators using Mailgun from an EU-based deployment who must keep email traffic
within EU infrastructure for data-residency compliance.

```yaml
email:
  transport: mailgun
  from: "Hearth Auth <auth@example.com>"
  mailgun:
    api_key: "${MAILGUN_API_KEY}"
    domain:  "mg.example.com"       # your Mailgun sending domain
    region:  eu                     # us (default) | eu

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- `domain` is required — it is the Mailgun sending domain (e.g. `mg.example.com`), not your
  application domain.
- `region: eu` routes API calls to `api.eu.mailgun.net`. Omit (or set `region: us`) for US
  infrastructure.
- Add `mg.example.com` as a verified domain in the Mailgun dashboard and configure the
  required DNS records (MX, SPF, DKIM) on `mg.example.com`.

---

## Part 6 — TLS

Hearth can terminate TLS itself using a PEM certificate and key. When `tls_cert_path` is set,
Hearth automatically starts an HTTP→HTTPS redirect listener on `port - 1` (or port 80 when
`port: 443`). Send `SIGHUP` to hot-reload the certificate without restarting the process.

For deployments that already terminate TLS at a load balancer or ingress, leave these fields
absent and configure `server.trusted_proxies` + `server.trust_forwarded_proto` instead.

### Example 23 — HTTPS / TLS termination

**Audience:** operators running Hearth directly on the internet without a separate TLS-terminating
reverse proxy.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

oidc:
  issuer: "https://auth.example.com"
```

- Both `tls_cert_path` and `tls_key_path` must be set together; specifying only one is a config
  error.
- With `port: 443`, the redirect listener binds to port 80 automatically.
- `SIGHUP` triggers a hot-reload: Hearth re-reads the certificate and key files without
  dropping existing connections. Use this with ACME/certbot hooks to rotate certificates.
- Use PEM format (the concatenated certificate chain, not just the leaf certificate).

---

### Example 24 — Mutual TLS (mTLS)

**Audience:** operators building machine-to-machine (M2M) APIs or zero-trust service meshes where
clients must present a certificate signed by a known CA.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 8420
  tls_cert_path:            "/etc/hearth/tls/server.crt"
  tls_key_path:             "/etc/hearth/tls/server.key"
  tls_client_ca_path:       "/etc/hearth/tls/client-ca.crt"
  tls_require_client_cert:  true

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

oidc:
  issuer: "https://auth.example.com"
```

- `tls_client_ca_path` sets the CA that signs client certificates. Hearth verifies the client
  certificate against this CA on every TLS handshake.
- `tls_require_client_cert: true` makes a missing or invalid client certificate a hard TLS
  rejection (no 401 response — the connection is dropped at the transport layer).
- `tls_require_client_cert: false` (default) with `tls_client_ca_path` set puts Hearth in
  *optional client cert* mode — the certificate is verified if presented but not required.
- The client CA file may contain multiple PEM-encoded certificates for CA rotation.

---

## Part 7 — Multi-Tenancy

Realms in Hearth are isolated identity namespaces: separate user stores, signing keys,
session pools, and OAuth clients. Declare them under the top-level `realms:` map; the key
becomes the realm's slug and display name.

A few structural notes:
- `realms.<name>.session_ttl` is a top-level override on the realm (not under `auth:`).
- `realms.<name>.auth.*` controls MFA, password policy, allowed methods, and rate limits.
- `realms.<name>.web.theme` selects the UI color theme for that realm's login pages.
- When `realms:` is present in YAML, Hearth manages realms declaratively: realms in storage
  but absent from YAML are archived automatically. When `realms:` is absent, realms are
  created via the API or the onboarding flow.

### Example 25 — Two realms (consumer + internal)

**Audience:** operators running a product with separate public-facing and internal/employee login
surfaces that need different session lifetimes, MFA postures, and visual themes.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  default_realm: consumer    # bare /ui/* URLs serve the consumer realm login page

realms:
  consumer:
    session_ttl: "24h"         # top-level per-realm override
    web:
      theme: ocean             # ember (default) | ocean | midnight | forest | cloud | slate
    auth:
      mfa_required: false
      registration:
        mode: open

  internal:
    session_ttl: "8h"
    web:
      theme: midnight
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: disabled         # admins provision internal accounts
```

- `session_ttl` at the realm level (not under `auth:`) overrides the global `auth.session_ttl`
  default.
- Realm slugs become the routing token: the consumer login page is at
  `/ui/realms/consumer/login`.
- `server.default_realm: consumer` makes `/ui/login` resolve to the consumer realm — useful
  when only one realm needs a vanity URL.
- Available themes: `ember` (dark, default), `ocean`, `midnight`, `forest`, `cloud` (light),
  `slate` (light).

---

### Example 26 — Single realm with organizations (B2B)

**Audience:** operators building a B2B SaaS product where a single Hearth realm serves multiple
customer organizations. Organizations group users and gate invite-based registration.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: smtp
  from: "Hearth Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

onboarding:
  base_url: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: invite_only       # users join only via org invitation

    organizations:
      acme-corp:
        name: "Acme Corporation"
        description: "Primary enterprise customer"
        config:
          max_members: 500      # hard cap; further invitations are rejected

      starter-co:
        name: "Starter Co"
        config:
          max_members: 10
```

- Organization slugs (the YAML map keys: `acme-corp`, `starter-co`) are reconciled with storage
  at startup. Changing a slug in YAML creates a new organization — the old one is not deleted
  automatically.
- `config.max_members` is optional; omit it for unlimited membership.
- Members and invitations are runtime-only: invite users via the Admin API or UI, not YAML.
- `registration.mode: invite_only` works with organizations: Hearth validates the invitation
  token against the target organization and adds the user as a member on acceptance.

---

### Example 27 — Full B2B SaaS (multi-realm, per-realm SCIM + branding + auth policy)

**Audience:** operators building a product that serves both external customers
(`customer-portal` realm) and internal staff (`internal-tools` realm), with SCIM provisioning
for enterprise customers, strict MFA for internal users, and separate branding for each surface.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: sendgrid
  from: "Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

onboarding:
  base_url: "https://auth.example.com"

branding:
  product_name: "MyApp"
  theme: ember                  # global default; realms can override

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  default_realm: customer-portal

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

realms:
  customer-portal:
    session_ttl: "12h"
    web:
      theme: ocean
      product_name: "MyApp Customer Portal"
    auth:
      mfa_required: false
      registration:
        mode: invite_only
    scim:
      bearer_token: "${SCIM_CUSTOMER_TOKEN}"   # SCIM provisioning for enterprise customers

    organizations:
      example-enterprise:
        name: "Example Enterprise"
        config:
          max_members: 1000

  internal-tools:
    session_ttl: "8h"
    web:
      theme: midnight
      product_name: "MyApp Internal"
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: disabled
      token:
        access_token_ttl: "5m"     # short-lived tokens for internal services
        refresh_token_ttl: "1d"
    scim:
      bearer_token: "${SCIM_INTERNAL_TOKEN}"
```

- Each realm is a fully isolated identity namespace: separate signing keys, user stores,
  sessions, and OAuth clients. Cross-realm SSO is not automatic — users must log in to each
  realm separately.
- `scim.bearer_token` enables the SCIM 2.0 provisioning endpoint at
  `/scim/v2/realms/<realm-slug>/`. Tokens are hashed with Argon2id before storage; the
  plaintext value is never persisted.
- `realms.<name>.web.product_name` scopes the UI title and email subjects to that realm's
  branding without affecting the global `branding.product_name`.
- `auth.token.access_token_ttl` / `auth.token.refresh_token_ttl` under a realm override the
  global `token.*` TTLs for that realm only.
- Add a `federation:` block to `customer-portal` to let enterprise customers log in via their
  corporate IdP (SAML/OIDC) without creating Hearth passwords.

---

## Part 8 — RBAC & OAuth

Custom permissions and roles are declared per-realm under `realms.<name>.permissions` and
`realms.<name>.roles`. Scope bundles map OAuth scope strings to permission sets. OAuth
applications are declared under `realms.<name>.applications`.

A few structural notes:
- Roles reference permission names, not definitions. A permission must exist in `permissions:`
  (or be a Hearth seed permission) before a role can reference it.
- `scope_kind: realm` (the default) issues the permission in the JWT for the whole realm.
  `scope_kind: organization` includes the active org context — use for per-customer isolation.
- `parents:` wires up role inheritance; child roles inherit all parent permissions.
- Public clients (`confidential: false`, the default) need no `client_secret`. Confidential
  clients (`confidential: true`) require `client_secret` — hashed with Argon2id, never stored
  in plaintext.

### Example 28 — Custom permissions + roles

**Audience:** operators who need fine-grained access control beyond Hearth's built-in
seed roles (`realm.admin`, `realm.member`, `org.owner`, `org.member`).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    permissions:
      - name: invoice.read
        display_name: "Read Invoices"
        description: "View invoices and line items"
        category: billing
      - name: invoice.write
        display_name: "Write Invoices"
        category: billing
      - name: invoice.approve
        display_name: "Approve Invoices"
        category: billing
      - name: report.run
        display_name: "Run Reports"
        category: analytics

    roles:
      - name: billing-viewer
        description: "Can read but not modify invoices"
        scope_kind: realm           # realm (default) | organization | any
        permissions:
          - invoice.read
          - report.run

      - name: billing-admin
        description: "Full billing control at realm level"
        scope_kind: realm
        parents:
          - billing-viewer          # inherits invoice.read + report.run
        permissions:
          - invoice.write
          - invoice.approve

      - name: org-billing-manager
        description: "Org-scoped billing role — one per customer org"
        scope_kind: organization    # org context included in the JWT
        permissions:
          - invoice.read
          - invoice.write
```

- Permissions are defined once and referenced by name in roles and scope bundles.
- `parents:` is resolved in two passes at startup so role order in the YAML list does not
  matter — parents may appear after their children.
- `scope_kind: organization` roles are only meaningful when the realm has organizations and the
  access token was issued with an active org context (`?org_id=<id>` on the authorization
  request).
- Hearth's seed permissions (`user.read`, `user.write`, `user.impersonate`, `session.revoke`)
  are always available; you do not need to redeclare them.

---

### Example 29 — OAuth scope bundles

**Audience:** operators who want clients to request coarse OAuth scopes (`billing`) while
Hearth expands them into fine-grained permissions inside the JWT.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    permissions:
      - name: invoice.read
        display_name: "Read Invoices"
      - name: invoice.write
        display_name: "Write Invoices"
      - name: report.run
        display_name: "Run Reports"

    scopes:
      - name: billing:read
        display_name: "Billing (read-only)"
        description: "View invoices and billing data"
        permissions:
          - invoice.read

      - name: billing
        display_name: "Billing (full access)"
        description: "Create, update, and approve invoices"
        permissions:
          - invoice.read
          - invoice.write

      - name: analytics
        display_name: "Analytics"
        permissions:
          - report.run
```

- A client that requests `scope=billing:read openid` receives a token with
  `permissions: ["invoice.read"]` embedded at issuance time — no runtime permission check
  needed.
- Scope bundles do not enforce that the _user_ has the underlying permissions; they only gate
  which permissions flow into the token for that authorization request. Assign roles to users
  for enforcement.
- `declared_scopes` on an application controls which scopes that client may request.

---

### Example 30 — Public OAuth client — SPA

**Audience:** operators registering a browser-based single-page application that uses
PKCE-protected authorization code flow with public credentials.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      my-spa:
        name: "My Single-Page App"
        redirect_uris:
          - "https://app.example.com/callback"
          - "https://app.example.com/silent-renew"
        grant_types:
          - authorization_code
          - refresh_token
        # confidential: false  (default — public clients have no client_secret)
        declared_scopes:
          - openid
          - profile
          - email
          - billing:read
```

- Hearth requires PKCE (`code_challenge` + `code_verifier`) for all public clients; the
  `authorization_code` flow without PKCE is rejected.
- `silent-renew` as a redirect URI supports token refresh via a hidden iframe in the browser.
- List only scopes the SPA actually needs in `declared_scopes`; requesting an undeclared scope
  at runtime is rejected.

---

### Example 31 — Confidential OAuth client — M2M

**Audience:** operators registering a backend service that authenticates to Hearth with its
own credentials (machine-to-machine), not on behalf of a user.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      billing-service:
        name: "Billing Microservice"
        confidential: true
        client_secret: "${BILLING_CLIENT_SECRET}"   # Argon2id-hashed before storage
        grant_types:
          - client_credentials
        declared_scopes:
          - billing
          - analytics
```

- `client_credentials` tokens are not tied to a user session. They carry the scopes
  requested at the time of the grant and are revocable via the token revocation endpoint.
- `client_secret` is stored as an Argon2id hash; the plaintext value is never persisted.
  Rotate it by changing the env var and restarting (or via the Admin API).
- Add `authorization_code` alongside `client_credentials` if the service also performs
  user-delegated flows.

---

### Example 32 — First-party SSO — no consent

**Audience:** operators whose app is first-party (they own both the auth server and the
client app), so the OAuth consent screen adds friction without adding security.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      main-app:
        name: "Main Application"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false   # skip the consent screen — first-party only
```

- `require_consent: false` means users are redirected directly to the `redirect_uri` after
  login without being shown the scope-grant screen.
- Only use this for apps you fully control. Third-party clients must go through consent so
  users can see what data they are granting access to.
- The field is named `require_consent`; setting it to `false` disables the prompt (double
  negative — read it as "require consent? no").

---

## Part 9 — Enterprise Integrations

### Example 33 — SCIM provisioning

**Audience:** operators whose enterprise customers provision and de-provision user accounts
from an identity provider (Okta, Azure AD, Workday) using the SCIM 2.0 protocol.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

realms:
  enterprise:
    scim:
      bearer_token: "${SCIM_TOKEN}"    # static token; Argon2id-hashed before storage
    auth:
      registration:
        mode: invite_only              # SCIM is the only provisioning path
```

- The SCIM endpoint is available at `/scim/v2/realms/enterprise/` once `bearer_token` is set.
  Configure this URL and the hashed token in your IdP's SCIM provisioning settings.
- `bearer_token` is stored as an Argon2id hash; the plaintext value is never persisted.
  Rotate it by updating the env var and restarting (or via the Admin API).
- Set `registration.mode: invite_only` (or `disabled`) so users cannot self-register and
  bypass the SCIM-controlled user lifecycle.

---

### Example 34 — SAML SP registration

**Audience:** operators who need Hearth to act as a SAML Identity Provider, issuing SAML
assertions to external service providers (Salesforce, Workday, internal wikis, etc.).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  enterprise:
    saml_service_providers:
      salesforce:
        entity_id: "https://saml.salesforce.com"
        acs_url: "https://salesforce.com/services/oauth2/callback"
        slo_url: "https://salesforce.com/services/auth/logout"
        nameid_format: emailAddress   # emailAddress | persistent | transient | unspecified
        sign_assertions: true
        sign_responses: false
        attribute_map:
          email: "User.Email"
          display_name: "User.Name"
          department: "User.Department"

      internal-wiki:
        entity_id: "https://wiki.internal.example.com/saml"
        acs_url: "https://wiki.internal.example.com/saml/acs"
        nameid_format: persistent
        sign_assertions: true
```

- `saml_service_providers` keys (e.g. `salesforce`) are the SP identifier in Hearth's routing.
- `entity_id` and `acs_url` are required; all other fields are optional.
- Hearth signs assertions with the realm's Ed25519 signing key. Download the realm's public
  key from `GET /v1/realms/<slug>/keys` in JWK format to configure trust in the SP.
- `attribute_map` maps Hearth's internal field names to the SAML attribute names the SP
  expects (`email` → `User.Email` in this example).
- Set `slo_url` to participate in SAML Single Logout; omit it to skip SLO support.

---

### Example 35 — Custom claim mappings

**Audience:** operators who need to add, rename, or gate custom claims in access tokens,
ID tokens, or the UserInfo endpoint beyond Hearth's default claim set.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    claims:
      mappings:
        # Embed assigned roles as a JSON array
        - claim: roles
          source: roles_from_assignments

        # Embed all effective permissions
        - claim: permissions
          source: effective_permissions

        # Map a canonical user field to a custom claim name
        - claim: preferred_username
          source: canonical_user_field
          field: preferred_username

        # Expose a profile attribute stored on the user record
        - claim: department
          source: user_attribute
          attribute: department
          include_in_access_token: true
          include_in_id_token: true
          include_in_userinfo: true

        # Inject a static constant for all tokens issued by this realm
        - claim: iss_env
          source: constant
          value: "production"
          include_in_access_token: true
          include_in_id_token: false
          include_in_userinfo: false

        # Gate a sensitive claim to requests that include a specific scope
        - claim: billing_account_id
          source: user_attribute
          attribute: billing_account_id
          required_scopes:
            - billing
          include_in_userinfo: true
```

- `source` is a YAML inline tag: simple sources (`roles_from_assignments`,
  `effective_permissions`, `org_context`) need no additional fields. Structured sources
  (`canonical_user_field`, `user_attribute`, `constant`) require their companion key (`field`,
  `attribute`, `value`) at the same YAML indentation level.
- `include_in_access_token` and `include_in_id_token` default to `true`. `include_in_userinfo`
  defaults to `false`. Set them explicitly when the defaults are wrong for your use case.
- `required_scopes` is an OR gate: the claim is included if the token has _any_ of the listed
  scopes. Use `allowed_clients` to restrict to specific client slugs.
- Tier-1 reserved claim names (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`) cannot be mapped.
  Hearth rejects the configuration with an error on startup.

---

### Example 36 — Production observability

**Audience:** operators deploying Hearth in a production environment with a centralized log
aggregator, distributed tracing collector, and ops alerting.

```yaml
observability:
  log_level: info          # trace | debug | info | warn | error
  log_format: json         # text | json — use json for log aggregators (Datadog, Loki)
  otlp:
    endpoint: "http://otel-collector.internal:4317"
    protocol: grpc          # grpc (default, port 4317) | http (port 4318)
    service_name: "hearth-prod"
    headers:
      x-honeycomb-team: "${HONEYCOMB_API_KEY}"   # omit if collector is unauthenticated

metrics:
  enabled: true             # expose Prometheus /metrics endpoint (default: true)

onboarding:
  notification_email: "ops@example.com"   # emailed the setup URL on first boot
```

- `observability.otlp` ships OpenTelemetry spans to any OTLP-compatible collector
  (Jaeger, Honeycomb, Grafana Tempo, AWS X-Ray via ADOT, etc.).
- `observability.log_format: json` is recommended in production; it makes structured fields
  (trace IDs, realm, user IDs) searchable in aggregators.
- `metrics.enabled: true` is the default. The Prometheus scrape endpoint is at `/metrics`.
  To disable it (e.g. when a sidecar scrapes instead), set `enabled: false`.
- `onboarding.notification_email` is only used at first boot, before the admin account
  exists. Hearth emails the setup URL to this address so you can complete onboarding without
  tailing container logs.

---

### Example 37 — Storage tuning

**Audience:** operators sizing the hot tier and compaction schedule for production workloads,
or moving data to a non-default path.

```yaml
storage:
  data_dir: "/var/lib/hearth/data"   # default: "hearth-data" in the working directory
  fsync: true                         # must be true in production — WAL durability
  hot_tier_capacity: 100000           # max entries held in the in-process hot tier
  # hot_tier_max_memory: 268435456   # alternative: size cap in bytes (256 MiB here)
  compaction:
    enabled: true
    interval_secs: 3600               # background SST compaction sweep every hour
```

- Set either `hot_tier_capacity` (entry count) or `hot_tier_max_memory` (byte cap), not both.
  `hot_tier_capacity` is simpler to reason about for a known dataset size.
- `fsync: true` is mandatory in production. Setting it to `false` loses WAL durability;
  `hearth serve --dev` does this for local development only.
- Compaction merges fragmented SST files and reclaims deleted-entry space. Lower
  `interval_secs` reduces space amplification at the cost of more background I/O.
- The WAL is always fsynced before acknowledging a write regardless of the `compaction`
  setting — compaction only affects SST merging, not write durability.

---

## Part 10 — Branding & Complex Scenarios

### Example 38 — Custom branding

**Audience:** operators who want to replace Hearth's default logo and theme with their own
product branding, with per-realm overrides for multi-surface deployments.

```yaml
branding:
  product_name: "Acme Auth"
  logo_url: "https://cdn.example.com/logo.svg"
  theme: ocean               # ember (dark, default) | ocean | midnight | forest | cloud | slate

realms:
  customer-portal:
    web:
      theme: cloud             # light theme for the customer-facing login page
      product_name: "Acme Customer Portal"
      custom_css: |
        :root { --ht-accent: #c04000; }   /* brand-specific accent override */

  internal-tools:
    web:
      theme: midnight
      product_name: "Acme Internal"
```

- `branding.logo_url` accepts HTTPS URLs or absolute local paths (e.g.
  `/opt/hearth/branding/logo.svg`). The file must be readable by the Hearth process.
- `branding.theme` sets the global default; per-realm `web.theme` overrides it for that
  realm's login and account pages only.
- `custom_css` is injected after Hearth's compiled stylesheet. Use CSS custom properties
  (`--ht-*`) from `ui/tailwind.config.js` to override tokens without breaking the layout.
- Available themes: `ember` (dark, default), `ocean` (dark), `midnight` (dark),
  `forest` (dark), `cloud` (light), `slate` (light).
- Dark-mode-only (`ember`, `ocean`, `midnight`, `forest`) and light themes (`cloud`, `slate`)
  are mutually exclusive per realm. Hearth has no automatic light/dark toggle.

---

### Example 39 — High-security / financial services

**Audience:** operators in regulated industries (finance, healthcare, government) who need
short-lived tokens, strict password policy, mandatory MFA, invite-only registration, and
aggressive rate limiting.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

email:
  transport: sendgrid
  from: "Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

token:
  access_token_ttl: "5m"          # very short-lived; force frequent re-validation
  refresh_token_ttl: "8h"         # session-length window; no remember-me

auth:
  session_ttl: "8h"
  mfa_required: true
  mfa_methods:
    - totp
  password_policy:
    min_length: 16
    require_uppercase: true
    require_number: true
    require_special: true
    not_username: true
    not_email: true
    history_depth: 24              # reject last 24 passwords
    max_age_days: 90               # force reset every 90 days
  registration:
    mode: invite_only              # no self-registration; accounts created by admins only
  rate_limit:
    max_failed_logins: 5
    lockout_duration: "30m"

observability:
  log_level: warn
  log_format: json
```

- `token.access_token_ttl: "5m"` minimizes the window for a stolen bearer token. Pair this
  with refresh token rotation (enabled by default) so legitimate clients transparently
  re-issue tokens without user interaction.
- `password_policy.history_depth: 24` prevents users cycling through a small set of
  passwords to bypass `max_age_days`. Both settings are enforced at password-change time.
- `rate_limit.max_failed_logins: 5` with `lockout_duration: "30m"` exceeds NIST SP 800-63B
  guidance; tune to your threat model.
- Add `auth.mfa_methods: [webauthn]` alongside `totp` to support phishing-resistant
  WebAuthn / passkey second factors in addition to TOTP.
- Registering an application for this realm? Set `require_consent: false` only for
  first-party apps; all third-party integrations must go through consent.

---

### Example 40 — Full enterprise kitchen sink

**Audience:** operators who need to validate a complete production configuration covering
multiple realms, MFA, social login, SCIM, SAML, custom RBAC, branding, SMTP, TLS, and
observability in a single file. Use as a template, not as a copy-paste-and-go config.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  default_realm: consumer

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true
  hot_tier_capacity: 200000
  compaction:
    enabled: true
    interval_secs: 3600

email:
  transport: smtp
  from: "Acme Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

branding:
  product_name: "Acme Auth"
  logo_url: "https://cdn.example.com/logo.svg"
  theme: ember

observability:
  log_level: info
  log_format: json
  otlp:
    endpoint: "http://otel-collector.internal:4317"
    service_name: "hearth-prod"
    headers:
      x-honeycomb-team: "${HONEYCOMB_API_KEY}"

metrics:
  enabled: true

onboarding:
  base_url: "https://auth.example.com"
  notification_email: "ops@example.com"

token:
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"

auth:
  session_ttl: "24h"

realms:
  # ── Consumer realm: open registration, Google login, SPA client ────────────
  consumer:
    session_ttl: "24h"
    web:
      theme: ocean
      product_name: "Acme — Consumer"
    auth:
      mfa_required: false
      registration:
        mode: open
    federation:
      link_existing_accounts: confirm
      providers:
        google:
          type: google
          client_id: "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
    applications:
      consumer-app:
        name: "Consumer Web App"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false
        declared_scopes:
          - openid
          - profile
          - email

  # ── Enterprise realm: invite-only, MFA, SCIM, SAML, RBAC, orgs ────────────
  enterprise:
    session_ttl: "8h"
    web:
      theme: midnight
      product_name: "Acme — Enterprise"
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: invite_only
      password_policy:
        min_length: 14
        require_uppercase: true
        require_number: true
        require_special: true
        not_username: true
        history_depth: 12
        max_age_days: 90
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "30m"
      token:
        access_token_ttl: "5m"
        refresh_token_ttl: "1d"
    scim:
      bearer_token: "${SCIM_ENTERPRISE_TOKEN}"
    saml_service_providers:
      workday:
        entity_id: "https://wd5.myworkday.com/acme/login-saml2.htmld"
        acs_url: "https://wd5.myworkday.com/acme/login-saml2.htmld"
        nameid_format: emailAddress
        sign_assertions: true
        attribute_map:
          email: "wd:Worker_AuthenticationAlias"
          display_name: "wd:Worker_PreferredName"
    federation:
      link_existing_accounts: confirm
      providers:
        microsoft:
          type: microsoft
          display_name: "Microsoft (Acme)"
          # Pin to your tenant to prevent cross-tenant token acceptance.
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          client_id: "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
    permissions:
      - name: doc.read
        display_name: "Read Documents"
        category: content
      - name: doc.write
        display_name: "Write Documents"
        category: content
      - name: admin.users
        display_name: "Manage Users"
        category: administration
    roles:
      - name: editor
        scope_kind: organization
        permissions:
          - doc.read
          - doc.write
      - name: enterprise-admin
        scope_kind: realm
        permissions:
          - doc.read
          - doc.write
          - admin.users
    scopes:
      - name: docs
        display_name: "Documents"
        permissions:
          - doc.read
          - doc.write
    claims:
      mappings:
        - claim: roles
          source: roles_from_assignments
        - claim: org_id
          source: org_context
    organizations:
      acme-corp:
        name: "Acme Corporation"
        config:
          max_members: 500
      beta-customer:
        name: "Beta Customer Inc"
    applications:
      enterprise-portal:
        name: "Enterprise Portal"
        redirect_uris:
          - "https://enterprise.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false
        declared_scopes:
          - openid
          - profile
          - email
          - docs
      m2m-service:
        name: "Internal Automation Service"
        confidential: true
        client_secret: "${M2M_CLIENT_SECRET}"
        grant_types:
          - client_credentials
        declared_scopes:
          - docs
```

- Each realm is an isolated identity namespace with its own signing key, user store, and
  session pool. Cross-realm SSO is not automatic.
- `auth.token.*` inside a realm overrides global `token.*` TTLs for that realm only.
- `scim.bearer_token` and `saml_service_providers` can coexist; each handles a different
  enterprise integration path (SCIM = provisioning, SAML = authentication).
- `federation.providers.microsoft.issuer` pins to a single Azure AD tenant. Omitting the
  tenant-specific issuer allows tokens from _any_ Microsoft tenant — a security risk for
  B2B deployments.
- `claims.mappings` with `source: org_context` injects the user's active organization ID
  (`oid` claim) so downstream services can make org-scoped authorization decisions without
  querying Hearth.
- YAML-declared organizations (`organizations:`) are reconciled at startup; membership and
  invitations remain runtime-only and are managed via the Admin API or Admin UI.

---

*Re-check this file when `src/config/types.rs`, `src/identity/federation/`, or
`src/identity/types.rs` change public API surface (new YAML keys, renamed variants).*
