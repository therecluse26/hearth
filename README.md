# Hearth — a purpose-built identity database

**Identity is a database problem. Hearth is the database.**

Every other identity provider is an application sitting on top of a generic database — Keycloak on Postgres, Ory split across four binaries, Auth0 on its managed stack. That architecture is why auth is slow, operationally heavy, and fragile. Hearth inverts it: the storage engine is specialized for the identity access pattern, and the OAuth/OIDC/Zanzibar surfaces are thin protocol adapters on top. That's why it ships as one process instead of four.

> **Pre-1.0:** APIs and on-disk formats may change before 1.0.

---

## Why Hearth is different

### One engine, not four services

The typical self-hosted identity stack is four moving pieces: an auth server (Keycloak, Ory), a relational database (Postgres, MySQL), a session cache (Redis), and a separate policy engine for fine-grained authorization. Four processes to deploy, four to secure, four versions to keep in sync, four failure domains to reason about — plus a cache that can quietly disagree with the database about who still has access.

Hearth is **one binary, one port, one config file, zero external dependencies**. No database to provision, no cache to invalidate, no policy store to operate, no dual-write synchronization between an identity store and an authorization service. One process to deploy. One thing to back up.

### Specialized storage, not a generic DB

A generic database has to serve every workload; an identity engine only has to serve one, and the shape of that workload is known. Hearth's storage engine is a hybrid built around those shapes:

- **User profiles and credentials** — B-tree-like structures indexed by email, username, external ID, and realm for point lookups.
- **Sessions** — time-partitioned, tuned for TTL-based expiration and recent-window scans.
- **Zanzibar relationship tuples** — adjacency-list layout tuned for the exact traversal pattern of `Check` and `Expand`.
- **Audit log** — append-only with a SHA-256 hash chain per realm.

A **hot/cold tier** serves the working set from memory-mapped, cache-line-aligned structures and transparently demotes inactive records to on-disk SSTs, so a single node can manage datasets far larger than RAM without paying for it on every request.

### In-process authorization, not a network hop

Because Zanzibar tuples live in the same storage engine as users, realms, and sessions, **permission checks are in-process function calls, not network requests**. A `check()` does not serialize a payload, does not cross a socket, does not wait on a connection pool — it's a memory read against an adjacency list. This is the structural reason Hearth targets a sub-millisecond hot path: not runtime tuning, but one fewer network hop per permission decision. It's also why creating a user and assigning their initial roles is a single atomic storage write instead of a dual-write across two services.

### Your data, your rules

Apache-2.0, self-hosted, no per-seat pricing, no vendor lock-in, no phone-home telemetry. Your users' data stays on your infrastructure.

---

## What's in the box

**Authentication**
- Password login (Argon2id, OWASP parameters)
- OAuth 2.0 Authorization Code + PKCE, Refresh Token, Client Credentials, Device Authorization (RFC 8628)
- Magic link / passwordless
- TOTP (RFC 6238) with recovery codes
- WebAuthn / passkeys (Level 2)

**Authorization**
- Zanzibar-style relationship tuples
- `check`, `expand`, `write_tuples`, `watch` with consistency tokens

**Multi-tenancy**
- Realm-isolated keyspace (every key prefixed with `RealmId`)
- Per-realm Ed25519 signing keys with JWKS rotation
- Cascading deletion across users, sessions, credentials, OAuth clients, authz tuples, device codes, signing keys

**Protocols**
- OIDC Core 1.0 + Discovery 1.0 + Dynamic Client Registration (RFC 7591 / 7592)
- Token Introspection (RFC 7662), Revocation (RFC 7009)
- REST/JSON over HTTP/1.1 and HTTP/2

**Operations**
- Single static binary
- Embedded WAL + memtable + SST storage with hot/cold tiering
- TLS 1.3 + mTLS, SIGHUP cert hot-reload, HTTP→HTTPS redirect
- Audit log with SHA-256 hash chain and per-realm integrity verification

**Migration**
- Keycloak realm-export import (`hearth migrate keycloak`) — users, clients, realm roles, and PBKDF2-SHA256 credentials imported natively so existing passwords keep working without a forced reset

---

## How we build it

Identity infrastructure has zero tolerance for data loss and low tolerance for inconsistency. Hearth backs that with eight testing layers, all runnable locally and wired into CI:

1. **Unit** — inline `#[cfg(test)]`, TDD-first. A failing test precedes every feature.
2. **Integration / black box** — a `TestHarness` runs the same suite in embedded *and* HTTP server modes.
3. **Property** — `proptest`, 256 cases locally, 10,000+ in CI.
4. **Fuzz** — `cargo-fuzz` against wire parsers (CBOR, protobuf, JWT, authenticator data).
5. **Deterministic simulation** — `madsim` replays disk faults, WAL-tail corruption, network partitions, and clock skew from fixed seeds: [`realm_crash`](simulation/src/tests/realm_crash.rs), [`audit_crash`](simulation/src/tests/audit_crash.rs), [`watch_partition`](simulation/src/tests/watch_partition.rs), [`cache_stampede`](simulation/src/tests/cache_stampede.rs), [`realm_concurrent_io`](simulation/src/tests/realm_concurrent_io.rs).
6. **Adversarial** — timing attacks, brute-force lockout, enumeration resistance, TLS downgrade, privilege escalation.
7. **Conformance** — OIDC Core 1.0, Discovery 1.0, Dynamic Client Registration, WebAuthn Level 2 ceremony.
8. **Benchmarks** — `criterion`, with regression gating in CI.

**Crash-survival is part of the spec.** The storage engine must survive `kill -9` at any point and recover to a consistent state. Every WAL invariant has a madsim scenario that exercises it.

**CI tiers:** Fast (every commit) · Standard (merge) · Extended (nightly) · Full (weekly).

**Current status.** Phase 0 complete (148/148 scenarios); Phase 1 complete (135/135 scenarios). 671 Rust tests + 27 simulation tests + TypeScript and Go SDK tests passing.

---

## Quick Start

### Prerequisites

- **Rust 1.75+** (see [`Cargo.toml`](Cargo.toml) `rust-version`)
- `buf` (optional — only needed if you edit `proto/**/*.proto`; see [`CONTRIBUTING.md`](CONTRIBUTING.md))

### 1. Build

```bash
cargo build --release
# Binary: target/release/hearth
```

### 2. Run in dev mode

```bash
./target/release/hearth serve --dev
```

Dev mode uses in-memory storage in a temp directory, `debug` logging, `fsync` disabled, and enables the `/admin/bootstrap` endpoint. The server binds to `127.0.0.1:8420`.

### 3. Verify

```bash
curl -fsS http://127.0.0.1:8420/health
curl -fsS http://127.0.0.1:8420/.well-known/openid-configuration | head
```

---

## Bootstrap an Admin (dev mode only)

Dev mode exposes a convenience endpoint that creates a realm, an admin user, a session, the Zanzibar `hearth#admin` tuple, and issues tokens — everything you need to try the OAuth flow locally:

```bash
curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap
```

Response (JSON):

```json
{
  "realm_id":    "<uuid>",
  "user_id":      "<uuid>",
  "access_token": "<jwt>",
  "refresh_token":"<opaque>"
}
```

In production mode the endpoint returns `404 Not Found` (`src/protocol/http.rs:1794`).

---

## Configuration

`hearth serve` resolves configuration in this order (`src/main.rs:308-327`):

1. `--dev` flag → in-memory dev defaults (overrides everything else).
2. `-c, --config <path>` → load the specified YAML file.
3. Otherwise, `./hearth.yaml` if it exists in the working directory.
4. Otherwise, built-in production defaults.

CLI flags `--port` and `--bind` override any of the above.

YAML files support `${VAR_NAME}` environment variable substitution (`src/config/env.rs`); a missing variable is a hard error.

Copy [`hearth.example.yaml`](hearth.example.yaml) to `hearth.yaml` and edit. Every section is `#[serde(default)]`, so you can omit anything you don't want to change.

### Config reference

| Section | Field | Type | Default | Notes |
|---|---|---|---|---|
| `server` | `bind_address` | string | `127.0.0.1` | |
| `server` | `port` | u16 | `8420` | |
| `server` | `tls_cert_path` | path? | — | Requires `tls_key_path` |
| `server` | `tls_key_path` | path? | — | Requires `tls_cert_path` |
| `server` | `tls_client_ca_path` | path? | — | For mTLS |
| `server` | `tls_require_client_cert` | bool | `false` | Requires `tls_client_ca_path` |
| `server` | `default_realm` | string? | — | Realm name used for bare `/ui/*` URLs on multi-realm deployments. See [Web UI realm routing](#web-ui-realm-routing). Must name an existing realm; validated at startup. |
| `storage` | `data_dir` | string | `./data` | |
| `storage` | `wal_max_size_bytes` | u64 | `268435456` | 256 MiB |
| `storage` | `memtable_flush_bytes` | u64 | `67108864` | 64 MiB |
| `storage` | `hot_tier_capacity` | usize | `10000` | |
| `storage` | `fsync` | bool | `true` | **MUST be true in production** |
| `observability` | `log_level` | string | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error` |
| `observability` | `log_format` | string | `text` | `text` \| `json` |
| `operational` | `request_timeout_secs` | u64 | `30` | |
| `operational` | `shutdown_timeout_secs` | u64 | `10` | |
| `operational` | `max_connections` | u32 | `1024` | |
| `operational` | `queue_depth` | u32 | `4096` | |
| `email` | `transport` | string | `log` | `log` \| `smtp` |
| `email` | `from` | string? | — | `From:` header; required when `transport: smtp` |
| `email.smtp` | `host` | string | — | SMTP server hostname; required when `transport: smtp` |
| `email.smtp` | `port` | u16 | — | SMTP server port (e.g. `587`, `465`, `1025`) |
| `email.smtp` | `encryption` | string | `starttls` | `none` \| `starttls` \| `tls` |
| `email.smtp` | `username` | string? | — | SMTP AUTH username (pair with `password`) |
| `email.smtp` | `password` | string? | — | SMTP AUTH password (pair with `username`) |

---

## Theming the Admin UI

Hearth's admin UI is fully themeable via CSS custom properties. Six named themes ship built in; operators can also supply arbitrary CSS to override any token.

### Named themes

Configure with `branding.theme` in `hearth.yaml`:

| Name | Mode | Description |
|---|---|---|
| `ember` | dark | Default — amber/orange brand on cool graphite |
| `ocean` | dark | Teal/cyan brand on deep graphite |
| `midnight` | dark | Violet/purple brand on deep graphite |
| `forest` | dark | Emerald/green brand on deep graphite |
| `cloud` | light | Blue brand on near-white surfaces |
| `slate` | light | Steel-blue brand on cool blue-gray surfaces |

```yaml
branding:
  theme: slate
```

An unknown theme name is a config error at startup.

### Custom CSS

Append a CSS file after the named theme to override any `--ht-*` variable or add custom rules. The file is read once at startup:

```yaml
branding:
  theme: ember
  custom_css: /etc/hearth/brand.css
```

### Per-realm themes

Each realm can override the global theme independently:

```yaml
realms:
  acme:
    web:
      theme: cloud
      custom_css: /etc/hearth/realms/acme.css
```

The per-realm theme CSS is served from `GET /ui/static/realm-theme/{realm_id}` and is cached with `ETag` support.

### CSS custom property API

All theme tokens are `--ht-*` CSS custom properties. A custom CSS file need only override the variables it changes; unset variables fall back to the `ember` defaults. Key variables:

```css
:root {
  --ht-surface-base:      /* page background (RGB triple, no alpha) */
  --ht-surface-raised:    /* sidebar / panel background */
  --ht-surface-elevated:  /* card / modal background */
  --ht-content-primary:   /* primary text */
  --ht-content-secondary: /* secondary text */
  --ht-content-muted:     /* muted / placeholder text */
  --ht-content-brand:     /* brand-colored text and icons */
  --ht-content-on-brand:  /* text on top of brand gradient buttons */
  --ht-brand-from:        /* gradient start color */
  --ht-brand-via:         /* gradient midpoint */
  --ht-brand-deep:        /* gradient end / hover state */
}
```

For the full token list and design rationale see [`docs/specs/THEME.md`](docs/specs/THEME.md).

---

## Running with Docker Compose

A two-service compose stack (Hearth + [Mailpit](https://mailpit.axllent.org/) as a dev SMTP sink) lives at the repo root:

```bash
docker compose up --build -d
docker compose logs hearth | grep "setup_url"   # grab the first-run setup URL
open http://localhost:8420                      # Hearth
open http://localhost:8025                      # Mailpit UI
docker compose down                             # stop (keeps data volume)
docker compose down -v                          # stop + wipe data volume
```

Container config lives in [`deploy/hearth.docker.yaml`](deploy/hearth.docker.yaml); tune knobs there, not in `compose.yaml`. The compose stack ships with `email.transport: smtp` pointed at Mailpit over compose DNS as `mailpit:1025`, so verification emails sent from the first-run `/ui/setup` flow land in the Mailpit inbox at http://localhost:8025 — click the link inside Mailpit to complete setup.

---

## CLI Reference

```text
hearth serve [--dev] [-c, --config <path>] [--port <u16>] [--bind <addr>]
hearth realm create
hearth app create --server <url> --realm_id <uuid> --name <name> --redirect_uri <url>
hearth migrate keycloak --file <export.json> [--data-dir <path>] [--realm <uuid>] [--dry-run]
```

- **`serve`** starts the HTTP(S) server. `--dev` implies in-memory storage, relaxed validation, and the bootstrap endpoint.
- **`realm create`** prints `{"realm_id": "<uuid>"}` on stdout. It's a pure UUID generator and does not require a running server.
- **`app create`** registers an OAuth 2.0 client by POSTing to `/clients` on a running Hearth server. The server URL must be reachable over HTTP.
- **`migrate keycloak`** imports a Keycloak realm export directly into the embedded store. Operates on the data directory offline (no running server needed) — see [Migrating from Keycloak](#migrating-from-keycloak).

---

## Integrating: Authorization Code Flow (end-to-end)

Every step below uses live HTTP endpoints. Multi-tenancy is header-based: every request carries `X-Realm-ID: <realm_uuid>`.

### 1. Create a realm

```bash
REALM_ID=$(./target/release/hearth realm create | jq -r .realm_id)
```

(In dev mode you can skip this and use the realm from `/admin/bootstrap`.)

### 2. Register a client

```bash
./target/release/hearth app create \
  --server http://127.0.0.1:8420 \
  --realm_id "$REALM_ID" \
  --name "my-app" \
  --redirect_uri "https://myapp.example.com/callback"
```

Response includes `client_id` and `client_secret`. Save both.

### 3. Start an authorization request

```bash
curl -fsS -X POST http://127.0.0.1:8420/authorize \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id":            "<client_id>",
    "redirect_uri":         "https://myapp.example.com/callback",
    "response_type":        "code",
    "scope":                "openid profile email",
    "state":                "<csrf_state>",
    "code_challenge":       "<S256(verifier)>",
    "code_challenge_method":"S256",
    "user_id":              "<authenticated_user_uuid>"
  }'
```

Returns an authorization `code`.

### 4. Exchange the code for tokens

```bash
curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&client_id=<cid>&client_secret=<secret>&redirect_uri=https://myapp.example.com/callback&code_verifier=<verifier>"
```

Returns `access_token`, `id_token`, `refresh_token`, `expires_in`, `token_type=Bearer`.

### 5. Fetch user info

```bash
curl -fsS http://127.0.0.1:8420/userinfo \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer <access_token>"
```

Returns OIDC claims filtered by the granted scopes (`sub` always; `profile` → `name`; `email` → `email`, `email_verified`).

### 6. Refresh the access token

```bash
curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=<rt>&client_id=<cid>&client_secret=<secret>"
```

Refresh tokens rotate on use. Presenting an already-rotated refresh token triggers theft detection and revokes the grant family.

---

## API Endpoints

| Group | Method | Path | Purpose |
|---|---|---|---|
| Discovery | `GET` | `/health` | Liveness probe |
| Discovery | `GET` | `/.well-known/openid-configuration` | OIDC Discovery 1.0 metadata |
| Discovery | `GET` | `/jwks` | Per-realm public signing keys |
| OAuth/OIDC | `POST` | `/authorize` | Authorization request |
| OAuth/OIDC | `POST` | `/token` | Token exchange (code / refresh / client_credentials / device_code) |
| OAuth/OIDC | `POST` | `/revoke` | RFC 7009 revocation |
| OAuth/OIDC | `POST` | `/introspect` | RFC 7662 introspection |
| OAuth/OIDC | `GET` | `/userinfo` | OIDC UserInfo |
| OAuth/OIDC | `POST` | `/device_authorization` | RFC 8628 device code start |
| OAuth/OIDC | `POST` | `/register` | RFC 7591 dynamic client registration |
| OAuth/OIDC | `POST` | `/clients` | Static client registration (used by `hearth app create`) |
| Admin | `GET`/`POST` | `/admin/users` | List / create users |
| Admin | `POST` | `/admin/users/bulk` | Bulk user creation |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/users/{id}` | CRUD a user |
| Admin | `GET`/`POST` | `/admin/realms` | List / create realms |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/realms/{id}` | CRUD a realm |
| Admin | `GET`/`POST` | `/admin/applications` | List / register OAuth clients |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/applications/{id}` | CRUD a client |
| Admin | `POST` | `/admin/bootstrap` | Dev-only bootstrap (404 in prod) |

All `/admin/*` routes require a bearer token whose subject has the Zanzibar tuple `hearth#admin@user:<uuid>` for the target realm.

---

## Client SDKs

Two first-party SDKs live under [`sdks/`](sdks):

**TypeScript** — [`sdks/typescript/`](sdks/typescript) (package `@hearth/sdk`)

```ts
import { HearthClient } from "@hearth/sdk";
const hearth = new HearthClient({ baseUrl: "https://auth.example.com", realmId });
```

**Go** — [`sdks/go/`](sdks/go) (module `github.com/anthropics/hearth/sdks/go`)

```go
import "github.com/anthropics/hearth/sdks/go/hearth"
client := hearth.NewClient("https://auth.example.com", realmID)
```

Dedicated SDK READMEs with full API docs are planned.

---

## TLS and mTLS

Enable TLS by setting **both** `server.tls_cert_path` and `server.tls_key_path` — either both or neither (`src/config/mod.rs:108-123`). When TLS is active, Hearth spawns an HTTP → HTTPS redirect listener on `port - 1` (or `80` if the TLS port is `443`).

For mTLS, add `server.tls_client_ca_path` and set `server.tls_require_client_cert: true`. Sending `SIGHUP` to the process reloads the cert + key from disk without dropping connections.

```yaml
server:
  tls_cert_path: "/etc/hearth/server.crt"
  tls_key_path:  "/etc/hearth/server.key"
  tls_client_ca_path: "/etc/hearth/clients-ca.crt"
  tls_require_client_cert: true
```

---

## Web UI realm routing

Every `/ui/*` page belongs to exactly one realm — that's where the user's session, credentials, and policy live. Hearth resolves the realm for each pre-auth request *before* touching the identity engine, and never walks realms looking for a match. Which realm applies depends on the URL shape and how many realms exist.

| Realm count | `server.default_realm` | Bare `/ui/login` etc. behavior |
|---|---|---|
| 1 | — (ignored) | Implicit — the sole realm is used. Zero config needed. |
| >1 | Set | Resolves to the declared default. Forms POST back to the bare URL. |
| >1 | Unset | GETs render a realm picker (`templates/ui/choose_realm.html`) listing active realms; POSTs return 400. |

Explicit **`/ui/realms/<name>/...`** URLs bypass the fallback chain entirely. Unknown realm names return 404.

Pre-auth route families (each has a bare and a path-scoped form):

```
/ui/{login, register, register/sent, forgot-password, forgot-password/sent,
     reset-password, verify-email, accept-invitation,
     login/passkey-begin, login/passkey-complete}

/ui/realms/<name>/{...same set...}
```

Bare URLs are convenient; path-scoped URLs are canonical. Email verification links, password-reset links, and form POSTs generated on a path-scoped page all stay path-scoped so the realm binding survives the round trip. Authenticated pages (`/ui/admin/*`, `/ui/account/*`, `/ui`) resolve the realm from the session cookie and need no path segment.

Operators opt in per deployment:

```yaml
server:
  bind_address: 0.0.0.0
  port: 8420
  default_realm: public    # optional; only needed when you host >1 realm
```

Startup hard-fails if `server.default_realm` names a realm that doesn't exist after reconciliation — it's a config bug, not a runtime fallback. Leave it unset on a multi-realm deployment to force every user through an explicit `/ui/realms/<name>/...` URL.

For the exact resolution rules see [`src/protocol/web/realm_resolver.rs`](src/protocol/web/realm_resolver.rs).

---

## Migrating from Keycloak

Hearth reads Keycloak realm exports natively and imports them into the embedded store offline — no running server required, no HTTP body limits, no forced password reset for end users whose hashes Hearth can verify directly.

### Validate an export

Run `--dry-run` first to parse the export, validate every record, and print a report of what *would* be written:

```bash
./target/release/hearth migrate keycloak \
  --file /path/to/realm-export.json \
  --dry-run
```

### Import into a data directory

Drop `--dry-run` and point `--data-dir` at the directory `hearth serve` will later use:

```bash
./target/release/hearth migrate keycloak \
  --file /path/to/realm-export.json \
  --data-dir ./data
```

Optionally pass `--realm <uuid>` to force a specific Hearth `RealmId` (defaults to the realm's own UUID from the export).

### What gets imported

| Keycloak                     | Hearth                                                     |
|------------------------------|------------------------------------------------------------|
| realm (`id`, `realm`)        | realm                                                     |
| user (`id`, `email`, …)      | user (Keycloak UUID preserved when valid)                  |
| user → `realmRoles`          | Zanzibar tuple `realm:<tid>#<role>@user:<uid>`             |
| client + `secret`            | `OAuthClient` (secret re-hashed with Argon2id on import)   |
| password — PBKDF2-SHA256     | PHC string; verifies natively, no password reset required  |
| password — PBKDF2-SHA512     | *Skipped* with a warning; user must reset password         |

### What's not imported (yet)

Groups, composite roles, client roles, federated identity providers, and required actions are out of scope for the initial importer. Users affected by unsupported credentials land in the store with no password set and appear in the report's `warnings` list so operators can reconcile.

---

## Architecture at a glance

| Layer | Path | Role |
|---|---|---|
| Core | `src/core/` | Shared types and traits only. No logic, no state. |
| Protocol | `src/protocol/` | Stateless wire adapters (REST, gRPC, OIDC, SAML, SCIM). |
| Identity | `src/identity/` | Users, credentials, sessions, realms, tokens. |
| Authorization | `src/authz/` | Zanzibar tuples: `check`, `expand`, `write_tuples`, `watch`. |
| Cluster | `src/cluster/` | Raft consensus (`openraft`). Invisible in single-node mode. |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

Dependencies flow strictly downward; `identity/` is the only layer allowed to call `authz/`.

---

## Development

After cloning, run `make setup` to install the repo-managed git hooks, then `make check` before each PR (runs `clippy`, `rustfmt`, and `cargo-nextest`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

Apache-2.0 (declared in [`Cargo.toml`](Cargo.toml)). A formal `LICENSE` file at the repo root is pending.
