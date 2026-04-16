# Hearth — a purpose-built identity database

[Identity](#features) · [authorization](#features) · [sessions](#features) — one single-binary Rust server, backed by an embedded WAL + SST storage engine tuned for the identity access pattern.

> **Pre-1.0:** APIs and on-disk formats may change before 1.0. Follow progress in [`docs/specs/IMPLEMENTATION_ORDER.md`](docs/specs/IMPLEMENTATION_ORDER.md).

---

## What is Hearth?

Hearth is the identity layer for your app — logins, permissions, users, tenants — running as **one small self-hosted binary** instead of a stack of services you have to operate, secure, and keep in sync.

If you've ever glued together Keycloak, Postgres, Redis, and a policy engine just to answer *"who is this user and what can they do?"*, Hearth replaces all of it. One process to deploy. One config file. One thing to back up. No external database to provision, no cache to invalidate, no policy store to babysit.

**Auth stops being your latency tax.** A traditional stack bounces every permission check across the network — app to auth service, auth service to database, maybe to a cache, back again. Hearth keeps the whole decision in one process, so permission checks and token validation finish in well under a millisecond. Your sign-in screen, every API call, and every page load stay snappy even under load.

**Smaller surface, fewer ways to get it wrong.** Four services mean four places a CVE can land, four sets of credentials moving over the network, and a cache that can disagree with the database about who still has access — stale permissions are a security bug, not just a UX one. Hearth is one process: signing keys and session state never leave it, and there's no separate cache to serve yesterday's answer after a revoke.

**Your data, your rules.** Users' data stays on your infrastructure. Apache-2.0, no per-seat pricing, no vendor lock-in, no phone-home telemetry.

See [`docs/vision/VISION.md`](docs/vision/VISION.md) for the design rationale, storage-engine internals, and performance targets.

---

## Features

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
- Tenant-isolated keyspace (every key prefixed with `TenantId`)
- Per-tenant Ed25519 signing keys with JWKS rotation
- Cascading deletion across users, sessions, credentials, OAuth clients, authz tuples, device codes, signing keys

**Protocols**
- OIDC Core 1.0 + Discovery 1.0 + Dynamic Client Registration (RFC 7591 / 7592)
- Token Introspection (RFC 7662), Revocation (RFC 7009)
- REST/JSON over HTTP/1.1 and HTTP/2

**Operations**
- Single static binary
- Embedded WAL + memtable + SST storage with hot/cold tiering
- TLS 1.3 + mTLS, SIGHUP cert hot-reload, HTTP→HTTPS redirect
- Audit log with SHA-256 hash chain and per-tenant integrity verification

**Migration**
- Keycloak realm-export import (`hearth migrate keycloak`) — users, clients, realm roles, and PBKDF2-SHA256 credentials imported natively so existing passwords keep working without a forced reset

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

Dev mode exposes a convenience endpoint that creates a tenant, an admin user, a session, the Zanzibar `hearth#admin` tuple, and issues tokens — everything you need to try the OAuth flow locally:

```bash
curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap
```

Response (JSON):

```json
{
  "tenant_id":    "<uuid>",
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

---

## CLI Reference

```text
hearth serve [--dev] [-c, --config <path>] [--port <u16>] [--bind <addr>]
hearth tenant create
hearth app create --server <url> --tenant_id <uuid> --name <name> --redirect_uri <url>
hearth migrate keycloak --file <export.json> [--data-dir <path>] [--tenant <uuid>] [--dry-run]
```

- **`serve`** starts the HTTP(S) server. `--dev` implies in-memory storage, relaxed validation, and the bootstrap endpoint.
- **`tenant create`** prints `{"tenant_id": "<uuid>"}` on stdout. It's a pure UUID generator and does not require a running server.
- **`app create`** registers an OAuth 2.0 client by POSTing to `/clients` on a running Hearth server. The server URL must be reachable over HTTP.
- **`migrate keycloak`** imports a Keycloak realm export directly into the embedded store. Operates on the data directory offline (no running server needed) — see [Migrating from Keycloak](#migrating-from-keycloak).

---

## Integrating: Authorization Code Flow (end-to-end)

Every step below uses live HTTP endpoints. Multi-tenancy is header-based: every request carries `X-Tenant-ID: <tenant_uuid>`.

### 1. Create a tenant

```bash
TENANT_ID=$(./target/release/hearth tenant create | jq -r .tenant_id)
```

(In dev mode you can skip this and use the tenant from `/admin/bootstrap`.)

### 2. Register a client

```bash
./target/release/hearth app create \
  --server http://127.0.0.1:8420 \
  --tenant_id "$TENANT_ID" \
  --name "my-app" \
  --redirect_uri "https://myapp.example.com/callback"
```

Response includes `client_id` and `client_secret`. Save both.

### 3. Start an authorization request

```bash
curl -fsS -X POST http://127.0.0.1:8420/authorize \
  -H "X-Tenant-ID: $TENANT_ID" \
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
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&client_id=<cid>&client_secret=<secret>&redirect_uri=https://myapp.example.com/callback&code_verifier=<verifier>"
```

Returns `access_token`, `id_token`, `refresh_token`, `expires_in`, `token_type=Bearer`.

### 5. Fetch user info

```bash
curl -fsS http://127.0.0.1:8420/userinfo \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "Authorization: Bearer <access_token>"
```

Returns OIDC claims filtered by the granted scopes (`sub` always; `profile` → `name`; `email` → `email`, `email_verified`).

### 6. Refresh the access token

```bash
curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Tenant-ID: $TENANT_ID" \
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
| Discovery | `GET` | `/jwks` | Per-tenant public signing keys |
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
| Admin | `GET`/`POST` | `/admin/tenants` | List / create tenants |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/tenants/{id}` | CRUD a tenant |
| Admin | `GET`/`POST` | `/admin/applications` | List / register OAuth clients |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/applications/{id}` | CRUD a client |
| Admin | `POST` | `/admin/bootstrap` | Dev-only bootstrap (404 in prod) |

All `/admin/*` routes require a bearer token whose subject has the Zanzibar tuple `hearth#admin@user:<uuid>` for the target tenant.

---

## Client SDKs

Two first-party SDKs live under [`sdks/`](sdks):

**TypeScript** — [`sdks/typescript/`](sdks/typescript) (package `@hearth/sdk`)

```ts
import { HearthClient } from "@hearth/sdk";
const hearth = new HearthClient({ baseUrl: "https://auth.example.com", tenantId });
```

**Go** — [`sdks/go/`](sdks/go) (module `github.com/anthropics/hearth/sdks/go`)

```go
import "github.com/anthropics/hearth/sdks/go/hearth"
client := hearth.NewClient("https://auth.example.com", tenantID)
```

Dedicated SDK READMEs with full API docs are planned (see [`docs/specs/THINGS_WE_NEED.md`](docs/specs/THINGS_WE_NEED.md) item #3).

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

Optionally pass `--tenant <uuid>` to force a specific Hearth `TenantId` (defaults to the realm's own UUID from the export).

### What gets imported

| Keycloak                     | Hearth                                                     |
|------------------------------|------------------------------------------------------------|
| realm (`id`, `realm`)        | tenant                                                     |
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
| Identity | `src/identity/` | Users, credentials, sessions, tenants, tokens. |
| Authorization | `src/authz/` | Zanzibar tuples: `check`, `expand`, `write_tuples`, `watch`. |
| Cluster | `src/cluster/` | Raft consensus (`openraft`). Invisible in single-node mode. |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

Dependencies flow strictly downward; `identity/` is the only layer allowed to call `authz/`. Full rules: [`docs/specs/ARCHITECTURE.md`](docs/specs/ARCHITECTURE.md).

---

## Documentation map

- [`docs/vision/VISION.md`](docs/vision/VISION.md) — why Hearth exists, design rationale, roadmap
- [`docs/specs/ARCHITECTURE.md`](docs/specs/ARCHITECTURE.md) — structural MUST/SHOULD rules
- [`docs/specs/TESTING.md`](docs/specs/TESTING.md) — eight testing layers, TDD workflow, CI tiers
- [`docs/specs/TEST_SCENARIOS.md`](docs/specs/TEST_SCENARIOS.md) — granular test checklist by module
- [`docs/specs/IMPLEMENTATION_ORDER.md`](docs/specs/IMPLEMENTATION_ORDER.md) — mandatory Phase 0/1 build sequence
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contributor setup and pre-commit hooks

---

## Development

After cloning, run `make setup` to install the repo-managed git hooks, then `make check` before each PR (runs `clippy`, `rustfmt`, and `cargo-nextest`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

Apache-2.0 (declared in [`Cargo.toml`](Cargo.toml)). A formal `LICENSE` file at the repo root is pending.
