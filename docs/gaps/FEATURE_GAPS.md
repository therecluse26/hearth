# Feature Gaps & Roadmap Priorities

## Overview

Hearth has completed Phase 0 (18 steps, 148 scenarios), Phase 1 (13 steps, 135 scenarios), Phase 1.5 (production email), and Phase 2 (organizations). The system totals **941 Rust tests + 27 simulation + 6 SDK tests** across 8 testing layers.

**What works today:** Password authentication, TOTP/MFA, WebAuthn/Passkeys, magic links, public self-registration (per-realm policy: disabled/open/domain-restricted/invite-only, with email verification and IP+email rate limiting), password reset / account recovery, self-service session management (list own sessions, revoke one, revoke all other devices), explicit realm routing in the web UI (`/ui/realms/<name>/...` path segments, optional `server.default_realm` for bare URLs, no cross-realm walk), OAuth 2.0 (authorization code, client credentials, device authorization, refresh rotation, revocation, introspection) with a **browser-facing consent screen** (per-scope checkboxes, trusted-client bypass, self-service + admin consent management, `prompt=none|consent` semantics), OIDC (discovery, UserInfo, dynamic client registration, conformance), SAML 2.0 (SP + IdP sides, signed assertions, SLO wiring), **SCIM 2.0 provisioning** (Users + Groups CRUD + PATCH + filter + discovery endpoints, externalId idempotency, admin-scoped Bearer auth), claims-based RBAC authorization (roles, groups, permissions, JWT claim embedding, scope narrowing — see [`../specs/AUTHORIZATION.md`](../specs/AUTHORIZATION.md)), multi-tenancy (realm isolation, per-realm signing keys, cascading deletes), organizations (membership, invitations), audit logging (SHA-256 hash chain, tamper detection), TLS termination (1.3, hot-reload, mTLS), admin API + web console, gRPC management API, Keycloak migration, TypeScript + Go SDKs, and 5 email transports (SMTP, SendGrid, Postmark, Mailgun, Log).

This document inventories **features not yet implemented** that would block or hinder production adoption, compared against the commitments in `docs/vision/VISION.md`. Each gap cites the relevant Vision section for traceability.

## Priority Tiers

| Tier | Meaning |
|------|---------|
| **P0** | Blocks production deployment. Without these, an operator cannot safely run Hearth for real users. |
| **P1** | Expected for competitive parity. Enterprises and developers evaluating Hearth against Keycloak, Auth0, or Okta will expect these. |
| **P2** | Enhances operational maturity. Not blocking, but significantly improves operations, observability, and resilience. |
| **P3** | Post-release enhancements. Explicitly deferred in the Vision roadmap or listed as open questions. |

---

## P0 — Blocks Production Deployment

*(All P0 gaps now closed. See "Completed Items" below — gap #3 OAuth Consent Screen was the last remaining P0.)*

---

## P1 — Expected for Competitive Parity

### 5. Social Login / External IdP Federation — COMPLETED ✅

Implemented feature-complete. Hearth now acts as an OIDC **relying party** in addition to its provider role.

- **Generic OIDC connector** (`src/identity/federation/oidc.rs`) — single code path covers Google, Microsoft/Azure AD, Apple, Okta, Auth0, Keycloak, Zitadel, and any OIDC Core 1.0-compliant provider. PKCE-S256 mandatory; RS256 ID-token verification via `ring::signature::RSA_PKCS1_2048_8192_SHA256`; iss/aud/exp/nbf/nonce validation with 60s clock-skew.
- **GitHub OAuth2 connector** (`src/identity/federation/github.rs`) — non-OIDC path: `/user` + (fallback) `/user/emails` for private-email users, `User-Agent` header required, `email_verified` derived from the primary+verified row.
- **Preset shortcuts** (`src/identity/federation/presets.rs`) — YAML `type: google|microsoft|apple|github` fills in issuer/endpoints/scopes so operators don't look them up.
- **Per-realm YAML config** — `realms.{name}.federation.{link_existing_accounts, providers.{idp_name}.{type,client_id,client_secret,...}}` reconciled at startup. Connector `IdpId`s are deterministic (UUIDv5 of `realm:idp_name`) so existing links survive config edits.
- **Account linking** — per-realm `LinkMode` (`disabled` / `confirm` / `auto`). Default `confirm` matches Keycloak's safety posture: on email-match, the user must re-authenticate locally before the external identity is attached. `auto` silently links on `email_verified=true`. `disabled` always JIT-provisions.
- **Confirm-to-link** — HMAC-SHA256-bound ticket cookie (domain-separated `"fed-confirm|"`) prevents cross-user replay. Ticket is single-use, 10-minute TTL.
- **Self-service** — `/ui/account/linked-accounts` lists the user's linked IdPs with per-row unlink. CSRF-enforced; emits `FederationAccountUnlinked` audit event.
- **Login-page buttons** — each realm's configured connectors render as "Sign in with {name}" buttons between the password form and the passkey option.
- **Cascading deletes** — `delete_user` removes both forward (`fed:ext_fwd:*`) and reverse (`fed:ext:*`) indexes; `delete_idp` severs every link but leaves users; `delete_realm` sweeps all `fed:*` prefixes.
- **Audit** — five new `AuditAction` variants: `FederationLoginStarted`, `FederationLoginCompleted`, `FederationAccountLinked` (with `mode: auto|confirm|initial`), `FederationAccountUnlinked` (`via: self|admin`), `FederationJitProvisioned`.

**Key files:**
- Engine: `src/identity/engine.rs` (`register_idp`, `list_idps`, `delete_idp`, `put/take_federation_state`, `put/take_confirm_link_ticket`, `link/unlink/find_by_external_identity`, `list_external_identities_for_user`; cascades in `delete_user`, `delete_realm`)
- Federation module: `src/identity/federation/{mod,types,http,state,connector,oidc,github,presets,service}.rs`
- Storage keys: `src/identity/keys.rs` (`fed:idp:`, `fed:state:`, `fed:confirm:`, `fed:ext:`, `fed:ext_fwd:`)
- Errors: `src/identity/error.rs` (9 new `Federation*` variants)
- YAML: `src/config/types.rs::FederationYamlConfig` + `FederationProviderYaml` + `LinkModeYaml`
- Reconcile: `src/identity/reconcile.rs::reconcile_federation_for_realm`
- Web: `src/protocol/web/federation.rs`, `src/protocol/web/account_linked.rs`
- Templates: `templates/ui/federation/confirm_link.html`, `templates/ui/account/linked_accounts.html`, login-page IdP button row in `templates/ui/login.html`
- Audit: `proto/hearth/events/v1/audit.proto`, `src/audit/types.rs`, `src/protocol/convert/audit.rs`
- Tests: unit tests in each federation submodule (53 across types/http/state/connector/oidc/github/presets), integration tests in `tests/federation.rs` (11 covering registration, realm isolation, state single-use, state expiry, link roundtrip, cross-user-link refusal, unlink idempotency, delete_user cascade, delete_idp cascade leaves users intact, confirm-link single-use, default link mode)

**Design principle — system config is YAML-only, permanently:**

Hearth draws a deliberate line between **data** (users, orgs, sessions, linked external identities — all manageable via the admin UI) and **system configuration** (realms, OAuth clients, email transports, **federation connectors**, themes — all YAML-only, reconciled at startup, version-controlled alongside the rest of the deployment). Federation connectors sit on the config side of that line; there will **never** be an admin UI for `register_idp` / `update_idp` / `delete_idp`. Rationale: Infrastructure-as-Code, avoiding Keycloak-style config-UI sprawl, and keeping the declarative bootstrap path (`git clone && hearth serve --config hearth.yaml`) intact.

**Remaining enhancements (not blocking, genuinely future work):**
- Admin-side `/ui/admin/users/{id}/linked-accounts` view (admin-assisted revocation — that IS data management, so it's in-scope for the UI, just not built yet).
- ES256 / EdDSA ID-token verification (RS256 covers every provider Hearth targets in v1; swap the `ring::signature::VerificationAlgorithm` instance in `verify_rs256`).
- Claim-mapping application at claim-extraction time (scaffold exists in `IdpConfig.claim_mappings`; wiring to apply the rename before `IdTokenClaims` deserialize is a small addition when the first real consumer appears — e.g., Azure AD `upn` → `email`).
- JWKS caching with TTL (today `fetch_jwks` hits the upstream on every callback — acceptable since federation is off the hot path, but wasteful at scale).
- Approximate geolocation in federation audit metadata (same deferral as `/account/sessions`).

### 6. SAML 2.0 IdP / SP Support — COMPLETED ✅ (Phase 1 — requires hardening)

Implemented in one pass: SP side, IdP side, both SSO directions, metadata in both directions. Phase 1 scope ships working code that passes its own integration tests; the narrow XML-DSIG subset and the scoped algorithm suite are documented rather than hidden — real enterprise deployments will want additional review before production use.

- **SP side (Hearth consumes external IdP assertions):**
  - SP metadata at `GET /ui/realms/{realm}/federation/saml/metadata?idp=<name>`.
  - Begin endpoint at `GET /ui/realms/{realm}/federation/saml/begin?idp=<name>` — builds AuthnRequest, serializes for HTTP-Redirect binding, persists state, redirects.
  - ACS at `POST /ui/realms/{realm}/federation/saml/acs` — parses POSTed `SAMLResponse`, validates signature, timestamps, audience, destination, issuer, `InResponseTo`, and enforces single-use assertion-ID replay protection.
- **IdP side (Hearth issues assertions to registered SPs):**
  - IdP metadata at `GET /ui/realms/{realm}/saml/metadata`.
  - SSO at `GET|POST /ui/realms/{realm}/saml/sso` — consumes AuthnRequest, issues signed Response via HTTP-POST binding (auto-submitting form).
  - IdP-initiated SSO at `GET /ui/realms/{realm}/saml/sso/init?sp=<key>`.
- **Algorithm suite (locked by design):**
  - Canonicalization: exclusive C14N 1.0 (without comments) only.
  - Digest: SHA-256 only. SHA-1 digests are rejected.
  - Signature: RSA-PKCS1-v1.5-SHA256 only. RSA-SHA1 is rejected (algorithm downgrade defense).
  - Reference transforms: `enveloped-signature` + `exc-c14n` only.
  - Signature-wrapping defense: `Reference URI` must equal the enclosing element's `ID` attribute.
- **Per-realm RSA-2048 signing keys**: generated lazily on first SAML operation, persisted as PKCS#8 DER under a new `realm:saml_key:{uuid}` prefix in the system realm, wrapped with self-signed X.509 certs via `rcgen`. Zeroize-on-drop mirrors the Ed25519 path.
- **YAML config (per design — SAML IdPs and SPs are system config, not data):**
  - SP-side: `realms.{name}.federation.providers.<idp>.{type: saml, entity_id, sso_url, slo_url, idp_certificate_pem, attribute_map, ...}` — reuses the existing federation reconcile path with a new `IdpKind::Saml` branch.
  - IdP-side: `realms.{name}.saml_service_providers.<sp_key>.{entity_id, acs_url, slo_url, sp_certificate_pem, nameid_format, attribute_map, ...}` — reconciled via a dedicated `reconcile_saml_sps_for_realm`.
- **Audit**: 8 new `AuditAction` variants: `SamlLoginInitiated`, `SamlLoginCompleted`, `SamlLoginFailed` (with `reason: signature|expired|replay|audience|issuer|destination|algorithm|parse`), `SamlIdpAuthnRequestReceived`, `SamlIdpResponseIssued`, `SamlIdpInitiatedSso`, `SamlSloRequested`, `SamlSloCompleted`. Proto enum + convert tables updated in sync.
- **Cascading deletes**: `delete_realm` sweeps `saml:sp:*`, `saml:state:*`, `saml:asn:*`, `saml:sp_session:*`, `saml:logout:*` prefixes plus the per-realm SAML RSA key.

**Key files:**
- Module: `src/identity/federation/saml/{mod,types,xml,c14n,signature,metadata,authn_request,response,logout,binding,sp,idp}.rs` (~2500 LOC).
- RSA key type: `src/identity/tokens.rs` (`RsaSigningKey`).
- Storage keys: `src/identity/keys.rs` (5 new prefixes + encoders).
- Errors: `src/identity/error.rs` (12 new `Saml*` variants; HTTP + gRPC mapping).
- Engine trait + impl: `src/identity/mod.rs` (10 new trait methods), `src/identity/engine.rs` (implementations + cascade updates).
- Web: `src/protocol/web/saml.rs` (SP + IdP handlers), `src/protocol/web/mod.rs` (6 new routes).
- Config: `src/config/types.rs` (`SamlServiceProviderYaml`; SAML fields on `FederationProviderYaml`).
- Reconcile: `src/identity/reconcile.rs` (`build_saml_idp_config`, `reconcile_saml_sps_for_realm`).
- Audit: `src/audit/types.rs`, `proto/hearth/events/v1/audit.proto`, `src/protocol/convert/audit.rs`, `src/protocol/grpc/audit.rs`.
- Tests: 22 new library unit tests + 7 new integration tests in `tests/saml.rs`.

**Known limitations / planned hardening:**
- The exclusive C14N implementation is a focused subset that handles the XML shapes Hearth produces and consumes in practice; it is NOT a general-purpose exc-c14n processor (no inclusive-namespace prefix lists, no processing instructions inside signed subtrees, no `#WithComments`). Interop with IdPs that emit unusual XML edge cases may require C14N extension.
- X.509 certificate parsing uses a focused DER walker rather than a full X.509 crate. Cert extensions, path validation, and revocation are out of scope — we trust the operator-supplied cert PEM verbatim.
- SAML SLO is wired at the library level (`LogoutRequest`, `LogoutResponse`, both-direction build + parse + HTTP bindings) but the web handler fan-out is not yet connected to session revocation. Enable this before relying on SLO.
- IdP-side SSO currently uses a placeholder user identity — integrating with live `UiSession` / login redirect requires a small additional patch.
- No AuthnRequest-side signing yet on the outbound HTTP-Redirect binding (IdPs that require signed requests won't work without this).
- XMLDSIG signing only `<Response>` (when `sign_responses=true`); signing only the inner `<Assertion>` is not yet separately supported — Hearth always wraps the whole Response.
- Signature-wrapping defense is narrow: it checks the Reference URI equals the enclosing element's ID but does not deep-walk for secondary Signatures planted inside Extensions.

**Security note:** XML-DSIG has a long CVE history in mature SAML libraries. The single-session implementation reuses `ring::signature::RSA_PKCS1_2048_8192_SHA256` (the same primitive as OIDC RS256 verification in this codebase) and narrows the algorithm suite aggressively. Even so, any production deployment consuming untrusted IdP assertions should have the `signature.rs` + `c14n.rs` + `xml.rs` trio independently reviewed before being exposed to real enterprise traffic.

### 7. SCIM 2.0 Provisioning — COMPLETED ✅ (Phase 1 — requires hardening)

Implemented in one pass: users + groups CRUD + PATCH + filter + discovery endpoints, mounted at `/scim/v2/*`. Phase 1 covers the subset of RFC 7643 / 7644 that Okta and Azure AD actually exercise against provisioning endpoints; the deferred items are documented below rather than hidden.

**What ships:**

- **Endpoints:** `POST|GET /scim/v2/Users`, `GET|PUT|PATCH|DELETE /scim/v2/Users/{id}`, `POST|GET /scim/v2/Groups`, `GET|PUT|PATCH|DELETE /scim/v2/Groups/{id}`, `GET /scim/v2/{ServiceProviderConfig,Schemas,ResourceTypes}`.
- **User schema:** `userName` (maps to `User.email`), `externalId` (idempotent IdP provisioning key), `name.{givenName,familyName}` (first-class fields on `User`), `displayName`, `emails[]` (primary only persisted), `active` (↔ `UserStatus::{Active,Disabled}`), `meta` (includes weak ETag).
- **Group schema:** `displayName` (↔ `Organization.name`), `externalId`, `members[]` with role `Member`. Slug is derived via `slugify(displayName)` with UUID suffix on collision.
- **Filter:** flat `eq` / `ne` / `co` / `sw` / `ew` / `pr` with `and` / `or`. Bracketed paths (`emails[type eq "work"].value`) return `400 invalidFilter`. Case-insensitive string comparison.
- **PATCH:** simple dotted paths (`active`, `name.familyName`, `emails`, `members`, …) and root-object replacement with an implicit per-field apply. `add` / `replace` / `remove` all supported.
- **Auth:** reuses the admin Bearer + `X-Realm-ID` extractor (now `pub(crate)` on `http.rs`) and the shared `AdminRateLimiter` — SCIM calls count against the same 100/min bucket as REST and gRPC admin. Non-admin tokens → 403 with the SCIM error envelope, not the plain `{error}` envelope.
- **Engine-level externalId indexes:** new storage prefixes `scim:ext_user:*`, `scim:ext_user_fwd:*`, `scim:ext_group:*`, `scim:ext_group_fwd:*`, plus six new `IdentityEngine` methods (`{set,clear,get}_scim_external_id`, `find_user_by_scim_external_id`, same four for groups). Duplicate externalId returns the new `IdentityError::DuplicateScimExternalId`. Cascade in `delete_user`, `delete_organization`, `delete_realm`.
- **Audit:** six new `AuditAction` variants — `ScimUser{Created,Updated,Deleted}` + `ScimGroup{Created,Updated,Deleted}`. Metadata carries `{"via": "scim", "external_id": "..."}`. Proto enum + wire conversion tables updated in lockstep.
- **ETag:** weak `W/"<updated_at_micros>"` on every individual-resource response. Inbound `If-Match` is accepted and ignored (see hardening).
- **First-class name fields on `User`:** `first_name` + `last_name` are now required (empty string allowed) on the core user model — not a SCIM-only sidecar. Federation JIT provisioning and Keycloak import populate them from upstream `given_name` / `family_name` / `firstName` / `lastName`. Admin-UI and self-registration forms expose them. `display_name` auto-synthesizes as `"{first} {last}"` when the caller omits it.

**Key files (new):**
- Module: `src/protocol/scim/{mod,types,filter,patch_apply,error,users,groups,discovery}.rs` (~2100 LOC)
- Tests: `src/identity/engine.rs::tests::scim_*` (6 engine unit tests), `src/protocol/scim/{filter,patch_apply,types}::tests` (18 unit tests), `tests/scim.rs` (11 integration tests).

**Key files (modified):**
- `src/identity/types.rs` — `User`, `CreateUserRequest`, `UpdateUserRequest`, `ImportUserRequest`, `RegisterUserRequest` gained `first_name` / `last_name`. `UpdateUserRequest` treats them as `Option<String>` (patch-marker).
- `src/identity/engine.rs` — synthesis of `display_name` when caller omits it; SCIM externalId trait methods; cascade in `delete_user` + `delete_organization` + `delete_realm`.
- `src/identity/mod.rs` — six new `IdentityEngine` methods.
- `src/identity/validation.rs` — new `validate_name_part` (empty allowed, null + length bounds).
- `src/identity/keys.rs` — four new prefix constants + encoders.
- `src/identity/error.rs` — `DuplicateScimExternalId` variant.
- `src/identity/federation/{types,oidc,github,saml/sp}.rs` — `ExternalIdentity` gained `first_name` / `last_name`; OIDC `IdTokenClaims` reads `given_name` / `family_name`; SAML attribute map resolves `first_name` / `last_name`.
- `src/identity/federation/oidc.rs` — populate names from upstream claims.
- `src/identity/migration/keycloak.rs` — import Keycloak `firstName` / `lastName`.
- `src/protocol/http.rs` — `extract_admin_auth` + `AdminAuth` exposed `pub(crate)`; `/scim/v2` mounted.
- `src/protocol/convert/identity.rs` + `proto/hearth/identity/v1/identity.proto` — wire types carry `first_name` / `last_name`.
- `src/protocol/web/admin.rs` + `templates/ui/admin/users/{new,edit}.html` — first/last inputs.
- `src/protocol/web/handlers.rs` + `templates/ui/register.html` — first/last inputs on the registration form.
- `src/audit/types.rs` + `proto/hearth/events/v1/audit.proto` + `src/protocol/{convert,grpc}/audit.rs` — six new `AuditAction` variants.

**Known limitations / planned hardening:**

- **Bracketed filter paths** (`emails[type eq "work"].value`) are rejected. Real IdPs don't send them against provisioning endpoints, but RFC 7644 §3.4.2.2 allows them.
- **Bracketed PATCH paths** are also rejected. Same justification.
- **`/Bulk` endpoint** is not implemented. Okta + Azure batch behind the scenes by issuing many individual requests, which the current endpoints handle.
- **Sorting / attribute projection / `excludedAttributes`** are not implemented. List responses always return the full resource representation.
- **Enterprise User schema extension** (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`) is not advertised or accepted. Manager, cost-center, division, etc. are dropped if the client sends them.
- **Pagination is in-memory.** The handler scans up to 1000 resources via the existing `list_users` / `list_organizations` cursor and slices the result in process. Engine-level filter / pagination push-down is Phase 2.
- **`If-Match` is accepted and ignored.** ETag is emitted on responses but optimistic concurrency is not enforced; two concurrent PUTs both win-last.
- **Service-account / long-lived SCIM tokens** are not a separate construct. Phase 1 reuses admin Bearer tokens — production deployments typically want a scope-limited SCIM-only token.
- **`displayName` uniqueness for Groups** is not enforced. Hearth's `Organization.slug` uniqueness is preserved by appending a UUID suffix on collision; a SCIM client that renames via PATCH triggers the same slug-rewrite path.
- **Non-primary emails** in a user POST are accepted-and-dropped. Hearth stores a single email; subsequent emails are visible only as the `primary: true` entry on GET.
- **`userName` assumed to equal email.** Azure AD configurations that emit `userPrincipalName` as non-email are out of scope.

**Security note:** All SCIM writes go through the same `IdentityEngine` paths that admin UI / gRPC use — the SCIM layer is a thin translator, so existing invariants (email uniqueness, Argon2id hashing, audit trail) hold uniformly. There is no credential provisioning via SCIM; Phase 1 clients cannot set passwords through the endpoint.

### 8. gRPC Management API — COMPLETED ✅

Implemented feature-complete. Hearth now exposes a tonic-based gRPC server alongside the existing REST surface, reusing the same engines and rate-limit state.

- **Services (5):**
  - `hearth.identity.v1.IdentityAdminService` — Users, realms, organizations CRUD.
  - `hearth.identity.v1.ApplicationAdminService` — OAuth client CRUD.
  - `hearth.identity.v1.OAuthService` — Authorize, TokenExchange, Revoke, Introspect, DeviceAuthorize, ClientCredentials, RegisterClient (RFC 6749 + RFC 8628 + RFC 7009 + RFC 7662 + RFC 7591 over gRPC).
  - `hearth.rbac.v1.RbacAdminService` — Role CRUD, group CRUD, role assignment CRUD, effective-permissions introspection. See [`../specs/AUTHORIZATION.md`](../specs/AUTHORIZATION.md) § 8.4.
  - `hearth.events.v1.AuditService` — ListEvents, VerifyIntegrity (runs the SHA-256 chain verifier).
- **Plus:** `grpc.health.v1.Health` via `tonic-health` and `grpc.reflection.v1.ServerReflection` via `tonic-reflection` so grpcurl / Postman can enumerate services at runtime.
- **Admin auth:** Same rules as REST — `authorization: Bearer <token>` + `x-realm-id: <uuid>` metadata → `identity.validate_token()` + check for the `hearth.admin` permission claim → [`AdminRateLimiter`](../../src/protocol/admin_auth.rs) (100 req/min per admin user, **shared** with the REST surface so a caller cannot evade limits by switching protocols).
- **OAuth auth:** Client credentials travel in the request body per RFC 6749 §2.3 (no admin interceptor), consistent with REST `/token` shape.
- **Error mapping:** Centralized [`identity_to_status`](../../src/protocol/grpc/convert.rs) and `rbac_to_status` tables map domain errors to `tonic::Code` (`NotFound`, `AlreadyExists`, `Unauthenticated`, `PermissionDenied`, `InvalidArgument`, `FailedPrecondition`, `ResourceExhausted`, `Internal`).
- **Cross-realm isolation:** Admin of realm A requesting B's resources gets `NOT_FOUND` (not `PERMISSION_DENIED`) — same enumeration-resistance posture as REST.
- **Transport:** Spawned off the main HTTP listener in `src/main.rs`. New config fields `server.grpc_port` (optional — when unset gRPC is disabled) and `server.grpc_bind_address` (defaults to `server.bind_address`). Graceful shutdown is wired through the same ctrl+c channel so both listeners stop together. Max decoding message size clamped to 1 MiB (matches REST `BODY_LIMIT_DEFAULT`).

**Key files:**
- Proto: `proto/hearth/identity/v1/identity.proto`, `oauth.proto`; `proto/hearth/rbac/v1/rbac.proto`; `proto/hearth/events/v1/audit.proto` (all gained `service` stanzas).
- Build: `build.rs` switched from `prost_build` to `tonic_build` (wraps prost + emits server traits and client stubs). File descriptor set is reused by pbjson (HTTP JSON codec) and tonic-reflection.
- gRPC module: `src/protocol/grpc/{mod,server,auth,identity,oauth,rbac_admin,audit,convert}.rs`.
- Shared rate limiter: `src/protocol/admin_auth.rs` (extracted from `http.rs`).
- Config: `src/config/types.rs::ServerConfig` gained `grpc_port` + `grpc_bind_address`.
- Harness: `tests/common/mod.rs` exposes `identity_arc`, `rbac_arc`, `audit_arc` for rigs that need `Arc<dyn Trait>`.
- Tests: `tests/grpc_admin.rs` (integration tests — health, reflection, unauthenticated/forbidden/rate-limit, user+app+rbac+audit+OAuth round-trips, cross-realm isolation).
- Runnable example: `examples/grpc-admin-flow/` — one-command Node walkthrough (`./run.sh`) that boots Hearth, bootstraps an admin, and drives the full surface end-to-end (admin CRUD, role/group/assignment CRUD, effective-permissions introspection, audit, health, reflection).

**Remaining enhancements (not blocking):**
- mTLS on the gRPC listener (today plaintext over h2c; operators bring their own TLS terminator via service mesh / Envoy). The existing `ReloadableTlsConfig` in `src/protocol/tls.rs` can be reused when the need for direct TLS arises.
- Rich error details via `google.rpc.ErrorInfo` / `BadRequest` (`tonic-types` is wired; current Status carries string message only).
- Terraform provider / Kubernetes operator using the generated clients.
- SDK wiring for `sdks/ts` and `sdks/go` to consume the tonic-generated clients.

**Verification:** `cargo nextest run` passes 1251 tests (13 new gRPC + 1238 existing). Manual probe via grpcurl:
```text
grpcurl -plaintext localhost:<grpc_port> list
grpcurl -plaintext -H 'authorization: Bearer $TOKEN' -H 'x-realm-id: $UUID' \
  -d '{"limit": 10}' localhost:<port> hearth.identity.v1.IdentityAdminService/ListUsers
grpc_health_probe -addr=localhost:<port>
```

### 9. Documentation Site

- **Vision ref:** Phase 1 exit criteria include "Documentation site" as a deliverable.
- **Current State:** Documentation exists as raw markdown files in `docs/` (specs, vision, gaps, theme). There is no built documentation site — no mdbook, docusaurus, or equivalent. No getting-started guide beyond code-level docs.
- **What's Missing:**
  - Static site generator setup (mdbook for Rust projects, or docusaurus for broader reach).
  - Getting started guide: install → configure → first login flow.
  - API reference: auto-generated from proto definitions and/or OpenAPI spec.
  - SDK documentation for TypeScript and Go.
  - Configuration reference (exists as markdown, needs to be in the site).
  - Migration guides (Keycloak, and eventually Auth0/Clerk).
  - Architecture overview for contributors.
  - Search functionality.
  - Deployment to a public URL (e.g., docs.hearth.dev via GitHub Pages or Vercel).
- **Why It Matters:** Developer adoption requires discoverable, navigable documentation. Raw markdown in a Git repository is not a documentation site. This is explicitly a Phase 1 deliverable that was not completed.
- **Priority Rationale:** P1 — Phase 1 exit criteria explicitly lists this. Open-source projects without documentation don't get adopted.

### 10. Additional Migration Tools — PARTIALLY COMPLETED ✅ (Auth0 Phase 1 shipped)

- **Vision ref:** §8.3 describes migration paths for Auth0, Clerk, Cognito, Firebase Auth, and generic SCIM/CSV/JSON import.
- **Current State:**
  - **Keycloak**: implemented (`src/identity/migration/keycloak.rs`, `hearth migrate keycloak` CLI).
  - **Auth0 Phase 1**: implemented. Bundle-file input format (`{tenant, users, clients, organizations, roles}`); separate Node bundler (`examples/auth0-migration-bundler/`) assembles the bundle from the Management API. Bcrypt / argon2 / pbkdf2-sha256 / scrypt password-hash passthrough when exportable; md5/sha1 land the user without a credential + warning. Organizations + members + role assignments + `blocked` / `email_verified` → `UserStatus` all mapped.
  - CLI: `hearth migrate auth0 --file bundle.json --data-dir ./data [--dry-run] [--realm <uuid>]`.
  - Tests: 7 integration tests (`tests/migration_auth0.rs`) + 30 unit tests co-located in `src/identity/migration/auth0{,_credentials}.rs`.
- **Still Missing:**
  - **Auth0 live Management API client inside Hearth** (deferred — bundler is a separate Node process).
  - **Auth0 federated-identity connections** (Google / SAML / AD — orthogonal to Hearth's own federation module).
  - **Auth0 Rules / Actions / Hooks** (server-side logic has no Hearth equivalent).
  - Clerk migration: import users and organizations via Clerk API.
  - Generic import: CSV/JSON bulk import for custom user databases.
  - SCIM-based bulk import for systems with SCIM export.
  - Shadow mode: run Hearth alongside existing auth, replaying traffic to validate correctness before cutover (Vision §5.5).
  - Export tools: full realm export to standard formats.
- **Key files (Auth0 Phase 1):**
  - Engine-adjacent: `src/identity/migration/auth0.rs`, `auth0_credentials.rs`, `mod.rs` (re-exports)
  - CLI: `src/main.rs` (`MigrateSource::Auth0`, `run_migrate_auth0`)
  - Fixture: `tests/fixtures/auth0/tenant-export.json`
  - Tests: `tests/migration_auth0.rs`
  - Bundler: `examples/auth0-migration-bundler/{bundle.mjs,README.md,package.json,.env.example}`
- **Why It Matters:** Migration friction is the #1 barrier to adoption. Keycloak is one source among many. Teams on Auth0, Clerk, or homegrown systems need a path in.
- **Priority Rationale:** P1 for Auth0/Clerk (large addressable market). P2 for Cognito/Firebase. Shadow mode is P2.

---

## P2 — Enhances Operational Maturity

### 11. Prometheus / OpenTelemetry Observability

- **Vision ref:** Phase 2 deliverable: "Prometheus metrics and OpenTelemetry tracing."
- **Current State:** Hearth uses `tracing` for structured logging throughout all layers. Benchmarks exist (`benches/`) but are dev-only. No metrics exporter, no trace exporter.
- **What's Missing:**
  - Prometheus metrics endpoint (`/metrics`) with counters, gauges, and histograms:
    - `hearth_auth_total{method,realm,status}` — authentication attempts.
    - `hearth_token_issued_total{grant_type,realm}` — tokens issued.
    - `hearth_rbac_resolve_total{result,realm}` — permission resolutions at token-issue time.
    - `hearth_session_active{realm}` — gauge of active sessions.
    - `hearth_request_duration_seconds{endpoint,method}` — request latency histograms.
    - `hearth_storage_wal_bytes`, `hearth_storage_memtable_entries`, `hearth_storage_sst_count`.
  - OpenTelemetry trace export (OTLP) via `tracing-opentelemetry`.
  - Grafana dashboard template.
- **Why It Matters:** Production operators need dashboards and alerting. Without metrics, detecting degradation, capacity planning, and incident response require log parsing. Every comparable system (Keycloak, Ory, Zitadel) exposes Prometheus metrics.
- **Priority Rationale:** P2 per Vision roadmap. Practically essential for any production deployment.

### 12. Backup / Restore / Snapshots

- **Vision ref:** §6.1 cluster layer mentions snapshot-based recovery. §3.1 mentions S3 for snapshots.
- **Current State:** WAL + SST provides crash recovery (survive `kill -9`). No user-facing backup, restore, or snapshot mechanism. No S3 integration.
- **What's Missing:**
  - Online snapshot: consistent point-in-time capture without stopping writes.
  - Snapshot export to local filesystem or S3-compatible object storage.
  - `hearth backup` and `hearth restore` CLI subcommands.
  - Incremental backup: ship WAL segments since last snapshot.
  - Per-realm export/import for migration between Hearth instances.
  - Restore validation: checksum verification on restore.
- **Why It Matters:** WAL provides crash safety, not disaster recovery. Operators need protection against DC failure, disk corruption, accidental deletion, and the ability to migrate data between environments.
- **Priority Rationale:** P2 because crash safety exists, but no production team deploys a database without backup/restore.

### 13. Webhook / Event Delivery

- **Vision ref:** §A Open Question #3: "Should Hearth provide a built-in event system?"
- **Current State:** Audit events are recorded internally with SHA-256 hash chain integrity. No external push notification mechanism exists.
- **What's Missing:**
  - Webhook subscription management: register per-realm HTTPS endpoints with event type filters.
  - Reliable delivery: at-least-once semantics with exponential backoff retry.
  - Payload signing (HMAC-SHA256) for recipient verification.
  - Delivery log: status tracking (pending, delivered, retrying, failed, disabled).
  - Event types: `user.created`, `user.deleted`, `session.created`, `session.revoked`, `permission.changed`, `realm.updated`, `org.member.added`.
  - Admin UI for managing webhook subscriptions and viewing delivery logs.
- **Why It Matters:** Downstream systems (billing, analytics, SIEM, Slack notifications) need real-time event feeds. Without webhooks, operators must poll the audit API.
- **Priority Rationale:** P2 — the audit log provides queryable history, but push-based integration is the modern standard.

### 14. Encryption at Rest

- **Vision ref:** §5.4 "Encryption at rest: credentials and sensitive fields are encrypted with per-realm keys. Compromising the storage layer does not compromise credentials."
- **Current State:** Credentials are hashed (Argon2id), sensitive fields use `Zeroize`-on-drop. The storage engine writes plaintext keys and values to WAL and SST files. There is **no encryption of data on disk** and no per-realm encryption key management.
- **What's Missing:**
  - Per-realm data encryption keys (DEKs) for encrypting stored values.
  - Key encryption key (KEK) hierarchy: master key wraps per-realm DEKs.
  - Transparent encryption/decryption in the storage engine write/read path.
  - Key rotation without re-encrypting all data (envelope encryption pattern).
  - Optional HSM/KMS integration for master key storage (Vision §A Open Question #6).
  - `hearth rotate-keys` CLI subcommand.
- **Why It Matters:** The Vision explicitly commits to this feature. Compliance-sensitive deployments (healthcare, finance, government) require encryption at rest. Password hashes alone don't satisfy this — user profiles, session data, audit logs, and RBAC state are all stored in cleartext on disk.
- **Priority Rationale:** P2 for general use (hashed credentials are the primary defense). P1 for compliance-regulated environments.

### 15. CI/CD Pipelines

- **Current State:** No `.github/workflows/` directory. No automated testing, linting, or release pipeline. All testing is manual (`cargo nextest run`).
- **What's Missing:**
  - GitHub Actions workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo nextest run` on every PR.
  - CI tiers matching TESTING.md: Fast (every commit), Standard (merge), Extended (nightly), Full (weekly).
  - Release pipeline: build binaries for Linux/macOS/Windows, publish Docker images, create GitHub releases.
  - Security scanning: `cargo audit`, `cargo deny check`.
  - Benchmark regression detection (compare against baseline).
- **Why It Matters:** Open-source credibility requires visible CI badges. Contributors need automated feedback. Release engineering requires automation.
- **Priority Rationale:** P2 per typical project lifecycle, but practically P0 for open-source project launch.

### 16. Global Configurable Rate Limiter

- **Current State:** Rate limiting exists per-feature: password auth (5 attempts/15min), admin API (100/min), TOTP (5 attempts/5min), magic link (per-email). No unified middleware.
- **What's Missing:**
  - Global rate limiter middleware: IP-based, configurable per endpoint and per realm.
  - Token bucket or sliding window algorithm with configurable parameters.
  - Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`).
  - Per-realm quota allocation (realm A: 1000 req/s, realm B: 100 req/s).
  - Connection-level limits (max concurrent connections per IP).
- **Why It Matters:** Per-feature limits protect specific abuse vectors. A unified system is needed for fair multi-tenant resource allocation and general API protection.
- **Priority Rationale:** P2 because critical paths are already protected.

### 17. Deployment Artifacts

- **Vision ref:** Phase 2: "Helm chart and systemd service file."
- **Current State:** Dockerfile and docker-compose.yaml exist. No Kubernetes or bare-metal deployment artifacts.
- **What's Missing:**
  - Helm chart: configurable values for single-node and future cluster mode.
  - systemd service file with proper sandboxing (`ProtectSystem=strict`, `PrivateTmp=true`).
  - Kubernetes manifests (StatefulSet for persistence, Service, ConfigMap, Secret).
  - Example Terraform module for cloud VM deployment.
- **Why It Matters:** Production teams deploy to Kubernetes or Linux VMs. Without official deployment artifacts, every team writes their own.
- **Priority Rationale:** P2 per Vision roadmap.

---

## P3 — Post-Release Enhancements

### 18. Policy-as-Code Integration (optional)

- **Vision ref:** §A Open Question #1.
- **Current State:** Hearth issues JWT claims carrying the user's resolved roles, groups, and permissions. Applications with policy-as-code needs (Cedar, OPA/Rego, Polar) consume those claims as inputs to their own policy engine.
- **What's Missing (optional, community-driven):**
  - Canonical integration example showing a Hearth-authenticated request feeding Cedar or OPA for resource-specific decisions.
  - Helper utilities in SDKs for extracting claims in formats commonly expected by policy engines.
- **Priority Rationale:** P3 — not required for any Hearth user; included because policy-as-code layers cleanly on top of the claim-based RBAC surface.

### 19. Dedicated Authorization-Service Integration (optional)

- **Vision ref:** §A Open Question #2.
- **Current State:** Teams that need graph-structured authorization (delegated sharing, Google-Drive-shaped ACLs) pair Hearth with a dedicated Zanzibar-family service (SpiceDB, OpenFGA, Cerbos). Hearth's JWT claims provide the identity context these services need.
- **What's Missing (optional):**
  - Canonical integration example wiring a Hearth-authenticated request through to a SpiceDB / OpenFGA permission check.
  - SDK helper for threading the JWT `sub` / `tid` into Zanzibar API calls idiomatically.
- **Priority Rationale:** P3 — narrow audience; the integration pattern is standard across identity vendors.

### 20. Additional SDKs

- **Vision ref:** §8.2 lists priority order: TypeScript, Go, Python, Rust, PHP, Java, C#, Ruby, Elixir.
- **Current State:** TypeScript and Go SDKs exist with tests.
- **What's Missing:** Python, Rust, PHP, Java/Kotlin, C#, Ruby, Elixir SDKs.
- **Priority Rationale:** P3 for most. Python and Rust are Phase 2 deliverables per Vision roadmap.

### 21. Raft Clustering

- **Vision ref:** Phase 2 (v1.0): "Raft-based consensus and log replication."
- **Current State:** `src/cluster/mod.rs` is a 4-line stub. No Raft, no replication, no failover.
- **What's Missing:** Full Raft consensus (openraft), leader election, log replication, membership changes, snapshot recovery.
- **Priority Rationale:** P3 — explicitly Phase 2 / v1.0 scope. Single-node is the Phase 1 target.

### 22. Embedded Mode API Documentation

- **Vision ref:** §6.2 describes embedded mode as a key differentiator: "linked directly into the application process as a library."
- **Current State:** `src/lib.rs` exists as a library root. Trait-based APIs are used internally. No public documentation, no usage examples, no API stability guarantees.
- **What's Missing:**
  - Documented public API surface for embedded usage.
  - Example project showing embedded Hearth in a Rust application.
  - C ABI or language-specific bindings (Vision mentions "C ABI or language-specific bindings").
  - API stability policy for the library interface.
- **Priority Rationale:** P3 — server mode is the primary target. Embedded mode is a future differentiator.

---

## Completed Items (Previously Listed as Gaps)

### Production Email Provider Integration — COMPLETED ✅

Implemented in Phase 1.5. Five transports: Log (dev), SMTP, SendGrid, Postmark, Mailgun. Per-realm branding overrides, Askama + Tera templates, `ApiKey` zeroize-on-drop wrapper. Module: `src/identity/email/`.

**Remaining enhancements (not blocking):**
- AWS SES adapter (requires SigV4 signing).
- Delivery status tracking / bounce handling.
- Per-realm email provider configuration.

### User Self-Registration — COMPLETED ✅

Implemented as the public signup flow with per-realm `RegistrationPolicy` (disabled / open / domain-restricted / invite-only), per-email (3/hr) and per-IP (10/hr) rate limiting, and enumeration-resistant duplicate-email handling. Routes: `GET|POST /ui/register`, `GET /ui/register/sent`. Consumes the existing `issue_email_verification_token` + `verify_email_token` primitives, so registered users land in `PendingVerification` until they click the email link.

**Key files:**
- Engine: `src/identity/engine.rs` (`register_user`, `create_user_with_status`, `check_registration_rate_limit`)
- Types: `src/identity/types.rs` (`RegistrationPolicy`, `RegisterUserRequest`, `RegisterUserResponse`)
- Errors: `src/identity/error.rs` (`RegistrationDisabled`, `RegistrationDomainNotAllowed`, `RegistrationRequiresInvitation`)
- Validation: `src/identity/validation.rs` (`validate_password_against_policy`)
- Web: `src/protocol/web/handlers.rs` (`register_form`, `register_submit`, `register_sent`)
- Templates: `templates/ui/register.html`, `register_sent.html`
- YAML config: `src/config/types.rs` (`RegistrationPolicyYaml`, `RegistrationModeYaml`)
- Tests: `tests/self_registration.rs` (9 integration + adversarial tests)

**Remaining enhancements (not blocking):**
- CAPTCHA / proof-of-work (scope: pluggable anti-abuse). IP rate limit is the minimum viable defense today.
- Custom profile fields during registration.
- HTTP-layer handler tests (engine-layer tests cover the critical security paths).

### Password Reset / Account Recovery — COMPLETED ✅

Verified end-to-end functional: `request_password_reset` + `reset_password_with_token` in `src/identity/engine.rs:3400+`, UI handlers in `src/protocol/web/handlers.rs:1500+`, templates at `templates/ui/forgot_password*.html`, `templates/ui/reset_password*.html`, email template at `templates/email/password_reset.html`. Rate-limited (3/hr/email), SHA-256 token hash, 30-min expiry, single-use, enumeration-resistant (silent success for unknown emails).

**Remaining enhancements (not blocking):**
- Dedicated end-to-end integration test for the full forgot → email → reset flow (core methods covered indirectly).
- Optional notification to secondary verified channels on password change.

### Self-Service Session Management — COMPLETED ✅

Implemented as the `/ui/account/sessions` page backed by the pre-existing `list_sessions_by_user` + `revoke_session` engine primitives. Signed-in users can now review every active session (device label, client IP, created/last-active/expires timestamps), revoke any individual session, or revoke every session except the current one. Revoking the current session acts as an implicit logout: session cookie cleared, redirect to `/ui/login`.

**Key behaviors:**
- **Ownership enforcement:** the revoke handler loads the target session and compares its `user_id` against the authenticated user before calling `revoke_session`. A cross-user revoke attempt returns 404 (not 403), which also hides session-id existence across users. Covered by `revoke_other_users_session_is_rejected` in `tests/web_ui_account_sessions.rs`.
- **Current-session handling:** the current row in the table carries a "This device" badge and `data-current-session="true"` attribute; its action button says "Log out this device". Revoking it clears both UI cookies via the shared `clearing_cookies()` helper.
- **Audit trail:** every self-service revocation emits `AuditAction::SessionRevoked` with `actor = user_id` and `metadata = {"via": "self"}` (batch operations add `"batch": true`). Admin revocations continue to tag `metadata.via = "ui"`, so the two channels are cleanly distinguishable in the audit query API.
- **No proto / engine changes:** the entire feature is a new protocol-layer surface — no new trait methods, no new `AuditAction` variants, no new storage keys.

**Key files:**
- Handlers: `src/protocol/web/account.rs` (`sessions_index`, `revoke_session`, `revoke_other_sessions`, `audit_self_session_revoke`)
- Routes: `src/protocol/web/mod.rs` (`/account/sessions`, `/account/sessions/{sid}/revoke`, `/account/sessions/revoke-others`)
- Template: `templates/ui/account/sessions.html`; entry-point link added to `templates/ui/account/index.html`
- Shared helper promoted: `append_cookie` in `src/protocol/web/handlers.rs` is now `pub(super)` so both `logout_submit` and `revoke_session` can reuse the cookie-clearing idiom
- Tests: `tests/web_ui_account_sessions.rs` (7 integration tests — listing isolation, current-session marker, own-revoke + audit, cross-user rejection, current-session logout, revoke-all-others, CSRF enforcement)

**Remaining enhancements (not blocking):**
- Approximate geolocation hint from IP (requires a GeoIP dataset — previously listed under this gap's "what's missing"; deferred to keep the dependency footprint small).
- JSON/REST and gRPC API variants of these endpoints (gap #8 tracks the management-API surface separately).
- HTMX/AJAX revoke-in-place UX (current implementation is PRG).

### OAuth Consent Screen — COMPLETED ✅

Implemented feature-complete:

- **Browser-facing authorize endpoint**: `GET /ui/oauth/authorize` (bare + `/ui/realms/{realm}/oauth/authorize` scoped). The existing JSON `POST /authorize` at `src/protocol/http.rs` stays as-is for SDK/machine clients. The browser endpoint validates query parameters, requires a `UiSession`, loads the `OAuthClient`, and — when the existing `ConsentRecord` covers every requested scope or the client has `require_consent=false` — skips straight to code issuance. Otherwise it persists a `PendingAuthorizationRequest` under an opaque 10-minute TTL ticket and redirects to the consent page.
- **Consent interstitial**: `templates/ui/oauth/consent.html` renders the client name, optional logo, and per-scope checkboxes. Submitting with `decision=approve` performs a **subset check** (approved scopes must be ⊆ requested), upserts the consent record (merging with any prior-granted scopes), emits `AuditAction::ConsentGranted`, and redirects to `redirect_uri?code=...&state=...`. `decision=deny` emits `ConsentDenied` and redirects with `error=access_denied&state=...` per RFC 6749 §4.1.2.1.
- **Self-service management**: `GET /ui/account/consents` lists every consent the signed-in user has granted (client name + logo + scopes), with per-client revoke and "revoke all" actions. Revoking emits `ConsentRevoked` with `metadata.via = "self"`.
- **Admin visibility**: `GET /ui/admin/users/{id}/consents` shows any user's consents within the admin's target realm. `POST .../consents/{client_id}/revoke` performs admin revoke-on-behalf, emitting `ConsentRevoked` with `metadata.via = "admin"` and `target_user` set to distinguish from self-revokes.
- **REST / JSON surface**: `GET /oauth/consents` + `DELETE /oauth/consents/{client_id}` (Bearer-token, current user) and `GET /admin/users/{id}/consents` + `DELETE .../consents/{client_id}` (admin). Matches the self-service/admin split used by sessions and organizations.
- **Trusted client bypass**: new `OAuthClient.require_consent: bool` (default `true`) and `client_logo_url: Option<String>`. Exposed through `RegisterClientRequest`, `UpdateClientRequest`, and the YAML `applications.{name}.require_consent` / `.client_logo_url` fields — YAML reconciliation creates the client then applies consent-policy fields via `update_client`.
- **OIDC `prompt` semantics**: `prompt=none` without sufficient consent returns `error=consent_required` per OIDC Core §3.1.2.1; `prompt=consent` forces the prompt even if a matching record exists.
- **Cascading deletes**: `delete_user` scrubs `oauth:consent:{user}:*`; `delete_client` scans `oauth:consent:*` and removes every record ending with the deleted client's UUID; `delete_realm` adds `oauth:consent:*` and `oauth:pending_auth:*` to the existing 11-prefix sweep.
- **Ticket security**: the in-flight ticket cookie is HMAC-SHA256-bound to the signed-in user's `UserId` and the ticket UUID. Cross-user replay fails MAC verification; the engine `take_pending_authorization` then independently re-checks the user_id embedded in the stored pending record. Tickets are single-use and expire after 10 minutes.
- **Audit**: three new variants — `AuditAction::{ConsentGranted, ConsentDenied, ConsentRevoked}` — wired through `proto/hearth/events/v1/audit.proto`, the `From<&domain>` mapping in `src/protocol/convert/audit.rs`, and the AS_STR / FROM_STR round-trips.

**Key files:**
- Engine: `src/identity/engine.rs` (`grant_consent`, `get_consent`, `list_consents_by_user`, `revoke_consent`, `revoke_all_consents_for_user`, `put_pending_authorization`, `get_pending_authorization`, `take_pending_authorization`, `issue_authorization_code`; cascades in `delete_user`, `delete_client`, `delete_realm`)
- Types: `src/identity/types.rs` (`ConsentRecord`, `ConsentListEntry`, `PendingAuthorizationRequest`, `ConsentDecision`, `canonicalize_scopes`)
- Trait: `src/identity/mod.rs` (8 new methods on `IdentityEngine`)
- Errors: `src/identity/error.rs` (`ConsentRequired`, `ConsentTicketNotFound`, `ConsentTicketExpired`, `ConsentScopeNotRequested`, `ConsentNotFound`)
- Storage keys: `src/identity/keys.rs` (`encode_consent_key`, `encode_consent_prefix_for_user`, `oauth_consent_scan_prefix`, `encode_pending_auth_key`, `oauth_pending_auth_scan_prefix`)
- OAuth client fields: `src/identity/oidc.rs` (`OAuthClient::{require_consent, client_logo_url, set_require_consent, set_client_logo_url}`; `RegisterClientRequest` / `UpdateClientRequest` fields)
- Web UI: `src/protocol/web/oauth_consent.rs` (`authorize_get` + scoped + `consent_page` + `consent_submit`), `src/protocol/web/account_consents.rs` (`consents_index` + revoke + revoke-all), `src/protocol/web/admin.rs::admin_user_consents_list` + `admin_user_consent_revoke`
- Templates: `templates/ui/oauth/consent.html`, `templates/ui/account/consents.html`, `templates/ui/admin/users/consents.html`
- REST/JSON: `src/protocol/http.rs` (`self_list_consents`, `self_revoke_consent`, `admin_list_user_consents`, `admin_revoke_user_consent`, `extract_user_auth`)
- Audit: `src/audit/types.rs`, `proto/hearth/events/v1/audit.proto`, `src/protocol/convert/audit.rs`
- YAML: `src/config/types.rs::ApplicationYamlConfig.{require_consent, client_logo_url}` + `src/identity/reconcile.rs`
- Tests: `tests/oauth_consent.rs` (26 integration + adversarial + conformance + admin RBAC tests); engine-layer unit tests in `src/identity/engine.rs` (11) and `src/identity/types.rs` (6)
- Runnable example: `examples/oauth-consent-flow/` — browser-visible Express client that drives the flow end-to-end, demonstrating the prompt, trusted-client bypass, partial-scope approval, `prompt=consent` re-prompting, and user + admin revocation with audit trail

**Remaining enhancements (not blocking):**
- Admin UI toggle for `require_consent` on the application edit page (the YAML path ships with this PR; the in-UI form is deferred until the applications edit handler itself is implemented — current admin UI is read-only from YAML).
- HTMX/AJAX consent-decision UX (current flow is PRG).
- Per-scope human-readable descriptions (the UI currently renders the raw scope string — e.g. `profile`, `email`).

### Explicit Realm Routing in the Web UI — COMPLETED ✅

Discovered while testing self-registration: pre-auth `/ui/*` handlers had no explicit realm binding — they walked every realm until one matched. That leaked realm existence and prevented per-realm policy (like `RegistrationPolicy`) from applying correctly when the wrong realm was picked first.

The fix introduces explicit path-segment routes and a centralized resolver:

- **New route family:** `/ui/realms/<name>/login`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email`, `/accept-invitation`, `/login/passkey-begin`, `/login/passkey-complete`, plus their `/sent` confirmation pages. Each scoped variant resolves the realm from the URL path.
- **Bare `/ui/*` resolution rules** (in [`src/protocol/web/realm_resolver.rs`](../../src/protocol/web/realm_resolver.rs)):
  1. Single-realm deployment → implicit use of the sole realm (no config needed).
  2. Multi-realm + `server.default_realm` set → the declared default is used.
  3. Multi-realm + `default_realm` unset → **terse 400 page** (`templates/ui/realm_required.html`) with no realm names. Hearth deliberately does not present an anonymous picker; enumerating tenants is a discovery leak.
- **Walk-all-realms fallback eliminated** from `login_submit`, `forgot_password_submit`, `reset_password_submit`, `verify_email`, `passkey_login_begin`, `passkey_login_complete`, `register_*`, and `accept_invitation_page`. All delegate to the shared `resolve_pre_auth_realm` helper in `src/protocol/web/handlers.rs`.
- **Startup validation:** if `server.default_realm` is set, the named realm MUST exist after reconciliation, else `main.rs` refuses to start.
- **Admin config editor:** new "Default Realm" field under the Server section of `/ui/admin/settings/editor`.

**Key files:**
- `src/config/types.rs` — `ServerConfig::default_realm: Option<String>`
- `src/protocol/web/realm_resolver.rs` — `resolve()` function returning `Resolved::Realm | NotFound | MustChoose | Storage`
- `src/protocol/web/handlers.rs` — `resolve_pre_auth_realm`, `PreAuthRealm`, `ChooseRealmTemplate`, plus `_impl` + `_scoped` variants of every pre-auth handler
- `src/protocol/web/mod.rs` — new `/ui/realms/{realm}/*` route family; `WebState::default_realm_name`, `with_default_realm`, `realm_theme_css_for`
- `templates/ui/choose_realm.html` (new), `templates/ui/admin/settings/_editor_sections.html` (default-realm input)
- `tests/web_ui_realm_routing.rs` — 10 integration tests covering single-realm, multi-realm with default, multi-realm picker, path-scoped routes, unknown realm, no-walk regression, and per-realm verify-email scoping.

**Remaining enhancements (not blocking):**
- Subdomain-per-realm routing (orthogonal; layer on top of path segments later if needed).
- Email-based home realm discovery (lookup email domain → realm) for enterprise SSO scenarios.
- Per-realm `primary: true` flag (YAGNI until a concrete use case appears).

### Admin (system) realm — COMPLETED ✅

Addresses two admin-setup bugs on multi-realm deployments: verification links hitting the wrong resolver; admin users bound to whichever application realm sorted first by UUID byte order. The fix introduces an **invisible system realm** (`RealmId::nil()`) that holds all Hearth admins; operators administer application realms via a `TargetRealm` extractor.

**Engine + onboarding:**
- Singleton system realm auto-seeded at engine construction (`seed_system_realm_if_absent` in `src/identity/engine.rs`).
- Invisible on public surfaces: `list_realms()` filters it, `get_realm_by_name("system")` returns `None`, YAML `realms.system` rejected at parse time (`src/config/mod.rs` `validate_realm_names`).
- Structural guardrails via new `IdentityError::SystemRealmProtected { operation }`: `create_realm` rejects name `"system"`; `update_realm` rejects nil UUID + renaming-to-`system`; `delete_realm`, `register_user`, `register_client`, `create_organization` all reject the nil UUID.
- `onboarding::complete_setup` always targets system realm. Admin user + `realm.admin` role assignment both land there. Verification URL is `/ui/admin/verify-email?token=...`.

**Admin pre-auth surface:**
- New routes `/ui/admin/login` (GET+POST) and `/ui/admin/verify-email`; admin session cookies carry the nil UUID.
- `RequireAdmin` asserts `session.realm_id == system_realm_id()` — a tenant session can never pass an admin gate, even if it somehow carried the `hearth.admin` permission locally.

**Admin UI target-realm refactor:**
- New `TargetRealm` extractor in `src/protocol/web/auth.rs`: resolution order is `?realm=<name>` query → `hearth_ui_admin_target` cookie → first non-system realm. Rejects `?realm=system`.
- ~62 references to `session.realm_id` across ~30 admin handlers in `src/protocol/web/admin.rs` switched to `target.id()`. Audit helpers (`audit_user_event`, `audit_app_event`, `audit_session_event`, `audit_org_event`) take an explicit `target_realm: &Realm` so they record audit events in the right realm.
- `POST /ui/admin/switch-realm` sets the `hearth_ui_admin_target` cookie, allowing persistent per-admin realm selection without URL decoration.
- Realms list page (`templates/ui/admin/realms/_rows.html`) gets an "Administer this realm →" action that POSTs to the switcher.

**Tests:**
- `tests/admin_realm.rs` — 13 integration tests covering seeding, invisibility, engine guards, onboarding target, admin login rendering, full e2e setup→verify→login, and switcher authentication.
- `tests/web_ui_admin.rs` — rig updated to put admin users in the system realm; all 20 existing admin UI tests still pass.

**Shipped file map (21 files modified, 3 new):**
- Engine/types: `src/identity/keys.rs`, `src/identity/error.rs`, `src/identity/engine.rs`, `src/identity/reconcile.rs`, `src/identity/onboarding.rs`, `src/config/mod.rs`
- HTTP mapping: `src/protocol/http.rs`
- Web layer: `src/protocol/web/auth.rs`, `src/protocol/web/handlers.rs`, `src/protocol/web/admin.rs`, `src/protocol/web/mod.rs`
- Templates: `templates/ui/admin/realms/_rows.html`
- Tests: `tests/admin_realm.rs` (new), `tests/onboarding.rs`, `tests/web_ui_admin.rs`
- Docs: `README.md`, `memory/admin_realm.md` (new)

**Remaining enhancements (not blocking):**
- Visual realm switcher dropdown in admin chrome. Today operators switch via `/ui/admin/realms` (one-click "Administer this realm" button per row) or by typing `?realm=<name>` in the URL.
- Admin-side auxiliary flows: `/ui/admin/forgot-password`, `/ui/admin/reset-password`, `/ui/admin/login/passkey-*`, `/ui/admin/mfa-challenge`. Admins reset passwords via the identity engine's CLI or directly via storage today.
- `RequireAdmin` extractor could additionally assert the `hearth.admin` permission is scoped to the system realm explicitly (currently it relies on `session.realm_id` which is always system after the refactor — equivalent but worth making explicit for clarity).
- Migration CLI for existing deployments (`hearth admin migrate-to-system-realm`). Pre-1.0; wipe data dir for now.

---

## Gap Summary Matrix

| # | Gap | Priority | Vision Ref | Effort Estimate |
|---|-----|----------|------------|-----------------|
| 1 | ~~User self-registration~~ — **DONE** | P0 | §8.1 | Medium |
| 2 | ~~Self-service session management~~ — **DONE** | P0 | §5.3 | — |
| 3 | ~~OAuth consent screen~~ — **DONE** | P0 | §5.3 | — |
| 4 | ~~Password reset~~ — **DONE** (verified) | P0 | §5.3 | — |
| 5 | ~~Social login / external IdP~~ — **DONE** | P1 | §5.3 | — |
| 6 | ~~SAML 2.0~~ — **DONE** (Phase 1; hardening recommended) | P1 | §5.3, §6.1 | — |
| 7 | ~~SCIM 2.0~~ — **DONE** (Phase 1; hardening recommended) | P1 | §5.3, §6.1 | — |
| 8 | ~~gRPC management API~~ — **DONE** | P1 | §6.1 | — |
| 9 | Documentation site | P1 | Phase 1 exit | Medium |
| 10 | Additional migration tools — **Auth0 Phase 1 DONE** ✅ (Clerk/CSV/shadow-mode pending) | P1 | §8.3 | Medium per tool |
| 11 | Prometheus / OpenTelemetry | P2 | Phase 2 | Medium |
| 12 | Backup / restore / snapshots | P2 | §6.1 | Large |
| 13 | Webhook event delivery | P2 | §A Q#3 | Medium |
| 14 | Encryption at rest | P2 | §5.4 | Large |
| 15 | CI/CD pipelines | P2 | — | Small |
| 16 | Global rate limiter | P2 | — | Medium |
| 17 | Deployment artifacts | P2 | Phase 2 | Small |
| 18 | Authorization schema language | P3 | §A Q#1 | Large |
| 19 | Expression language (CEL) | P3 | §A Q#2 | Medium |
| 20 | Additional SDKs | P3 | §8.2 | Medium per SDK |
| 21 | Raft clustering | P3 | Phase 2 | Very Large |
| 22 | Embedded mode API docs | P3 | §6.2 | Small |

---

## Recommended Release Sequence

**Minimum viable public release (v0.1-alpha):**
Gaps 1 ✅, 2 ✅, 3 ✅, and 4 ✅ complete. Remaining: 15 — CI/CD.

**Production-ready single-node (v0.x per Phase 1 exit criteria):**
Add gaps 9, 11 — documentation site, Prometheus metrics. (Consent screen ✅, social login ✅.)

**Enterprise-ready (v1.0 per Phase 2 exit criteria):**
Add gaps 10 (remaining — Clerk / CSV / shadow mode), 12, 14, 17, 21 — migration tools, backup, encryption, deployment artifacts, Raft. (gRPC ✅. SAML Phase 1 ✅ and SCIM Phase 1 ✅ — recommend hardening pass before enterprise GA. Auth0 migration Phase 1 ✅.)

---

*Last updated: 2026-04-23. Revised to mark gap #7 (SCIM 2.0 provisioning) as completed — P1 list narrowed from 4 to 3 items.*

*Updated 2026-04-23: gap #10 Auth0 migration Phase 1 shipped (bundle-file input + separate Node bundler). Clerk, CSV/JSON, SCIM-based import, shadow mode, and export tools remain open.*

---

*Last updated: 2026-04-22. Generated by comparing VISION.md (§1–§12), ARCHITECTURE.md, IMPLEMENTATION_ORDER.md (steps 1–31), and codebase exploration against actual implementation. Revised 2026-04-22 to mark gap #2 (self-service session management) as completed.*
