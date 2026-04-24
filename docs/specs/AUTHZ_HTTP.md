# Authz HTTP API

SPA- and BFF-facing HTTP surface for Hearth's Zanzibar-style authorization engine.

The engine's primary interface is gRPC (`proto/hearth/authz/v1/authz.proto`) — browsers cannot speak native gRPC without a heavy gateway, so this small HTTP surface exists to let frontends perform per-user permission checks directly, without duplicating access control logic in every BFF.

See also: `ARCHITECTURE.md` § 4.2.1 (wire-protocol placement), `CONFIGURATION.md` (capability-page YAML shape).

## Endpoints

### `POST /v1/authz/check`

Batch permission check for the authenticated user. The subject is **always** derived from the bearer token's `sub` claim — callers cannot check permissions on behalf of another user.

**Headers:**
- `Authorization: Bearer <access_token>` — required.
- `X-Realm-ID: <realm_uuid>` — required.
- `Content-Type: application/json`.

**Request body:**
```json
{
  "checks": [
    { "object": "doc:readme",  "relation": "viewer" },
    { "object": "doc:readme",  "relation": "editor" },
    { "object": "org:acme",    "relation": "member" }
  ],
  "at_least_as_fresh_as": 57
}
```
- `checks` — 1 to 64 entries. `object` is `"type:id"` (ASCII alphanumeric + `_` / `-`, max 128 chars each side of the colon). `relation` is ASCII alphanumeric + `_`, max 64 chars.
- `at_least_as_fresh_as` — optional zookie from a previous write. Guarantees each check sees at least this version of the tuple store.

**Response (200):**
```json
{
  "results": [
    { "allowed": true },
    { "allowed": false },
    { "allowed": true }
  ],
  "token": 57
}
```
Results are positionally aligned with the request's `checks` array. `token` is the echoed zookie (see *Consistency tokens* below).

**Errors:**
| Status | When |
|--------|------|
| `400` | `checks` missing / empty / > 64, malformed `"type:id"`, invalid relation, unresolved object reference |
| `401` | Missing / invalid / expired bearer token |
| `413` | Request body > 1 MiB (standard body-limit middleware) |

### `GET /v1/me/capabilities?page=<key>&<var>=<val>…`

Named capability bundle. The server owns the `(object, relation)` list per page key; the client passes a page key plus template-variable params. Designed so one round-trip per page replaces N per-element `Check` calls.

**Request:**
```
GET /v1/me/capabilities?page=org.settings&org_id=acme
Authorization: Bearer <access_token>
X-Realm-ID: <realm_uuid>
```

**Response (200):**
```json
{
  "capabilities": {
    "org:acme#member": true,
    "org:acme#admin":  false
  },
  "token": 0
}
```
Keys are `"object#relation"` where `object` is the fully-resolved template. Keys are sorted (server returns a `BTreeMap`) so snapshot tests are stable.

**Errors:**
| Status | When |
|--------|------|
| `400` | Missing `page` query param, or missing template variable |
| `401` | Missing / invalid / expired bearer token |
| `404` | Unknown page key (not configured) |

## Capability pages

Page configuration is server-owned, versioned alongside the rest of the Hearth config.

### Shape

At the Rust layer, a page is:
```text
CapabilityPage {
  entries: [
    CapabilityPageEntry {
      object_template: "org:{org_id}",
      relations:       ["owner", "admin", "member"]
    }
  ]
}
```
Each `entry` expands to `relations.len()` check results in the response, keyed by the resolved `"object#relation"`. Template `{var}` segments are replaced from the request's query string; any unresolved variable is a `400`.

Pages live on `AppState::capability_pages` (a `HashMap<String, CapabilityPage>`). Main wires them from config at startup.

### Example uses

- `org.settings` → checks `{owner, admin, member}` on `org:{org_id}` so the settings page can hide the danger-zone section to non-owners in one round trip.
- `doc.{id}.toolbar` → checks `{viewer, editor, owner}` on `doc:{id}` so the document toolbar can grey out edit controls without per-button checks.
- `realm.admin` → checks `{admin}` on `hearth` so layout shells can conditionally render an `/admin` nav entry.

## Consistency tokens (zookies)

A zookie is a monotonically-increasing `uint64` returned from writes. In single-node mode consistency is always satisfied; the token contract becomes load-bearing in the Phase 2 cluster, where reads may hit stale replicas.

**Write flow:**
1. Mutation returns `{ token: N }`.
2. Client records `N` as a floor.
3. Subsequent reads pass `at_least_as_fresh_as: N` — the server refuses to serve responses older than that.

**Current behavior (single-node, Phase 1):** `POST /v1/authz/check` echoes the input `at_least_as_fresh_as` (or `0`) rather than reporting the engine's current version — `AuthorizationEngine::check` does not expose a current-version accessor. Clients rely on *monotonicity*, not "latest known version" semantics. The TS and Go SDK `AuthzCache` implementations use monotonic write-recording, which is the safe pattern regardless.

## SDK usage

### TypeScript

```ts
import { HearthClient, AuthzCache } from "@hearth/sdk";

const hearth = new HearthClient({ baseUrl, realmId });

// Raw check — results positional with the request.
const { results, token } = await hearth.check(accessToken, [
  { object: "doc:readme", relation: "viewer" },
  { object: "doc:readme", relation: "editor" },
]);

// Named page bundle.
const bundle = await hearth.capabilities(accessToken, "org.settings", {
  org_id: "acme",
});
// bundle.capabilities = { "org:acme#owner": true, "org:acme#admin": false, ... }

// Cache with automatic zookie threading. Keep one per logical session.
const cache = new AuthzCache(hearth, () => accessToken);

const first  = await cache.capabilities("org.settings", { org_id: "acme" });
const second = await cache.capabilities("org.settings", { org_id: "acme" });
// second is served from cache — no HTTP round trip.

// After a mutation, surface the zookie so cached reads stay consistent.
cache.recordWrite(mutationResponse.token);

cache.invalidate("org.settings");  // drop; next read refetches
cache.invalidate();                // drop all
```

### Go

```go
import "github.com/anthropics/hearth/sdks/go/hearth"

client := hearth.NewClient(baseURL, realmID)

// Raw check.
resp, err := client.Check(ctx, accessToken, []hearth.CheckRequestItem{
    {Object: "doc:readme", Relation: "viewer"},
    {Object: "doc:readme", Relation: "editor"},
}, nil)

// With a zookie for read-after-write consistency.
zookie := uint64(57)
resp, err = client.Check(ctx, accessToken, checks, &hearth.CheckOptions{Zookie: &zookie})

// Named page bundle.
bundle, err := client.Capabilities(ctx, accessToken, "org.settings",
    map[string]string{"org_id": "acme"})

// Cache — safe for concurrent use.
cache := hearth.NewAuthzCache(client, func() string { return accessToken })

bundle, err = cache.Capabilities(ctx, "org.settings",
    map[string]string{"org_id": "acme"})

cache.RecordWrite(mutationToken)
cache.Invalidate("org.settings")
cache.Invalidate("")  // drop all
```

## When to use which tool

| Scenario | Use |
|----------|-----|
| "Can the current user do X on this specific object?" | `check(...)` — a single entry |
| "What can the user do on this page / feature?" | `capabilities(page, params)` |
| "What can the user do globally across the app?" (dozens of objects) | Several `capabilities` calls, one per logical page — don't build one giant bundle |
| "Service-to-service: can user Y do X?" | gRPC `AuthorizationService.Check` (admin-scoped, allows cross-user checks) — NOT this HTTP surface |
| "Subscribe to live permission changes" | gRPC `AuthorizationService.Watch` — an HTTP/SSE bridge is a deferred follow-up |

## Security boundaries

- The HTTP `check` and `capabilities` endpoints only let a user check **their own** permissions. The subject is pinned to the token's `sub`.
- "Check on behalf of another user" belongs on the gRPC admin surface, which enforces the `hearth#admin` relation.
- Error responses never include tuple text, stack traces, or storage paths — see `tests/cross_cutting_phase1.rs`.
- Standard body-limit middleware (1 MiB default) applies; the 64-entry batch cap is enforced before any authz work runs.

## Follow-ups

- SSE stream for live tuple-change invalidation (`GET /v1/authz/watch`), so `AuthzCache` can invalidate precisely on write rather than TTL-polling.
- Rust-native `current_version()` accessor so `check` responses carry a meaningful token, not just an echoed input.
- Config-file wiring for `capability_pages` at the YAML layer (currently settable directly on `AppState`).
- `POST /v1/me/capabilities` batched variant (multiple page keys in one call) — only once usage data shows it's needed.
