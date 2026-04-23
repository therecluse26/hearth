# SCIM 2.0 provisioning — end-to-end walkthrough

Hearth speaks **SCIM 2.0** (RFC 7643 + RFC 7644) at `/scim/v2/*`, so
external identity systems — Okta, Azure AD, Workday, any OIDC + SCIM
workforce platform — can provision users and groups into Hearth
automatically.

This example boots a local Hearth, mints an admin token, and drives the
full SCIM surface with a plain Node script so you can watch exactly what
an IdP sees when it points at Hearth. Every request and every response
is a raw HTTP call; there is no SDK between the demo and the server.

## What you'll see

Thirteen numbered scenarios run in order:

1. **Discovery** — `ServiceProviderConfig`, `Schemas`, `ResourceTypes` advertise what Hearth supports.
2. **Create Alice** — `POST /scim/v2/Users` with an `externalId`, structured `name`, and `emails`. Returns `201`, a `Location` header, and a weak `ETag`.
3. **Idempotency guard** — a second `POST` reusing the same `externalId` fails with `409` + the SCIM error envelope (`scimType: "uniqueness"`).
4. **Create Bob** — a second user so filter and pagination have more than one row to work with.
5. **Filter** — `?filter=userName eq "alice@example.com"` returns exactly one resource.
6. **Pagination** — `?startIndex=1&count=1` demonstrates the `ListResponse` envelope (`totalResults`, `itemsPerPage`, `startIndex`).
7. **PATCH deactivate** — `{op: "replace", path: "active", value: false}` disables Alice's account without deleting it.
8. **PUT full replace** — re-enables Alice and sets a new `displayName` in one call.
9. **Filter boundary** — bracketed filter paths like `emails[type eq "work"].value` are rejected with `400 invalidFilter`. Real IdPs never send them; the demo surfaces the error envelope so the boundary is explicit.
10. **Create a Group** — `POST /scim/v2/Groups` with Alice and Bob as members. SCIM Groups map onto Hearth `Organization` + `OrganizationMembership` rows with role `Member`.
11. **PATCH group members** — remove Bob via `{op: "remove", path: "members"}`.
12. **DELETE + reprovision** — deleting Alice cascades her `externalId` mapping, so a fresh `POST` that reuses `"okta-alice"` succeeds.
13. **Audit trail** — `GET /admin/audit?action=scim_user_created` etc. surfaces the six new `Scim*` audit actions, each tagged with `metadata = {"via": "scim", "external_id": ...}`.

## Prerequisites

- Rust toolchain (for `cargo build`) — the script builds `hearth` in release mode on first run.
- Node.js 18 or later. No `npm install` is required: the demo uses the built-in `fetch` global and has zero runtime dependencies.
- `curl` on `PATH` (used by `run.sh` to wait for Hearth's `/health` endpoint).

## Run it

```bash
cd examples/scim-provisioning
./run.sh
```

The script will:

1. `cargo build --release --bin hearth` (slow on first run, instant after).
2. Wipe any previous demo data under `./data/scim-provisioning/`.
3. Start `hearth serve --dev --config ./hearth.yaml` on `http://127.0.0.1:8422` in the background; logs go to `.hearth.log`.
4. Wait for `/health` to respond.
5. Run `node demo.mjs`, which prints each scenario with colorized section headers and the relevant response shape.
6. Kill Hearth on exit (trap on `EXIT`/`INT`/`TERM`).

Expected final line on success:

```
✓ SCIM walkthrough complete.
```

Exit code `0` means every scenario passed. A failure line from `demo.mjs`
prints the offending HTTP status and body before exiting non-zero.

## What the demo does NOT do

Deliberate omissions that match the deferred-hardening list for
[gap #7 in `docs/gaps/FEATURE_GAPS.md`](../../docs/gaps/FEATURE_GAPS.md#7-scim-20-provisioning--completed--phase-1--requires-hardening):

- **No production auth.** The demo uses `/admin/bootstrap` (only available under `--dev`) to mint an admin Bearer. Production deployments should issue a scope-limited SCIM token — that work is called out as hardening in `src/protocol/scim/mod.rs`.
- **No `If-Match` enforcement.** Hearth emits weak ETags on every response, but inbound `If-Match` headers are accepted and ignored. Two racing PUTs both win-last.
- **No `/Bulk`.** Okta and Azure provision without it; adding the endpoint is straightforward follow-up work.
- **No sorting or attribute projection.** List responses always return the full resource representation.
- **No bracketed filter paths.** The demo exercises the rejection path so you can see where the boundary lives.

## Troubleshooting

- **`bootstrap failed (404)`** — the `--dev` flag is missing. `run.sh` sets it; if you're running `demo.mjs` by hand, boot Hearth with `hearth serve --dev --config hearth.yaml` first.
- **`cargo build` fails** — check `rustc --version`; Hearth tracks stable.
- **`timed out waiting for http://127.0.0.1:8422/health`** — `.hearth.log` has the reason. The most common cause is a prior Hearth instance left running on the same port.
- **Port already in use** — edit `hearth.yaml` (`server.port`) and `demo.mjs` (`HTTP` constant) in lockstep.

## Further reading

- [`src/protocol/scim/`](../../src/protocol/scim/) — the server implementation. Handlers: `users.rs`, `groups.rs`. Types: `types.rs`. Filter parser: `filter.rs`. PATCH applier: `patch_apply.rs`. Errors: `error.rs`.
- [`tests/scim.rs`](../../tests/scim.rs) — integration tests that drive the same router via `tower::ServiceExt::oneshot`, i.e. without spinning up a real listener. Useful reference for embedding Hearth in a test harness.
- [RFC 7643 — SCIM Core Schema](https://www.rfc-editor.org/rfc/rfc7643)
- [RFC 7644 — SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644)
- Vision § 5.3 and § 6.1 in [`docs/vision/VISION.md`](../../docs/vision/VISION.md) — the commitment to SCIM in Hearth's roadmap.

## File map

| File | Purpose |
|---|---|
| `run.sh` | Builds Hearth, wipes data, starts the server, runs the demo, tears down. |
| `demo.mjs` | The 13-scenario SCIM walkthrough. Plain Node 18+ `fetch`; no deps. |
| `hearth.yaml` | Minimal server config: HTTP 8422, ephemeral data dir, dev-friendly logging. |
| `package.json` | `type: module`, `scripts.start`, zero runtime dependencies. |
| `.gitignore` | Keeps `data/`, logs, and pidfiles out of version control. |
