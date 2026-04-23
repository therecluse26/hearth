# gRPC Admin Flow — Runnable Example

An end-to-end walkthrough of Hearth's gRPC management API in a single
command. Demonstrates the admin surface, authorization engine with live
`Watch` streaming, audit log, health checking, and reflection.

## Run it

```bash
./run.sh
```

That builds Hearth (on first run), installs Node deps (on first run),
wipes any prior demo data, starts Hearth with `--dev` bound to HTTP
`127.0.0.1:8420` and gRPC `127.0.0.1:9420`, then runs
[`demo.mjs`](./demo.mjs). Hearth is killed on exit.

## What the demo does

1. **Bootstrap admin** — `POST /admin/bootstrap` (HTTP, dev-only) to
   create a realm + admin user + Zanzibar `hearth#admin` tuple + access
   token. Everything after this point talks gRPC.
2. **Health** — `grpc.health.v1.Health/Check` → `SERVING`.
3. **Reflection** — `grpc.reflection.v1.ServerReflection/ListServices`
   enumerates every service Hearth exposes (useful for `grpcurl`).
4. **Users** — `IdentityAdminService/CreateUser` twice, then
   `ListUsers` returns them.
5. **Watch streaming** — subscribe to
   `AuthorizationService/Watch`, then `WriteTuples` a fresh tuple in a
   second call. The subscribed stream yields the tuple-change event
   live.
6. **Check** — `AuthorizationService/Check` confirms the tuple takes
   effect.
7. **Audit** — `AuditService/ListEvents` shows the last few events
   (realm created, user created, tuples written…); `VerifyIntegrity`
   walks the SHA-256 hash chain.

## Prerequisites

- Rust toolchain (to build Hearth from source).
- Node.js 18 or later.
- Three free local ports: **8420** (Hearth HTTP), **9420** (Hearth
  gRPC). The Node demo opens no ports of its own.

## Poking around after the demo

The `run.sh` script tears Hearth down when the demo exits. If you'd
rather leave Hearth running so you can `grpcurl` against it, start it
manually:

```bash
cargo run --release -- serve --dev --config examples/grpc-admin-flow/hearth.yaml
```

In another terminal:

```bash
# Enumerate services.
grpcurl -plaintext localhost:9420 list

# Mint an admin token via HTTP (dev-only endpoint).
TOKEN=$(curl -s -X POST http://localhost:8420/admin/bootstrap | jq -r .access_token)
REALM=$(curl -s -X POST http://localhost:8420/admin/bootstrap | jq -r .realm_id)

# Call any admin RPC.
grpcurl -plaintext \
  -H "authorization: Bearer $TOKEN" \
  -H "x-realm-id: $REALM" \
  -d '{"limit": 10}' \
  localhost:9420 hearth.identity.v1.IdentityAdminService/ListUsers
```

## Files

| File | What it is |
|---|---|
| `run.sh` | One-command wrapper — build, boot, run, teardown. |
| `hearth.yaml` | Minimal config: HTTP 8420, gRPC 9420, local data dir. |
| `demo.mjs` | The walkthrough. Plain ESM, no TypeScript, no bundler. |
| `package.json` | Two deps: `@grpc/grpc-js` + `@grpc/proto-loader`. |
| `health.proto` / `reflection.proto` | Local copies of the standard gRPC protos so `@grpc/proto-loader` can resolve them without a network fetch. |

## Shortcuts this example takes (don't copy into production)

- `--dev` enables the `/admin/bootstrap` endpoint, which mints a fully
  privileged admin token with no authentication. That endpoint returns
  404 in production builds.
- The gRPC listener is plaintext h2c. A production deployment should
  front the gRPC port with mTLS (Hearth's `tls_cert_path` /
  `tls_key_path` path is not yet wired into the gRPC listener — tracked
  in `docs/gaps/FEATURE_GAPS.md` §8).
- The demo uses `@grpc/proto-loader` (dynamic codegen) rather than
  `grpc-tools`-generated static stubs. For production Node services
  prefer static codegen for type safety and startup speed.
