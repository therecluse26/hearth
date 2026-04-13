# Hearth Architecture

## Purpose

This document defines the structural rules that govern all Hearth source code. It is enforced in every PR. Violations of MUST-level rules block merge.

Terminology follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** carry their standard meaning. MUST-level rules are hard gates — violations block merge with no exceptions. SHOULD-level rules are strong preferences — violations require a comment in the PR explaining the justification for deviation.

Changes to this document require the same review rigor as breaking API changes.

### Related Documents

- [VISION.md](../vision/VISION.md) — design rationale, performance targets, competitive positioning, and roadmap. The "why" and "what."
- [TESTING.md](./TESTING.md) — verification strategy, eight testing layers, tooling, and CI tiers. The "how we prove it works."
- This document — structural rules, constraints, and architectural decisions. The "how code must be written."

---

## 1. Layer Architecture

### 1.1 The Six Modules

Hearth is organized into five architectural layers plus a shared core module:

| Module | Path | Responsibility |
|--------|------|----------------|
| **Core** | `src/core/` | Shared types (`UserId`, `TenantId`, `SessionId`, `Timestamp`), error traits, the `Clock` trait, and other foundational types used by every layer. Contains only types and traits — no logic, no state, no I/O. |
| **Protocol** | `src/protocol/` | Wire format translation: HTTP REST, gRPC, OIDC, OAuth 2.0, SAML, SCIM, WebAuthn. Thin adapters that translate wire requests into Identity Engine calls and serialize responses. Stateless. |
| **Identity Engine** | `src/identity/` | Domain logic: users, credentials, sessions, tenants, tokens, audit. Orchestrates authentication flows. Enforces the opinionated decisions about supported flows. |
| **Authorization Engine** | `src/authz/` | Zanzibar-style relationship tuples: `check()`, `expand()`, `write_tuples()`, `watch()`. Graph traversal. Permission evaluation. |
| **Cluster** | `src/cluster/` | Raft consensus via `openraft`, log replication, leader election, membership changes, snapshots. Wraps the storage engine — in clustered mode, writes go through Raft before reaching storage. Skipped entirely in single-node mode. |
| **Storage Engine** | `src/storage/` | WAL, memtable, SSTs, hot/cold tiered storage, indexes, encryption at rest. The leaf layer. Pure data persistence with no knowledge of identity, auth, or authorization concepts. |

### 1.2 Dependency Direction

Dependencies flow strictly downward. The dependency graph is:

```
         core/  ←──────────────── (available to all layers)
           │
    ┌──────┴──────┐
    │  protocol/   │
    └──────┬──────┘
           │
    ┌──────┴──────┐      ┌──────────┐
    │  identity/   │─────→│  authz/  │  (lateral: identity may call authz)
    └──────┬──────┘      └────┬─────┘
           │                  │
           └────────┬─────────┘
                    │
           ┌────────┴────────┐
           │    cluster/      │
           └────────┬────────┘
                    │
           ┌────────┴────────┐
           │    storage/      │
           └─────────────────┘
```

**Rules:**

- Every layer MAY depend on `core/`.
- Dependencies MUST flow downward. No layer MAY import from a layer above it. `storage/` MUST NOT import from `cluster/`, `authz/`, `identity/`, or `protocol/`. `authz/` MUST NOT import from `identity/` or `protocol/`.
- **One lateral exception**: `identity/` MAY call into `authz/` (permission checks during authentication flows). `authz/` MUST NOT call into `identity/`.
- Lateral dependencies within the same layer are permitted but SHOULD be minimized.
- `src/main.rs` is the binary entry point. It wires layers together and starts the server. It MAY import from any layer.

### 1.3 Inter-Layer Communication

- Layers communicate through **trait interfaces** defined in each layer's `mod.rs`. Internal implementation details MUST NOT leak upward.
- Each layer MUST define its public interface as traits and types in its `mod.rs`. Internal types MUST be `pub(crate)` or private.
- The storage engine MUST NOT expose WAL, memtable, or SST types to upper layers. It exposes a storage trait with get/put/delete/scan operations.
- The authz engine MUST NOT expose graph internals. It exposes `check()`, `expand()`, `write_tuples()`, `watch()`.

---

## 2. Async Model

Hearth uses **Tokio** as its async runtime. No other async runtime MAY be used.

All layers expose `async fn` interfaces. This provides a uniform API and ensures the cluster layer (which is inherently asynchronous due to Raft network operations) integrates without sync/async boundary friction.

**Rules:**

- Blocking operations (file I/O, cryptographic hashing, DNS) MUST be offloaded to `tokio::task::spawn_blocking` or a dedicated blocking thread pool. They MUST NOT execute on Tokio worker threads.
- Long-running CPU-bound work MUST use `spawn_blocking` or `tokio::task::yield_now()` to avoid starving other tasks.
- Hot path functions (see [Section 3](#3-hot-path-rules)) are `async fn` but MUST NOT yield — they complete synchronously within an async context, performing no `.await` on I/O operations.

---

## 3. Hot Path Rules

The hot path is the most performance-critical code in the system — it executes on every authenticated request. The vision document targets sub-millisecond p99 latency for these operations (see [VISION.md Section 7](../vision/VISION.md) for specific targets).

### 3.1 Definition

The hot path is any code reachable from these operations **when data is in the hot tier**:

- `validate_token()` — session lookup (not signature re-verification; see [Section 10.1](#101-token-validation))
- `lookup_session()` — session by ID
- `check_permission()` — direct relationship tuple lookup (1-hop)
- `lookup_user()` — by indexed field (email, ID)

**Everything else is off the hot path**: user creation, credential hashing, token issuance, WAL writes, cold-tier promotion, audit materialization, multi-hop graph traversal, SAML/SCIM handling, admin API operations.

### 3.2 Hard Rules

Hot path code MUST obey all of the following:

1. **Zero heap allocations.** MUST NOT call `Box::new`, `Vec::new`, `String::from`, `format!()`, `to_string()`, or any other allocating operation in the steady state. Pre-allocated buffers and arena allocators are the alternatives.
2. **No syscalls for reads.** Hot-tier reads MUST be satisfied from memory-mapped structures or in-process data. No `read()`, `pread()`, or file I/O.
3. **No locks on the read path.** Readers MUST NOT acquire mutexes, `RwLock` write locks, or any blocking synchronization primitive. Epoch-based reclamation (e.g., `crossbeam-epoch`) or read-copy-update patterns are required.
4. **No yielding.** Hot path async functions MUST NOT `.await` on I/O operations. They complete synchronously within the async context.
5. **Cache-line alignment.** Hot path data structures SHOULD use `#[repr(C)]` and align to 64-byte cache lines where beneficial.

### 3.3 Cold Path Exemptions

- Cold-tier promotion (disk I/O to load evicted records) is NOT hot path. It MAY allocate, perform I/O, and acquire locks.
- Write path code (WAL append, memtable insert) is NOT hot path and has different constraints (see [Section 6.1](#61-write-path-invariants)).
- Multi-hop graph traversal (3+ hops) is NOT hot path. It has a performance budget enforced by benchmarks, not by allocation rules.
- Cold path reads MUST NOT degrade hot path performance. Cold-tier promotion MUST NOT lock or invalidate hot-tier data structures.

### 3.4 Benchmark Enforcement

Any PR that touches hot path code MUST include benchmark results demonstrating no regression beyond the thresholds defined in [TESTING.md Section 8](./TESTING.md). A regression beyond threshold blocks merge.

---

## 4. API Contracts and Wire Protocols

### 4.1 Protobuf as Single Source of Truth

All API contracts MUST be defined in `.proto` files. Protobuf is the single source of truth for request/response shapes, event schemas, and SDK type generation.

**Rules:**

- `.proto` files MUST live in `proto/` at the project root.
- REST and gRPC endpoints MUST serialize from protobuf-generated Rust types (via `prost`).
- Event schemas (webhooks, streaming) MUST use protobuf definitions from the same `.proto` files.
- Standard protocol shapes (OIDC, OAuth 2.0) MUST have `.proto` definitions that mirror their RFC-mandated schemas.
- SDK type generation SHOULD be derived from the `.proto` definitions.
- `buf` is the protobuf toolchain for linting, breaking change detection, and code generation.

### 4.2 Wire Protocols

- **REST** (JSON over HTTP) is the primary wire protocol, required from Phase 0. Standard protocol endpoints (OIDC, OAuth 2.0, SAML, SCIM) MUST conform strictly to their respective RFCs.
- **gRPC** SHOULD be supported as a secondary interface by Phase 1, for service-to-service communication in microservice environments.
- The HTTP framework MUST be `tower`-compatible to share middleware with the gRPC stack (`tonic`). The specific framework choice is an implementation decision.
- The **Identity Engine MUST NOT depend on any wire format or serialization framework.** Protocol adapters are thin translation layers that call into the Identity Engine's trait interface. This decoupling ensures new wire formats can be added without restructuring the core.

### 4.3 API Versioning

**Pre-1.0**: Breaking changes to wire format, config, and on-disk storage are permitted with a changelog entry. However, on-disk format changes MUST NOT silently corrupt data — if the format is incompatible, startup MUST fail with a clear error directing the operator to re-initialize.

**Post-1.0**:

- HTTP/gRPC endpoints MUST be versioned (`/v1/...`). Breaking changes require a new API version. Previous versions MUST be supported for at least one major release.
- Config changes MUST NOT break existing config files. New required fields MUST have defaults. Removed fields MUST produce a clear error, not silent behavior change.
- On-disk format changes MUST include automatic migration on startup. Hearth MUST read data written by the previous minor version without manual intervention.

---

## 5. Error Handling

### 5.1 Error Types

- Each layer MUST define its own error enum (`StorageError`, `IdentityError`, `AuthzError`, `ProtocolError`, `ClusterError`).
- All error enums MUST be `#[non_exhaustive]`.
- All error enums MUST implement `std::error::Error` and `Display`.
- Errors MUST NOT cross layer boundaries as concrete types. Upper layers convert lower-layer errors into their own types via `From` implementations, using categorized conversion: `LayerError::Internal { source: Box<dyn Error> }`. Upper layers see "internal failure" and can walk the error chain via `source()`, but do not match on lower-layer error variants.

### 5.2 Error Content

- Error messages MUST NOT include sensitive data: passwords, tokens, session IDs, cryptographic keys, PII.
- Error messages SHOULD include enough context for debugging: operation attempted, entity ID (if non-sensitive), reason for failure.
- Internal errors (storage corruption, invariant violations) MUST be logged at `error` level with full context before being converted to an opaque error for the caller.

### 5.3 Panic Policy

- Production code MUST NOT use `unwrap()` or `expect()` on fallible operations.
- `#[deny(clippy::unwrap_used)]` MUST be enabled for all non-test code, from day one.
- `unwrap()` is permitted ONLY when the invariant is provably unreachable, annotated with `#[allow(clippy::unwrap_used)]` and a `// INVARIANT:` comment explaining why it cannot fail. These sites are auditable by grepping for `allow(clippy::unwrap_used)`.
- `expect()` is permitted in test code and one-time initialization (startup).
- Public functions MUST return `Result<T, LayerError>`.

---

## 6. Storage Engine

### 6.1 Write Path Invariants

- Every mutation MUST be written to the WAL before being acknowledged. No write is considered committed until the WAL entry is `fsync`'d.
- Memtable insertions happen after WAL append. If the process crashes between WAL write and memtable update, WAL replay MUST reconstruct the correct state.
- Writes SHOULD be batched where possible to amortize `fsync` cost.
- `fsync()` is non-optional in production builds. A `--dev` flag MAY relax this for development mode only.
- The storage engine MUST survive `kill -9` at any point and recover to a consistent state. This is verified by deterministic simulation tests (see [TESTING.md Section 5](./TESTING.md)).

### 6.2 Tiered Storage

- The hot tier MUST auto-size based on available system memory (physical memory or cgroup limit) unless overridden by operator configuration.
- Hot-to-cold eviction MUST NOT block the read path.
- Cold-to-hot promotion MUST be asynchronous with respect to hot-tier readers — it MUST NOT lock or invalidate hot-tier data structures.
- The eviction policy is clock-based LRU approximation. Strict LRU is prohibited because it requires linked-list mutation on every access, violating hot path constraints.

### 6.3 Encryption at Rest

- Credentials and sensitive fields MUST be encrypted at rest using per-tenant keys.
- Encryption keys MUST NOT appear in log output, error messages, or debug dumps.
- The storage engine MUST support key rotation without downtime.

---

## 7. Multi-Tenancy

Hearth uses **logical isolation** with type-system-enforced tenant scoping. This is a MUST-level invariant — the highest enforcement tier.

### 7.1 Isolation Rules

1. **Type-system enforcement.** Every storage operation MUST require a `TenantId` parameter (a newtype, not a raw string). The storage API MUST make it impossible to construct a query without a tenant context. This is enforced at compile time.
2. **Key prefix encoding.** The storage engine MUST prefix all keys with the tenant ID. There is no code path to construct a storage key without a `TenantId`.
3. **Bounded scans.** All scan operations MUST be bounded to a single tenant's key space. The storage engine MUST NOT return results spanning multiple tenants from a single query.
4. **No cross-tenant API.** The standard storage API MUST NOT expose operations that query across tenants. Cross-tenant operations (admin, migration) MUST use a separate, explicitly privileged API path.

### 7.2 Verification

Tenant isolation MUST be verified by:

- **Property-based tests**: Random sequences of operations across random tenants, asserting that data written under tenant A is never readable under tenant B. 10,000+ cases in CI.
- **Adversarial tests**: Write data under tenant A, attempt every read operation under tenant B, assert zero results. Concurrent writes across tenants asserting no cross-contamination. Tenant deletion followed by recreation with the same ID asserting no ghost data.
- **Debug-mode runtime assertions**: In debug builds, every value returned from the storage engine is checked — does this record's tenant ID match the requested tenant ID? A redundant tripwire on top of the key prefix guarantee.

---

## 8. Security

### 8.1 Token Validation and Signing

Hearth's internal hot path validates tokens via **session lookup**, not signature re-verification. Hearth issued the token and stores the session — it does not need to cryptographically re-verify its own signatures on every request. The hot path extracts the session reference from the token, looks up the session in the hot tier, and checks expiration/revocation status.

**Signing:**

- Token signing MUST use asymmetric algorithms only. **Ed25519 (EdDSA)** is the primary signing algorithm. RS256 and ES256 MAY be supported for ecosystem compatibility.
- Symmetric signing algorithms (HS256, HS384, HS512) MUST NOT be supported. This eliminates the class of vulnerabilities where a verification key can forge tokens.
- `alg: none` MUST be rejected unconditionally.
- Hearth MUST manage its own signing key lifecycle: generation, rotation, and JWKS endpoint for external consumers. Operators MUST NOT need to manually generate or distribute keys in the default configuration.

**External consumers** (microservices that verify tokens offline without calling Hearth) use the JWKS endpoint and perform their own asymmetric signature verification.

### 8.2 Cryptographic Primitives

- Use `ring` or `RustCrypto` crates only. No hand-rolled cryptography.
- All comparisons of secrets (tokens, hashes, keys) MUST use constant-time comparison functions.

### 8.3 Password Hashing

- Argon2id MUST be the default algorithm for new password hashes.
- Parameters MUST meet or exceed current OWASP recommendations at time of implementation.
- Parameters MUST be stored alongside the hash so they can be upgraded without rehashing all users.
- Verification of legacy hashes (bcrypt, PBKDF2, scrypt) MUST be supported for migration, with automatic upgrade-on-login to Argon2id.
- Security parameters MUST NOT be weakened to meet latency targets. Password hashing is off the hot path and has no latency constraint.

### 8.4 Input Validation

Each layer validates what it is responsible for. **Each layer MUST validate its own invariants and MUST NOT assume upstream validation occurred.**

- **Protocol layer**: Wire-level validation. Max request size, content type, required fields present, string length limits, null byte rejection, Unicode NFC normalization on usernames and email addresses.
- **Identity layer**: Domain validation. Email format, password policy, username rules, tenant existence, session not expired.
- **Storage layer**: Structural validation. Key fits in index, value within size bounds, tenant ID present.

### 8.5 Audit Trail

- Security-critical mutations MUST emit structured `tracing` events at `info` level with sufficient context for forensic investigation: actor, action, target entity, tenant, result (success/failure). This provides real-time breach detection via log alerting from Phase 0.
- The WAL is the authoritative durable record of all mutations.
- An audit trail MAY be materialized asynchronously from the WAL as a background process in Phase 1+. This background job tails the WAL, extracts mutation events, and writes them into a separate append-only, queryable audit store. The write path MUST NOT block on audit trail materialization.
- The WAL MUST NOT be truncated past the audit materialization job's read cursor.
- When present, the audit store MUST be append-only and immutable — no update, no delete through any API.

---

## 9. Concurrency and Safety

### 9.1 Shared State

- Global mutable state is prohibited. All shared state MUST be passed explicitly via function parameters or held in typed state containers (e.g., `Arc<AppState>`).
- Read-heavy shared data MUST use lock-free structures (`crossbeam-epoch`, `arc-swap`). `RwLock` is a fallback when lock-free is impractical.
- `Mutex` MUST NOT be held across `.await` points. Use `tokio::sync::Mutex` only when necessary, with a comment explaining why.

### 9.2 Unsafe Code

`unsafe` MUST be minimized and isolated. Hearth leans on well-audited crates (`memmap2`, `crossbeam-epoch`, `arc-swap`) for operations that would otherwise require custom `unsafe` code.

- Every `unsafe` block MUST have a `// SAFETY:` comment explaining why the operation is sound.
- `unsafe` MUST NOT appear in the protocol or identity layers. It is permitted only in:
  - Storage engine (memory-mapped I/O, pointer arithmetic for data structures) — only if crate abstractions prove insufficient via profiling
  - Performance-critical data structures in `authz/` (graph adjacency structures, if needed)
- All `unsafe` code MUST be covered by Miri tests where feasible, and by address sanitizer runs in CI.
- New `unsafe` blocks require explicit reviewer approval.

---

## 10. Development Process

### 10.1 Test-Driven Development

All code MUST be developed test-first, following strict TDD (red-green-refactor):

1. **Write a failing test** that describes the expected behavior.
2. **Run it — confirm it fails** (red).
3. **Write the minimal implementation** to make it pass (green).
4. **Refactor** while keeping tests green.

**Rules:**

- All new functionality MUST have a failing test written before the implementation.
- All bug fixes MUST start with a failing test that reproduces the bug before the fix is written.
- A PR that adds functionality without corresponding tests written *before* the implementation is incomplete.

See [TESTING.md](./TESTING.md) for the full eight-layer testing strategy, tooling, and CI tiers.

### 10.2 Code Style

- `clippy::pedantic` MUST pass. Allowed lints MUST be documented in `Cargo.toml` or `clippy.toml`.
- `rustfmt` with the project's `rustfmt.toml`. No formatting debates in PRs.
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- All `pub` and `pub(crate)` items MUST have doc comments describing behavior and invariants, not implementation details.

---

## 11. Configuration

### 11.1 Format and Lifecycle

- Server configuration uses **YAML** — a single `hearth.yaml` file. YAML is familiar to operators managing infrastructure, regardless of Hearth's implementation language.
- Config MUST be validated at startup. Invalid config MUST cause a fast failure with a clear error message pointing to the exact problem.
- Config is **immutable after startup** in production mode. Config changes require a process restart. No `SIGHUP` reload, no runtime mutation.
- The `--dev` flag enables development mode: in-memory storage, no TLS, relaxed security, pre-configured test data, hot-reload for config changes. `--dev` mode is explicitly not for production.

### 11.2 Sensitive Values

Sensitive config values (signing keys, encryption keys, secrets) MUST support environment variable substitution (e.g., `${HEARTH_SIGNING_KEY}`). Secrets MUST NOT be required in plaintext in the config file.

### 11.3 Config Categories

The configuration file covers these categories:

- **Server**: bind address, ports, TLS certificate paths
- **Storage**: data directory, hot-tier memory limit (optional override), fsync policy
- **Auth**: token lifetimes, supported authentication flows, MFA policy
- **Cluster**: node ID, peer addresses, Raft timeouts (Phase 2+)
- **Observability**: log level, log format (human-readable or JSON), metrics endpoint

---

## 12. Type and Data Model Conventions

### 12.1 Newtype IDs

All entity IDs MUST be distinct newtypes: `struct UserId(Uuid)`, `struct SessionId(Uuid)`, `struct TenantId(Uuid)`, etc.

- Newtypes MUST NOT implement `Deref` to their inner type.
- Access to the inner value is via an explicit method (e.g., `.as_uuid()`, `.as_bytes()`).
- This prevents accidentally passing a `UserId` where a `SessionId` is expected.

### 12.2 Time

- All timestamps MUST be stored as UTC.
- Internal representation SHOULD be Unix timestamps in microseconds.
- The clock MUST be injectable via a `Clock` trait for deterministic testing (see [TESTING.md — Minimal Mocking](./TESTING.md)).

### 12.3 Sensitive Data

- Passwords, tokens, and cryptographic keys MUST be wrapped in types that implement `Zeroize` on drop.
- Sensitive types MUST NOT implement `Debug`, `Display`, or `Serialize` in ways that reveal their contents. Use a redacted placeholder (e.g., `Password(***)`).
- Sensitive types MUST NOT appear in log output at any level.

### 12.4 Serialization

- **Wire format**: JSON for REST, Protobuf for gRPC. Both generated from `.proto` definitions (see [Section 4.1](#41-protobuf-as-single-source-of-truth)).
- **Storage format**: A compact binary format defined by the storage engine, optimized for identity access patterns. NOT JSON. NOT Protobuf. The storage format is internal and opaque to upper layers.
- Serialization round-trips (`deserialize(serialize(x)) == x`) MUST be verified by property tests.

---

## 13. Module Internal Structure

### 13.1 File Organization

Each layer module SHOULD follow this pattern:

```
src/storage/
├── mod.rs          # Public trait definitions and re-exports ONLY — no implementation logic
├── wal.rs          # WAL implementation
├── memtable.rs     # Memtable implementation
├── sst.rs          # SST implementation
├── tiered.rs       # Hot/cold tier management
├── error.rs        # StorageError enum
└── types.rs        # Internal types (pub(crate))
```

- `mod.rs` MUST contain only trait definitions, re-exports, and module declarations. No implementation logic.
- Each implementation file SHOULD contain a single major type or concept.
- Inline `#[cfg(test)] mod tests` at the bottom of each implementation file.

### 13.2 Visibility

- Default to private. Make things `pub(crate)` only when another module needs access.
- `pub` (fully public) is reserved for types and functions exported as public API.
- MUST NOT use `pub` on struct fields unless they are part of the public API.

---

## 14. Logging and Observability

### 14.1 Logging

- Use `tracing` exclusively. No `println!`, `eprintln!`, or the `log` crate.
- **Log levels**: `error` (system is degraded), `warn` (unexpected but recoverable), `info` (significant events — startup, shutdown, config changes, security-critical mutations), `debug` (internal state for troubleshooting), `trace` (hot path tracing, disabled by default).
- Hot path code MUST NOT log at `info` level or above in the steady state.
- Use structured fields: user IDs, tenant IDs, operation names. MUST NOT log passwords, tokens, keys, or PII.
- Default output format is human-readable text. JSON format MUST be available via config for production log aggregation.

### 14.2 Metrics

- Prometheus-compatible metrics MUST be exposed via a `/metrics` endpoint.
- Key metrics: request latency histograms (by operation), active sessions gauge, error counters (by layer and error type), hot/cold tier sizes, WAL size.

### 14.3 Distributed Tracing

- OpenTelemetry-compatible distributed tracing SHOULD be supported for requests spanning protocol → identity → authz → storage.
- Trace spans MUST NOT be created on the hot read path unless tracing is explicitly enabled by the operator.

---

## 15. Dependency Policy

### 15.1 Adding Dependencies

- Adding a new dependency MUST be justified in the PR description: what it provides, why a hand-written solution is not appropriate, and its maintenance status (last release, bus factor, known issues).
- All new dependencies MUST pass `cargo-audit` with no known vulnerabilities.
- All new dependencies MUST be reviewed for license compatibility. Acceptable: Apache 2.0, MIT, BSD, MPL-2.0. Not acceptable: GPL, AGPL, SSPL.
- Dependencies MUST NOT introduce a C/C++ build toolchain requirement unless absolutely necessary (`ring` is acceptable; a dependency requiring `cmake` is suspect).

### 15.2 Approved Crates

These crates are pre-approved and need no additional justification:

| Purpose | Crate | Notes |
|---------|-------|-------|
| Async runtime | `tokio` | Full features |
| TLS | `rustls` | No OpenSSL dependency |
| Crypto primitives | `ring` | |
| Password hashing | `argon2` | Argon2id default |
| Serialization | `serde`, `serde_json` | Derive-based |
| Protobuf | `prost`, `prost-build`, `pbjson` | API contract codegen |
| Protobuf toolchain | `buf` | Linting, breaking change detection, codegen |
| gRPC | `tonic` | `tower`-compatible |
| Logging | `tracing`, `tracing-subscriber` | Structured, async-aware |
| CLI | `clap` | Derive-based |
| Lock-free concurrency | `crossbeam-epoch`, `arc-swap` | |
| Memory-mapped I/O | `memmap2` | |
| Raft consensus | `openraft` | Phase 2+ |
| HTTP framework | TBD | MUST be `tower`-compatible |
| Time handling | TBD | |
| Testing | `proptest`, `criterion`, `insta`, `madsim` | Test-only |
| HTTP client (test) | `reqwest` | Test-only |

### 15.3 Banned Patterns

- No ORM crates. There is no external database.
- No `lazy_static`. Use `std::sync::OnceLock` or `std::sync::LazyLock`.
- No `async-trait` on hot path code — it heap-allocates. Use return-position `impl Trait` in traits (RPITIT, stable since Rust 1.75).
- No `reqwest` in production code. Hearth is a server, not an HTTP client. Test-only is fine.

### 15.4 Auditing

- `cargo-audit` MUST run in CI on every PR.
- `cargo-deny` MUST be configured to enforce license and duplicate-crate policies.
- `cargo-vet` SHOULD be used to track audit status of third-party crates.

---

## 16. Cluster Layer

### 16.1 Raft Implementation

The cluster layer MUST use `openraft` for Raft consensus. A custom Raft implementation MUST NOT be written — Raft is a well-specified but notoriously subtle protocol, and `openraft` is battle-tested with existing production users.

Hearth provides the `RaftLogStorage` and `RaftStateMachine` trait implementations, giving full control over the storage and application layer while relying on `openraft` for leader election, log replication, and membership management.

### 16.2 Single-Node Mode

The cluster layer MUST be invisible in single-node mode — no configuration, no port allocation, no performance overhead. Writes go directly to the storage engine, bypassing Raft entirely.

---

## 17. Project Structure

```
hearth/
├── Cargo.toml
├── hearth.yaml                 # Example / default config
├── proto/                      # Protobuf contract definitions (single source of truth)
│   ├── buf.yaml
│   ├── hearth/
│   │   ├── identity/v1/        # User, session, tenant contracts
│   │   ├── authz/v1/           # Permission check, tuple contracts
│   │   ├── admin/v1/           # Admin API contracts
│   │   └── events/v1/          # Event schemas
│   └── third_party/
│       └── oidc/               # RFC-mirroring .proto for OIDC/OAuth2
├── src/
│   ├── main.rs                 # Binary entry point
│   ├── core/                   # Shared types, traits, error foundations
│   ├── protocol/               # Wire format adapters (REST, gRPC, OIDC, SAML, SCIM)
│   ├── identity/               # Domain logic (users, credentials, sessions, tenants)
│   ├── authz/                  # Zanzibar authorization engine
│   ├── cluster/                # Raft consensus (openraft)
│   └── storage/                # WAL, memtable, SSTs, tiered storage
├── tests/                      # Black box integration tests
├── fuzz/                       # cargo-fuzz targets
├── benches/                    # Criterion benchmarks
└── simulation/                 # madsim deterministic simulation tests
```

---

## 18. SDK Strategy

SDKs are the primary interface between application developers and Hearth. They are separate repositories, not part of the core binary. Architectural constraints that affect SDK design:

- SDK types SHOULD be generated from the `.proto` contract definitions (see [Section 4.1](#41-protobuf-as-single-source-of-truth)), ensuring type safety and eliminating drift between server and client.
- The server API MUST be SDK-friendly: consistent naming, predictable error shapes, pagination patterns, and idempotency keys where appropriate.
- SDKs MUST be idiomatic to their target language — a Go SDK feels like Go, not like a Rust SDK ported to Go.

SDK priority order is defined in [VISION.md Section 8.2](../vision/VISION.md).

---

## Appendix: Decision Log

Key architectural decisions codified in this document, with rationale:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust | Memory safety for credentials, no GC for sub-ms latency, mature async ecosystem |
| Async runtime | Tokio, async all layers | Uniform API, cluster layer needs async for Raft network I/O |
| Storage | Custom embedded engine | Purpose-built for identity access patterns, no external dependencies |
| Authorization model | Zanzibar relationship tuples | One model covering RBAC → ReBAC → conditional, co-located with identity data |
| Token validation (hot path) | Session lookup, not signature re-verification | Sub-microsecond vs 5-50μs, instant revocation, smaller key exposure surface |
| Signing algorithm | Ed25519 (asymmetric only) | No HS256 eliminates token forgery from compromised verification keys |
| Password hashing | Argon2id, OWASP parameters | Security over latency — hashing is off the hot path |
| Multi-tenancy | Logical isolation, type-enforced | Cross-tenant users are inherent to identity systems; physical isolation makes this painful |
| Cluster consensus | `openraft` | Proven library, not custom — Raft is subtle and `openraft` is battle-tested |
| Config format | YAML | Operators manage infrastructure with YAML; Hearth targets ops engineers, not Rust developers |
| Config lifecycle | Immutable after startup | Simplifies concurrency model — config loaded once into `Arc<Config>`, no synchronization |
| API contracts | Protobuf (`.proto` files) | Single source of truth for REST, gRPC, events, and SDK codegen |
| Audit trail | WAL-derived, async materialization | Zero write-path overhead; WAL is the durable record, audit store is a materialized view |
| Embedded mode | Not supported | FFI tax unjustified without proven demand; sync core makes future addition feasible |
| Unsafe code | Lean on crates | `memmap2`, `crossbeam-epoch`, `arc-swap` over custom `unsafe`. Matches Hearth's "leverage ecosystem" philosophy |
| TDD | Strict, test-first | Database + security = zero tolerance for "I think this works." Tests define correctness before implementation. |
| Pre-1.0 compatibility | Breaking changes permitted | Semver 0.x convention; strict compatibility rules activate at v1.0 |
