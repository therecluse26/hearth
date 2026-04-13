# Hearth — Development Rules

Hearth is a purpose-built identity database: a single-binary Rust server for authentication, authorization (Zanzibar-style), and session management with a custom embedded storage engine. It targets sub-millisecond p99 latency on the hot path.

## Ground Rules (Claude: ALWAYS follow)

### 🚨 CRITICAL: Tool Selection

**Before using ANY search tool, check if Reflex MCP tools are available (`mcp__reflex__*`). These should be preferred
over built-in tools.**

If you see a message like `Index not found. Run 'rfx index' to build the cache first`, run `mcp__reflex__index_project`
immediately, and once the indexing completes, run the previously failed tool again.

## Reference Documents

Read these before writing any code. They are the canonical source of truth:

- `docs/specs/ARCHITECTURE.md` — structural rules (MUST/SHOULD per RFC 2119). Violations of MUST-level rules block merge.
- `docs/specs/TESTING.md` — eight testing layers, TDD workflow, tooling, CI tiers.
- `docs/specs/TEST_SCENARIOS.md` — granular checkbox-tracked test scenario checklist by module and layer.
- `docs/specs/IMPLEMENTATION_ORDER.md` — **mandatory build sequence for Phase 0.** Steps MUST be completed in order (1→18). Do not skip ahead or work out of sequence.
- `docs/vision/VISION.md` — design rationale, performance targets, competitive positioning, roadmap. Read this to understand *why* decisions were made.

## Implementation Order (MANDATORY)

All implementation work MUST follow the sequence defined in `docs/specs/IMPLEMENTATION_ORDER.md`. This is not a suggestion — it is a strict dependency chain where each step depends on the ones before it.

**Rules:**
- Complete steps in order: 1 → 2 → 3 → ... → 18. Do not skip ahead.
- Each step MUST pass verification (`cargo nextest run`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`) before proceeding to the next.
- Within each step, tackle P0 `fast` scenarios first, then P0 `extended`, then P1.
- Read the corresponding TEST_SCENARIOS.md section before starting each step to understand the full scope of tests required.
- Do not create proto files, HTTP endpoints, or wire format code until step 15 (OIDC) demands it.

## Architecture

### Layer Structure

Six modules with strict downward dependency flow:

| Layer | Path | Role |
|-------|------|------|
| Core | `src/core/` | Shared types and traits only. No logic, no state, no I/O. |
| Protocol | `src/protocol/` | Wire adapters (REST, gRPC, OIDC, SAML, SCIM). Stateless, thin. |
| Identity Engine | `src/identity/` | Domain logic. Users, credentials, sessions, tenants, tokens. |
| Authorization Engine | `src/authz/` | Zanzibar relationship tuples. `check()`, `expand()`, `write_tuples()`, `watch()`. |
| Cluster | `src/cluster/` | Raft consensus via `openraft`. Invisible in single-node mode. |
| Storage Engine | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

**Dependency rules:**
- Dependencies MUST flow downward. No layer imports from above.
- One lateral exception: `identity/` may call `authz/`. Never the reverse.
- Every layer MAY depend on `core/`.
- `src/main.rs` wires layers together; it may import from any layer.

### Inter-Layer Communication

- `mod.rs` contains ONLY trait definitions, re-exports, and module declarations. No implementation logic.
- Internal types MUST be `pub(crate)` or private. Default to private.
- Identity Engine MUST NOT depend on any wire format or serialization framework.
- See ARCHITECTURE.md § 1.3 for layer-specific encapsulation rules.

### Hot Path Rules

Hot path = `validate_token()`, `lookup_session()`, `check_permission()` (1-hop), `lookup_user()` when data is in hot tier.

Hot path code MUST obey ALL of:
1. **Zero heap allocations** — no `Box::new`, `Vec::new`, `String::from`, `format!()`, `to_string()`.
2. **No syscalls for reads** — serve from memory-mapped structures or in-process data.
3. **No locks on read path** — no mutexes, no `RwLock` write locks. Use epoch-based reclamation.
4. **No yielding** — MUST NOT `.await` on I/O. Complete synchronously within async context.

Everything else (user creation, hashing, token issuance, WAL writes, cold-tier promotion, admin ops) is off the hot path.

### Storage Engine

- WAL MUST be `fsync`'d before acknowledging any write. Engine MUST survive `kill -9`. See ARCHITECTURE.md § 6.

### Multi-Tenancy

- Every storage operation MUST require a `TenantId` parameter (newtype, not raw string).
- All keys MUST be prefixed with tenant ID. No code path to construct a key without `TenantId`.
- Scans MUST be bounded to a single tenant's key space.

### API Contracts

- `.proto` files in `proto/` are the single source of truth for all API contracts (`prost` + `buf`). See ARCHITECTURE.md § 4.

## TDD Workflow (Mandatory)

**Every feature and bug fix follows strict TDD — no exceptions:**

1. Write a failing test that describes expected behavior.
2. Run it — confirm it fails (red).
3. Write the minimal implementation to make it pass (green).
4. Refactor while keeping tests green.
5. Add a black box test through the public API if applicable.

A PR that adds functionality without a test written *before* the implementation is incomplete.

### Eight Testing Layers

Hearth uses eight testing layers (unit, integration, property, fuzz, simulation, adversarial, conformance, benchmarks). For each feature, consider which layers apply. See TESTING.md for the full matrix, locations, and conventions.

### Testing Tooling

- **Test runner**: `cargo-nextest` (not `cargo test`)
- **Watch mode**: `bacon test` for TDD loop
- **Property tests**: `proptest` (256 cases dev, 10k+ CI)
- **Benchmarks**: `criterion`
- **Coverage**: `cargo-llvm-cov`
- **Simulation**: `madsim`
- **Mocking**: Minimal. Real implementations preferred. DI only for clock, filesystem, randomness.

### TestHarness Pattern

Black box tests use `TestHarness` (`tests/common/mod.rs`) with embedded and server modes. See TESTING.md for the dual-mode pattern.

### CI Tiers

CI runs four tiers: Fast (every commit), Standard (merge), Extended (nightly), Full (weekly). See TESTING.md for triggers and time budgets.

## Code Style & Conventions

- `clippy::pedantic` MUST pass. Allowed lints documented in `Cargo.toml`/`clippy.toml`.
- `rustfmt` with project `rustfmt.toml`. No formatting debates.
- All `pub`/`pub(crate)` items MUST have doc comments.
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).

### Error Handling

- Each layer defines its own error enum (`StorageError`, `IdentityError`, etc.).
- All error enums: `#[non_exhaustive]`, implement `std::error::Error` + `Display`.
- Errors MUST NOT cross layer boundaries as concrete types — convert via `From`.
- Error messages MUST NOT contain sensitive data (passwords, tokens, keys, PII).

### Panic Policy

- **No `unwrap()` or `expect()` in production code.** `#[deny(clippy::unwrap_used)]` enforced.
- `unwrap()` permitted ONLY with `#[allow(clippy::unwrap_used)]` + `// INVARIANT:` comment.
- `expect()` permitted in test code and one-time startup initialization.
- Public functions MUST return `Result<T, LayerError>`.

### Observability

- `tracing` ONLY — no `println!`, `eprintln!`, or `log` crate.
- Hot path MUST NOT log at `info` or above in steady state.
- MUST NOT log passwords, tokens, keys, or PII.

### Types

- Entity IDs are distinct newtypes: `UserId(Uuid)`, `SessionId(Uuid)`, `TenantId(Uuid)`, etc.
- Newtypes MUST NOT implement `Deref` to inner type. Use `.as_uuid()`.
- Timestamps stored as UTC. Internal representation: Unix microseconds.
- Clock injectable via `Clock` trait for deterministic testing.
- Sensitive data (passwords, tokens, keys) MUST wrap in `Zeroize`-on-drop types. MUST NOT implement `Debug`/`Display`/`Serialize` revealing contents.

## Security Rules

- **Signing**: Ed25519 (asymmetric only). No HS256, no `alg:none`.
- **Password hashing**: Argon2id, OWASP parameters. Off hot path, no latency compromise.
- **Input validation**: Each layer validates its own invariants. MUST NOT assume upstream validated.
- **Crypto**: `ring` or `RustCrypto` only. No hand-rolled crypto. Constant-time secret comparisons.
- **Encryption at rest**: Per-tenant keys. Keys MUST NOT appear in logs/errors/debug output.
- **Audit**: Security-critical mutations emit structured `tracing` events at `info` level.

### Concurrency & Safety

- No global mutable state. Shared state passed explicitly or in `Arc<AppState>`.
- `Mutex` MUST NOT be held across `.await` points.
- `unsafe` minimized and isolated. Every `unsafe` block MUST have a `// SAFETY:` comment.
- `unsafe` MUST NOT appear in protocol or identity layers.
- No `lazy_static` — use `std::sync::OnceLock` or `LazyLock`.
- No `async-trait` on hot path (heap-allocates). Use RPITIT.

## Dependency Policy

- New deps MUST be justified in PR, pass `cargo-audit`, and have compatible license (Apache 2.0/MIT/BSD/MPL-2.0).
- Bans: no ORM, no `lazy_static`, no `async-trait` on hot path, no `reqwest` in prod. See ARCHITECTURE.md § 15 for approved crates.

## Async Model

- **Tokio only.** No other async runtime.
- Blocking operations (file I/O, crypto hashing, DNS) MUST use `spawn_blocking`.
- Config is immutable after startup — loaded once into `Arc<Config>`.
