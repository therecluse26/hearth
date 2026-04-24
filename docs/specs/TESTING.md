# Hearth Testing Architecture

## Why This Exists

Auth systems have uniquely high stakes. A subtle bug in session handling or token validation is a security vulnerability, not just a feature regression. Hearth's testing infrastructure is established as part of initial project scaffolding (Phase 0) so that every line of production code is written test-first from day one.

This document is the canonical reference for Hearth's testing strategy. It defines eight testing layers, the tooling that supports them, and the phased rollout that grows test coverage alongside the codebase.

---

## Testing Layers

### 1. Unit Tests (Inline, TDD)

Unit tests live alongside production code in `#[cfg(test)]` modules. They test internal invariants, algorithms, and data structures. They are written *before* the implementation following red-green-refactor.

**Scope**: Storage engine internals (WAL append, memtable operations, compaction logic), crypto helpers (key derivation, constant-time comparisons), data serialization (identity records, RBAC role/group/assignment records), RBAC resolution (group BFS, role composition DAG, cycle detection, cap enforcement).

**Example locations**:
```
src/storage/wal.rs         → #[cfg(test)] mod tests { ... }
src/identity/credential.rs → #[cfg(test)] mod tests { ... }
src/rbac/resolve.rs        → #[cfg(test)] mod tests { ... }
```

**Convention**: Every public function in an internal module has at least one unit test. Every bug fix adds a regression test before the fix.

**No doctests.** Hearth deliberately does not use Rust doctests (runnable `///` example blocks). Every test goes in a `#[cfg(test)] mod tests` block or under `tests/`. Reasons: doctests compile as separate crates (slow), can't share the `tests/common` harness, require a second runner (`cargo test --doc`) because `cargo nextest` doesn't execute them, and offer no coverage that a regular test can't. Runnable documentation examples belong in [`examples/`](../../examples/); non-runnable illustrative snippets inside doc comments MUST be fenced as `\`\`\`text`, `\`\`\`json`, or similar — never a bare `\`\`\`` or `\`\`\`rust`, either of which rustdoc treats as an executable doctest.

### 2. Integration / Black Box Tests (`tests/` Directory)

Black box tests interact with Hearth exclusively through its public API surface. They never import from internal modules — if a refactor breaks these tests, the public contract changed.

Two modes are supported from day one:

- **Embedded API**: Link against `hearth` as a library, call public functions directly. Available immediately.
- **Server API**: Spin up a Hearth process on a random port, make HTTP requests to OIDC/SCIM/admin endpoints. Initially stubs/skipped until the HTTP layer exists, but the harness infrastructure is ready.

The same test logic runs against both modes via shared async test functions, ensuring the public contract is identical regardless of deployment mode.

**Scope**: Auth flows end-to-end (OAuth2 authorization code, client credentials, device flow), session lifecycle (create, validate, refresh, revoke, expire), authorization (role assignment, token claim population, `hasPermission` semantics, realm/org scoping), user CRUD (create, read, update, delete, list, search), token issuance and validation (JWT signing, verification, claims, expiration).

**Key constraint**: Zero imports from `hearth::internal::*` or any non-public module. Tests use only the public API defined in `src/lib.rs`.

### 3. Property-Based Tests (`proptest`)

Property tests generate random inputs and assert that invariants hold universally, catching edge cases that hand-written tests miss.

**Scope**:
- **Storage engine**: Random sequences of writes, reads, and deletes maintain data integrity. WAL replay after any prefix of operations produces a consistent state.
- **Authorization**: Random role DAGs and group-membership graphs (cycle-free) produce correct resolved permission sets. Cycle detection rejects arbitrary cyclic topologies.
- **Credential handling**: Arbitrary byte inputs to parsing functions never panic. Round-trip serialization is identity: `deserialize(serialize(x)) == x`.

**Configuration**: Property tests default to 256 cases in development and 10,000+ cases in CI extended runs. Regressions are persisted in `proptest-regressions/` files alongside the test source.

### 4. Fuzz Testing (`cargo-fuzz` / `libFuzzer`)

Coverage-guided mutation testing for all parsing and input-handling code paths. Fuzz targets run under `libFuzzer` and integrate with OSS-Fuzz for continuous fuzzing.

**Scope**:
- Token parsing (JWT header, payload, signature)
- OIDC request parsing (authorization requests, token requests, discovery documents)
- SAML XML parsing (when SAML is implemented in Phase 2)
- Configuration file parsing (TOML/YAML server config)
- Wire protocol deserialization (client-server protocol messages)

**Structure**:
```
fuzz/
├── Cargo.toml
└── fuzz_targets/
    ├── token_parse.rs
    ├── oidc_request.rs
    ├── config_parse.rs
    └── wire_protocol.rs
```

Each fuzz target is a standalone binary that accepts arbitrary bytes and exercises a single parsing entry point.

### 5. Deterministic Simulation Testing (`madsim`)

Hearth uses [`madsim`](https://github.com/madsim-rs/madsim) for deterministic simulation testing, inspired by FoundationDB's approach to proving correctness under failure.

**How it works**:
- `madsim` replaces `tokio` with a simulated async runtime where time, network, and filesystem I/O are controlled via a seed
- Production code stays unchanged (normal async Rust with tokio); `madsim` intercepts at the runtime level
- **Built-in fault injection**: disk I/O failures, network partitions, packet loss/reorder, clock skew
- **Deterministic replay**: failing tests produce a seed that reproduces the exact failure sequence

**We provide the domain-specific test oracles** — assertions about what must be true regardless of the failure scenario:
- "After crash recovery, no committed session is lost"
- "Permission graph remains acyclic after any operation sequence"
- "WAL replay produces identical state to the original write sequence"
- "Hot/cold tier transitions preserve all data"

**Phasing**: Simulation testing grows incrementally:
- **Phase 0**: Storage engine fault injection — simulated disk failures during WAL writes, crashes mid-flush, recovery verification
- **Phase 2+**: Full network partition simulation — Raft consensus correctness, leader election under partition, split-brain prevention, replication consistency

**Structure**:
```
simulation/
├── Cargo.toml            # Depends on madsim, hearth as lib
└── src/
    ├── lib.rs            # Simulation harness + oracle traits
    └── tests/
        ├── wal_crash.rs  # WAL crash-recovery scenarios
        └── ...
```

### 6. Adversarial / Security Tests

A dedicated test module that actively tries to break security properties. These tests are written from an attacker's perspective.

**Scope**:

| Category | What We Test |
|----------|-------------|
| Timing attacks | Constant-time password comparison (statistical timing analysis) |
| Token forgery | Modified JWTs, expired tokens, wrong signing keys, alg=none, key confusion |
| Privilege escalation | Reserved-namespace abuse, role-composition cycles, group-membership cycles, cap-bypass attempts, oversized JWT claims |
| Replay attacks | Reused authorization codes, replayed session tokens, nonce reuse |
| Input injection | Null bytes in usernames, unicode normalization attacks, oversized inputs, header injection |
| Credential stuffing | Rate limiting under sustained credential guessing attempts |

These tests live in `tests/adversarial.rs` and are part of the standard CI test suite (not gated behind extended runs).

### 7. Conformance Tests

Run official specification test suites against Hearth's protocol endpoints to verify standards compliance.

**Scope**:
- **OpenID Connect**: Certification test suite (added when OIDC endpoints are implemented in Phase 0/1)
- **SAML**: Conformance suite (added when SAML is implemented in Phase 2)
- **SCIM**: Compliance tests for user provisioning (added when SCIM is implemented in Phase 2)

Conformance tests are treated as required-pass in CI once their protocol layer is implemented.

### 8. Benchmarks (`criterion`)

Performance regression detection with statistical rigor. Benchmarks validate the latency targets defined in the [vision document](../vision/VISION.md).

**Benchmark targets and thresholds** (from vision doc section 7.1):

| Operation | Target p50 | Target p99 | Regression Threshold |
|-----------|-----------|-----------|---------------------|
| Token validation (JWT verify + session lookup) | < 50 us | < 500 us | +20% |
| Session lookup by ID | < 10 us | < 100 us | +20% |
| Permission check (direct relationship) | < 20 us | < 200 us | +20% |
| Permission check (3-hop traversal) | < 100 us | < 1 ms | +20% |
| User lookup by email/ID | < 20 us | < 200 us | +20% |
| Token issuance (full OAuth2 flow) | < 1 ms | < 5 ms | +20% |

**Structure**:
```
benches/
├── token_validation.rs
├── session_lookup.rs
├── permission_check.rs
├── user_lookup.rs
└── token_issuance.rs
```

Benchmarks run with `criterion`, comparing against a baseline stored in version control. CI fails if any benchmark regresses beyond its threshold.

---

## Rust Tooling

| Purpose | Tool/Crate | Notes |
|---------|-----------|-------|
| Test runner | `cargo-nextest` | Parallel execution, better output, test retries |
| Watch mode | `bacon` | TDD red-green-refactor loop, faster than cargo-watch |
| Property testing | `proptest` | Mature shrinking, regression persistence |
| Fuzz testing | `cargo-fuzz` (libFuzzer) | Coverage-guided, OSS-Fuzz integration |
| Benchmarks | `criterion` | Statistical benchmarking, regression detection |
| HTTP testing | `reqwest` (test dependency) | For black box server-mode tests |
| Test fixtures | Custom `TestHarness` | Spins up embedded or server instance, handles cleanup |
| Coverage | `cargo-llvm-cov` | LLVM-based, accurate line/branch coverage |
| Simulation | `madsim` | Deterministic async runtime, fault injection |
| Snapshot testing | `insta` | Serialization format stability, error message stability |
| Mocking | Minimal / avoid | Prefer real implementations; trait-based DI only where essential (clock, filesystem) |

### Why Minimal Mocking

Hearth avoids mocks in favor of real implementations. Mocks test that your code calls the right functions with the right arguments — they don't test that the behavior is correct. For an auth system where correctness is a security property, this distinction matters.

The only places where trait-based dependency injection is used are true environmental boundaries:
- **Clock**: Injected for deterministic time in tests (token expiration, session timeout)
- **Filesystem**: Injected for simulation testing (fault injection on disk I/O)
- **Randomness**: Injected for deterministic token generation in tests

Everything else uses real implementations, including the storage engine, the permission graph, and the crypto stack.

---

## Black Box Test Infrastructure

### TestHarness

```rust
// tests/common/mod.rs

/// TestHarness wraps a running Hearth instance (embedded or server mode)
/// and provides only public API access.
pub struct TestHarness {
    mode: HarnessMode,
}

enum HarnessMode {
    /// Direct library access through the public API
    Embedded {
        // Public Hearth client handle
        // Temp directory for data
    },
    /// HTTP client pointed at a running Hearth server
    Server {
        // Base URL (http://127.0.0.1:{random_port})
        // HTTP client (reqwest::Client)
        // Child process handle
        // Temp directory for data
    },
}

impl TestHarness {
    /// Start an embedded Hearth instance with an isolated temp directory.
    pub async fn embedded() -> Self { /* ... */ }

    /// Start a Hearth server process on a random port.
    /// Returns Err if the server binary is not built.
    pub async fn server() -> Self { /* ... */ }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Stop server process (if server mode)
        // Remove temp data directory
    }
}
```

### Dual-Mode Test Pattern

The same test logic runs against both embedded and server modes:

```rust
// tests/sessions.rs

mod common;
use common::TestHarness;

async fn run_session_lifecycle_test(h: &TestHarness) {
    // Create a user
    // Authenticate, obtain a session
    // Validate the session
    // Refresh the session
    // Revoke the session
    // Confirm validation now fails
}

#[tokio::test]
async fn session_lifecycle_embedded() {
    let h = TestHarness::embedded().await;
    run_session_lifecycle_test(&h).await;
}

#[tokio::test]
async fn session_lifecycle_server() {
    let h = TestHarness::server().await;
    run_session_lifecycle_test(&h).await;
}
```

Server-mode tests are `#[ignore]`-tagged until the HTTP layer exists, but the harness and test structure are ready from day one.

---

## Project Structure

```
hearth/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Public embedded API
│   ├── main.rs                 # Binary entry point
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── wal.rs              # + inline #[cfg(test)] unit tests
│   │   └── ...
│   ├── identity/
│   ├── rbac/
│   └── protocol/
├── tests/                      # Black box integration tests
│   ├── common/
│   │   └── mod.rs              # TestHarness
│   ├── auth_flows.rs           # OIDC/OAuth end-to-end
│   ├── sessions.rs             # Session lifecycle
│   ├── permissions.rs          # Authorization checks
│   ├── users.rs                # User CRUD
│   └── adversarial.rs          # Security-focused tests
├── fuzz/                       # cargo-fuzz targets
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── token_parse.rs
│       └── ...
├── benches/                    # Criterion benchmarks
│   ├── token_validation.rs
│   ├── session_lookup.rs
│   ├── permission_check.rs
│   ├── user_lookup.rs
│   └── token_issuance.rs
└── simulation/                 # madsim deterministic simulation tests
    ├── Cargo.toml              # Depends on madsim, hearth as lib
    └── src/
        ├── lib.rs              # Simulation harness + oracle traits
        └── tests/
            ├── wal_crash.rs    # WAL crash-recovery scenarios
            └── ...
```

---

## TDD Workflow

The development loop for every feature:

1. **Write a failing test** that describes the desired behavior
2. **Run `bacon test`** (continuous watch) — see it fail (red)
3. **Write the minimal implementation** to make it pass (green)
4. **Refactor** while keeping tests green
5. **Add a black box test** for the same behavior through the public API (if applicable)

### Nextest Configuration

```toml
# .config/nextest.toml

[profile.default]
retries = 0
slow-timeout = { period = "30s", terminate-after = 2 }
fail-fast = true

[profile.ci]
retries = 2
fail-fast = false
```

### Bacon Configuration

```toml
# bacon.toml

[jobs.test]
command = ["cargo", "nextest", "run"]
watch = ["src", "tests"]

[jobs.test-unit]
command = ["cargo", "nextest", "run", "--lib"]
watch = ["src"]
```

---

## CI/CD Test Tiers

| Tier | Trigger | Tests | Time Budget |
|------|---------|-------|-------------|
| **Fast** | Every commit / PR | Unit + black box integration | < 5 min |
| **Standard** | PR merge to main | + benchmarks (regression check) | < 15 min |
| **Extended** | Nightly | + property tests (high iteration count), fuzz (time-boxed) | < 60 min |
| **Full** | Weekly / pre-release | + simulation, extended fuzz, conformance suites | < 4 hrs |

### Tier Details

**Fast** (every commit): Runs `cargo nextest run` with the default profile. This covers all `#[cfg(test)]` unit tests and all non-ignored integration tests. Developers should be able to run this locally in under 5 minutes.

**Standard** (merge to main): Adds `cargo bench` with regression comparison against the stored baseline. A benchmark regression beyond the threshold blocks the merge.

**Extended** (nightly): Runs `proptest` with a high case count (10,000+), `cargo fuzz` time-boxed to 30 minutes per target, and simulation tests with a broad seed range. Failures file issues automatically.

**Full** (weekly): Everything in Extended plus longer fuzz runs (4 hours per target), simulation tests with exhaustive seed exploration, and conformance test suites. This is the "prove it's correct" tier.

---

## Coverage Policy

Coverage is measured with `cargo-llvm-cov` and tracked in CI.

**Targets** (aspirational, not gating):
- Storage engine: > 90% line coverage
- Auth/identity logic: > 85% line coverage
- Protocol handling: > 80% line coverage
- Overall: > 80% line coverage

Coverage is a useful signal, not a goal in itself. 100% coverage of trivial code is less valuable than 70% coverage of carefully-chosen properties. The property tests and simulation tests provide confidence that raw coverage numbers cannot.

Coverage reports are generated on every merge to main and published as CI artifacts.

---

## Phasing

### Day 1 (Project Scaffolding)
- Set up Cargo workspace with `tests/`, `benches/`, `fuzz/`, `simulation/` directories
- Install and configure `cargo-nextest`, `bacon`, `cargo-llvm-cov`
- Create `TestHarness` skeleton in `tests/common/mod.rs`
- Write first failing test (storage engine WAL append + read back)
- Establish `.config/nextest.toml` and `bacon.toml` configuration

### Phase 0 (Storage Engine + Basic Auth)
- Unit tests for WAL, memtable, persistence, tiered storage
- Property tests for storage engine operations (random op sequences)
- Deterministic simulation for crash recovery (madsim + WAL fault injection)
- Black box tests for user CRUD, session lifecycle, basic OIDC flow
- Benchmarks for core operations (token validation, session lookup, permission check)
- Adversarial tests for credential handling (timing attacks, input injection)

### Phase 1 (Full Protocol Support)
- Black box tests for all OAuth 2.0 flows (authorization code, PKCE, client credentials, device flow)
- Black box tests for WebAuthn registration and authentication
- Black box tests for magic link and TOTP flows
- OIDC conformance test suite integration
- Fuzz targets for protocol parsing (JWT, OIDC requests, SAML if applicable)
- Adversarial tests for token handling (forgery, replay, algorithm confusion)

### Phase 2+ (Clustering, SAML, SCIM)
- Simulation tests with network partitions (Raft consensus, leader election, split-brain)
- Multi-node black box tests (replication consistency, failover behavior)
- SAML conformance tests
- SCIM compliance tests
- Benchmarks for clustered operations (cross-node permission check, replicated session lookup)
