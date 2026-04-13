# Phase 0 Implementation Order

Short implementation sequence mapping TEST_SCENARIOS.md sections to build order. Each step follows strict TDD: write failing test → make it pass → refactor.

Dependencies flow bottom-up (leaf → root), matching the layer architecture.

## Sequence

| # | What | TEST_SCENARIOS Section | Why this order |
|---|------|----------------------|----------------|
| 1 | **Project scaffold** | — | Cargo.toml, .gitignore, rustfmt.toml, clippy.toml, deny.toml, empty `src/` module tree, bacon.toml |
| 2 | **Core types** | — | `TenantId`, `UserId`, `SessionId`, `Timestamp`, `Clock` trait, error trait foundations. Everything depends on these. |
| 3 | **Storage: WAL** | Storage: WAL (12 scenarios) | Leaf dependency. All durability guarantees start here. Start with the 5 P0 unit tests. |
| 4 | **Storage: Memtable** | Storage: Memtable (7 scenarios) | Depends on WAL for crash recovery. 5 unit tests first. |
| 5 | **Storage: SST/Persistence** | Storage: Persistence (9 scenarios) | Depends on memtable flush. 4 unit tests first. |
| 6 | **Storage: Tiered Hot/Cold** | Storage: Tiered Hot/Cold (12 scenarios) | Depends on all storage components. Introduces hot path constraints. |
| 7 | **Storage: Public trait API** | (implicit) | `mod.rs` trait interface wrapping WAL+memtable+SST+tiered into clean `get/put/delete/scan` with `TenantId` enforcement. |
| 8 | **Configuration** | Configuration (5 scenarios) | Standalone, needed before wiring layers. YAML parsing, `--dev` flag, validation. |
| 9 | **Test infrastructure** | Test Infrastructure (4 scenarios) | `TestHarness` embedded mode. Server mode stays `#[ignore]` until HTTP exists. |
| 10 | **Authorization engine** | Authorization Engine (15 scenarios) | Standalone module. Identity depends on it (lateral), so build it first. |
| 11 | **Identity: User CRUD** | User CRUD (14 scenarios) | First domain logic. Depends on storage + core types. |
| 12 | **Identity: Credentials** | Credential Storage (12 scenarios) | Depends on users. Argon2id hashing, multi-algo verification. |
| 13 | **Identity: Sessions** | Session Management (17 scenarios) | Depends on users + credentials. Introduces hot path session lookup. |
| 14 | **Identity: JWT/Tokens** | JWT / Tokens (14 scenarios) | Depends on sessions. Ed25519 signing, JWKS endpoint shape. |
| 15 | **Protocol: OIDC** | OIDC (15 scenarios) | First wire protocol. Auth code flow, PKCE, discovery endpoint. |
| 16 | **CLI** | CLI Tool (3 scenarios) | `hearth serve --dev`, management commands. Wires layers together in `main.rs`. |
| 17 | **E2E flows** | End-to-End Flows (4 scenarios) | Integration tests spanning all layers. |
| 18 | **Cross-cutting** | Cross-Cutting Concerns (5 scenarios) | Adversarial tests applied globally (timing, leaks, zeroing). |

## Notes

- Within each step, tackle P0 `fast` scenarios first, then P0 `extended`, then P1.
- Property tests (`proptest`) and simulation tests (`madsim`) come after unit tests pass for each module.
- Benchmarks (`criterion`) added alongside steps 6, 11, 13, 14, 15 — not deferred to the end.
- Proto files created when step 15 (OIDC) demands wire format definitions, not before.

## Verification

After each step: `cargo nextest run` passes, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
