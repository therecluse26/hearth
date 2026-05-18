# Hearth — Development Rules

Hearth is a purpose-built identity database: a single-binary Rust server for authentication, claims-based RBAC authorization, and session management with a custom embedded storage engine. Targets sub-millisecond p99 latency on the hot path.

## Ground Rules (ALWAYS follow)

### Tool Selection — ALWAYS use Reflex, NEVER use built-in grep/glob

Reflex MCP tools (`mcp__reflex__*`) are available. Use them for ALL code search and exploration — never use the built-in `grep`, `glob`, or `read` tools for searching code.

| Instead of | Use |
|-----------|-----|
| `grep` / `rg` | `mcp__reflex__search_code` (simple text) or `mcp__reflex__search_regex` (regex patterns) |
| `glob` | `mcp__reflex__search_code` with `paths=true` or `mcp__reflex__list_locations` |
| `read` (to explore unknown files) | `mcp__reflex__search_code` first to find relevant locations, THEN `read` |

If you see `Index not found. Run 'rfx index' to build the cache first`, run `mcp__reflex__index_project` immediately, then retry the failed tool.

### First Commands After Clone

```bash
make setup          # enables repo-managed git hooks (.githooks/)
make tailwind-install  # downloads Tailwind standalone CLI to ui/tailwindcss
```

### Development Commands

| Command | What it does |
|---------|-------------|
| `make check` | clippy + fmt + nextest — run before every PR |
| `make test` | `cargo nextest run --workspace` (PROTOC env var required) |
| `make clippy` | `cargo clippy --all-targets -- -D warnings` |
| `make fmt` | `cargo fmt --check` |
| `make build` | Tailwind CSS + `cargo build` |
| `make css` | Rebuilds `src/protocol/web/assets/app.css` from Tailwind |
| `make css-check` | CI gate — fails if app.css is stale |
| `bacon test` | TDD watch loop (configured in `bacon.toml`) |

**Build prerequisites:**
- `PROTOC` env var must point to `protoc` (or set `make PROTOC=protoc check`).
- `buf` is optional unless editing `proto/**/*.proto`.
- `ui/tailwindcss` must be present for CSS changes (`make tailwind-install`).
- `hearth.yaml` is **gitignored** — copy from `hearth.example.yaml`.

### Quick Start

```bash
make dev                              # cargo run -- serve --dev  (preferred)
# or:
cargo build --release
./target/release/hearth serve --dev   # binds 127.0.0.1:8420, in-memory storage
curl http://127.0.0.1:8420/health
curl -X POST http://127.0.0.1:8420/admin/bootstrap  # dev-only, creates realm+admin+token
```

`--dev` auto-enables the in-process **mailcatcher** email transport. All outbound emails are captured and visible at `http://127.0.0.1:8420/dev/mail`. No Docker or external mail server needed.

## Reference Documents

Read these before writing code. They are the canonical source of truth:

- `docs/specs/ARCHITECTURE.md` — structural rules (MUST/SHOULD per RFC 2119).
- `docs/specs/AUTHORIZATION.md` — normative spec for roles, groups, permissions, JWT claims, SDK contract.
- `docs/specs/TESTING.md` — eight testing layers, TDD workflow, tooling, CI tiers.
- `docs/specs/TEST_SCENARIOS.md` — granular checkbox-tracked scenario checklist.
- `docs/specs/IMPLEMENTATION_ORDER.md` — **mandatory build sequence.** Do not skip ahead.
- `docs/vision/VISION.md` — design rationale, performance targets, competitive positioning.
- `docs/specs/THEME.md` — mandatory design theme for all UI code.

## Workspace Structure

Two crates in the workspace:

| Crate | Path | Purpose |
|-------|------|---------|
| `hearth` | `.` | Main binary + library (`src/main.rs`, `src/lib.rs`) |
| `hearth-simulation` | `simulation/` | Deterministic simulation tests (`madsim`), depends on `hearth` with `features = ["test-hooks"]` |

Generated proto code lives at `src/protocol/generated/` (gitignored, produced by `build.rs` on every `cargo build`). Proto sources at `proto/` are the single source of truth.

### Git Hooks

The pre-commit hook (`.githooks/pre-commit`) auto-regenerates:
- SDK types (TS + Go) when `proto/**/*.proto` is staged
- `src/protocol/web/assets/app.css` when templates, `ui/input.css`, or `ui/tailwind.config.js` are staged

It falls back cleanly if `buf` or `ui/tailwindcss` are missing (fails with instructions rather than silently skipping). CI still runs `make css-check` and `make proto-check` as belt-and-suspenders.

## Architecture

### Layer Structure

Six modules with strict downward dependency flow:

| Layer | Path | Role |
|-------|------|------|
| Core | `src/core/` | Shared types and traits only. No logic, no state, no I/O. |
| Protocol | `src/protocol/` | Wire adapters (REST, gRPC, OIDC, SAML, SCIM). Stateless, thin. |
| Identity | `src/identity/` | Domain logic. Users, credentials, sessions, realms, tokens. |
| RBAC | `src/rbac/` | Claims-based RBAC. Resolves effective permissions for JWT claims. |
| Cluster | `src/cluster/` | Raft consensus via `openraft`. Invisible in single-node mode. |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

**Rules:**
- Dependencies flow strictly downward. No layer imports from above.
- One lateral exception: `identity/` may call `rbac/` during token issuance. Never the reverse.
- Every layer may depend on `core/`.
- `mod.rs` contains ONLY trait definitions, re-exports, and module declarations. No implementation.
- Internal types default to private. `pub(crate)` where necessary.

### Hot Path Rules

Hot path = `validate_token()`, `lookup_session()`, `lookup_user()` when data is in hot tier. Authorization is NOT on the hot path (permissions are embedded in the JWT at issue time).

Hot path code MUST obey ALL of:
1. **Zero heap allocations** — no `Box::new`, `Vec::new`, `String::from`, `format!()`, `to_string()`.
2. **No syscalls for reads** — serve from memory-mapped structures or in-process data.
3. **No locks on read path** — no mutexes, no `RwLock` write locks. Use epoch-based reclamation.
4. **No yielding** — MUST NOT `.await` on I/O. Complete synchronously.

Everything else (user creation, hashing, token issuance, WAL writes, admin ops) is off the hot path.

### Storage Engine

- WAL MUST be `fsync`'d before acknowledging any write. Must survive `kill -9`.
- Every storage operation requires a `RealmId` parameter (newtype, not raw string).
- All keys are prefixed with realm ID. Scans bounded to a single realm.

## TDD Workflow (Mandatory)

1. Write a failing test that describes expected behavior.
2. Run it — confirm it fails (red).
3. Write the minimal implementation to make it pass (green).
4. Refactor while keeping tests green.
5. Add a black box test through the public API if applicable.

**A PR without a test written *before* the implementation is incomplete.**

Avoid false-confidence anti-patterns (vacuous `is_ok()`/`is_err()` asserts, zero-assert test bodies, stale ignores, etc.) — see `docs/specs/TESTING.md` § "Test Quality Anti-Patterns" for the full A–I taxonomy.

### Testing Tooling

- **Test runner**: `cargo nextest` only — never `cargo test`.
- **Watch mode**: `bacon test` for TDD loop.
- **No doctests — ever.** No `/// ```rust` fenced blocks in doc comments. Use `#[cfg(test)] mod tests` blocks or `tests/`. Runnable examples live under `examples/`.
- **Property tests**: `proptest` (256 cases dev, 10k+ CI).
- **Simulation**: `madsim` (simulation crate).
- **Black box tests**: `TestHarness` (`tests/common/mod.rs`) — embedded + server modes.

## Code Style

- `clippy::pedantic` MUST pass (enforced via `-- -D warnings`). Allowed lints in `Cargo.toml`/`clippy.toml`.
- `clippy::unwrap_used` is **denied**. `unwrap()` permitted ONLY with `#[allow(clippy::unwrap_used)]` + `// INVARIANT:` comment. `expect()` only in tests and startup.
- `rustfmt` with `rustfmt.toml` (max_width=100, edition=2021).
- All `pub`/`pub(crate)` items MUST have doc comments.
- **No `println!`, `eprintln!`, or `log` crate.** Use `tracing` only.
- Hot path MUST NOT log at `info` or above in steady state.
- MUST NOT log passwords, tokens, keys, or PII.
- Entity IDs are newtypes: `UserId(Uuid)`, `RealmId(Uuid)`, etc. No `Deref` — use `.as_uuid()`.
- Sensitive data (passwords, tokens, keys) wraps in `Zeroize`-on-drop types; MUST NOT implement `Debug`/`Display`/`Serialize` revealing contents.

### Error Handling

- Each layer defines its own error enum (`#[non_exhaustive]`, `Error` + `Display`).
- Errors MUST NOT cross layer boundaries as concrete types — convert via `From`.
- Error messages MUST NOT contain sensitive data.

## Security

- **Signing**: Ed25519 only. No HS256, no `alg:none`.
- **Password hashing**: Argon2id, OWASP parameters. Off hot path.
- **Crypto**: `ring` or `RustCrypto`. No hand-rolled crypto. Constant-time secret comparisons.
- **Input validation**: Each layer validates its own invariants. Must not assume upstream validated.
- Every `unsafe` block MUST have a `// SAFETY:` comment. No `unsafe` in protocol or identity layers.
- No `lazy_static` — use `std::sync::OnceLock` or `LazyLock`.
- `Mutex` MUST NOT be held across `.await` points.

## UI Theme (MANDATORY)

All UI code MUST comply with `docs/specs/THEME.md`. Read it before touching anything in `templates/ui/`.

**Key rules:**
- **Dark-mode only.** No light mode, no `dark:` Tailwind prefixes, no theme toggle.
- **Color tokens** from `ui/tailwind.config.js`. Never use raw hex outside the config.
- **Typography**: Fraunces (display), Manrope (body/UI), JetBrains Mono (code/labels).
- **Ember gradient** (`btn-ember`) appears at most once per visible region.
- **Borders**: alpha-based white (`border-white/6`), not solid grays.
- **Primary text**: `graphite-50` (`#f5f1e8`), never `#ffffff`.
- Rebuild Tailwind after CSS/template changes: `cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify`

## Async Model

- **Tokio only.** No other async runtime.
- Blocking operations (file I/O, crypto hashing) use `spawn_blocking`.
- Config is immutable after startup — loaded into `Arc<Config>`.

## Dependency Policy

- New deps must be justified, pass `cargo-audit`, and have compatible license (Apache 2.0/MIT/BSD/MPL-2.0).
- Bans: no ORM, no `lazy_static`, no `async-trait` on hot path, no `reqwest` in production.

## Changelog Process

Every PR that ships a user-visible change **MUST** include a `CHANGELOG.md` entry written at implementation time — not after review, not at release. "User-visible" means any new or changed HTTP endpoint, config key, CLI flag, gRPC method, SDK surface, or security fix.

### Entry format

Entries go under `## [Unreleased]` in `CHANGELOG.md`, in the appropriate category:

| Category | When to use |
|----------|-------------|
| `### Added` | New endpoint, config key, CLI flag, feature, or SDK method |
| `### Changed` | Behavioral change to an existing surface (including breaking changes) |
| `### Fixed` | Bug fix visible to operators or integrators |
| `### Security` | Any security fix, hardening, or CVE remediation |
| `### Removed` | Deleted endpoint, config key, CLI flag, or SDK method |

Write entries from the operator/integrator perspective, not the implementation perspective. One bullet per logical change; reference the issue or PR number in parentheses when relevant (e.g., `(HEA-501)`).

**Example:**

```markdown
### Added
- **PKCE mandatory** — all public clients must supply a `code_challenge`; server rejects
  authorization requests without one (HEA-501).

### Fixed
- Double-slash 404s on Admin Users workspace links (HEA-306).
```

### What does NOT need a changelog entry

- Refactoring with no behavior change
- Test additions or test fixes
- CI/tooling/build changes with no operator-visible effect
- Doc-only PRs (like this one)

### Release-cut procedure

When cutting a versioned release (`vX.Y.Z`):

1. Replace `## [Unreleased]` with `## [X.Y.Z] — YYYY-MM-DD`.
2. Add a fresh `## [Unreleased]` section above it (empty categories can be omitted).
3. Tag the commit: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`.
4. The changelog entry for the release commit itself is the version heading — no bullet needed.
