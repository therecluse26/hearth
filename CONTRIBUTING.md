# Contributing to Hearth

## Contributor Setup

Run once after cloning the repo:

```sh
make setup
```

This points git at the repo-managed hook directory
(`git config core.hooksPath .githooks`). The pre-commit hook handles
two auto-regeneration tasks:

**Proto/SDK regeneration** — when you stage any `proto/**/*.proto` file:

- Runs `buf generate` (outputs to `sdks/typescript/src/generated/`
  and `sdks/go/generated/`).
- Re-stages the regenerated files so they land in the same commit.
- No-op when a commit touches no `.proto` files.

The hook requires [`buf`](https://buf.build/docs/installation) on
`PATH`. If it's missing, the hook fails with install instructions
rather than silently skipping — silent skips are how generated code
drifts from the proto source of truth.

CI still runs `make proto-check` as a belt-and-suspenders guard: if
someone bypasses the hook with `git commit --no-verify` and pushes
stale generated files, the merge is blocked.

**CSS regeneration** — when you stage any template file, `ui/input.css`,
or `ui/tailwind.config.js`:

- Rebuilds `src/protocol/web/assets/app.css` via the Tailwind standalone
  CLI at `ui/tailwindcss`.
- Re-stages `app.css` so it lands in the same commit.
- No-op when a commit touches no UI files.

Run `make tailwind-install` once after cloning to download the Tailwind
CLI. If it's missing the hook fails with instructions. CI runs
`make css-check` as a belt-and-suspenders guard.

## Before you commit

Before opening a PR, make sure all Rust checks pass locally:

```sh
make check   # clippy + fmt + nextest
```

See [`CLAUDE.md`](CLAUDE.md) and [`docs/specs/`](docs/specs/) for the
architecture, testing, and implementation-order rules every change
must follow.

## Performance benchmarks and CI gates

Hearth targets sub-millisecond p99 latency on the hot path. Two benchmark
binaries enforce hard latency limits in CI (`make bench-gate`).

### Running the gates locally

```sh
make bench-gate          # compile + run both gate binaries
```

Each binary runs threshold checks *before* Criterion sampling begins.
A failed assertion exits non-zero, which fails the CI Standard tier
(`make ci-standard`).

### Gate thresholds

| Binary | Operation | p50 limit | p99 limit |
|--------|-----------|-----------|-----------|
| `rbac_check` | `resolve_permissions` (JWT decode + scan) | — | 1 ms |
| `rbac_check` | `hasPermission` (`HashSet::contains`) | — | 1 µs |
| `storage_gate` | Storage hot-tier key lookup | 10 µs | 100 µs |
| `storage_gate` | Session lookup by ID | 10 µs | 100 µs |
| `storage_gate` | User lookup by ID | 20 µs | 200 µs |
| `storage_gate` | User lookup by email | 20 µs | 200 µs |

Thresholds derive from `docs/specs/ARCHITECTURE.md` § Hot Path Rules
and `docs/specs/TEST_SCENARIOS.md` benchmark scenarios.

### Running individual Criterion benchmarks

```sh
# All benchmarks with HTML reports (target/criterion/):
PROTOC=protoc cargo bench

# A single bench group:
PROTOC=protoc cargo bench --bench tiered_storage
PROTOC=protoc cargo bench --bench session_lookup
PROTOC=protoc cargo bench --bench user_lookup
PROTOC=protoc cargo bench --bench rbac_check
PROTOC=protoc cargo bench --bench storage_gate
```

### Interpreting results

Criterion reports **mean**, **median** (≈ p50), and standard deviation.
The gate binaries independently compute p50 and p99 from 10 000 raw
samples taken after 200 warm-up iterations, matching the hot-tier
steady state (data already in the `ArcSwap`-backed lock-free tier).

If a gate fails on your machine but passes elsewhere, check for
background load, frequency scaling (`cpupower frequency-info`), or
running under a hypervisor that inflates tail latency.
