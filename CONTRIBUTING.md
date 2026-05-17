# Contributing to Hearth

## Local development without Docker

Hearth runs fully in-process — no external services required.

**Cargo-only path (recommended for day-to-day development):**

```sh
make dev   # cargo run -- serve --dev
```

`--dev` mode:
- Binds to `127.0.0.1:8420` with in-memory storage (no `data/` directory needed).
- Auto-enables the **mailcatcher** transport, which captures all outgoing email
  in-process. Inspect captured mail at <http://127.0.0.1:8420/dev/mail>.
- No `hearth.yaml` required — all defaults are development-safe.

Bootstrap a realm and admin token after the server starts:

```sh
curl -X POST http://127.0.0.1:8420/admin/bootstrap
```

**Docker path (for production-parity or team demos):**

```sh
cp hearth.example.yaml hearth.yaml        # edit to taste
docker compose -f deploy/docker-compose.yml up -d
```

This starts **hearth only** — email is still handled by mailcatcher by default.
To also start [Mailpit](https://mailpit.axllent.org/) (an external SMTP sink with
a richer web UI at <http://localhost:8025>):

```sh
docker compose -f deploy/docker-compose.yml --profile mail up -d
```

Then point `email.transport: smtp` and `email.smtp.host: mailpit` in your
`hearth.yaml` to route mail through Mailpit.

---

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

Hearth targets sub-millisecond p99 latency on the hot path. Two complementary
benchmark gates enforce this in CI.

### Gate 1 — Absolute threshold gate (`make bench-gate`)

Three bench binaries assert hard p50 and p99 limits before Criterion sampling
begins. A failed assertion exits non-zero, failing `make ci-standard`.

```sh
make bench-gate          # compile + run all three gate binaries
```

| Binary | Operation | p50 limit | p99 limit |
|--------|-----------|-----------|-----------|
| `rbac_check` | `resolve_permissions` (JWT decode + scan) | — | 1 ms |
| `rbac_check` | `hasPermission` (`HashSet::contains`) | — | 1 µs |
| `storage_gate` | Storage hot-tier key lookup | 10 µs | 100 µs |
| `storage_gate` | Session lookup by ID | 10 µs | 100 µs |
| `storage_gate` | User lookup by ID | 20 µs | 200 µs |
| `storage_gate` | User lookup by email | 20 µs | 200 µs |
| `demotion_latency` | Pre-demotion read (hot tier full) | — | 500 µs |
| `demotion_latency` | During-demotion read (eviction churn) | — | 500 µs |
| `demotion_latency` | Post-demotion read (re-promotion) | — | 500 µs |

Thresholds derive from `docs/specs/ARCHITECTURE.md` § Hot Path Rules
and `docs/specs/TEST_SCENARIOS.md` benchmark scenarios. The demotion
thresholds are intentionally generous (500 µs) to tolerate the memtable
fallback path during clock-sweep eviction without false CI failures.

### Gate 2 — Regression gate (`.github/workflows/bench-regression.yml`)

The regression workflow detects when a PR introduces a latency regression
relative to the current `main` branch, regardless of absolute thresholds.

**How it works:**

1. On every push to `main`: benchmarks run with `--save-baseline main`,
   and `target/criterion/` is cached under a commit-SHA key.
2. On every PR: the workflow restores the nearest main baseline, runs the
   same benchmarks, and calls `scripts/check-bench-regression.sh 5`.
3. The script compares `target/criterion/<bench>/main/estimates.json`
   (baseline) against `target/criterion/<bench>/new/estimates.json`
   (current run). If any benchmark's mean increases by more than 5%,
   the step exits non-zero and the check fails.

**Running the regression check locally:**

```sh
# 1. Save a baseline on a clean checkout of main:
PROTOC=protoc cargo bench --bench storage_gate   -- --save-baseline main --noplot
PROTOC=protoc cargo bench --bench tiered_storage -- --save-baseline main --noplot
PROTOC=protoc cargo bench --bench demotion_latency -- --save-baseline main --noplot

# 2. Switch to your branch and run:
PROTOC=protoc cargo bench --bench storage_gate   -- --save-baseline pr --noplot
PROTOC=protoc cargo bench --bench tiered_storage -- --save-baseline pr --noplot
PROTOC=protoc cargo bench --bench demotion_latency -- --save-baseline pr --noplot

# 3. Check for regressions > 5%:
bash scripts/check-bench-regression.sh 5
```

**Testing that the gate catches a regression:**

Temporarily replace a hot-path constant (e.g., add a `std::thread::sleep(Duration::from_micros(10))` inside `EmbeddedStorageEngine::get`) and confirm the regression check exits non-zero.

### Running individual Criterion benchmarks

```sh
# All benchmarks with HTML reports (target/criterion/):
PROTOC=protoc cargo bench

# Individual bench groups:
PROTOC=protoc cargo bench --bench tiered_storage
PROTOC=protoc cargo bench --bench demotion_latency
PROTOC=protoc cargo bench --bench session_lookup
PROTOC=protoc cargo bench --bench user_lookup
PROTOC=protoc cargo bench --bench rbac_check
PROTOC=protoc cargo bench --bench storage_gate
```

### Interpreting results

Criterion reports **mean**, **median** (≈ p50), and standard deviation.
The gate binaries independently compute p50 and p99 from raw samples
taken after warm-up iterations, matching the hot-tier steady state (data
already in the `ArcSwap`-backed lock-free tier). See each bench file's
module doc for sample count and warm-up details.

If a gate fails on your machine but passes elsewhere, check for
background load, frequency scaling (`cpupower frequency-info`), or
running under a hypervisor that inflates tail latency.

For capacity planning and hot/cold working-set sizing guidance, see
[`docs/guides/storage-sizing.md`](docs/guides/storage-sizing.md).
