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
