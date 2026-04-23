# Hearth Examples

Runnable demos of Hearth features. Each subdirectory is a self-contained
example you can copy, read, or run end-to-end against a local Hearth
server. The goal is *"show me what using this feature looks like from the
outside"* — not exhaustive coverage, not a template starter kit.

## Available examples

| Example | What it demonstrates | Runtime |
|---|---|---|
| [`oauth-consent-flow/`](./oauth-consent-flow/) | Browser-facing OAuth 2.0 / OIDC authorization code flow with the consent screen, per-scope approval, trusted-client bypass, and user-driven revocation. Hearth as an OIDC **provider**. | Node.js 18+ / TypeScript |
| [`federation-flow/`](./federation-flow/) | External IdP federation (social login): Hearth as an OIDC **relying party**. Local upstream built on `node-oidc-provider`, walkthrough of JIT provisioning, confirm-to-link, auto-link, and self-service unlinking. | Node.js 18+ / TypeScript |
| [`grpc-admin-flow/`](./grpc-admin-flow/) | End-to-end tour of the gRPC management API: admin CRUD, authorization engine with live `Watch` streaming, audit log, health, reflection. Single-command runner (`./run.sh`) boots Hearth and tears it down when the demo exits. | Node.js 18+ (plain ESM) |

Contributions welcome — see [Adding a new example](#adding-a-new-example) below.

## Conventions

1. **Self-contained.** Each example directory has everything it needs:
   toolchain files (`package.json` / `go.mod` / `Cargo.toml`), a
   `hearth.yaml` configuring the server for the demo scenario, a
   `.env.example` if environment variables are involved, and a
   step-by-step `README.md`.

2. **Out of the Cargo workspace.** Hearth's workspace
   (`[workspace] members = [".", "simulation"]` in the root `Cargo.toml`)
   does not include `examples/`. That keeps `cargo check` / `cargo build`
   / `cargo nextest` fast regardless of how many examples exist, and it
   lets each example pick whatever runtime fits the scenario — Node, Go,
   Python, Rust, Docker Compose — without polluting the main build.

3. **Each example has its own README.** The top-level README (this file)
   only lists what's available; the walkthrough lives with the code.

4. **Minimal dependencies.** Examples should showcase Hearth, not a
   specific framework. Prefer a hand-rolled Express/Gin/Flask app over a
   meta-framework; prefer the Hearth SDK for a given language over raw
   HTTP where an SDK exists.

5. **Demo, not production.** Every example is for learning. Shortcuts
   (in-memory session stores, hard-coded secrets, permissive CORS) are
   called out in the README so nobody copy-pastes them into a real
   system.

6. **The README is the product.** For an example, the walkthrough is the
   feature. Prerequisites, exact commands, expected output at each step,
   and pointers back to the relevant source code and specs should all be
   in the example's README.

## Adding a new example

1. Create a new subdirectory at the repo root: `examples/<feature>/`.
2. Add a `README.md` following the pattern in
   [`oauth-consent-flow/README.md`](./oauth-consent-flow/README.md):
   prerequisites → run steps → scenario walkthroughs → further reading →
   troubleshooting.
3. Include a minimal `hearth.yaml` tailored to the demo. Reference the
   top-level [`hearth.example.yaml`](../hearth.example.yaml) for the
   authoritative config schema; keep your own YAML focused on *just*
   what the scenario needs.
4. If the example needs a client app in a specific language, put it in a
   language-suffixed subdirectory (`client-ts/`, `client-go/`, etc.) so
   polyglot ports can live alongside each other.
5. Add the new example to the table at the top of this file.
6. Make sure `cargo check` and `cargo nextest run` still pass — new
   examples must not modify `src/` or `tests/`. If they do, that's a
   signal the feature has a missing surface, and the fix belongs in a
   code PR, not an example PR.
