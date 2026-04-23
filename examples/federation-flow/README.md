# Federation Flow — Runnable Example

A browser-visible demo of Hearth as an **OIDC relying party** — the
counterpart to [`../oauth-consent-flow/`](../oauth-consent-flow/),
which demonstrates Hearth as an OIDC *provider*.

You'll run three processes:

1. **A local OIDC upstream** at `http://localhost:9090`, built on
   [`node-oidc-provider`](https://github.com/panva/node-oidc-provider).
   Stands in for Google / Azure AD / Okta / etc.
2. **Hearth** at `http://localhost:8420`, configured via
   [`hearth.yaml`](./hearth.yaml) to federate against the local upstream.
3. **A tiny client app** at `http://localhost:3000` whose authentication
   backend is Hearth.

---

## What this example demonstrates

- **JIT provisioning.** First login from an unknown upstream user
  creates a fresh Hearth account on the fly.
- **Existing-user path.** Second login with the same external identity
  lands on the same Hearth user — Hearth's `fed:ext:*` reverse index
  resolves it in one lookup.
- **Confirm-to-link (default).** When the upstream asserts a verified
  email matching an existing Hearth user, Hearth redirects to a page
  that requires local re-authentication before attaching the identity.
  Matches Keycloak's default First Broker Login flow.
- **Auto-link mode.** Flip `link_existing_accounts: auto` in `hearth.yaml`
  and restart to see silent linking on email match.
- **Disabled mode.** Flip to `disabled` — every external login
  JIT-provisions a fresh user, never linking.
- **Self-service unlinking** at `/ui/account/linked-accounts`.
- **Audit trail:** each start / complete / link / unlink / JIT event
  shows up in `/ui/admin/audit` with a `metadata` blob describing the
  mode (`confirm` | `auto` | `initial`) and actor.

---

## Prerequisites

- Rust toolchain (to build Hearth from source).
- Node.js 18 or later (for both Node sub-projects).
- Three free local ports: **8420** (Hearth), **9090** (upstream IdP),
  **3000** (client).

---

## Steps

Everything below assumes you're at the repo root (`/path/to/hearth/`).

### 1. Start the upstream OIDC provider

```bash
cd examples/federation-flow/upstream-idp
npm install
npm start
```

You should see:

```
Local OIDC upstream listening on http://localhost:9090
  Discovery: http://localhost:9090/.well-known/openid-configuration
  Accounts:  alice-ext-id (alice@example.com), bob-ext-id (bob@example.com)
  Password:  demo
```

Leave it running. If port 9090 is taken, edit both `ISSUER` in
`src/server.ts` and `federation.providers.upstream.issuer` (plus all
its endpoints) in `hearth.yaml`.

### 2. Start Hearth in a second terminal

```bash
cargo run --release -- serve --dev \
  --config examples/federation-flow/hearth.yaml
```

Log lines to look for:

```
INFO hearth::identity::reconcile: reconciled federation connector realm="demo" idp="upstream"
INFO hearth::protocol::http: HTTP server listening local_addr=127.0.0.1:8420
```

If you do **not** see the `reconciled federation connector` line the
YAML didn't take effect — rebuild with `cargo build --release` and try
again.

### 3. Onboard the admin

Complete the one-time admin onboarding at
<http://localhost:8420/ui/setup>. This creates the system-realm admin.
Because `email.transport` defaults to `log` in dev mode, Hearth prints
the verification URL in its own log:

```
WARN hearth::identity::onboarding: onboarding: verification link
   verification_url=http://127.0.0.1:8420/ui/admin/verify-email?token=...
```

Open that URL, then sign in at <http://localhost:8420/ui/admin/login>.

> **Realm rule.** The federation connector lives inside the `demo`
> realm, not the system realm. The admin account you just created
> **cannot** complete the federation flow — you'll do that in a
> private browsing window shortly.

### 4. Start the client app in a third terminal

```bash
cd examples/federation-flow/client-ts
npm install
npm start
```

You should see:

```
Hearth federation demo client on http://localhost:3000
  Hearth:    http://localhost:8420
  Realm:     demo
  IdP name:  upstream
  Sign-in:   http://localhost:8420/ui/realms/demo/federation/begin?idp=upstream&return_to=http%3A%2F%2Flocalhost%3A3000%2Fcallback-complete
```

### 5. Run the scenarios

**Open <http://localhost:3000> in a private/incognito window** to avoid
the admin session cookie left behind by `/ui/setup`. Alternatively:
DevTools → Application → Cookies → delete everything under
`http://localhost:8420`.

#### Scenario 1 — JIT provisioning (fresh user)

1. Click **Sign in** on the client page.
2. You're sent to Hearth's `/ui/realms/demo/federation/begin?idp=upstream`,
   which 302s to the upstream IdP at `localhost:9090`.
3. The upstream's built-in login page asks for an account id —
   enter `alice-ext-id` (or `bob-ext-id`) and password `demo`.
4. Approve the (dev-mode) interaction prompt.
5. You land back at `http://localhost:3000/me` — Hearth silently
   created a new user for the upstream identity and signed you in.

Verify in the Hearth admin:

- <http://localhost:8420/ui/admin/users?realm=demo> — Alice appears.
- <http://localhost:8420/ui/admin/audit?realm=demo> — three events:
  `federation_login_started`, `federation_jit_provisioned`,
  `federation_login_completed`.

#### Scenario 2 — repeat login hits the existing user

Sign out by visiting `http://localhost:3000/signout`, clear your
cookies, then click **Sign in** again. You log back into the same Alice
user — audit shows just `federation_login_completed` this time (no
fresh JIT event).

#### Scenario 3 — confirm-to-link

1. In a new private window, go to
   <http://localhost:8420/ui/admin/users?realm=demo> and create a new
   *local* user with email `bob@example.com` and set a password — say,
   `localpassword`.
2. Delete Bob's previous `fed:ext:*` link if one exists: visit
   <http://localhost:8420/ui/admin/users/{bob-uuid}?realm=demo>, or
   just delete Bob and recreate with a local password.
3. Open a *fresh* private window for the client.
4. Click **Sign in** at `http://localhost:3000`.
5. At the upstream login page, use `bob-ext-id` / `demo`.
6. Hearth detects the email match (`bob@example.com` exists locally
   and the upstream asserts `email_verified=true`). Because
   `link_existing_accounts: confirm` is set in the YAML, Hearth
   redirects to `/ui/federation/confirm-link`.
7. Enter Bob's local password (`localpassword`) to prove ownership.
8. The external identity attaches. Future logins via the upstream land
   on this same local Bob.

Audit shows `federation_account_linked` with `metadata.mode = "confirm"`.

#### Scenario 4 — auto-link mode

Edit `hearth.yaml`:

```yaml
realms:
  demo:
    federation:
      link_existing_accounts: auto   # was: confirm
```

Restart Hearth (Ctrl-C then the same cargo command). Now repeat
scenario 3 with a fresh local-password user — Hearth attaches the
external identity silently, no confirmation step. `metadata.mode = "auto"`
in the audit log.

#### Scenario 5 — disabled mode (duplicates by design)

Flip to `link_existing_accounts: disabled` and restart. Now the
email match does **not** trigger linking — Hearth JIT-provisions a
fresh user every time, even when the email collides with an existing
local account. You'll see two separate Bob users in the admin list.

#### Scenario 6 — self-service unlinking

As the signed-in user:

1. Visit <http://localhost:8420/ui/account/linked-accounts>.
2. The Upstream connector is listed — click **Unlink**.
3. Sign back in via the client → Hearth now JIT-provisions a fresh
   user (the link is gone).

Audit: `federation_account_unlinked` with `metadata.via = "self"`.

#### Scenario 7 — error paths

- **Tamper the state.** On the `/ui/federation/callback?state=...` URL,
  change the `state` query parameter before letting Hearth process the
  callback. Result: 302 to `/ui/login?error=federation_failed`
  (state-bag take fails).
- **Upstream denies consent.** oidc-provider's built-in UI doesn't
  expose a Deny button by default, but you can simulate the code path
  by manually hitting
  `/ui/federation/callback?state=xxx&error=access_denied` — Hearth
  gracefully 302s to `/ui/login?error=federation_denied`.

---

## Configuration notes

- All three ports are hard-coded; change any one and you must update
  the others (`hearth.yaml`, `upstream-idp/src/server.ts`,
  `client-ts/src/server.ts`).
- The upstream IdP's signing keys are **regenerated on every restart**
  — a nice side effect is that the JWKS endpoint is realistically
  dynamic, so Hearth's JWK-selection code is exercised properly.
- There is no real user consent screen on the upstream; we enable
  `devInteractions` in the oidc-provider config to keep the demo
  focused on Hearth's linking behavior. A production upstream would
  have its own consent UX.
- This demo is *offline*. No external credentials, no Google console
  registration, no network egress.

---

## Using a real upstream instead (appendix)

You can point Hearth at a real OIDC provider by swapping the YAML:

### Google

```yaml
realms:
  demo:
    federation:
      providers:
        google:
          type: google
          client_id: ${GOOGLE_CLIENT_ID}
          client_secret: ${GOOGLE_CLIENT_SECRET}
```

Register the OAuth 2.0 client at
<https://console.cloud.google.com/apis/credentials> with redirect URI
`http://localhost:8420/ui/federation/callback` (or your deployed
URL). Then set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in your
shell before starting Hearth. The rest of the walkthrough — JIT,
confirm-to-link, unlink — works identically.

### Dex

If you'd rather run a local Go-based OIDC provider instead of
node-oidc-provider, [Dex](https://dexidp.io/) works the same way:

```bash
# Minimal dex.yaml — see dex docs for full reference
cat > /tmp/dex.yaml <<'EOF'
issuer: http://localhost:9090
storage:
  type: memory
web:
  http: 0.0.0.0:9090
staticClients:
- id: hearth-demo
  redirectURIs:
  - http://localhost:8420/ui/federation/callback
  name: Hearth Demo
  secret: demo-secret-do-not-use-in-production
enablePasswordDB: true
staticPasswords:
- email: alice@example.com
  hash: $2a$10$2b2cu2a7fEvhZFBNS4HQxeirBH2B5g.X6kzWqQM80sHBM.y3KgGXG
  username: alice
  userID: alice-ext-id
EOF

dex serve /tmp/dex.yaml
```

(The password hash above is `demo`.) The same `hearth.yaml`
configuration works unchanged.

---

## Troubleshooting

- **"Federation connector not found"** when clicking sign-in: the YAML
  reconciler didn't run. Make sure `--config
  examples/federation-flow/hearth.yaml` is on the `cargo run` command,
  and check the Hearth startup log for `reconciled federation connector`.
- **Redirect loop after signing in at the upstream**: the redirect URI
  registered at the upstream must exactly match
  `http://localhost:8420/ui/federation/callback`. The IdP's error page
  will call out any mismatch.
- **"Invalid federation state"**: the `fed:state:*` row was consumed or
  expired. Each state token is single-use and lives for 10 minutes —
  start the flow over from `http://localhost:3000`.
- **`email not verified`** on callback: the upstream returned
  `email_verified=false`. Hearth refuses to link to an existing user
  on unverified email even in `auto` mode; it falls through to JIT.
- **Port conflicts**: edit the constants in `hearth.yaml`,
  `upstream-idp/src/server.ts`, and `client-ts/src/server.ts` in
  lockstep — the redirect URI and the three listen addresses all have
  to stay consistent.

---

## Further reading

- **Federation feature spec**:
  [`docs/gaps/FEATURE_GAPS.md §5`](../../docs/gaps/FEATURE_GAPS.md)
  — file map, architectural notes, remaining enhancements.
- **Server-side implementation**:
  [`src/identity/federation/`](../../src/identity/federation/) — the
  connector trait, generic OIDC impl, GitHub impl, state primitives.
- **Handlers**:
  [`src/protocol/web/federation.rs`](../../src/protocol/web/federation.rs).
- **Integration tests**:
  [`tests/federation.rs`](../../tests/federation.rs),
  [`tests/federation_adversarial.rs`](../../tests/federation_adversarial.rs),
  [`tests/federation_conformance.rs`](../../tests/federation_conformance.rs),
  [`tests/web_ui_federation.rs`](../../tests/web_ui_federation.rs).
- **Consent screen demo** (the sibling example, showing Hearth as an
  OIDC *provider*): [`../oauth-consent-flow/`](../oauth-consent-flow/).
