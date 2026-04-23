# OAuth Consent Flow — Runnable Example

A browser-visible demo of Hearth's OAuth 2.0 / OIDC authorization code
flow with the consent screen, per-scope approval, trusted-client bypass,
and user-driven revocation.

You'll run two processes:

1. **Hearth** — the identity server (this repo).
2. **A small Express client app** in
   [`client-ts/`](./client-ts/) that plays the part of "third-party SaaS
   signing in with Hearth". The client uses raw `fetch` calls (no SDK
   wrapper) so the OAuth/OIDC HTTP contract is visible in one file.

---

## What this example demonstrates

- The browser-facing `GET /ui/oauth/authorize` endpoint and the consent
  interstitial rendered at `/ui/oauth/consent`.
- Per-scope checkboxes (uncheck `email` to see partial approval persist
  to storage and show up in the `/userinfo` response).
- The `require_consent: false` trusted-client bypass — same flow, no
  prompt, useful for first-party SSO.
- User-driven consent revocation via the `DELETE /oauth/consents/{id}`
  REST endpoint.
- OIDC `prompt=consent` parameter — force re-prompting even when a
  prior consent record covers every requested scope.
- Audit trail: each consent grant/deny/revoke shows up in
  `/ui/admin/audit` with `metadata.via = "self"`.

---

## Prerequisites

- Rust toolchain (to build Hearth from source — workspace root has the
  Cargo project).
- Node.js 18 or later (for the client app).
- Two free local ports: **8420** (Hearth) and **3000** (client).

---

## Steps

Everything below assumes you're at the repo root
(`/path/to/hearth/`).

### 1. Start Hearth

```bash
cargo run --release -- serve --dev \
  --config examples/oauth-consent-flow/hearth.yaml
```

On a first run you'll see log lines like:

```
INFO hearth: Hearth identity server starting dev_mode=true port=8420
INFO hearth::identity::reconcile: created application from YAML realm="demo" app="third-party-app"
INFO hearth::identity::reconcile: created application from YAML realm="demo" app="first-party-sso"
INFO hearth: realm reconciliation complete created=1
INFO hearth::protocol::http: HTTP server listening local_addr=127.0.0.1:8420
```

If you do **not** see both `created application from YAML` lines,
something is wrong — rebuild (`cargo build --release`) and retry.

### 2. Onboard the admin + find the realm UUID

Complete the one-time admin onboarding at
`http://localhost:8420/ui/setup`. This creates a system-realm admin
— you'll use it to browse the admin UI and create a demo user in
the next step. **Remember the admin email + password.**

After submitting the setup form, the admin account starts in
`PendingVerification` state. The example uses Hearth's default
`log` email transport (no real SMTP), so Hearth prints the
verification URL directly in the server's log:

```
WARN hearth::identity::onboarding: onboarding: verification link
   verification_url=http://127.0.0.1:8420/ui/admin/verify-email?token=...
```

Open that URL in your browser to activate the admin account, then
sign in at `http://localhost:8420/ui/admin/login`.

Once signed in, open `http://localhost:8420/ui/admin/realms` and
copy the UUID shown for the `demo` realm.

> **Realm rule:** OAuth clients are realm-scoped. The
> `third-party-app` and `first-party-sso` clients live inside the
> `demo` realm, and an OAuth flow signs the user into the client's
> realm. The system-realm admin you just created **cannot** be used
> to complete the OAuth flow from the example client — the two
> realms are isolated.

### 3. Create a demo-realm user

Still in the admin UI:

1. Switch the admin's target realm to `demo` using the realm
   switcher (URL: `http://localhost:8420/ui/admin/users?realm=demo`).
2. Click **"New user"** and create a user with any email + display
   name. Set an initial password on the detail page.
3. Confirm the user's status is **Active** (admin-created users are
   active immediately — no email verification dance).

This is the user you'll sign in as from the example client.

### 4. Install + start the client

```bash
cd examples/oauth-consent-flow/client-ts
npm install
HEARTH_REALM_ID=<paste-UUID-here> npm start
```

You should see:

```
Using realm 'demo' → <uuid>
OAuth consent demo client listening on http://localhost:3000
Hearth server:  http://localhost:8420
Third-party app client id: <uuid-v5>
First-party SSO client id: <uuid-v5>

Open http://localhost:3000 in a browser to start.
```

### 5. Run the scenarios

Before clicking any button, **open the example client
(`http://localhost:3000`) in a private/incognito browsing window**.
That's the most reliable way to avoid the two cookies left behind
by the `/ui/setup` admin flow:

- `hearth_ui_session` (cleared by `/ui/logout`)
- `hearth_ui_last_realm=__system__` (**not** cleared by logout —
  it's a long-lived UX hint that tells Hearth "last time you logged
  in, it was admin", which would send you to the admin login rather
  than the demo login on the next OAuth redirect)

Clearing both cookies via DevTools (Application → Cookies →
`http://localhost:8420` → delete all) also works.

Then open `http://localhost:3000` and click each button in turn.

#### Scenario 1 — consent prompt + partial approval

Click **"Sign in with Third-Party Analytics"**:

1. You're redirected to Hearth's login page for the `demo` realm
   (the URL will be `/ui/realms/demo/login`).
2. Sign in with the demo-realm user credentials you created in
   step 3.
3. Hearth's consent screen appears, showing the "Third-Party
   Analytics" header with a logo placeholder and per-scope
   checkboxes for `openid`, `profile`, and `email`.
4. **Uncheck `email`** and click **Approve**.
5. You land back on the example client. The page shows:
   - The decoded ID token payload — includes `sub`, `nonce`, `aud`.
   - The `/userinfo` response — includes `sub` and `name` but
     **no `email`** (you didn't approve that scope).
   - A preview of the access token and a "Revoke" button.

#### Scenario 2 — trusted-client bypass

Go back to `http://localhost:3000/` and click **"Sign in with Internal
SSO"**.

- No consent screen appears — the user is redirected straight from
  authorize to the client callback.
- The signed-in page shows the full `/userinfo` response, including
  `email` and `email_verified` (since the trusted client isn't
  scope-gated by consent).

This demonstrates the `require_consent: false` flag declared on the
`first-party-sso` app in `hearth.yaml`. Only apply this to clients
where the user's consent is already implicit (e.g., an internal SSO
portal).

#### Scenario 3 — revocation reinstates the prompt

From the "Third-Party Analytics" signed-in page, click **"Revoke my
consent for this app"**.

- The client hits `DELETE /oauth/consents/<client_id>` with the user's
  access token.
- You're redirected back to the home page.
- Click **"Sign in with Third-Party Analytics"** again — the consent
  screen reappears because the prior record was deleted.

The Hearth audit log at `/ui/admin/audit` now shows three events with
`action = "consent_granted" | "consent_revoked"` and `metadata.via = "self"`.

#### Scenario 4 — `prompt=consent` forces re-prompting

While still signed in (prior consent persisted), click **"Force
re-prompt for Third-Party Analytics"**. This adds `prompt=consent` to
the authorize URL. Per OIDC Core §3.1.2.1, Hearth re-renders the
consent screen even though a covering record exists.

#### Scenario 5 — admin revocation

Back in the Hearth admin UI, go to
`http://localhost:8420/ui/admin/users/<user-uuid>/consents?realm=demo`
(grab the user UUID from `/ui/admin/users`).

- See the same consent record the user granted in scenario 1.
- Click **"Revoke on behalf of user"**.
- Return to the client at `http://localhost:3000/` — the next sign-in
  attempt shows the consent prompt again.
- The audit log now distinguishes admin revocations via
  `metadata.via = "admin"`.

---

## Further reading

- **Consent feature spec + `Key files`**:
  [`docs/gaps/FEATURE_GAPS.md`](../../docs/gaps/FEATURE_GAPS.md) →
  *"OAuth Consent Screen — COMPLETED ✅"*.
- **Server-side implementation**:
  [`src/protocol/web/oauth_consent.rs`](../../src/protocol/web/oauth_consent.rs) —
  the browser-facing authorize + consent handlers.
- **Engine-level API**:
  [`src/identity/engine.rs`](../../src/identity/engine.rs) —
  `grant_consent`, `list_consents_by_user`, `revoke_consent`,
  `put_pending_authorization`, `take_pending_authorization`.
- **Integration tests**:
  [`tests/oauth_consent.rs`](../../tests/oauth_consent.rs) — 26 tests
  covering every scenario above at the HTTP layer.
- **YAML config for `require_consent` / `client_logo_url`**:
  [`src/config/types.rs`](../../src/config/types.rs) →
  `ApplicationYamlConfig`.

---

## Troubleshooting

- **`HEARTH_REALM_ID is not set`**: you skipped step 4 or the UUID in
  `.env` is malformed. Re-check the realm list at
  `/ui/admin/realms`.
- **Callback says "state mismatch"**: cookies are scoped to
  `localhost` on a specific port. Don't change `CLIENT_PORT` without
  also updating the `redirect_uris` in `hearth.yaml`.
- **Token exchange returns `invalid_grant`**: usually means the code
  expired (5-minute TTL) or was already used. Restart the flow from
  `/`.
- **Consent prompt doesn't appear even on first visit**: the
  `third-party-app` entry in `hearth.yaml` may be
  `require_consent: false`. Double-check the file hasn't been edited.
- **"Unknown client" error from Hearth**: two common causes.
  1. The YAML reconciler didn't run. Make sure
     `--config examples/oauth-consent-flow/hearth.yaml` is on the
     `cargo run` command, and check the Hearth startup log for both
     `created application from YAML` lines. If they're missing, you
     might be on an older binary — rebuild with `cargo build --release`.
  2. You're still signed in as the **system-realm admin** from
     `/ui/setup`. OAuth clients are realm-scoped: the
     `third-party-app` only exists inside the `demo` realm, so a
     system-realm session can't see it. Visit `/ui/logout`, clear
     cookies, or use a private browsing window, then click the
     demo button — you'll land on `/ui/realms/demo/login` and can
     sign in as the demo-realm user from step 3.

- **Admin sign-in says "email not verified"**: `--dev` uses the
  `log` email transport, so Hearth prints the verification URL in
  the server's log rather than sending an email. Grep the log for
  `verification_url=` and open the link in your browser.
- **Port 8420 or 3000 is in use**: change `server.port` /
  `CLIENT_PORT` and update `redirect_uris` / `HEARTH_BASE_URL`
  accordingly.

---

## What's *not* demonstrated

- **Signature verification of the ID token.** The example decodes the
  payload and trusts it because Hearth is running locally. Production
  clients should fetch `/jwks` and verify the signature — see
  `sdks/typescript/src/client.ts::jwks()` and any standard OIDC
  library (e.g. `jose`) for the pattern.
- **Refresh token rotation.** The access token here is short-lived
  (15 minutes by default); a real client would use the refresh token
  to mint new access tokens. See `POST /token` with `grant_type=refresh_token`.
- **Production session management.** The demo keeps everything in a
  single in-memory `Map`. Restart the client and all sessions are
  gone. A real app would use a session store (Redis, encrypted
  cookies, etc.) and proper rotation.
- **CSRF protection on `/revoke`.** The demo relies on
  `SameSite=Lax` cookies. A production client should use a
  double-submit CSRF token.
- **Public-client PKCE without secrets.** Both demo clients are
  registered without a `client_secret` (public clients) and use PKCE
  S256. Confidential clients add a client secret to the token
  request; Hearth supports both.

If any of these missing pieces matter for your use case, the
[integration tests](../../tests/oauth_consent.rs) are the
authoritative source of what the server supports.
