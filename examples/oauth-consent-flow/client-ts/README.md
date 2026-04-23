# OAuth consent flow — example client (TypeScript)

A ~300-line Express app that acts as a browser-visible OAuth client
against a local Hearth server. See the
[walkthrough README](../README.md) for the full demo guide; this file
is a code map for readers who want to see what each route does.

## Files

| File | Purpose |
|---|---|
| `src/server.ts` | Express app. Four routes (`/`, `/login/:app`, `/callback`, `/revoke`) + boot. |
| `src/views.ts` | Tiny HTML string templates — no framework. |
| `package.json` | Dependencies: `express`, `cookie-parser`, `dotenv`, `uuid`. |
| `tsconfig.json` | Node 18+ ESM + strict. |

## How the routes map to the OAuth flow

```
Browser                     /ui/oauth/*  (Hearth)        /token + /userinfo
─────────                   ─────────────────────        ──────────────────

GET /                   ┐
 (render index with     │
  two "Sign in" buttons)│
                        │
Click a button:         │
GET /login/:app         ├─ 302 to GET /ui/oauth/authorize?client_id=...
 - generate state, PKCE │      │
   challenge, nonce     │      │ (Hearth shows login if needed)
 - stash in session map │      ▼
 - redirect browser     │   User signs in
                        │      │
                        │   Hearth shows consent page
                        │      │ (per-scope checkboxes)
                        │      │
                        │   User approves
                        │      │
GET /callback?code=...  ├◄ 302 back to redirect_uri
 - verify state         │
 - POST /token  ────────┼─────────────────────────────▶ exchangeCode()
 - decode ID token JWT  │                                 (raw fetch)
 - GET /userinfo ───────┼─────────────────────────────▶ userinfo()
 - render signed-in page│                                 (raw fetch)
                        │
Click "Revoke":         │
POST /revoke            ├─ DELETE /oauth/consents/{id}
 - hit Hearth REST      │     (user access token in Authorization header)
 - clear session        │
 - redirect to /        │
```

## Why no SDK?

Hearth ships a TypeScript SDK at
[`sdks/typescript/`](../../../sdks/typescript/) that wraps these same
HTTP calls. **This example deliberately uses raw `fetch` instead** so
the OAuth/OIDC contract is visible in one file. The two calls worth
looking at are:

- `exchangeCode(realmId, clientId, code, codeVerifier)` in
  `src/server.ts` — POST to `/token`. Shows the JSON body shape,
  PKCE `code_verifier`, and the `X-Realm-ID` header requirement.
- `userinfo(realmId, accessToken)` in `src/server.ts` — GET to
  `/userinfo` with `Authorization: Bearer <token>`. The response is
  filtered by the scopes the user actually approved.

For a real app, use the SDK — it handles error response parsing,
discovery-document caching, and JWKS fetching for token verification.
See [`sdks/typescript/src/client.ts`](../../../sdks/typescript/src/client.ts).

## Deterministic client IDs

Hearth derives OAuth client UUIDs from `(realm_name, app_key)` using
**UUID v5** with a well-known namespace (see
`src/identity/reconcile.rs::APP_NAMESPACE`). The same namespace
constant is duplicated in `src/server.ts::HEARTH_APP_NAMESPACE` — any
change to that constant on the Hearth side must be reflected here.

This lets the client compute its OAuth client ID locally without
hitting an admin API, which is the main reason this example works
without storing any IDs in `.env`.

## Running

```bash
npm install
npm start          # tsx src/server.ts
npm run typecheck  # tsc --noEmit
npm run build      # tsc → dist/
```

## Not production code

See [the walkthrough README's *"What's not demonstrated"* section](../README.md#whats-not-demonstrated)
for the full list of shortcuts. Short version: in-memory session map,
no JWT signature verification, no CSRF token on `/revoke`. Don't
copy-paste into a real app.
