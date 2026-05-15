/**
 * Hearth OAuth consent flow demo — Express client.
 *
 * Walks a browser through an OIDC authorization code flow against a local
 * Hearth server, landing on a page that shows the decoded ID token claims
 * and the `/userinfo` response. Demonstrates the consent prompt, the
 * trusted-client bypass, and user-driven revocation.
 *
 * # Not production code
 *
 * This is a learning demo. Session state lives in a single in-memory
 * `Map`; PKCE is wired up, but the ID token's signature is only
 * inspected by decoding the payload (no JWKS verification). Don't paste
 * this into a real app. See the README in this directory for pointers
 * to the relevant SDK code and Hearth source.
 */

import { createHash, randomBytes } from "node:crypto";
import { config as loadEnv } from "dotenv";
import express from "express";
import cookieParser from "cookie-parser";
import { v5 as uuidv5 } from "uuid";

import { renderError, renderIndex, renderSignedIn } from "./views.js";

/**
 * Deliberately NOT using `@hearth/sdk` — this example uses raw `fetch`
 * calls so the OAuth 2.0 / OIDC HTTP contract is visible in one file.
 * Integrators building real apps should prefer the SDK (see
 * `sdks/typescript/src/client.ts`), but the teaching value of this
 * example is in seeing the exact endpoints, headers, and bodies.
 */
interface TokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}
interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

// Load .env from the example directory (one level up from client-ts/).
loadEnv({ path: new URL("../../.env", import.meta.url).pathname });

// --- Config -----------------------------------------------------------------

const HEARTH_BASE_URL = process.env.HEARTH_BASE_URL ?? "http://localhost:8420";
const HEARTH_REALM = process.env.HEARTH_REALM ?? "demo";
const CLIENT_PORT = Number(process.env.CLIENT_PORT ?? 3000);
const CLIENT_BASE_URL = `http://localhost:${CLIENT_PORT}`;
const REDIRECT_URI = `${CLIENT_BASE_URL}/callback`;

/**
 * Namespace UUID used by Hearth's YAML reconciler to derive deterministic
 * OAuth client IDs from `(realm_name, app_key)`. Must match the constant
 * in `src/identity/reconcile.rs::APP_NAMESPACE` — that file is the spec.
 */
const HEARTH_APP_NAMESPACE = "8b074e8c-3e6a-5a8e-961d-8f2baae71bf4";

/** The two applications declared in the example's hearth.yaml. */
const APPS = {
  "third-party-app": {
    key: "third-party-app",
    displayName: "Third-Party Analytics",
    trusted: false,
  },
  "first-party-sso": {
    key: "first-party-sso",
    displayName: "Internal SSO",
    trusted: true,
  },
} as const;
type AppKey = keyof typeof APPS;

function clientIdFor(appKey: AppKey): string {
  return uuidv5(`${HEARTH_REALM}/${appKey}`, HEARTH_APP_NAMESPACE);
}

// --- Realm ID ---------------------------------------------------------------

/**
 * The client is realm-scoped — every Hearth API call carries
 * `X-Realm-ID`. Realm UUIDs are NOT deterministic (unlike client IDs),
 * so the operator has to supply the demo realm's UUID via the
 * `HEARTH_REALM_ID` env var. See the README for how to find it.
 */
function resolveRealmId(): string {
  const id = process.env.HEARTH_REALM_ID ?? "";
  if (!id) {
    throw new Error(
      `HEARTH_REALM_ID is not set. After running /ui/setup on Hearth, ` +
        `open http://localhost:8420/ui/admin/realms, copy the UUID for the ` +
        `'${HEARTH_REALM}' realm, and paste it into ${new URL("../../.env", import.meta.url).pathname}.`,
    );
  }
  return id;
}

// --- In-memory session store -----------------------------------------------

interface Session {
  appKey: AppKey;
  state: string;
  codeVerifier: string;
  nonce: string;
  // Set after successful callback.
  accessToken?: string;
  idToken?: string;
  clientId?: string;
}
const sessions = new Map<string, Session>();
const SESSION_COOKIE = "demo_session";

function newSessionId(): string {
  return randomBytes(18).toString("base64url");
}

// --- PKCE helpers -----------------------------------------------------------

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

// --- JWT decode (no signature verification — demo only) ---------------------

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("malformed JWT");
  }
  const payload = Buffer.from(parts[1], "base64url").toString("utf8");
  return JSON.parse(payload) as Record<string, unknown>;
}

// --- Bootstrap --------------------------------------------------------------

/** POST /token — raw fetch against the Hearth token endpoint. */
async function exchangeCode(
  realmId: string,
  clientId: string,
  code: string,
  codeVerifier: string,
): Promise<TokenResponse> {
  const resp = await fetch(`${HEARTH_BASE_URL}/token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Realm-ID": realmId,
    },
    body: JSON.stringify({
      client_id: clientId,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    }),
  });
  if (!resp.ok) {
    throw new Error(`token exchange failed: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as TokenResponse;
}

/** GET /userinfo — OIDC Core §5.3 — returns scope-filtered claims. */
async function userinfo(
  realmId: string,
  accessToken: string,
): Promise<UserInfoResponse> {
  const resp = await fetch(`${HEARTH_BASE_URL}/userinfo`, {
    headers: {
      "X-Realm-ID": realmId,
      Authorization: `Bearer ${accessToken}`,
    },
  });
  if (!resp.ok) {
    throw new Error(`userinfo failed: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as UserInfoResponse;
}

async function main(): Promise<void> {
  const realmId = resolveRealmId();
  console.log(`Using realm '${HEARTH_REALM}' → ${realmId}`);

  const app = express();
  // Demo only — CSRF protection omitted intentionally; this is not production code.
  // codeql[js/missing-token-validation]
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: false }));

  // --- GET / : landing page ------------------------------------------------

  app.get("/", (_req, res) => {
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.send(
      renderIndex({
        thirdPartyClientId: clientIdFor("third-party-app"),
        firstPartyClientId: clientIdFor("first-party-sso"),
      }),
    );
  });

  // --- GET /login/:app : start OAuth flow ----------------------------------

  app.get("/login/:app", (req, res) => {
    const appKey = req.params.app as AppKey;
    if (!(appKey in APPS)) {
      res
        .status(404)
        .setHeader("content-type", "text/html")
        .send(
          renderError({
            title: "Unknown app",
            detail: `No app with key '${appKey}'. Valid keys: ${Object.keys(APPS).join(", ")}.`,
          }),
        );
      return;
    }

    const sessionId = newSessionId();
    const state = randomBytes(16).toString("base64url");
    const nonce = randomBytes(16).toString("base64url");
    const { verifier, challenge } = pkcePair();

    sessions.set(sessionId, {
      appKey,
      state,
      codeVerifier: verifier,
      nonce,
    });

    res.cookie(SESSION_COOKIE, sessionId, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
    });

    const params = new URLSearchParams({
      client_id: clientIdFor(appKey),
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid profile email",
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const prompt = typeof req.query.prompt === "string" ? req.query.prompt : "";
    if (prompt === "none" || prompt === "consent") {
      params.set("prompt", prompt);
    }

    // Use the realm-scoped authorize route (`/ui/realms/{realm}/oauth/authorize`)
    // so Hearth's login redirect lands on `/ui/realms/demo/login` rather
    // than the system-admin login — the OAuth client lives in the demo
    // realm, and the user must authenticate there to see it.
    res.redirect(
      `${HEARTH_BASE_URL}/ui/realms/${encodeURIComponent(HEARTH_REALM)}/oauth/authorize?${params.toString()}`,
    );
  });

  // --- GET /callback : OAuth code redirect target --------------------------

  app.get("/callback", async (req, res) => {
    const sessionId = req.cookies?.[SESSION_COOKIE];
    const session = sessionId ? sessions.get(sessionId) : undefined;

    res.setHeader("content-type", "text/html; charset=utf-8");

    if (!session) {
      res
        .status(400)
        .send(
          renderError({
            title: "Missing session",
            detail:
              "No in-memory session for this callback. Start from the home page at /.",
          }),
        );
      return;
    }

    const { code, state, error, error_description } = req.query as Record<
      string,
      string | undefined
    >;

    if (error) {
      res.send(
        renderError({
          title: `OAuth error: ${error}`,
          detail: error_description
            ? `${error}\n\n${error_description}`
            : error,
        }),
      );
      return;
    }

    if (!code || state !== session.state) {
      res.status(400).send(
        renderError({
          title: "State mismatch",
          detail:
            "The OAuth state parameter did not match the one we issued. " +
            "This protects against CSRF. Start over from /.",
        }),
      );
      return;
    }

    try {
      const clientId = clientIdFor(session.appKey);
      const tokens = await exchangeCode(
        realmId,
        clientId,
        code,
        session.codeVerifier,
      );

      const idTokenClaims = decodeJwtPayload(tokens.id_token);
      const claims = await userinfo(realmId, tokens.access_token);

      // Persist the token + client id for the revoke flow.
      sessions.set(sessionId!, {
        ...session,
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
        clientId,
      });

      res.send(
        renderSignedIn({
          appKey: session.appKey,
          clientName: APPS[session.appKey].displayName,
          idTokenClaims,
          userinfo: claims as unknown as Record<string, unknown>,
          accessTokenPreview: `${tokens.access_token.slice(0, 48)}…`,
        }),
      );
    } catch (e) {
      res.status(500).send(
        renderError({
          title: "Token exchange failed",
          detail: e instanceof Error ? e.message : String(e),
        }),
      );
    }
  });

  // --- POST /revoke : revoke the current user's consent for this client ----

  app.post("/revoke", async (req, res) => {
    const sessionId = req.cookies?.[SESSION_COOKIE];
    const session = sessionId ? sessions.get(sessionId) : undefined;
    res.setHeader("content-type", "text/html; charset=utf-8");

    if (!session?.accessToken || !session.clientId) {
      res
        .status(400)
        .send(
          renderError({
            title: "Nothing to revoke",
            detail: "No active session with a persisted access token.",
          }),
        );
      return;
    }

    try {
      // DELETE /oauth/consents/{client_id} — not yet surfaced through the
      // SDK, so we call it with raw fetch. Shows integrators exactly
      // what the REST contract looks like.
      const resp = await fetch(
        `${HEARTH_BASE_URL}/oauth/consents/${session.clientId}`,
        {
          method: "DELETE",
          headers: {
            "X-Realm-ID": realmId,
            Authorization: `Bearer ${session.accessToken}`,
          },
        },
      );
      if (!resp.ok && resp.status !== 404) {
        const body = await resp.text();
        res.status(500).send(
          renderError({
            title: "Revoke failed",
            detail: `${resp.status} ${body}`,
          }),
        );
        return;
      }
      // Clear the session so the user has to re-auth. A 404 is fine —
      // idempotent from the caller's perspective.
      sessions.delete(sessionId!);
      res.clearCookie(SESSION_COOKIE);
      res.redirect("/");
    } catch (e) {
      res.status(500).send(
        renderError({
          title: "Revoke failed",
          detail: String(e),
        }),
      );
    }
  });

  app.listen(CLIENT_PORT, () => {
    console.log(
      `OAuth consent demo client listening on ${CLIENT_BASE_URL}\n` +
        `Hearth server:  ${HEARTH_BASE_URL}\n` +
        `Realm:          ${HEARTH_REALM} (${realmId})\n` +
        `Third-party app client id: ${clientIdFor("third-party-app")}\n` +
        `First-party SSO client id: ${clientIdFor("first-party-sso")}\n\n` +
        `Open ${CLIENT_BASE_URL} in a browser to start.`,
    );
  });
}

main().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
