/**
 * Hearth federation demo — Express client.
 *
 * This app simulates a tiny "protected" web app whose authentication
 * backend is Hearth. The flow:
 *
 *   1. User visits http://localhost:3000 (this app).
 *   2. Clicks "Sign in" — we 302 to Hearth's federation begin URL.
 *   3. Hearth 302s to the local upstream OIDC provider (localhost:9090).
 *   4. User logs in at the upstream with demo/demo credentials.
 *   5. Upstream redirects to Hearth's callback.
 *   6. Hearth runs its federation pipeline (JIT / confirm / auto),
 *      sets its session cookie on :8420, then redirects back to us at
 *      http://localhost:3000/callback-complete.
 *   7. We set our OWN cookie on :3000 to remember "signed in via
 *      Hearth" and redirect to /me.
 *
 * # Why a separate cookie
 *
 * Hearth's session cookie lives on `localhost:8420`. Browsers scope
 * cookies per origin (scheme + host + port), so this app at :3000
 * cannot see the :8420 cookie — that would be a cross-site cookie
 * leak and is correctly blocked. The standard pattern for an OIDC
 * relying-party front-end is to establish its own local session on
 * successful callback; that's what the `fed_demo_session` cookie
 * below represents.
 *
 * # Not production
 *
 * The local session cookie here is just a flag; a real RP would:
 *   - Verify the Hearth-issued ID token / access token on callback.
 *   - Store the verified user id (and optionally a refresh token) in
 *     a signed + encrypted cookie, or in a server-side session store.
 *   - Check the cookie's signature on every request.
 * We keep the demo cookie unsigned to avoid obscuring the federation
 * flow with session-management ceremony.
 */

import express, { type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import { renderIndex, renderProfile } from "./views.js";

// --- Config -----------------------------------------------------------------

const HEARTH_BASE_URL = process.env.HEARTH_BASE_URL ?? "http://localhost:8420";
const CLIENT_PORT = Number(process.env.CLIENT_PORT ?? 3000);
const CLIENT_BASE_URL = `http://localhost:${CLIENT_PORT}`;
const IDP_NAME = process.env.HEARTH_IDP_NAME ?? "upstream";
const REALM_NAME = process.env.HEARTH_REALM ?? "demo";

const SIGN_IN_URL = `${HEARTH_BASE_URL}/ui/realms/${REALM_NAME}/federation/begin?idp=${encodeURIComponent(
  IDP_NAME,
)}&return_to=${encodeURIComponent(`${CLIENT_BASE_URL}/callback-complete`)}`;

const HEARTH_ACCOUNT_URL = `${HEARTH_BASE_URL}/ui/account`;
const LINKED_ACCOUNTS_URL = `${HEARTH_BASE_URL}/ui/account/linked-accounts`;

/** Local cookie name scoped to this demo client (origin :3000). */
const DEMO_SESSION_COOKIE = "fed_demo_session";

// --- App --------------------------------------------------------------------

const app = express();
app.use(cookieParser());

// Home: shows "Sign in" or "Signed in" based on the LOCAL demo cookie.
app.get("/", (req: Request, res: Response) => {
  const signedIn = Boolean(req.cookies[DEMO_SESSION_COOKIE]);
  res
    .type("html")
    .send(
      renderIndex({
        signInUrl: SIGN_IN_URL,
        signedIn,
        hearthAccountUrl: HEARTH_ACCOUNT_URL,
      }),
    );
});

// The `return_to` Hearth redirects to after completing the federation
// pipeline. We set our own demo session cookie here so subsequent
// requests know the user is signed in via Hearth, then redirect to /me.
//
// In a real app this is where you'd verify Hearth's ID/access token
// (e.g., via /userinfo or the SDK) and encode the verified user id
// into a signed cookie.
app.get("/callback-complete", (_req: Request, res: Response) => {
  res
    .cookie(DEMO_SESSION_COOKIE, "1", {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 1000 * 60 * 60, // 1 hour, demo-only
    })
    .redirect("/me");
});

// Show a "profile" page. The local cookie is the signal that
// authentication happened; profile details live on Hearth itself.
app.get("/me", (req: Request, res: Response) => {
  if (!req.cookies[DEMO_SESSION_COOKIE]) {
    return res.redirect("/");
  }
  res.type("html").send(
    renderProfile({
      hearthAccountUrl: HEARTH_ACCOUNT_URL,
      linkedAccountsUrl: LINKED_ACCOUNTS_URL,
    }),
  );
});

// Sign-out: clear OUR local cookie AND send the user to Hearth's
// logout endpoint so the Hearth session dies too. Without both,
// clicking "Sign in" again would silently re-authenticate off the
// still-live Hearth session.
app.get("/signout", (_req: Request, res: Response) => {
  res
    .clearCookie(DEMO_SESSION_COOKIE, { path: "/" })
    .redirect(`${HEARTH_BASE_URL}/ui/logout`);
});

app.listen(CLIENT_PORT, () => {
  console.log(`Hearth federation demo client on ${CLIENT_BASE_URL}`);
  console.log(`  Hearth:    ${HEARTH_BASE_URL}`);
  console.log(`  Realm:     ${REALM_NAME}`);
  console.log(`  IdP name:  ${IDP_NAME}`);
  console.log(`  Sign-in:   ${SIGN_IN_URL}`);
});
