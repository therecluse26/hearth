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
 *      sets its session cookie, then redirects back here.
 *   7. We read the Hearth session cookie on /me to show profile data.
 *
 * # Not production
 *
 * Real clients verify the Hearth-issued session cookie cryptographically
 * or exchange it for a real OAuth access token. This demo cheats: it
 * reads the cookie's presence as a signal that Hearth authenticated
 * the user, and fetches profile data directly from Hearth's own
 * account-info endpoint. The point is to exercise Hearth's federation
 * flow, not to build a real RP template.
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

const LINKED_ACCOUNTS_URL = `${HEARTH_BASE_URL}/ui/account/linked-accounts`;

// --- App --------------------------------------------------------------------

const app = express();
app.use(cookieParser());

// Home: shows either "Sign in" or "Signed in as ..." based on the
// Hearth session cookie's presence.
app.get("/", (req: Request, res: Response) => {
  const hearthSession = req.cookies["hearth_ui_session"];
  res
    .type("html")
    .send(
      renderIndex({
        signInUrl: SIGN_IN_URL,
        signedInEmail: hearthSession ? "signed-in (via Hearth)" : undefined,
      }),
    );
});

// The `return_to` Hearth redirects to after completing the federation
// pipeline. We just send the user to `/me`; Hearth has already set
// its session cookie at this point.
app.get("/callback-complete", (_req: Request, res: Response) => {
  res.redirect("/me");
});

// Show a "profile" page. In a real integration you'd verify the
// Hearth access token; here we just confirm the cookie is set.
app.get("/me", async (req: Request, res: Response) => {
  const hearthSession = req.cookies["hearth_ui_session"];
  if (!hearthSession) {
    return res.redirect("/");
  }
  // Hearth's /ui/account page renders the signed-in user's email in
  // the chrome. We forward the cookie and extract a rough
  // display name from that page's HTML. A real client would use the
  // Hearth SDK or hit /userinfo with a bearer token.
  try {
    const resp = await fetch(`${HEARTH_BASE_URL}/ui/account`, {
      headers: { cookie: `hearth_ui_session=${hearthSession}` },
      redirect: "manual",
    });
    if (resp.status !== 200) {
      return res
        .status(resp.status)
        .type("html")
        .send(
          `<p>Hearth returned status ${resp.status} when fetching /ui/account.</p><p><a href="/">Home</a></p>`,
        );
    }
    const html = await resp.text();
    // Crude extraction — enough for a demo that just wants to show the
    // user something.
    const emailMatch = html.match(/data-testid="account-email"[^>]*>([^<]+)</);
    const nameMatch = html.match(/data-testid="account-display-name"[^>]*>([^<]+)</);
    res
      .type("html")
      .send(
        renderProfile({
          email: emailMatch?.[1]?.trim() ?? "(email not exposed)",
          displayName: nameMatch?.[1]?.trim() ?? "(name not exposed)",
          linkedAccountsUrl: LINKED_ACCOUNTS_URL,
        }),
      );
  } catch (err) {
    res
      .status(502)
      .type("html")
      .send(
        `<p>Could not reach Hearth at ${HEARTH_BASE_URL}. Is it running?</p><p>${String(err)}</p>`,
      );
  }
});

// Sign-out: clear the Hearth UI session cookie by calling logout, then
// come back to home.
app.get("/signout", (_req: Request, res: Response) => {
  res.redirect(`${HEARTH_BASE_URL}/ui/logout`);
});

app.listen(CLIENT_PORT, () => {
  console.log(`Hearth federation demo client on ${CLIENT_BASE_URL}`);
  console.log(`  Hearth:    ${HEARTH_BASE_URL}`);
  console.log(`  Realm:     ${REALM_NAME}`);
  console.log(`  IdP name:  ${IDP_NAME}`);
  console.log(`  Sign-in:   ${SIGN_IN_URL}`);
});
