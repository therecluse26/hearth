/**
 * Tiny HTML view helpers for the federation-flow client.
 *
 * Not a template engine — the demo has two pages, both small enough
 * that tagged template literals keep the code readable. Output is
 * HTML-escape-free on inputs we don't trust; see the `esc` helper.
 */

const esc = (s: string | undefined): string =>
  (s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

function layout(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${esc(title)}</title>
  <style>
    :root { color-scheme: dark; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f0f12;
      color: #f5f1e8;
      max-width: 640px;
      margin: 3rem auto;
      padding: 0 1.5rem;
      line-height: 1.5;
    }
    h1 { font-weight: 500; letter-spacing: -0.01em; }
    .card {
      background: #17171c;
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 10px;
      padding: 1.5rem;
      margin: 1.25rem 0;
    }
    a.button, button {
      display: inline-block;
      background: linear-gradient(135deg, #ff6b35, #f59f00);
      color: #0f0f12;
      padding: 0.625rem 1.25rem;
      border-radius: 8px;
      border: 0;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    a.secondary {
      background: transparent;
      color: #f5f1e8;
      border: 1px solid rgba(255,255,255,0.12);
    }
    pre {
      background: #0b0b0e;
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      font-size: 0.85rem;
      color: #c8c3b6;
    }
    .muted { color: #7a756a; font-size: 0.85rem; }
  </style>
</head>
<body>${body}</body>
</html>`;
}

export function renderIndex(args: {
  signInUrl: string;
  signedIn: boolean;
  hearthAccountUrl: string;
}): string {
  const card = args.signedIn
    ? `
      <div class="card">
        <h1>Signed in via Hearth</h1>
        <p>
          This app has established a local session (cookie
          <code>fed_demo_session</code> on <code>localhost:3000</code>).
          Hearth has a separate session cookie on
          <code>localhost:8420</code> that the browser correctly keeps
          isolated from this origin.
        </p>
        <p>
          <a class="button" href="/me">Continue to profile</a>
          <a class="secondary button" href="${esc(args.hearthAccountUrl)}" target="_blank" rel="noopener">Open Hearth account</a>
          <a class="secondary button" href="/signout">Sign out</a>
        </p>
        <p class="muted">
          Clicking "Sign in" again would silently re-authenticate you
          off the still-live Hearth session; that's why the button is
          hidden while you're signed in.
        </p>
      </div>`
    : `
      <div class="card">
        <h1>Hearth federation demo</h1>
        <p>
          This app is backed by Hearth. Click below to sign in via the
          local upstream OIDC provider — you'll be sent through
          Hearth → upstream IdP → back to Hearth → back here.
        </p>
        <p><a class="button" href="${esc(args.signInUrl)}">Sign in</a></p>
        <p class="muted">
          Hearth runs at http://localhost:8420 · upstream IdP at http://localhost:9090 · this app at http://localhost:3000
        </p>
      </div>`;
  return layout("Hearth federation demo", card);
}

export function renderProfile(args: {
  hearthAccountUrl: string;
  linkedAccountsUrl: string;
}): string {
  return layout(
    "Signed in",
    `
      <div class="card">
        <h1>You're signed in</h1>
        <p>
          Authentication was completed through Hearth. This demo client
          intentionally shows no user details here — profile data lives
          on Hearth, and a real integration would call <code>/userinfo</code>
          with the access token Hearth issued on callback.
        </p>
        <p class="muted">
          Cookies are origin-scoped: Hearth's <code>hearth_ui_session</code>
          lives on <code>localhost:8420</code>, this app's
          <code>fed_demo_session</code> lives on <code>localhost:3000</code>.
          That isolation is correct — a cross-origin cookie would be
          a security hole.
        </p>
        <p>
          <a class="button" href="${esc(args.hearthAccountUrl)}" target="_blank" rel="noopener">View profile in Hearth</a>
          <a class="secondary button" href="${esc(args.linkedAccountsUrl)}" target="_blank" rel="noopener">Linked accounts</a>
          <a class="secondary button" href="/signout">Sign out</a>
        </p>
      </div>`,
  );
}
