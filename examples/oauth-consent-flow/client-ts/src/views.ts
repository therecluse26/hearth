/**
 * Tiny HTML string templates for the demo client. No framework — the
 * point of this example is the OAuth flow, not the UI.
 */

const BASE_STYLES = `
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
      background: #0c0a09;
      color: #f5f1e8;
      margin: 0;
      padding: 40px 20px;
      min-height: 100vh;
    }
    main { max-width: 720px; margin: 0 auto; }
    h1 { font-weight: 500; margin-bottom: 8px; }
    h2 { font-weight: 500; margin-top: 32px; font-size: 1.15rem; }
    p, li { color: #c9c0b0; line-height: 1.55; }
    code { font-family: "JetBrains Mono", ui-monospace, monospace;
           background: #1c1917; padding: 2px 6px; border-radius: 4px;
           font-size: 0.92em; }
    pre { background: #1c1917; padding: 16px; border-radius: 8px;
          overflow-x: auto; font-size: 0.88rem;
          border: 1px solid #292524; }
    .card { background: #1c1917; border: 1px solid #292524;
            border-radius: 12px; padding: 24px; margin: 16px 0; }
    .btn { display: inline-block; background: linear-gradient(135deg,
             #ff6b35 0%, #ff8f5e 100%);
           color: #0c0a09; padding: 10px 20px; border-radius: 8px;
           text-decoration: none; font-weight: 600; font-size: 0.95rem;
           border: none; cursor: pointer; margin: 4px 6px 4px 0; }
    .btn.secondary { background: transparent; color: #f5f1e8;
                     border: 1px solid #44403c; font-weight: 500; }
    .btn.danger { background: transparent; color: #ef4444;
                  border: 1px solid #3f1d1d; }
    .tag { display: inline-block; font-family: "JetBrains Mono",
           monospace; font-size: 0.78rem; padding: 2px 8px; border-radius:
           999px; background: #292524; color: #c9c0b0; margin-left: 6px; }
    .tag.trusted { background: #0f3f2e; color: #6ee7b7; }
    .err { background: #2a0f0f; border: 1px solid #7f1d1d; color: #fca5a5;
           padding: 14px; border-radius: 8px; margin: 16px 0; }
    .muted { color: #78716c; font-size: 0.88rem; }
    a { color: #ff8f5e; }
  </style>
`;

const layout = (title: string, body: string): string => `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>${escapeHtml(title)}</title>${BASE_STYLES}</head>
<body><main>${body}</main></body></html>`;

/** Landing page — three buttons demonstrating the three scenarios. */
export function renderIndex(args: {
  thirdPartyClientId: string;
  firstPartyClientId: string;
}): string {
  return layout(
    "Hearth OAuth Consent Demo",
    `
    <h1>Hearth OAuth Consent Flow</h1>
    <p>Three buttons, three scenarios. Start here.</p>

    <div class="card">
      <h2>1. Third-party app <span class="tag">require_consent: true</span></h2>
      <p>First click: you'll be redirected to Hearth, sign in, and see a
         consent screen with per-scope checkboxes. Uncheck any scope to
         see partial approval in action.</p>
      <a class="btn" href="/login/third-party-app">Sign in with Third-Party Analytics</a>
      <p class="muted">Client ID: <code>${escapeHtml(args.thirdPartyClientId)}</code></p>
    </div>

    <div class="card">
      <h2>2. First-party SSO <span class="tag trusted">require_consent: false</span></h2>
      <p>Trusted clients skip the consent prompt entirely — useful for
         first-party apps where user consent is implicit.</p>
      <a class="btn" href="/login/first-party-sso">Sign in with Internal SSO</a>
      <p class="muted">Client ID: <code>${escapeHtml(args.firstPartyClientId)}</code></p>
    </div>

    <div class="card">
      <h2>3. Force re-prompt <span class="tag">prompt=consent</span></h2>
      <p>Sends <code>prompt=consent</code> on the authorize request, which
         forces the consent screen to reappear even when a prior record
         covers every requested scope. Per OIDC Core §3.1.2.1.</p>
      <a class="btn secondary" href="/login/third-party-app?prompt=consent">Force re-prompt for Third-Party Analytics</a>
    </div>

    <p class="muted" style="margin-top:32px">
      See <a href="../README.md">the walkthrough README</a> for what to
      expect at each step. Audit log: <code>http://localhost:8420/ui/admin/audit</code> ·
      Admin consents: <code>http://localhost:8420/ui/admin/users/&lt;uid&gt;/consents?realm=demo</code>
    </p>
  `,
  );
}

/** Signed-in page — shows ID token claims, /userinfo, and revoke. */
export function renderSignedIn(args: {
  appKey: string;
  clientName: string;
  idTokenClaims: Record<string, unknown>;
  userinfo: Record<string, unknown>;
  accessTokenPreview: string;
}): string {
  return layout(
    `Signed in via ${args.clientName}`,
    `
    <h1>Signed in via ${escapeHtml(args.clientName)}</h1>
    <p class="muted">App: <code>${escapeHtml(args.appKey)}</code></p>

    <div class="card">
      <h2>ID token claims (decoded)</h2>
      <pre>${escapeHtml(JSON.stringify(args.idTokenClaims, null, 2))}</pre>
    </div>

    <div class="card">
      <h2>/userinfo response</h2>
      <p class="muted">Filtered by the scopes you actually approved — if
      you unchecked <code>email</code>, the <code>email</code> and
      <code>email_verified</code> claims will be missing here.</p>
      <pre>${escapeHtml(JSON.stringify(args.userinfo, null, 2))}</pre>
    </div>

    <div class="card">
      <h2>Access token</h2>
      <pre>${escapeHtml(args.accessTokenPreview)}</pre>
    </div>

    <form action="/revoke" method="post" style="display:inline">
      <button type="submit" class="btn danger">Revoke my consent for this app</button>
    </form>
    <a class="btn secondary" href="/">Back to home</a>
    <p class="muted" style="margin-top:20px">
      After revoking, click the third-party button again on the home page
      — the consent screen reappears, proving the revocation took effect.
    </p>
  `,
  );
}

/** Error page. */
export function renderError(args: {
  title: string;
  detail: string;
}): string {
  return layout(
    args.title,
    `
    <h1>${escapeHtml(args.title)}</h1>
    <div class="err"><pre style="background:transparent;border:0;padding:0;">${escapeHtml(args.detail)}</pre></div>
    <a class="btn secondary" href="/">Back to home</a>
  `,
  );
}

/**
 * Escapes HTML entities. Values rendered from Hearth (client names, claim
 * strings) are treated as untrusted — we're a demo app, but we don't want
 * to model bad habits.
 */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
