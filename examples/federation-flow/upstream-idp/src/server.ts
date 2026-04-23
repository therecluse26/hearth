/**
 * Local OIDC upstream provider for the Hearth federation demo.
 *
 * Built on `node-oidc-provider` — the same library used under the hood by
 * several commercial IdPs. We configure it with two hardcoded accounts
 * and register Hearth as a confidential OIDC client. The provider serves
 * standard endpoints at http://localhost:9090/*:
 *
 *   /.well-known/openid-configuration — OIDC Discovery
 *   /jwks                             — RSA signing key (generated on startup)
 *   /auth                             — authorization endpoint (built-in login UI)
 *   /token                            — token exchange
 *   /me                               — userinfo
 *
 * # Not production
 *
 * Keys are in-memory and regenerated on every restart. The accounts are
 * static, the passwords are "demo", and consent is auto-approved. Do
 * not copy this file into anything that handles real users.
 */

// oidc-provider 8.x ships its types via a companion package; to keep
// this demo zero-ceremony we import with implicit `any` and rely on
// the library's runtime validation.
// @ts-expect-error — no TypeScript declarations published
import Provider from "oidc-provider";

const ISSUER = "http://localhost:9090";
const PORT = 9090;

// --- Fake user store --------------------------------------------------------

interface DemoUser {
  id: string;
  email: string;
  name: string;
  email_verified: boolean;
  // Plaintext password is fine here — this whole process is an offline
  // demo. Production uses real IdPs.
  password: string;
}

const users: Record<string, DemoUser> = {
  "alice-ext-id": {
    id: "alice-ext-id",
    email: "alice@example.com",
    name: "Alice Example",
    email_verified: true,
    password: "demo",
  },
  "bob-ext-id": {
    id: "bob-ext-id",
    email: "bob@example.com",
    name: "Bob Example",
    email_verified: true,
    password: "demo",
  },
};

// --- oidc-provider Account adapter ------------------------------------------

function findAccountById(accountId: string): object | undefined {
  const user = users[accountId];
  if (!user) return undefined;
  return {
    accountId: user.id,
    // Called when the ID token / userinfo is built. Scopes selects the
    // claim subset the caller is allowed to see.
    async claims(_use: string, _scope: string) {
      return {
        sub: user.id,
        email: user.email,
        email_verified: user.email_verified,
        name: user.name,
      };
    },
  };
}

// --- oidc-provider configuration --------------------------------------------

const configuration = {
  // The single OIDC client — Hearth, with the demo redirect URI.
  clients: [
    {
      client_id: "hearth-demo",
      client_secret: "demo-secret-do-not-use-in-production",
      redirect_uris: ["http://localhost:8420/ui/federation/callback"],
      // Standard authorization code flow with RS256-signed ID tokens.
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    },
  ],

  // Plug the account resolver into oidc-provider's login pipeline.
  findAccount: async (_ctx: unknown, id: string) => findAccountById(id),

  // Include email + email_verified + name so Hearth's claim-extraction
  // sees them on every login.
  claims: {
    openid: ["sub"],
    email: ["email", "email_verified"],
    profile: ["name"],
  },

  // RS256 is what Hearth verifies. oidc-provider defaults to RS256 if
  // you don't list algorithms — listed here for documentation.
  idTokenSigningAlgValues: ["RS256"],

  // Dev-friendly policy: skip the consent screen entirely so the demo
  // focuses on Hearth's linking behavior, not oidc-provider's UI.
  features: {
    devInteractions: { enabled: true },
  },
};

// --- Boot -------------------------------------------------------------------

const oidc = new Provider(ISSUER, configuration);
oidc.proxy = true;

const app = oidc.app;

app.listen(PORT, () => {
  console.log(`Local OIDC upstream listening on ${ISSUER}`);
  console.log(`  Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`  Accounts:  alice-ext-id (alice@example.com), bob-ext-id (bob@example.com)`);
  console.log(`  Password:  demo`);
  console.log();
  console.log(`Hearth should be reachable at http://localhost:8420`);
  console.log(`with the demo realm configured via examples/federation-flow/hearth.yaml.`);
});
