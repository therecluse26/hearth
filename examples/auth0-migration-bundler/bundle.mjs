#!/usr/bin/env node
// Auth0 → Hearth migration bundler.
//
// Calls the Auth0 Management API to assemble a single bundle JSON in the
// shape Hearth's `hearth migrate auth0` subcommand expects. The output
// goes to stdout so you can pipe it or redirect it:
//
//   node bundle.mjs > tenant.json
//   hearth migrate auth0 --file tenant.json --data-dir ./data
//
// Progress messages go to stderr so they don't contaminate the JSON.
//
// Required env vars:
//   AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET
//
// Optional env vars:
//   AUTH0_TENANT_ID   — a UUID to use as the Hearth realm id
//                       (otherwise Hearth generates one).
//   INCLUDE_SECRETS=1 — attach `client_secret` fields (requires the
//                       `read:client_keys` Management API scope on the
//                       M2M app).

import { ManagementClient } from "auth0";

const {
  AUTH0_DOMAIN,
  AUTH0_CLIENT_ID,
  AUTH0_CLIENT_SECRET,
  AUTH0_TENANT_ID,
  INCLUDE_SECRETS,
} = process.env;

function fail(msg) {
  process.stderr.write(`auth0-migration-bundler: ${msg}\n`);
  process.exit(1);
}

if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
  fail("AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET must be set");
}

const includeSecrets = INCLUDE_SECRETS === "1";

function log(msg) {
  process.stderr.write(`[bundler] ${msg}\n`);
}

const mgmt = new ManagementClient({
  domain: AUTH0_DOMAIN,
  clientId: AUTH0_CLIENT_ID,
  clientSecret: AUTH0_CLIENT_SECRET,
});

// ----- Helpers -----

async function paginate(fn, { perPage = 100, max = Infinity } = {}) {
  const all = [];
  let page = 0;
  // Auth0's SDK v4 returns `{ data: [...], ... }`. Pre-v4 returned bare arrays.
  // Handle both shapes.
  while (all.length < max) {
    const resp = await fn({ page, per_page: perPage, include_totals: false });
    const batch = Array.isArray(resp) ? resp : resp?.data;
    if (!Array.isArray(batch)) {
      throw new Error(
        `unexpected response shape from Management API (page=${page})`
      );
    }
    if (batch.length === 0) break;
    all.push(...batch);
    if (batch.length < perPage) break;
    page += 1;
  }
  return all;
}

// ----- 1. Users (bulk export via job) -----

async function fetchUsers() {
  log("fetching users (bulk export job)");
  // The bulk-export endpoint is preferred because it returns a single
  // NDJSON file instead of requiring per-page paging, but it is an
  // async job that must be polled. For simplicity (and to avoid tying
  // this example to an S3 bucket), we use the synchronous per-page
  // /users endpoint. For tenants with >10k users, adapt this to use
  // /jobs/users-exports — see
  // https://auth0.com/docs/manage-users/user-migration/bulk-user-exports.
  const users = await paginate((q) => mgmt.users.getAll(q));
  log(`  got ${users.length} users`);

  // Auth0 returns identities[] separately; password hashes are not in the
  // normal `/users` response. If the tenant was configured to export
  // hashes (via support + "Import Users With Hashes" on the connection),
  // the hashes appear under `identities[0].profileData.custom_password_hash`
  // for some configurations. We surface whatever is present.
  return users.map((u) => {
    const out = {
      user_id: u.user_id,
      email: u.email,
      email_verified: !!u.email_verified,
      blocked: !!u.blocked,
      given_name: u.given_name,
      family_name: u.family_name,
      name: u.name,
      nickname: u.nickname,
      created_at: u.created_at,
    };
    const hash = extractPasswordHash(u);
    if (hash) out.custom_password_hash = hash;
    return out;
  });
}

function extractPasswordHash(u) {
  // Direct field (some tenant configurations).
  if (u.custom_password_hash) return u.custom_password_hash;
  // Nested under the primary identity's profile data.
  const primary = (u.identities || []).find((i) => i.isSocial === false);
  const pd = primary?.profileData;
  if (pd?.custom_password_hash) return pd.custom_password_hash;
  return null;
}

// ----- 2. Clients -----

async function fetchClients() {
  log("fetching clients");
  const clients = await paginate((q) => mgmt.clients.getAll(q));
  log(`  got ${clients.length} clients`);
  return clients.map((c) => {
    const out = {
      client_id: c.client_id,
      name: c.name,
      callbacks: c.callbacks || [],
      grant_types: c.grant_types || [],
      app_type: c.app_type,
    };
    if (includeSecrets && c.client_secret) {
      out.client_secret = c.client_secret;
    }
    return out;
  });
}

// ----- 3. Organizations + members -----

async function fetchOrganizations() {
  log("fetching organizations");
  const orgs = await paginate((q) => mgmt.organizations.getAll(q));
  log(`  got ${orgs.length} organizations`);
  const enriched = [];
  for (const o of orgs) {
    const members = await fetchOrgMembers(o.id);
    enriched.push({
      id: o.id,
      name: o.name,
      display_name: o.display_name,
      members,
    });
  }
  return enriched;
}

async function fetchOrgMembers(orgId) {
  const members = await paginate((q) =>
    mgmt.organizations.getMembers({ id: orgId, ...q })
  );
  const enriched = [];
  for (const m of members) {
    const roles = await paginate((q) =>
      mgmt.organizations.getMemberRoles({ id: orgId, user_id: m.user_id, ...q })
    );
    enriched.push({
      user_id: m.user_id,
      roles: roles.map((r) => r.name),
    });
  }
  return enriched;
}

// ----- 4. Roles + assignments -----

async function fetchRoles() {
  log("fetching roles");
  const roles = await paginate((q) => mgmt.roles.getAll(q));
  log(`  got ${roles.length} roles`);
  const enriched = [];
  for (const r of roles) {
    const assignments = await paginate((q) =>
      mgmt.roles.getUsers({ id: r.id, ...q })
    );
    enriched.push({
      id: r.id,
      name: r.name,
      description: r.description,
      assignments: assignments.map((u) => u.user_id),
    });
  }
  return enriched;
}

// ----- Main -----

const bundle = {
  tenant: {
    name: AUTH0_DOMAIN.split(".")[0],
    ...(AUTH0_TENANT_ID ? { id: AUTH0_TENANT_ID } : {}),
  },
  users: await fetchUsers(),
  clients: await fetchClients(),
  organizations: await fetchOrganizations(),
  roles: await fetchRoles(),
};

log("writing bundle JSON to stdout");
process.stdout.write(JSON.stringify(bundle, null, 2));
process.stdout.write("\n");
