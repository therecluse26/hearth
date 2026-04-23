// End-to-end walkthrough of Hearth's SCIM 2.0 provisioning API.
//
// Assumes Hearth is already running on HTTP 8420 with the adjacent
// `hearth.yaml` — `run.sh` boots it for you. If you run this script
// directly the bootstrap call at the top will fail fast with a hint.
//
// Each scenario exercises one piece of the SCIM surface and prints the
// response so you can see the shape of the wire protocol — what Okta,
// Azure AD, or any other IdP would receive when pointed at this server.

const HTTP = "http://127.0.0.1:8422";

function log(section, msg) {
  process.stdout.write(`\n\x1b[1;36m▸ ${section}\x1b[0m\n${msg}\n`);
}

function ok(msg) {
  process.stdout.write(`  \x1b[1;32m✓\x1b[0m ${msg}\n`);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2)
    .split("\n")
    .map((l) => `    ${l}`)
    .join("\n");
}

// --- 1. Bootstrap an admin token via the dev endpoint. -------------------

async function bootstrap() {
  const r = await fetch(`${HTTP}/admin/bootstrap`, { method: "POST" });
  if (!r.ok) {
    throw new Error(
      `bootstrap failed (${r.status}); is Hearth running with --dev?`,
    );
  }
  return r.json();
}

// --- 2. Shared SCIM fetch helper ----------------------------------------

function buildFetch(realmId, token) {
  return async function scim(method, path, body, opts = {}) {
    const headers = {
      "content-type": "application/scim+json",
      accept: "application/scim+json",
      authorization: `Bearer ${token}`,
      "x-realm-id": realmId,
    };
    const init = { method, headers };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const r = await fetch(`${HTTP}${path}`, init);
    const text = await r.text();
    const json = text.length === 0 ? null : safeJson(text);
    if (!r.ok && !opts.allowError) {
      throw new Error(
        `${method} ${path} -> ${r.status}\n${text}`,
      );
    }
    return {
      status: r.status,
      headers: Object.fromEntries(r.headers.entries()),
      body: json,
    };
  };
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// --- 3. Scenarios --------------------------------------------------------

async function discovery(scim) {
  log("1. Discovery", "GET /scim/v2/ServiceProviderConfig, /Schemas, /ResourceTypes");
  const spc = await scim("GET", "/scim/v2/ServiceProviderConfig");
  ok(`ServiceProviderConfig — patch=${spc.body.patch.supported} filter=${spc.body.filter.supported} bulk=${spc.body.bulk.supported}`);

  const schemas = await scim("GET", "/scim/v2/Schemas");
  const ids = schemas.body.map((s) => s.id).join(", ");
  ok(`Schemas advertised: ${ids}`);

  const rtypes = await scim("GET", "/scim/v2/ResourceTypes");
  const endpoints = rtypes.body.map((r) => `${r.id} @ ${r.endpoint}`).join(", ");
  ok(`ResourceTypes: ${endpoints}`);
}

async function createAlice(scim) {
  log(
    "2. Create a user",
    'POST /scim/v2/Users with externalId "okta-alice"',
  );
  const resp = await scim("POST", "/scim/v2/Users", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: "alice@example.com",
    externalId: "okta-alice",
    name: { givenName: "Alice", familyName: "Example" },
    emails: [{ value: "alice@example.com", primary: true, type: "work" }],
    active: true,
  });
  ok(`status=${resp.status} Location=${resp.headers.location} ETag=${resp.headers.etag}`);
  ok(`resource:\n${pretty(resp.body)}`);
  return resp.body;
}

async function externalIdConflict(scim) {
  log(
    "3. Idempotency guard",
    'POST another user with the same externalId — expect 409 uniqueness',
  );
  const resp = await scim(
    "POST",
    "/scim/v2/Users",
    {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "attacker@example.com",
      externalId: "okta-alice", // duplicate — Alice's
      name: { givenName: "Mal", familyName: "Lory" },
    },
    { allowError: true },
  );
  if (resp.status !== 409) {
    throw new Error(`expected 409 uniqueness, got ${resp.status}`);
  }
  ok(`status=${resp.status} scimType=${resp.body.scimType}`);
  ok(`error envelope:\n${pretty(resp.body)}`);
}

async function createBob(scim) {
  log(
    "4. Create Bob",
    "Second user so filter + pagination have multiple rows",
  );
  const resp = await scim("POST", "/scim/v2/Users", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: "bob@example.com",
    externalId: "okta-bob",
    name: { givenName: "Bob", familyName: "Example" },
    emails: [{ value: "bob@example.com", primary: true }],
    active: true,
  });
  ok(`Bob id=${resp.body.id}`);
  return resp.body;
}

async function filterUsers(scim) {
  log(
    "5. Filter users",
    'GET /scim/v2/Users?filter=userName eq "alice@example.com"',
  );
  const filter = encodeURIComponent('userName eq "alice@example.com"');
  const resp = await scim("GET", `/scim/v2/Users?filter=${filter}`);
  ok(
    `totalResults=${resp.body.totalResults} — ${resp.body.Resources.map((r) => r.userName).join(", ")}`,
  );
}

async function paginate(scim) {
  log("6. Pagination", "GET /scim/v2/Users?startIndex=1&count=1");
  const resp = await scim("GET", "/scim/v2/Users?startIndex=1&count=1");
  ok(
    `totalResults=${resp.body.totalResults} startIndex=${resp.body.startIndex} itemsPerPage=${resp.body.itemsPerPage}`,
  );
}

async function patchDeactivate(scim, alice) {
  log(
    "7. PATCH deactivate",
    'replace /active false — disables Alice without deleting',
  );
  const resp = await scim("PATCH", `/scim/v2/Users/${alice.id}`, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [{ op: "replace", path: "active", value: false }],
  });
  if (resp.body.active !== false) {
    throw new Error(`expected active=false, got ${resp.body.active}`);
  }
  ok(`active=${resp.body.active} meta.version=${resp.body.meta.version}`);
}

async function putReplace(scim, alice) {
  log(
    "8. PUT full replace",
    "rename Alice and re-enable her in one call",
  );
  const resp = await scim("PUT", `/scim/v2/Users/${alice.id}`, {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: "alice@example.com",
    externalId: "okta-alice",
    displayName: "Alice Example (renamed)",
    name: { givenName: "Alice", familyName: "Example" },
    emails: [{ value: "alice@example.com", primary: true }],
    active: true,
  });
  ok(`displayName="${resp.body.displayName}" active=${resp.body.active}`);
}

async function rejectBracketedFilter(scim) {
  log(
    "9. Filter boundary",
    'bracketed path is rejected with invalidFilter — real IdPs don\'t send these',
  );
  const filter = encodeURIComponent('emails[type eq "work"].value eq "x"');
  const resp = await scim(
    "GET",
    `/scim/v2/Users?filter=${filter}`,
    undefined,
    { allowError: true },
  );
  if (resp.status !== 400) {
    throw new Error(`expected 400, got ${resp.status}`);
  }
  ok(`status=${resp.status} scimType=${resp.body.scimType}`);
}

async function createGroup(scim, alice, bob) {
  log(
    "10. Create a group",
    'POST /scim/v2/Groups — maps to a Hearth Organization',
  );
  const resp = await scim("POST", "/scim/v2/Groups", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    displayName: "Engineering",
    externalId: "okta-grp-eng",
    members: [
      { value: alice.id, display: "Alice" },
      { value: bob.id, display: "Bob" },
    ],
  });
  ok(
    `id=${resp.body.id} members=${resp.body.members.length} externalId=${resp.body.externalId}`,
  );
  return resp.body;
}

async function patchGroupMembers(scim, group, bob) {
  log(
    "11. PATCH group members",
    'remove Bob via op=remove, path=members',
  );
  const resp = await scim("PATCH", `/scim/v2/Groups/${group.id}`, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [
      { op: "remove", path: "members", value: [{ value: bob.id }] },
    ],
  });
  ok(
    `members after remove: ${resp.body.members.map((m) => m.value).join(", ") || "(none)"}`,
  );
}

async function deleteAndReprovision(scim, alice) {
  log(
    "12. DELETE + reprovision",
    'deleting Alice frees her externalId for reuse',
  );
  const del = await scim("DELETE", `/scim/v2/Users/${alice.id}`);
  ok(`DELETE status=${del.status}`);

  const resp = await scim("POST", "/scim/v2/Users", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: "alice-returns@example.com",
    externalId: "okta-alice", // cascade freed it — should succeed
    name: { givenName: "Alice", familyName: "Returned" },
  });
  ok(
    `reprovisioned with externalId=${resp.body.externalId} status=${resp.status}`,
  );
}

async function auditTrail(realmId, token) {
  log(
    "13. Audit trail",
    'GET /admin/audit filtered to the new scim_* actions',
  );
  const actions = [
    "scim_user_created",
    "scim_user_updated",
    "scim_user_deleted",
    "scim_group_created",
    "scim_group_updated",
  ];
  const rows = [];
  for (const action of actions) {
    const r = await fetch(
      `${HTTP}/admin/audit?action=${encodeURIComponent(action)}`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-realm-id": realmId,
        },
      },
    );
    if (!r.ok) continue;
    const j = await r.json();
    for (const e of j.events || []) {
      rows.push({
        action: e.action,
        resource: `${e.resource_type}:${e.resource_id.slice(0, 8)}`,
        metadata: e.metadata ?? null,
      });
    }
  }
  if (rows.length === 0) {
    throw new Error("expected at least one scim_* audit event");
  }
  ok(`recorded ${rows.length} SCIM audit events:`);
  for (const row of rows) {
    const ext =
      row.metadata && typeof row.metadata === "object" && row.metadata.external_id
        ? ` external_id=${row.metadata.external_id}`
        : "";
    process.stdout.write(`      ${row.action.padEnd(22)} ${row.resource}${ext}\n`);
  }
}

// --- 4. Main orchestration ----------------------------------------------

async function main() {
  log("Bootstrap", "POST /admin/bootstrap (dev-only) → admin token + realm ID");
  const { realm_id: realmId, access_token: token } = await bootstrap();
  ok(`realm=${realmId}`);
  ok(`token=${token.slice(0, 16)}... (${token.length} chars)`);

  const scim = buildFetch(realmId, token);

  await discovery(scim);
  const alice = await createAlice(scim);
  await externalIdConflict(scim);
  const bob = await createBob(scim);
  await filterUsers(scim);
  await paginate(scim);
  await patchDeactivate(scim, alice);
  await putReplace(scim, alice);
  await rejectBracketedFilter(scim);
  const group = await createGroup(scim, alice, bob);
  await patchGroupMembers(scim, group, bob);
  await deleteAndReprovision(scim, alice);
  await auditTrail(realmId, token);

  process.stdout.write("\n\x1b[1;32m✓ SCIM walkthrough complete.\x1b[0m\n\n");
}

main().catch((err) => {
  process.stderr.write(`\n\x1b[1;31m✖ ${err.stack || err.message}\x1b[0m\n\n`);
  process.exit(1);
});
