// End-to-end walkthrough of Hearth's gRPC management API.
//
// Assumes Hearth is already running on HTTP 8420 + gRPC 9420 with the
// adjacent `hearth.yaml` — `run.sh` boots it for you. If you run this
// script directly the checks at the top will fail fast with a hint.

import { loadPackageDefinition, credentials, Metadata } from "@grpc/grpc-js";
import { loadSync } from "@grpc/proto-loader";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROTO_DIR = resolve(HERE, "../../proto");
const HTTP = "http://127.0.0.1:8420";
const GRPC = "127.0.0.1:9420";

function log(section, msg) {
  process.stdout.write(`\n\x1b[1;36m▸ ${section}\x1b[0m\n${msg}\n`);
}

function promisify(fn) {
  return (...args) =>
    new Promise((res, rej) => {
      fn(...args, (err, val) => (err ? rej(err) : res(val)));
    });
}

// --- 1. Mint an admin token via the HTTP bootstrap endpoint. ------------

async function bootstrap() {
  const r = await fetch(`${HTTP}/admin/bootstrap`, { method: "POST" });
  if (!r.ok) {
    throw new Error(
      `bootstrap failed (${r.status}); is Hearth running with --dev?`,
    );
  }
  return r.json();
}

// --- 2. Load proto definitions once and instantiate clients. ------------

function loadProtos() {
  const opts = {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_DIR],
  };
  const pkg = loadPackageDefinition(
    loadSync(
      [
        "hearth/identity/v1/identity.proto",
        "hearth/identity/v1/oauth.proto",
        "hearth/authz/v1/authz.proto",
        "hearth/events/v1/audit.proto",
      ],
      opts,
    ),
  );
  return pkg.hearth;
}

function adminMeta(realmId, token) {
  const md = new Metadata();
  md.add("authorization", `Bearer ${token}`);
  md.add("x-realm-id", realmId);
  return md;
}

// --- 3. Health + reflection don't need the proto files. -----------------

async function checkHealth() {
  // Minimal inline proto for grpc.health.v1
  const healthPkg = loadPackageDefinition(
    loadSync("health.proto", {
      keepCase: true,
      enums: String,
      includeDirs: [HERE],
    }),
  ).grpc.health.v1;
  const client = new healthPkg.Health(GRPC, credentials.createInsecure());
  const resp = await promisify(client.check.bind(client))({ service: "" });
  return resp.status;
}

async function listServices() {
  const reflectPkg = loadPackageDefinition(
    loadSync("reflection.proto", {
      keepCase: true,
      includeDirs: [HERE],
    }),
  ).grpc.reflection.v1;
  const client = new reflectPkg.ServerReflection(
    GRPC,
    credentials.createInsecure(),
  );
  return new Promise((res, rej) => {
    const stream = client.ServerReflectionInfo();
    const names = [];
    stream.on("data", (msg) => {
      if (msg.list_services_response) {
        for (const s of msg.list_services_response.service) names.push(s.name);
      }
    });
    stream.on("error", rej);
    stream.on("end", () => res(names));
    stream.write({ list_services: "" });
    stream.end();
  });
}

// --- 4. The main walkthrough. -------------------------------------------

async function main() {
  log("bootstrap", "Minting an admin access token via HTTP /admin/bootstrap");
  const boot = await bootstrap();
  console.log(`  realm_id    = ${boot.realm_id}`);
  console.log(`  user_id     = ${boot.user_id}`);
  console.log(`  access_token= ${boot.access_token.slice(0, 48)}…`);

  log("health", "Calling grpc.health.v1.Health/Check");
  console.log(`  status = ${await checkHealth()}`);

  log(
    "reflection",
    "Calling grpc.reflection.v1.ServerReflection/ListServices",
  );
  const services = await listServices();
  for (const s of services.sort()) console.log(`  • ${s}`);

  const proto = loadProtos();
  const meta = adminMeta(boot.realm_id, boot.access_token);

  // --- IdentityAdminService ---
  log("users", "Creating two users via IdentityAdminService/CreateUser");
  const users = new proto.identity.v1.IdentityAdminService(
    GRPC,
    credentials.createInsecure(),
  );
  const create = promisify(users.CreateUser.bind(users));
  const alice = await create(
    { email: "alice@demo.io", display_name: "Alice" },
    meta,
  );
  const bob = await create(
    { email: "bob@demo.io", display_name: "Bob" },
    meta,
  );
  console.log(`  created alice.id = ${alice.id}`);
  console.log(`  created bob.id   = ${bob.id}`);

  log("users", "Listing users via IdentityAdminService/ListUsers");
  const listUsers = promisify(users.ListUsers.bind(users));
  const page = await listUsers({ limit: 20 }, meta);
  for (const u of page.items) console.log(`  • ${u.email} (${u.status})`);

  // --- AuthorizationService (Watch streaming) ---
  log(
    "watch",
    "Subscribing to AuthorizationService/Watch, then writing a tuple",
  );
  const azClient = new proto.authz.v1.AuthorizationService(
    GRPC,
    credentials.createInsecure(),
  );
  const stream = azClient.Watch({}, meta);
  const firstEvent = new Promise((res, rej) => {
    stream.on("data", (msg) => {
      res(msg);
      stream.cancel();
    });
    stream.on("error", (e) => {
      // cancel() triggers a CANCELLED error — not a test failure.
      if (e.code !== 1) rej(e);
    });
  });

  // Give the subscription a moment to register before writing.
  await new Promise((r) => setTimeout(r, 150));

  const write = promisify(azClient.WriteTuples.bind(azClient));
  const tuple = {
    object: { object_type: "group", object_id: "eng" },
    relation: "member",
    subject: {
      direct: { object_type: "user", object_id: alice.id },
    },
  };
  const writeResp = await write(
    { writes: [{ operation: "TUPLE_WRITE_OPERATION_TOUCH", tuple }] },
    meta,
  );
  console.log(`  wrote tuple; consistency_token=${writeResp.token.version}`);

  const evt = await firstEvent;
  console.log(`  received live event:`);
  console.log(
    `    ${evt.event.object_type}:${evt.event.object_id}#${evt.event.relation}@${evt.event.subject}`,
  );
  console.log(`    action=${evt.event.action} seq=${evt.token.version}`);

  // --- Check that the tuple we just wrote takes effect ---
  log("check", "Calling AuthorizationService/Check");
  const check = promisify(azClient.Check.bind(azClient));
  const allowed = await check(
    {
      object: { object_type: "group", object_id: "eng" },
      relation: "member",
      subject: {
        direct: { object_type: "user", object_id: alice.id },
      },
    },
    meta,
  );
  console.log(`  alice ∈ group:eng#member → ${allowed.allowed}`);

  // --- AuditService ---
  log("audit", "Calling AuditService/ListEvents");
  const audit = new proto.events.v1.AuditService(
    GRPC,
    credentials.createInsecure(),
  );
  const listEvents = promisify(audit.ListEvents.bind(audit));
  const events = await listEvents({ limit: 10 }, meta);
  console.log(`  ${events.events.length} event(s) in this realm`);
  // Note: The admin CRUD RPCs above don't emit audit events (audit is
  // driven by the admin UI / engine methods that explicitly call
  // `audit.append`, not the gRPC handlers themselves). VerifyIntegrity
  // over an empty chain still returns `ok=true`.
  for (const e of events.events.slice(-5)) {
    console.log(`  • ${e.action}  ${e.resource_type}:${e.resource_id}`);
  }

  log("verify", "Calling AuditService/VerifyIntegrity");
  const verify = promisify(audit.VerifyIntegrity.bind(audit));
  const v = await verify({}, meta);
  console.log(`  ok=${v.ok}  event_count=${v.event_count}`);

  log("done", "All gRPC calls succeeded. Shutting down.");
}

main()
  .catch((e) => {
    console.error("\n\x1b[1;31m✖ demo failed:\x1b[0m", e.message || e);
    process.exit(1);
  })
  .finally(() => setTimeout(() => process.exit(0), 100));
