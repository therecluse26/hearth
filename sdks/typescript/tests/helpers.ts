import { execSync, spawn, type ChildProcess } from "node:child_process";
import { HearthClient } from "../src/client.js";
import type { BootstrapResponse } from "../src/types.js";

const PROJECT_ROOT = new URL("../../..", import.meta.url).pathname.replace(
  /\/$/,
  "",
);

/** Resolve the hearth binary path, respecting CARGO_TARGET_DIR. */
function hearthBinPath(): string {
  const targetDir = process.env.CARGO_TARGET_DIR ?? `${PROJECT_ROOT}/target`;
  return `${targetDir}/debug/hearth`;
}

/** Build the hearth binary if not already built. */
export function ensureBinary(): void {
  execSync("cargo build", { cwd: PROJECT_ROOT, stdio: "pipe" });
}

/** Find a free port by briefly binding to port 0. */
async function findFreePort(): Promise<number> {
  const net = await import("node:net");
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close();
        reject(new Error("failed to get port"));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
  });
}

export interface TestServer {
  port: number;
  baseUrl: string;
  process: ChildProcess;
  bootstrap: BootstrapResponse;
  client: HearthClient;
}

/** Start a Hearth dev server and bootstrap admin credentials. */
export async function startServer(): Promise<TestServer> {
  const port = await findFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;

  const proc = spawn(hearthBinPath(), ["serve", "--dev", "--port", String(port)], {
    stdio: "pipe",
    env: { ...process.env, RUST_LOG: "warn" },
  });

  // Wait for health endpoint
  const maxWait = 15_000;
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    try {
      const resp = await fetch(`${baseUrl}/health`);
      if (resp.ok) break;
    } catch {
      // Not ready yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  // Verify server is actually up
  const healthResp = await fetch(`${baseUrl}/health`);
  if (!healthResp.ok) {
    proc.kill();
    throw new Error("Hearth server failed to start");
  }

  // Bootstrap admin credentials
  const bootstrap = await HearthClient.bootstrap(baseUrl);
  const client = new HearthClient({
    baseUrl,
    tenantId: bootstrap.tenant_id,
  });

  return { port, baseUrl, process: proc, bootstrap, client };
}

/** Stop a running test server. */
export function stopServer(server: TestServer): void {
  server.process.kill("SIGTERM");
}
