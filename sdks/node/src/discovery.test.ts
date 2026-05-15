import { describe, it, expect, vi, afterEach } from "vitest";
import { DiscoveryClient } from "./discovery.js";
import { DiscoveryError } from "./errors.js";

const ISSUER = "https://auth.example.com";
const DISCOVERY_DOC = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/jwks`,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  introspection_endpoint: `${ISSUER}/introspect`,
};

function mockFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => DISCOVERY_DOC,
    ...response,
  } as Response);
}

describe("DiscoveryClient", () => {
  afterEach(() => vi.restoreAllMocks());

  it("fetches and returns discovery document", async () => {
    mockFetch({});
    const client = new DiscoveryClient(ISSUER, 10_000);
    const doc = await client.discover();
    expect(doc.jwks_uri).toBe(`${ISSUER}/jwks`);
    expect(doc.introspection_endpoint).toBe(`${ISSUER}/introspect`);
  });

  it("caches discovery document on second call (no re-fetch)", async () => {
    const spy = mockFetch({});
    const client = new DiscoveryClient(ISSUER, 10_000);
    await client.discover();
    await client.discover();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("deduplicates concurrent discover() calls", async () => {
    const spy = mockFetch({});
    const client = new DiscoveryClient(ISSUER, 10_000);
    await Promise.all([client.discover(), client.discover(), client.discover()]);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("re-fetches after reset()", async () => {
    const spy = mockFetch({});
    const client = new DiscoveryClient(ISSUER, 10_000);
    await client.discover();
    client.reset();
    await client.discover();
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("throws DiscoveryError on non-OK response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: false, status: 500 } as Response);
    const client = new DiscoveryClient(ISSUER, 10_000);
    await expect(client.discover()).rejects.toBeInstanceOf(DiscoveryError);
  });

  it("throws DiscoveryError on network failure", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    const client = new DiscoveryClient(ISSUER, 10_000);
    await expect(client.discover()).rejects.toBeInstanceOf(DiscoveryError);
  });

  it("throws DiscoveryError when jwks_uri is missing from document", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ issuer: ISSUER }),
    } as Response);
    const client = new DiscoveryClient(ISSUER, 10_000);
    await expect(client.discover()).rejects.toBeInstanceOf(DiscoveryError);
  });

  it("throws DiscoveryError on invalid JSON response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => { throw new Error("invalid json"); },
    } as Response);
    const client = new DiscoveryClient(ISSUER, 10_000);
    await expect(client.discover()).rejects.toBeInstanceOf(DiscoveryError);
  });
});
