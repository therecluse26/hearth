import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AuthzCache, HearthClient, type CapabilityBundle } from "../src/index.js";

/**
 * Queues stub responses for `globalThis.fetch`. Each call to the fetch
 * mock pops the next scripted response.
 */
function mockFetch(responses: CapabilityBundle[]): () => number {
  let callCount = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      const body = responses.shift();
      if (!body) throw new Error("no more scripted responses");
      callCount += 1;
      return {
        ok: true,
        json: async () => body,
      } as unknown as Response;
    }),
  );
  return () => callCount;
}

describe("AuthzCache", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function makeClient() {
    return new HearthClient({
      baseUrl: "http://localhost:9999",
      realmId: "00000000-0000-0000-0000-000000000001",
    });
  }

  test("caches a fetched bundle and returns it on subsequent reads", async () => {
    const callCount = mockFetch([
      {
        capabilities: { "org:acme#member": true },
        token: 5,
      },
    ]);
    const cache = new AuthzCache(makeClient(), () => "tok");

    const first = await cache.capabilities("org.settings", { org_id: "acme" });
    expect(first.capabilities["org:acme#member"]).toBe(true);

    const second = await cache.capabilities("org.settings", { org_id: "acme" });
    expect(second).toEqual(first);
    expect(callCount()).toBe(1); // served from cache
  });

  test("recordWrite raises the floor and forces refetch", async () => {
    const callCount = mockFetch([
      { capabilities: { "org:acme#member": true }, token: 5 },
      { capabilities: { "org:acme#member": false }, token: 10 },
    ]);
    const cache = new AuthzCache(makeClient(), () => "tok");

    const first = await cache.capabilities("org.settings", { org_id: "acme" });
    expect(first.capabilities["org:acme#member"]).toBe(true);

    // A mutation surfaces a newer zookie — future reads must refetch.
    cache.recordWrite(10);
    const second = await cache.capabilities("org.settings", { org_id: "acme" });
    expect(second.capabilities["org:acme#member"]).toBe(false);
    expect(callCount()).toBe(2);
  });

  test("recordWrite is monotonic: older zookie does not lower the floor", () => {
    const cache = new AuthzCache(makeClient(), () => "tok");
    cache.recordWrite(7);
    cache.recordWrite(3);
    expect(cache.currentFloor).toBe(7);
  });

  test("param changes produce distinct cache keys", async () => {
    const callCount = mockFetch([
      { capabilities: { "org:a#member": true }, token: 1 },
      { capabilities: { "org:b#member": true }, token: 1 },
    ]);
    const cache = new AuthzCache(makeClient(), () => "tok");

    await cache.capabilities("org.settings", { org_id: "a" });
    await cache.capabilities("org.settings", { org_id: "b" });
    expect(callCount()).toBe(2);
  });

  test("invalidate(page) drops cached entries for that page", async () => {
    const callCount = mockFetch([
      { capabilities: { "org:acme#member": true }, token: 1 },
      { capabilities: { "org:acme#member": true }, token: 1 },
    ]);
    const cache = new AuthzCache(makeClient(), () => "tok");

    await cache.capabilities("org.settings", { org_id: "acme" });
    cache.invalidate("org.settings");
    await cache.capabilities("org.settings", { org_id: "acme" });
    expect(callCount()).toBe(2);
  });
});
