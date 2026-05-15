import { describe, it, expect, vi, afterEach } from "vitest";
import { IntrospectionClient } from "./introspect.js";
import { IntrospectionError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import type { OidcDiscovery } from "./discovery.js";

const CONFIG: ResolvedConfig = {
  issuer_url: "https://auth.example.com",
  client_id: "client1",
  client_secret: "secret1",
  audience: [],
  jwks_ttl: 300_000,
  introspection_endpoint: "https://auth.example.com/introspect",
  http_timeout: 10_000,
  clock_skew_seconds: 60,
};

const DISCOVERY: OidcDiscovery = {
  issuer: "https://auth.example.com",
  jwks_uri: "https://auth.example.com/jwks",
  introspection_endpoint: "https://auth.example.com/introspect",
};

function makeClient(overrides: Partial<ResolvedConfig> = {}): IntrospectionClient {
  return new IntrospectionClient(
    { ...CONFIG, ...overrides },
    async () => DISCOVERY,
  );
}

describe("IntrospectionClient", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns active IntrospectionResult with all required fields", async () => {
    const raw = {
      active: true,
      sub: "user123",
      iss: "https://auth.example.com",
      aud: ["api.example.com"],
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      scope: "openid profile",
      custom_field: "value",
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => raw,
    } as Response);

    const result = await makeClient().introspect("token123");
    expect(result.active).toBe(true);
    expect(result.sub).toBe("user123");
    expect(result.iss).toBe("https://auth.example.com");
    expect(result.aud).toEqual(["api.example.com"]);
    expect(result.exp).toBe(1_700_003_600);
    expect(result.iat).toBe(1_700_000_000);
    expect(result.scope).toBe("openid profile");
    expect(result.extra.custom_field).toBe("value");
  });

  it("returns inactive result when active=false", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ active: false }),
    } as Response);
    const result = await makeClient().introspect("dead-token");
    expect(result.active).toBe(false);
    expect(result.sub).toBeUndefined();
  });

  it("uses configured introspection_endpoint without discovery", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ active: true }),
    } as Response);
    await makeClient().introspect("tok");
    expect(spy).toHaveBeenCalledWith(
      "https://auth.example.com/introspect",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("discovers introspection endpoint when not configured", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ active: true }),
    } as Response);
    const client = new IntrospectionClient(
      { ...CONFIG, introspection_endpoint: null },
      async () => DISCOVERY,
    );
    await client.introspect("tok");
    expect(spy.mock.calls[0][0]).toBe("https://auth.example.com/introspect");
  });

  it("throws IntrospectionError on non-OK HTTP response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 401,
    } as Response);
    await expect(makeClient().introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError on network failure", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    await expect(makeClient().introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError on invalid JSON response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => { throw new Error("bad json"); },
    } as Response);
    await expect(makeClient().introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError when endpoint missing from discovery", async () => {
    const client = new IntrospectionClient(
      { ...CONFIG, introspection_endpoint: null },
      async () => ({ issuer: "https://auth.example.com", jwks_uri: "https://auth.example.com/jwks" }),
    );
    await expect(client.introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("passes token_type_hint when provided", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ active: true }),
    } as Response);
    await makeClient().introspect("tok", "refresh_token");
    const body = spy.mock.calls[0][1]?.body;
    expect(String(body)).toContain("token_type_hint=refresh_token");
  });
});
