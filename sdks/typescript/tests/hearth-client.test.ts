import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HearthClient } from "../src/hearth-client.js";
import { ConfigurationError, DiscoveryError } from "../src/errors.js";

const DISCOVERY_DOC = {
  issuer: "https://auth.example.com",
  jwks_uri: "https://auth.example.com/jwks",
  introspection_endpoint: "https://auth.example.com/introspect",
};

describe("HearthClient — construction", () => {
  it("throws ConfigurationError when issuerUrl is absent", () => {
    expect(
      () => new HearthClient({ issuerUrl: "" }),
    ).toThrow(ConfigurationError);
  });

  it("throws ConfigurationError when issuerUrl is not a valid URL", () => {
    expect(
      () => new HearthClient({ issuerUrl: "not-a-url" }),
    ).toThrow(ConfigurationError);
  });

  it("normalises a trailing slash on issuerUrl", () => {
    const client = new HearthClient({ issuerUrl: "https://auth.example.com/" });
    expect(client.issuerUrl).toBe("https://auth.example.com");
  });

  it("defaults httpTimeout to 10 000 ms", () => {
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    expect(client.httpTimeout).toBe(10_000);
  });

  it("accepts a custom httpTimeout", () => {
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      httpTimeout: 5_000,
    });
    expect(client.httpTimeout).toBe(5_000);
  });
});

describe("HearthClient — OIDC discovery", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockFetch(body: unknown, status = 200): void {
    const mockedFetch = vi.mocked(fetch);
    mockedFetch.mockResolvedValueOnce(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    );
  }

  it("fetches discovery from {issuerUrl}/.well-known/openid-configuration", async () => {
    mockFetch(DISCOVERY_DOC);
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await client.discover();
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      "https://auth.example.com/.well-known/openid-configuration",
      expect.objectContaining({ signal: expect.anything() }),
    );
  });

  it("caches the discovery document on repeated calls", async () => {
    mockFetch(DISCOVERY_DOC);
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await client.discover();
    await client.discover();
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("throws DiscoveryError when fetch rejects (network error)", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await expect(client.discover()).rejects.toThrow(DiscoveryError);
  });

  it("throws DiscoveryError on non-2xx HTTP response", async () => {
    mockFetch({ error: "not found" }, 404);
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await expect(client.discover()).rejects.toThrow(DiscoveryError);
  });

  it("throws DiscoveryError when discovery document is missing jwks_uri", async () => {
    mockFetch({ issuer: "https://auth.example.com" });
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await expect(client.discover()).rejects.toThrow(DiscoveryError);
  });
});

describe("HearthClient — jwksClient()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockDiscovery(): void {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(DISCOVERY_DOC), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  }

  it("returns a JwksClient bound to the discovered jwks_uri", async () => {
    mockDiscovery();
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      jwksTtl: 60_000,
    });
    const jwks = await client.jwksClient();
    expect(jwks.ttl).toBe(60_000);
  });

  it("reuses the same JwksClient instance across calls", async () => {
    mockDiscovery();
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    const a = await client.jwksClient();
    const b = await client.jwksClient();
    expect(a).toBe(b);
    // Discovery fetched only once
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("passes httpTimeout to the JwksClient", async () => {
    mockDiscovery();
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      httpTimeout: 3_000,
    });
    const jwks = await client.jwksClient();
    expect(jwks.httpTimeout).toBe(3_000);
  });
});

describe("HearthClient — introspectionClient()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockDiscovery(): void {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(DISCOVERY_DOC), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  }

  it("throws ConfigurationError when clientId is absent", async () => {
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientSecret: "secret",
    });
    await expect(client.introspectionClient()).rejects.toThrow(
      ConfigurationError,
    );
  });

  it("throws ConfigurationError when clientSecret is absent", async () => {
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
    });
    await expect(client.introspectionClient()).rejects.toThrow(
      ConfigurationError,
    );
  });

  it("uses the introspection_endpoint from the discovery document", async () => {
    mockDiscovery();
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
      clientSecret: "secret",
    });
    const ic = await client.introspectionClient();
    expect(ic.httpTimeout).toBe(10_000);
  });

  it("prefers introspectionEndpoint override over discovered value", async () => {
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
      clientSecret: "secret",
      introspectionEndpoint: "https://custom.example.com/introspect",
    });
    // No fetch mock needed — override bypasses discovery
    const ic = await client.introspectionClient();
    expect(ic).toBeDefined();
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("reuses the same IntrospectionClient instance", async () => {
    mockDiscovery();
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
      clientSecret: "secret",
    });
    const a = await client.introspectionClient();
    const b = await client.introspectionClient();
    expect(a).toBe(b);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("throws ConfigurationError when discovery has no introspection_endpoint and no override", async () => {
    const docWithoutIntrospect = {
      issuer: "https://auth.example.com",
      jwks_uri: "https://auth.example.com/jwks",
    };
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(docWithoutIntrospect), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
      clientSecret: "secret",
    });
    await expect(client.introspectionClient()).rejects.toThrow(
      ConfigurationError,
    );
  });
});
