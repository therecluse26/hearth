import { describe, it, expect } from "vitest";
import { resolveConfig, JWKS_TTL_MAX_MS, JWKS_TTL_DEFAULT_MS, CLOCK_SKEW_DEFAULT_S, HTTP_TIMEOUT_DEFAULT_MS } from "./config.js";
import { ConfigurationError } from "./errors.js";

describe("resolveConfig", () => {
  const base = { issuer_url: "https://auth.example.com", client_id: "cid", client_secret: "sec" };

  it("applies defaults", () => {
    const r = resolveConfig(base);
    expect(r.jwks_ttl).toBe(JWKS_TTL_DEFAULT_MS);
    expect(r.http_timeout).toBe(HTTP_TIMEOUT_DEFAULT_MS);
    expect(r.clock_skew_seconds).toBe(CLOCK_SKEW_DEFAULT_S);
    expect(r.audience).toEqual([]);
    expect(r.introspection_endpoint).toBeNull();
  });

  it("strips trailing slash from issuer_url", () => {
    const r = resolveConfig({ ...base, issuer_url: "https://auth.example.com/" });
    expect(r.issuer_url).toBe("https://auth.example.com");
  });

  it("caps jwks_ttl at 24h", () => {
    const r = resolveConfig({ ...base, jwks_ttl: JWKS_TTL_MAX_MS + 1 });
    expect(r.jwks_ttl).toBe(JWKS_TTL_MAX_MS);
  });

  it("normalizes audience string to array", () => {
    const r = resolveConfig({ ...base, audience: "api.example.com" });
    expect(r.audience).toEqual(["api.example.com"]);
  });

  it("throws ConfigurationError on missing issuer_url", () => {
    expect(() => resolveConfig({ ...base, issuer_url: "" })).toThrow(ConfigurationError);
  });

  it("throws ConfigurationError on missing client_id", () => {
    expect(() => resolveConfig({ ...base, client_id: "" })).toThrow(ConfigurationError);
  });

  it("throws ConfigurationError on missing client_secret", () => {
    expect(() => resolveConfig({ ...base, client_secret: "" })).toThrow(ConfigurationError);
  });
});
