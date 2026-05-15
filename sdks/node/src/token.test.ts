import { describe, it, expect } from "vitest";
import { VerifiedToken } from "./token.js";
import type { JWTPayload } from "jose";

function makeToken(overrides: Partial<JWTPayload & { scope?: string; scopes?: string[]; roles?: string[]; permissions?: string[] }> = {}): VerifiedToken {
  const payload: JWTPayload = {
    sub: "user123",
    iss: "https://auth.example.com",
    aud: ["api.example.com", "admin.example.com"],
    iat: 1_700_000_000,
    exp: 1_700_003_600,
    nbf: 1_700_000_000,
    ...overrides,
  };
  return new VerifiedToken(payload, { alg: "RS256", kid: "key-1" });
}

describe("VerifiedToken claims accessors", () => {
  it("subject() returns sub", () => expect(makeToken().subject()).toBe("user123"));
  it("issuer() returns iss", () => expect(makeToken().issuer()).toBe("https://auth.example.com"));
  it("audience() returns normalized array", () => expect(makeToken().audience()).toEqual(["api.example.com", "admin.example.com"]));
  it("audience() returns [] when absent", () => expect(makeToken({ aud: undefined }).audience()).toEqual([]));
  it("audience() wraps single string in array", () => expect(makeToken({ aud: "only.one" }).audience()).toEqual(["only.one"]));
  it("issuedAt() returns Date", () => expect(makeToken().issuedAt()).toEqual(new Date(1_700_000_000_000)));
  it("expiresAt() returns Date", () => expect(makeToken().expiresAt()).toEqual(new Date(1_700_003_600_000)));
  it("notBefore() returns Date", () => expect(makeToken().notBefore()).toEqual(new Date(1_700_000_000_000)));
  it("issuedAt/expiresAt/notBefore return null when absent", () => {
    const t = makeToken({ iat: undefined, exp: undefined, nbf: undefined });
    expect(t.issuedAt()).toBeNull();
    expect(t.expiresAt()).toBeNull();
    expect(t.notBefore()).toBeNull();
  });

  it("scope() returns raw scope string", () => {
    const t = makeToken({ scope: "openid profile email" } as JWTPayload);
    expect(t.scope()).toBe("openid profile email");
  });

  it("scopes() splits scope string", () => {
    const t = makeToken({ scope: "openid profile email" } as JWTPayload);
    expect(t.scopes()).toEqual(["openid", "profile", "email"]);
  });

  it("scopes() prefers scopes array over scope string", () => {
    const t = makeToken({ scopes: ["a", "b"] } as unknown as JWTPayload);
    expect(t.scopes()).toEqual(["a", "b"]);
  });

  it("get(key) returns arbitrary claim", () => {
    const t = makeToken({ custom_claim: "hello" } as unknown as JWTPayload);
    expect(t.get("custom_claim")).toBe("hello");
  });

  it("raw() returns frozen payload copy", () => {
    const t = makeToken();
    const r = t.raw();
    expect(r.sub).toBe("user123");
    expect(Object.isFrozen(r)).toBe(true);
  });
});

describe("VerifiedToken hasScope / hasRole / hasPermission (timing-safe)", () => {
  it("hasScope returns true for present scope", () => {
    const t = makeToken({ scope: "openid read:users" } as unknown as JWTPayload);
    expect(t.hasScope("openid")).toBe(true);
    expect(t.hasScope("read:users")).toBe(true);
  });
  it("hasScope returns false for absent scope", () => {
    const t = makeToken({ scope: "openid" } as unknown as JWTPayload);
    expect(t.hasScope("admin")).toBe(false);
  });
  it("hasRole returns true/false correctly", () => {
    const t = makeToken({ roles: ["admin", "viewer"] } as unknown as JWTPayload);
    expect(t.hasRole("admin")).toBe(true);
    expect(t.hasRole("superuser")).toBe(false);
  });
  it("hasPermission returns true/false correctly", () => {
    const t = makeToken({ permissions: ["users:read", "users:write"] } as unknown as JWTPayload);
    expect(t.hasPermission("users:read")).toBe(true);
    expect(t.hasPermission("users:delete")).toBe(false);
  });
  it("hasScope handles empty scopes gracefully", () => {
    const t = makeToken({});
    expect(t.hasScope("anything")).toBe(false);
  });
});
