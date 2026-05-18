/**
 * §9 — JWKS verification tests:
 *   - key rotation integration (re-fetch after key miss)
 *   - clock skew boundary (exp/iat at exact tolerance)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as jose from "jose";
import { JwksVerifier } from "./jwks.js";
import { DiscoveryClient } from "./discovery.js";
import { TokenExpiredError, TokenVerificationError, JwksFetchError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import { JWKS_TTL_DEFAULT_MS, HTTP_TIMEOUT_DEFAULT_MS, CLOCK_SKEW_DEFAULT_S } from "./config.js";
import type { JwkSetFactory } from "./jwks.js";

const ISSUER = "https://auth.example.com";

function makeConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    issuer_url: ISSUER,
    client_id: "test-client",
    client_secret: "test-secret",
    audience: [],
    jwks_ttl: JWKS_TTL_DEFAULT_MS,
    introspection_endpoint: null,
    http_timeout: HTTP_TIMEOUT_DEFAULT_MS,
    clock_skew_seconds: CLOCK_SKEW_DEFAULT_S,
    ...overrides,
  };
}

interface KeyPairResult {
  privateKey: jose.KeyLike;
  publicKey: jose.KeyLike;
  kid: string;
  jwk: jose.JWK;
}

async function generateKeyPair(alg: "RS256" | "ES256" = "RS256"): Promise<KeyPairResult> {
  const { privateKey, publicKey } = await jose.generateKeyPair(alg);
  const kid = `key-${alg}-${Date.now()}`;
  const jwk = await jose.exportJWK(publicKey);
  return { privateKey, publicKey, kid, jwk: { ...jwk, kid, alg, use: "sig" } };
}

async function signToken(
  payload: jose.JWTPayload,
  privateKey: jose.KeyLike,
  alg: string,
  kid: string,
): Promise<string> {
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg, kid })
    .sign(privateKey);
}

/** Build a JwkSetFactory that serves a local (in-memory) JWKS, no network needed. */
function makeLocalFactory(jwks: jose.JSONWebKeySet): JwkSetFactory {
  return (_uri, _ttl) => jose.createLocalJWKSet(jwks);
}

/** Stub DiscoveryClient — never makes network calls. */
function stubDiscovery(): DiscoveryClient {
  const d = new DiscoveryClient(ISSUER, HTTP_TIMEOUT_DEFAULT_MS);
  vi.spyOn(d, "discover").mockResolvedValue({
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    introspection_endpoint: `${ISSUER}/introspect`,
  });
  return d;
}

// ─────────────────────────────────────────────────────────────────────────────
// Clock skew boundary tests (§9)
// ─────────────────────────────────────────────────────────────────────────────

describe("JwksVerifier — clock skew boundary (§9)", () => {
  const NOW = 1_700_000_000;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1000);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("accepts token with exp = now + skew_tolerance (boundary valid)", async () => {
    const kp = await generateKeyPair("RS256");
    // exp is now + clockSkew — still within tolerance (not yet expired)
    const exp = NOW + CLOCK_SKEW_DEFAULT_S;
    const token = await signToken(
      { sub: "u1", iss: ISSUER, exp, iat: NOW - 10 },
      kp.privateKey, "RS256", kp.kid,
    );

    const verifier = new JwksVerifier(
      makeConfig(),
      stubDiscovery(),
      makeLocalFactory({ keys: [kp.jwk] }),
    );
    const verified = await verifier.verifyToken(token);
    expect(verified.subject()).toBe("u1");
  });

  it("rejects token with exp = now - skew_tolerance - 1 (just outside tolerance)", async () => {
    const kp = await generateKeyPair("RS256");
    const exp = NOW - CLOCK_SKEW_DEFAULT_S - 1;
    const token = await signToken(
      { sub: "u1", iss: ISSUER, exp, iat: NOW - 200 },
      kp.privateKey, "RS256", kp.kid,
    );

    const verifier = new JwksVerifier(
      makeConfig(),
      stubDiscovery(),
      makeLocalFactory({ keys: [kp.jwk] }),
    );
    await expect(verifier.verifyToken(token)).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("accepts token with iat = now + skew_tolerance (future iat within tolerance)", async () => {
    const kp = await generateKeyPair("RS256");
    const iat = NOW + CLOCK_SKEW_DEFAULT_S;
    const exp = NOW + 3600;
    const token = await signToken(
      { sub: "u1", iss: ISSUER, exp, iat },
      kp.privateKey, "RS256", kp.kid,
    );

    const verifier = new JwksVerifier(
      makeConfig(),
      stubDiscovery(),
      makeLocalFactory({ keys: [kp.jwk] }),
    );
    const verified = await verifier.verifyToken(token);
    expect(verified.subject()).toBe("u1");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// JWKS key rotation integration (§9)
// ─────────────────────────────────────────────────────────────────────────────

describe("JwksVerifier — JWKS key rotation integration (§9)", () => {
  afterEach(() => vi.restoreAllMocks());

  it("re-fetches JWKS on key miss and succeeds with rotated key", async () => {
    const oldKey = await generateKeyPair("RS256");
    const newKey = await generateKeyPair("RS256");

    const NOW_REAL = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { sub: "u1", iss: ISSUER, exp: NOW_REAL + 3600, iat: NOW_REAL },
      newKey.privateKey, "RS256", newKey.kid,
    );

    // First factory call: stale JWKS with only old key; second: rotated JWKS
    let factoryCallCount = 0;
    const rotatingFactory: JwkSetFactory = (_uri, _ttl) => {
      factoryCallCount++;
      const keys = factoryCallCount === 1 ? [oldKey.jwk] : [newKey.jwk];
      return jose.createLocalJWKSet({ keys });
    };

    const verifier = new JwksVerifier(makeConfig(), stubDiscovery(), rotatingFactory);
    // First call: miss on old key → JwksVerifier invalidates and calls factory again
    const verified = await verifier.verifyToken(token);
    expect(verified.subject()).toBe("u1");
    // Should have called factory at least twice (once for old, once for new)
    expect(factoryCallCount).toBeGreaterThanOrEqual(2);
  });

  it("throws JwksFetchError when OIDC discovery is unreachable", async () => {
    const discovery = stubDiscovery();
    vi.spyOn(discovery, "discover").mockRejectedValue(new Error("ECONNREFUSED"));

    const verifier = new JwksVerifier(makeConfig(), discovery);
    // JwksFetchError is thrown when discovery/JWKS cannot be reached; it's a HearthError subtype
    await expect(verifier.verifyToken("dummy.token.here")).rejects.toBeInstanceOf(
      JwksFetchError,
    );
  });

  it("invalidateCache forces new factory call on next verifyToken", async () => {
    const kp = await generateKeyPair("ES256");
    const NOW_REAL = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { sub: "u2", iss: ISSUER, exp: NOW_REAL + 3600, iat: NOW_REAL },
      kp.privateKey, "ES256", kp.kid,
    );

    let factoryCallCount = 0;
    const countingFactory: JwkSetFactory = (_uri, _ttl) => {
      factoryCallCount++;
      return jose.createLocalJWKSet({ keys: [kp.jwk] });
    };

    const verifier = new JwksVerifier(makeConfig(), stubDiscovery(), countingFactory);
    await verifier.verifyToken(token);
    const afterFirst = factoryCallCount;

    verifier.invalidateCache();
    await verifier.verifyToken(token);
    expect(factoryCallCount).toBeGreaterThan(afterFirst);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm support
// ─────────────────────────────────────────────────────────────────────────────

describe("JwksVerifier — algorithm support", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each(["RS256", "ES256"] as const)("verifies %s tokens", async (alg) => {
    const kp = await generateKeyPair(alg);
    const NOW_REAL = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { sub: `user-${alg}`, iss: ISSUER, exp: NOW_REAL + 3600, iat: NOW_REAL },
      kp.privateKey, alg, kp.kid,
    );

    const verifier = new JwksVerifier(
      makeConfig(),
      stubDiscovery(),
      makeLocalFactory({ keys: [kp.jwk] }),
    );
    const verified = await verifier.verifyToken(token);
    expect(verified.subject()).toBe(`user-${alg}`);
  });
});
