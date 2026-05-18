import { describe, it, expect } from "vitest";
import {
  HearthError,
  ConfigurationError,
  DiscoveryError,
  JwksFetchError,
  TokenVerificationError,
  TokenExpiredError,
  TokenClaimsError,
  IntrospectionError,
  MiddlewareError,
} from "./errors.js";

describe("HearthError taxonomy", () => {
  it("all error classes extend HearthError", () => {
    const classes = [
      ConfigurationError,
      DiscoveryError,
      JwksFetchError,
      TokenVerificationError,
      TokenExpiredError,
      TokenClaimsError,
      IntrospectionError,
      MiddlewareError,
    ];
    for (const Cls of classes) {
      const err = Cls === TokenExpiredError
        ? new TokenExpiredError(new Date())
        : new (Cls as new (m: string) => HearthError)("test");
      expect(err).toBeInstanceOf(HearthError);
      expect(err).toBeInstanceOf(Cls);
      expect(err.name).toBe(Cls.name);
    }
  });

  it("supports cause chaining", () => {
    const cause = new Error("original");
    const err = new DiscoveryError("wrapped", { cause });
    expect(err.cause).toBe(cause);
  });

  it("sanitizes JWT-like strings from messages", () => {
    const fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123";
    const err = new HearthError(`Token was: ${fakeJwt}`);
    expect(err.message).not.toContain(fakeJwt);
    expect(err.message).toContain("[redacted]");
  });

  it("TokenExpiredError formats expiry date in message", () => {
    const date = new Date("2024-01-01T00:00:00Z");
    const err = new TokenExpiredError(date);
    expect(err.message).toContain("2024-01-01T00:00:00.000Z");
  });

  it("TokenVerificationError is instance of TokenVerificationError via TokenExpiredError", () => {
    const err = new TokenExpiredError(new Date());
    expect(err).toBeInstanceOf(TokenVerificationError);
  });
});
