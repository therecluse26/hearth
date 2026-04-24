import { describe, expect, it } from "vitest";
import { createHearth } from "../src/hearth.js";

/**
 * Build a syntactically valid three-segment JWT around the given claims.
 * The signature segment is arbitrary — `jose.decodeJwt` does not verify
 * it, which matches what `createHearth` does on every check.
 */
function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const sig = Buffer.from("not-a-real-signature").toString("base64url");
  return `${header}.${body}.${sig}`;
}

describe("createHearth — hasPermission", () => {
  it("returns true when the JWT permissions claim contains the permission", () => {
    const token = forgeJwt({
      sub: "user_1",
      permissions: ["docs.edit", "docs.view"],
    });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.hasPermission("docs.edit")).toBe(true);
    expect(hearth.hasPermission("docs.view")).toBe(true);
  });

  it("returns false when the permission is absent", () => {
    const token = forgeJwt({ permissions: ["docs.view"] });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the token is absent", () => {
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => null,
    });
    expect(hearth.hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the token is malformed", () => {
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => "not.a.jwt",
    });
    expect(hearth.hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the permissions claim is missing", () => {
    const token = forgeJwt({ sub: "user_1" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.hasPermission("docs.edit")).toBe(false);
  });

  it("calls getToken on every invocation (no caching)", () => {
    let current: string | null = null;
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => current,
    });
    expect(hearth.hasPermission("docs.edit")).toBe(false);
    current = forgeJwt({ permissions: ["docs.edit"] });
    expect(hearth.hasPermission("docs.edit")).toBe(true);
    current = null;
    expect(hearth.hasPermission("docs.edit")).toBe(false);
  });
});

describe("createHearth — hasRole", () => {
  it("returns true when the JWT roles claim contains the role", () => {
    const token = forgeJwt({ roles: ["admin", "editor"] });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.hasRole("admin")).toBe(true);
    expect(hearth.hasRole("viewer")).toBe(false);
  });

  it("returns false when the roles claim is missing or malformed", () => {
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => forgeJwt({ roles: "admin" as unknown }),
    });
    expect(hearth.hasRole("admin")).toBe(false);
  });
});

describe("createHearth — inGroup", () => {
  it("returns true when the JWT groups claim contains the group", () => {
    const token = forgeJwt({ groups: ["engineering", "security"] });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.inGroup("engineering")).toBe(true);
    expect(hearth.inGroup("marketing")).toBe(false);
  });

  it("returns false when no token", () => {
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => undefined,
    });
    expect(hearth.inGroup("engineering")).toBe(false);
  });
});

describe("createHearth — inOrg", () => {
  it("returns true when the JWT oid claim equals the org", () => {
    const token = forgeJwt({ oid: "org_42" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.inOrg("org_42")).toBe(true);
    expect(hearth.inOrg("org_7")).toBe(false);
  });

  it("returns false when oid is missing", () => {
    const token = forgeJwt({ sub: "user_1" });
    const hearth = createHearth({
      baseUrl: "http://localhost",
      realmId: "r1",
      getToken: () => token,
    });
    expect(hearth.inOrg("org_42")).toBe(false);
  });
});
