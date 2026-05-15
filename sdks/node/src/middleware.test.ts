import { describe, it, expect, vi, beforeEach } from "vitest";
import { hearthMiddleware } from "./middleware.js";
import { HearthClient } from "./client.js";
import { TokenExpiredError } from "./errors.js";
import { VerifiedToken } from "./token.js";
import type { JWTPayload } from "jose";

const BASE_CONFIG = { issuer_url: "https://auth.example.com", client_id: "app", client_secret: "secret" };

function makeReqRes(authHeader?: string) {
  const req = { headers: { authorization: authHeader } as Record<string, string | undefined>, hearthToken: undefined as VerifiedToken | undefined };
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) { this.statusCode = code; return this; },
    json(body: unknown) { this.body = body; return this; },
    setHeader(name: string, value: string) { this.headers[name] = value; return this; },
  };
  const next = vi.fn();
  return { req, res, next };
}

function makeVerifiedToken(payload: Partial<JWTPayload & { scope?: string; scopes?: string[]; roles?: string[]; permissions?: string[] }> = {}): VerifiedToken {
  return new VerifiedToken({
    sub: "user1",
    iss: "https://auth.example.com",
    exp: 9_999_999_999,
    iat: 1_700_000_000,
    ...payload,
  } as JWTPayload, { alg: "RS256" });
}

describe("hearthMiddleware", () => {
  beforeEach(() => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockReset();
  });

  it("calls next with req.hearthToken populated when token is valid", async () => {
    const token = makeVerifiedToken();
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware(BASE_CONFIG);
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req as never, res as never, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.hearthToken).toBe(token);
  });

  it("returns 401 with WWW-Authenticate header when no token (required=true)", async () => {
    const mw = hearthMiddleware(BASE_CONFIG);
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next without hearthToken when token missing and required=false", async () => {
    const mw = hearthMiddleware({ ...BASE_CONFIG, required: false });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(next).toHaveBeenCalled();
    expect(req.hearthToken).toBeUndefined();
  });

  it("returns 401 with WWW-Authenticate when verification fails", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new TokenExpiredError(new Date()));
    const mw = hearthMiddleware(BASE_CONFIG);
    const { req, res, next } = makeReqRes("Bearer bad-token");
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when token valid but required scope is missing", async () => {
    const token = makeVerifiedToken({ scope: "openid" } as unknown as JWTPayload);
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, requiredScope: "admin" });
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when token valid but required role is missing", async () => {
    const token = makeVerifiedToken({ roles: ["viewer"] } as unknown as JWTPayload);
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, requiredRole: "admin" });
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
  });

  it("returns 403 when token valid but required permission is missing", async () => {
    const token = makeVerifiedToken({ permissions: ["read"] } as unknown as JWTPayload);
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, requiredPermission: "delete" });
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
  });

  it("allows request with all required scope/role/permission", async () => {
    const token = makeVerifiedToken({
      scope: "openid admin",
      roles: ["superuser"],
      permissions: ["delete"],
    } as unknown as JWTPayload);
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, requiredScope: "admin", requiredRole: "superuser", requiredPermission: "delete" });
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });
});
