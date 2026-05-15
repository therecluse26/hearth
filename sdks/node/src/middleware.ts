/** §6 — Framework-decoupled Express and Fastify middleware for JWT verification. */

import { HearthClient } from "./client.js";
import type { HearthConfig } from "./config.js";
import type { VerifiedToken } from "./token.js";
import { TokenVerificationError } from "./errors.js";

// No import from 'express' or 'fastify' — decoupled from any framework.

export interface MiddlewareOptions extends HearthConfig {
  /** If true (default), return 401 when no Bearer token is present. */
  required?: boolean;
  /** If provided, return 403 when the verified token is missing this scope. */
  requiredScope?: string;
  /** If provided, return 403 when the verified token is missing this role. */
  requiredRole?: string;
  /** If provided, return 403 when the verified token is missing this permission. */
  requiredPermission?: string;
}

const WWW_AUTHENTICATE = 'Bearer realm="hearth"';

// Generic framework-agnostic types — satisfied by both Express and Fastify request shapes.
interface MinimalRequest {
  headers: Record<string, string | string[] | undefined>;
}

interface MinimalResponse {
  status(code: number): MinimalResponse;
  setHeader?(name: string, value: string): void;
  json(body: unknown): unknown;
  send?(body: unknown): unknown;
  header?(name: string, value: string): void;
}

// Module augmentation for Express (optional — safe if express is not installed).
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      hearthToken?: VerifiedToken;
    }
  }
}

type ExpressRequest = MinimalRequest & { hearthToken?: VerifiedToken };
type NextFn = (err?: unknown) => void;

function extractBearer(headers: Record<string, string | string[] | undefined>): string | null {
  const raw = headers["authorization"];
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

function sendUnauthorized(res: MinimalResponse, description: string): void {
  if (res.setHeader) res.setHeader("WWW-Authenticate", WWW_AUTHENTICATE);
  if (res.header) res.header("WWW-Authenticate", WWW_AUTHENTICATE);
  res.status(401);
  const body = { error: "unauthorized", error_description: description };
  if (res.json) res.json(body);
  else if (res.send) res.send(body);
}

function sendForbidden(res: MinimalResponse): void {
  res.status(403);
  const body = { error: "forbidden", error_description: "Insufficient scope, role, or permission" };
  if (res.json) res.json(body);
  else if (res.send) res.send(body);
}

function checkAuthorization(token: VerifiedToken, opts: MiddlewareOptions): boolean {
  if (opts.requiredScope && !token.hasScope(opts.requiredScope)) return false;
  if (opts.requiredRole && !token.hasRole(opts.requiredRole)) return false;
  if (opts.requiredPermission && !token.hasPermission(opts.requiredPermission)) return false;
  return true;
}

/** Express-compatible middleware factory. Attaches verified token to `req.hearthToken`. */
export function hearthMiddleware(options: MiddlewareOptions) {
  const client = new HearthClient(options);
  const required = options.required !== false;

  return async (req: ExpressRequest, res: MinimalResponse, next: NextFn): Promise<void> => {
    const token = extractBearer(req.headers);
    if (!token) {
      if (required) {
        sendUnauthorized(res, "Bearer token required");
        return;
      }
      next();
      return;
    }

    let verified: VerifiedToken;
    try {
      verified = await client.verifyToken(token);
    } catch (err) {
      if (required) {
        const desc = err instanceof TokenVerificationError ? err.message : "Token verification failed";
        sendUnauthorized(res, desc);
        return;
      }
      next();
      return;
    }

    if (!checkAuthorization(verified, options)) {
      sendForbidden(res);
      return;
    }

    req.hearthToken = verified;
    next();
  };
}

// ── Fastify ──────────────────────────────────────────────────────────────────

interface FastifyRequest {
  headers: Record<string, string | undefined>;
  hearthToken?: VerifiedToken;
}

interface FastifyReply {
  code(statusCode: number): FastifyReply;
  header(name: string, value: string): FastifyReply;
  send(body: unknown): void;
}

/** Fastify hook/plugin factory. Attaches verified token to `request.hearthToken`. */
export function hearthFastifyHook(options: MiddlewareOptions) {
  const client = new HearthClient(options);
  const required = options.required !== false;

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const authHeader = request.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      if (required) {
        reply.header("WWW-Authenticate", WWW_AUTHENTICATE).code(401).send({
          error: "unauthorized",
          error_description: "Bearer token required",
        });
        return;
      }
      return;
    }

    const token = authHeader.slice(7);
    let verified: VerifiedToken;
    try {
      verified = await client.verifyToken(token);
    } catch (err) {
      if (required) {
        const desc = err instanceof TokenVerificationError ? err.message : "Token verification failed";
        reply.header("WWW-Authenticate", WWW_AUTHENTICATE).code(401).send({
          error: "unauthorized",
          error_description: desc,
        });
        return;
      }
      return;
    }

    if (!checkAuthorization(verified, options)) {
      reply.code(403).send({
        error: "forbidden",
        error_description: "Insufficient scope, role, or permission",
      });
      return;
    }

    request.hearthToken = verified;
  };
}
