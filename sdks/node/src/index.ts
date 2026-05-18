/** @hearth/node — server-side Hearth SDK for Node.js. Public API surface. */

// §1 — Configuration & unified client
export { HearthClient } from "./client.js";
export type { HearthConfig } from "./config.js";

// §2 — Token verification
export { JwksVerifier } from "./jwks.js";

// §3 — Token introspection
export { IntrospectionClient } from "./introspect.js";
export type { IntrospectionResult } from "./introspect.js";

// §4 — Claims API
export { VerifiedToken } from "./token.js";

// §5 — Error taxonomy
export {
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

// §6 — Middleware
export { hearthMiddleware, hearthFastifyHook } from "./middleware.js";
export type { MiddlewareOptions } from "./middleware.js";
