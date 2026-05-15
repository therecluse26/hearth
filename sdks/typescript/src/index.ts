// Primary entry point — recommended for all new integrations.
export { HearthClient } from "./hearth-client.js";
export type { HearthClientConfig } from "./hearth-client.js";

// Lower-level primitives (JWKS and introspection).
export { JwksClient } from "./jwks-client.js";
export type { JwksClientConfig } from "./jwks-client.js";
export { IntrospectionClient } from "./introspection-client.js";
export type {
  IntrospectionClientConfig,
  IntrospectionResult,
} from "./introspection-client.js";

// Error types (spec §5).
export {
  ConfigurationError,
  DiscoveryError,
  HearthSdkError,
  IntrospectionError,
  JWKSFetchError,
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
} from "./errors.js";

// Claims API (spec §4).
export { Claims } from "./claims.js";

// Lower-level API client (kept for backwards-compatibility).
export { HearthApiClient, HearthError } from "./client.js";
export type { HearthApiClientConfig } from "./client.js";
export { AdminClient } from "./admin.js";
export { createHearth } from "./hearth.js";
export type {
  HearthFacade,
  HearthHttpClient,
  HearthOptions,
} from "./hearth.js";
export {
  HearthContext,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "./react.js";
export type { HearthProviderProps } from "./react.js";
export type {
  AuthorizeParams,
  AuthorizeResponse,
  BootstrapResponse,
  CreateRealmParams,
  CreateUserParams,
  JwksDocument,
  JsonWebKey,
  MePermissionsResponse,
  OAuthClient,
  PageResponse,
  RegisterClientParams,
  Realm,
  TokenExchangeParams,
  TokenResponse,
  UpdateRealmParams,
  UpdateUserParams,
  User,
  UserInfoResponse,
} from "./types.js";
