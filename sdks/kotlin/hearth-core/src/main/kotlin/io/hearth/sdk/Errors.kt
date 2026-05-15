package io.hearth.sdk

/**
 * Base exception for all Hearth SDK errors.
 *
 * Tokens and secrets never appear in messages or causes per sdk-spec §11.
 */
open class HearthException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/** Missing required config or invalid issuer URL. */
class ConfigurationError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** OIDC discovery endpoint unreachable or returned invalid JSON. */
class DiscoveryError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWKS endpoint unreachable or returned invalid response. */
class JWKSFetchError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `exp` claim is in the past. */
class TokenExpiredError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `nbf` claim is in the future beyond allowed clock skew. */
class TokenNotYetValidError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Signature invalid, malformed JWT, or algorithm mismatch. */
class TokenInvalidError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `iss` does not match configured issuer. */
class TokenIssuerError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `aud` does not contain expected audience. */
class TokenAudienceError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Introspection endpoint unreachable or returned an error. */
class IntrospectionError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Hearth API returned a non-2xx response. */
class ApiError(
    val statusCode: Int,
    message: String,
    cause: Throwable? = null,
) : HearthException(message, cause)
