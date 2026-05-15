package io.hearth.sdk.spring

import io.hearth.sdk.JWKS_DEFAULT_TTL_MS
import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Spring Boot configuration properties for the Hearth SDK.
 *
 * ```yaml
 * hearth:
 *   issuer-url: https://auth.example.com
 *   client-id: my-app
 *   client-secret: secret
 *   jwks-ttl-ms: 3600000   # 1 hour (default)
 *   http-timeout-ms: 10000  # 10 seconds (default)
 *   verify-audience: true
 * ```
 */
@ConfigurationProperties(prefix = "hearth")
data class HearthProperties(
    /** Root URL of the Hearth instance. Required. */
    val issuerUrl: String = "",
    /** OAuth 2.0 client ID. */
    val clientId: String? = null,
    /** OAuth 2.0 client secret. */
    val clientSecret: String? = null,
    /** JWKS cache TTL in milliseconds. Default: 1 hour. */
    val jwksTtlMs: Long = JWKS_DEFAULT_TTL_MS,
    /** HTTP timeout in milliseconds. Default: 10 seconds. */
    val httpTimeoutMs: Long = 10_000L,
    /** Override introspection endpoint URL. */
    val introspectionEndpoint: String? = null,
    /**
     * When true (default), token verification requires `aud` to contain `client-id`.
     * Set to false for pure server-side resource servers that skip audience validation.
     */
    val verifyAudience: Boolean = true,
)
