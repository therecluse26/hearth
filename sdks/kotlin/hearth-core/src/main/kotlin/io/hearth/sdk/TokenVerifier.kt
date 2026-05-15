package io.hearth.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.ParseException

/** Allowed clock skew for `exp` and `iat` validation per sdk-spec §2. */
private const val CLOCK_SKEW_SECONDS = 5

/**
 * JWT signature verifier backed by a [JwksClient].
 *
 * Implements the mandatory validation order from sdk-spec.md §2:
 * 1. Signature against JWKS (RS256 / ES256)
 * 2. `exp` claim
 * 3. `iss` matches configured issuer
 * 4. `aud` contains configured client_id (optional — server SDK mode)
 * 5. `iat` not in the future (±5s clock skew)
 *
 * Tokens and secrets never appear in thrown error messages.
 */
class TokenVerifier(
    private val jwksClient: JwksClient,
    private val issuerUrl: String,
    /** When set, `aud` must contain this value. Omit for pure server-side verification. */
    private val expectedAudience: String? = null,
) {
    /**
     * Verifies [token] and returns the decoded [Claims] on success.
     *
     * On kid-cache miss, re-fetches JWKS once before failing (sdk-spec §2.2 rule 3).
     *
     * @throws TokenInvalidError   on bad signature, malformed JWT, or unsupported algorithm
     * @throws TokenExpiredError   when `exp` is in the past
     * @throws TokenIssuerError    when `iss` does not match [issuerUrl]
     * @throws TokenAudienceError  when `aud` does not contain [expectedAudience]
     * @throws JWKSFetchError      when the JWKS endpoint is unreachable
     */
    suspend fun verify(token: String): Claims = withContext(Dispatchers.IO) {
        val jwt = try {
            SignedJWT.parse(token)
        } catch (e: ParseException) {
            throw TokenInvalidError("Malformed JWT — could not parse token structure")
        }

        // First attempt with the cached key set.
        try {
            return@withContext processJwt(jwt, jwksClient.getOrFetchSet())
        } catch (e: HearthException) {
            // Re-throw all typed errors immediately — they aren't key-miss errors.
            if (e !is TokenInvalidError) throw e
        }

        // kid not found or signature failed — re-fetch once per sdk-spec §2.2 rule 3.
        val freshSet = try {
            jwksClient.invalidateAndRefetch()
        } catch (fetchErr: JWKSFetchError) {
            throw fetchErr
        }

        processJwt(jwt, freshSet)
    }

    private fun processJwt(jwt: SignedJWT, keySet: com.nimbusds.jose.jwk.JWKSet): Claims {
        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            // Build a composite selector that supports RS256 + ES256 (sdk-spec §2).
            val source = ImmutableJWKSet<SecurityContext>(keySet)
            val rsaSelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, source)
            val ecSelector  = JWSVerificationKeySelector(JWSAlgorithm.ES256, source)
            jwsKeySelector = CompositeKeySelector(rsaSelector, ecSelector)
            jwtClaimsSetVerifier = buildClaimsVerifier()
        }

        return try {
            Claims(processor.process(jwt, null))
        } catch (e: BadJWTException) {
            mapBadJwtException(e)
        } catch (e: com.nimbusds.jose.JOSEException) {
            throw TokenInvalidError("JWT signature verification failed")
        } catch (e: Exception) {
            val msg = e.message ?: ""
            when {
                msg.contains("expired", ignoreCase = true) ->
                    throw TokenExpiredError("Token has expired")
                msg.contains("issuer", ignoreCase = true) ->
                    throw TokenIssuerError("Token issuer does not match configured issuer")
                msg.contains("audience", ignoreCase = true) ->
                    throw TokenAudienceError("Token audience does not include expected client_id")
                else -> throw TokenInvalidError("JWT verification failed")
            }
        }
    }

    private fun buildClaimsVerifier(): DefaultJWTClaimsVerifier<SecurityContext> {
        val exactMatchClaims = JWTClaimsSet.Builder()
            .issuer(issuerUrl)
            .build()
        val requiredClaims = mutableSetOf("sub", "exp", "iat", "iss")
        return DefaultJWTClaimsVerifier<SecurityContext>(
            expectedAudience?.let { setOf(it) },
            exactMatchClaims,
            requiredClaims,
            null,
        ).apply {
            maxClockSkew = CLOCK_SKEW_SECONDS
        }
    }

    private fun mapBadJwtException(e: BadJWTException): Nothing {
        val msg = e.message ?: ""
        when {
            msg.contains("expired", ignoreCase = true) ->
                throw TokenExpiredError("Token has expired")
            msg.contains("issue time", ignoreCase = true) || msg.contains("iat", ignoreCase = true) ->
                throw TokenNotYetValidError("Token issued-at is in the future beyond clock skew")
            msg.contains("issuer", ignoreCase = true) ->
                throw TokenIssuerError("Token issuer does not match configured issuer")
            msg.contains("audience", ignoreCase = true) ->
                throw TokenAudienceError("Token audience does not include expected client_id")
            else -> throw TokenInvalidError("JWT claims verification failed")
        }
    }
}

/**
 * Tries each [JWSKeySelector] in order; returns keys from the first that matches the header's alg.
 *
 * This enables transparent RS256+ES256 support without hard-coding which algorithm a token uses.
 */
private class CompositeKeySelector(
    private vararg val selectors: JWSKeySelector<SecurityContext>,
) : JWSKeySelector<SecurityContext> {
    override fun selectJWSKeys(
        header: com.nimbusds.jose.JWSHeader,
        ctx: SecurityContext?,
    ): List<java.security.Key> {
        for (sel in selectors) {
            try {
                val keys = sel.selectJWSKeys(header, ctx)
                if (keys.isNotEmpty()) return keys
            } catch (_: Exception) {
                // Try next selector
            }
        }
        return emptyList()
    }
}
