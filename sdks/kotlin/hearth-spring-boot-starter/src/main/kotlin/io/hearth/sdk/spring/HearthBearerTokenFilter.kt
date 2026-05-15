package io.hearth.sdk.spring

import io.hearth.sdk.Claims
import io.hearth.sdk.HearthClient
import io.hearth.sdk.HearthException
import io.hearth.sdk.TokenExpiredError
import io.hearth.sdk.TokenInvalidError
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import org.springframework.web.filter.OncePerRequestFilter

/** Request attribute key for the verified [Claims] object. */
const val HEARTH_CLAIMS_ATTRIBUTE = "hearth.claims"

/**
 * Servlet filter that validates Bearer tokens on every request (sdk-spec §6).
 *
 * Behaviour:
 * - Extracts `Authorization: Bearer <token>` from the request header.
 * - Verifies the token locally via JWKS (introspection is opt-in, not done here).
 * - On success: stores verified [Claims] in request attribute [HEARTH_CLAIMS_ATTRIBUTE]
 *   and calls `chain.doFilter`.
 * - On missing token: responds with `401 Unauthorized`.
 * - On invalid/expired token: responds with `401 Unauthorized`.
 * - Never calls `chain.doFilter` on auth failure (sdk-spec §6 rule 6).
 *
 * Registered automatically by [HearthAutoConfiguration].
 * Routes that should be public can be exempted by overriding [shouldNotFilter].
 */
open class HearthBearerTokenFilter(
    private val client: HearthClient,
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            unauthorized(response)
            return
        }

        val token = authHeader.removePrefix("Bearer ").trim()
        if (token.isEmpty()) {
            unauthorized(response)
            return
        }

        val claims: Claims = try {
            runBlocking { client.verifyToken(token) }
        } catch (e: TokenExpiredError) {
            unauthorized(response, "Token has expired")
            return
        } catch (e: TokenInvalidError) {
            unauthorized(response, "Token is invalid")
            return
        } catch (e: HearthException) {
            unauthorized(response, "Token verification failed")
            return
        }

        request.setAttribute(HEARTH_CLAIMS_ATTRIBUTE, claims)
        chain.doFilter(request, response)
    }

    private fun unauthorized(response: HttpServletResponse, detail: String? = null) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.addHeader("WWW-Authenticate", "Bearer realm=\"hearth\"")
        response.contentType = "application/json"
        val body = if (detail != null) {
            """{"error":"unauthorized","message":"$detail"}"""
        } else {
            """{"error":"unauthorized"}"""
        }
        response.writer.write(body)
    }
}

/**
 * Retrieves the verified [Claims] from the current request.
 *
 * Returns null when the request did not pass through [HearthBearerTokenFilter]
 * or the token was not verified.
 */
fun HttpServletRequest.hearthClaims(): Claims? =
    getAttribute(HEARTH_CLAIMS_ATTRIBUTE) as? Claims
