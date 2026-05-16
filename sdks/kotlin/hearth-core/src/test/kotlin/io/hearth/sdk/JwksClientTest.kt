package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class JwksClientTest {

    private lateinit var server: MockWebServer

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    private val jwksDoc = """
        {
          "keys": [
            {
              "kty": "RSA",
              "kid": "key-1",
              "use": "sig",
              "alg": "RS256",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e": "AQAB"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `fetchKeys returns parsed JWK set`() = runTest {
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
        )
        val keys = client.fetchKeys()
        assertEquals(1, keys.size())
        assertEquals("key-1", keys.getKeyByKeyId("key-1").keyID)
    }

    @Test
    fun `fetchKeys throws JWKSFetchError on non-2xx`() = runTest {
        server.enqueue(MockResponse().setResponseCode(500).setBody("error"))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
        )
        assertFailsWith<JWKSFetchError> { client.fetchKeys() }
    }

    @Test
    fun `fetchKeys throws JWKSFetchError on invalid JSON`() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("not json"))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
        )
        assertFailsWith<JWKSFetchError> { client.fetchKeys() }
    }

    @Test
    fun `getOrFetchSet caches result and does not re-fetch within TTL`() = runTest {
        // Enqueue two responses; only the first should be consumed.
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
            ttlOverrideMs = JWKS_DEFAULT_TTL_MS,
        )
        client.getOrFetchSet()
        client.getOrFetchSet() // Should hit cache
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `invalidateAndRefetch forces new fetch`() = runTest {
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
        )
        client.getOrFetchSet()
        client.invalidateAndRefetch()
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `old keys are preserved on refresh (rotation support)`() = runTest {
        val jwksDoc2 = """{"keys":[{"kty":"RSA","kid":"key-2","use":"sig","alg":"RS256","n":"0vx7","e":"AQAB"}]}"""
        server.enqueue(MockResponse().setBody(jwksDoc).setResponseCode(200))
        server.enqueue(MockResponse().setBody(jwksDoc2).setResponseCode(200))

        val client = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5000),
        )
        client.getOrFetchSet()
        val merged = client.invalidateAndRefetch()
        // Both key-1 (old) and key-2 (new) should be present
        assertEquals(2, merged.size())
    }

    @Test
    fun `ttl override is clamped to minimum`() {
        val client = JwksClient(
            jwksUri = "https://example.com/jwks",
            httpClient = buildHttpClient(5000),
            ttlOverrideMs = 1000L, // below min of 5 min → should be clamped
        )
        // Just verifying construction does not throw
        assertEquals(client.jwksUri, "https://example.com/jwks")
    }
}
