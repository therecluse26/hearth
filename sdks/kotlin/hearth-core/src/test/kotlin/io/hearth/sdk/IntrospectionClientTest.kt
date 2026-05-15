package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class IntrospectionClientTest {

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

    private fun makeClient() = IntrospectionClient(
        introspectionEndpoint = server.url("/introspect").toString(),
        clientId = "app",
        clientSecret = "secret",
        httpClient = buildHttpClient(5000),
    )

    @Test
    fun `introspect returns active=true for valid token`() = runTest {
        server.enqueue(MockResponse().setBody("""
            {
              "active": true,
              "sub": "user-123",
              "exp": 9999999999,
              "iat": 1000000000,
              "iss": "https://auth.example.com",
              "scope": "read write"
            }
        """.trimIndent()).setResponseCode(200))

        val result = makeClient().introspect("some-token")
        assertTrue(result.active)
        assertEquals("user-123", result.sub)
        assertEquals("read write", result.scope)
    }

    @Test
    fun `introspect returns active=false for revoked token`() = runTest {
        server.enqueue(MockResponse().setBody("""{"active": false}""").setResponseCode(200))

        val result = makeClient().introspect("revoked-token")
        assertFalse(result.active)
    }

    @Test
    fun `introspect uses HTTP Basic auth`() = runTest {
        server.enqueue(MockResponse().setBody("""{"active":false}""").setResponseCode(200))

        makeClient().introspect("token")

        val request = server.takeRequest()
        val auth = request.getHeader("Authorization") ?: ""
        assertTrue(auth.startsWith("Basic "))
        // Decode and verify credentials
        val decoded = String(java.util.Base64.getDecoder().decode(auth.removePrefix("Basic ")))
        assertEquals("app:secret", decoded)
    }

    @Test
    fun `introspect never caches results`() = runTest {
        repeat(3) {
            server.enqueue(MockResponse().setBody("""{"active":true,"sub":"u"}""").setResponseCode(200))
        }
        val client = makeClient()
        client.introspect("token")
        client.introspect("token")
        client.introspect("token")
        assertEquals(3, server.requestCount)
    }

    @Test
    fun `introspect throws IntrospectionError on non-2xx`() = runTest {
        server.enqueue(MockResponse().setResponseCode(503))

        assertFailsWith<IntrospectionError> { makeClient().introspect("token") }
    }

    @Test
    fun `introspect captures extra non-standard claims`() = runTest {
        server.enqueue(MockResponse().setBody("""
            {"active":true,"sub":"u","custom_claim":"custom_value"}
        """.trimIndent()).setResponseCode(200))

        val result = makeClient().introspect("token")
        assertTrue(result.active)
        assertTrue(result.extra.containsKey("custom_claim"))
    }
}
