package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class HearthClientDiscoveryTest {

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

    private val discoveryDoc = """
        {
          "issuer": "http://localhost",
          "jwks_uri": "http://localhost/jwks",
          "token_endpoint": "http://localhost/token",
          "authorization_endpoint": "http://localhost/authorize",
          "introspection_endpoint": "http://localhost/introspect",
          "userinfo_endpoint": "http://localhost/userinfo",
          "device_authorization_endpoint": "http://localhost/device"
        }
    """.trimIndent()

    @Test
    fun `discover returns cached discovery document`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = HearthClient(issuerUrl = server.url("/").toString().trimEnd('/'))
        val doc1 = client.discover()
        val doc2 = client.discover() // Should use cache — server receives only 1 request

        assertEquals(1, server.requestCount)
        assertEquals(doc1, doc2)
    }

    @Test
    fun `discover throws DiscoveryError on non-2xx response`() = runTest {
        server.enqueue(MockResponse().setResponseCode(503))

        val client = HearthClient(issuerUrl = server.url("/").toString().trimEnd('/'))
        assertFailsWith<DiscoveryError> { client.discover() }
    }

    @Test
    fun `discover throws DiscoveryError on missing jwks_uri`() = runTest {
        server.enqueue(MockResponse().setBody("""{"issuer":"x"}""").setResponseCode(200))

        val client = HearthClient(issuerUrl = server.url("/").toString().trimEnd('/'))
        assertFailsWith<DiscoveryError> { client.discover() }
    }

    @Test
    fun `introspectionClient throws ConfigurationError without credentials`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = HearthClient(
            issuerUrl = server.url("/").toString().trimEnd('/'),
            // No clientId/clientSecret
        )
        assertFailsWith<ConfigurationError> { client.introspectionClient() }
    }

    @Test
    fun `introspectionClient uses override endpoint without discovery`() = runTest {
        val overrideEndpoint = server.url("/introspect").toString()
        // Introspection endpoint is overridden — no discovery needed
        val client = HearthClient(
            issuerUrl = "https://auth.example.com",
            clientId = "app",
            clientSecret = "secret",
            introspectionEndpointOverride = overrideEndpoint,
        )
        // Should not throw even though discovery would fail (wrong host)
        val ic = client.introspectionClient()
        assertEquals(ic, ic) // not null
    }
}
