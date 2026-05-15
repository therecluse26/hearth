package io.hearth.sdk.spring

import io.hearth.sdk.ConfigurationError
import io.hearth.sdk.HearthClient
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean

/**
 * Spring Boot autoconfiguration for the Hearth SDK.
 *
 * Activated when `hearth.issuer-url` is set in application properties.
 * Registers a shared [HearthClient] bean that is reused across the application.
 *
 * Override any bean by declaring your own `@Bean` of the same type — Spring Boot's
 * `@ConditionalOnMissingBean` guarantees the auto-configured bean is skipped.
 *
 * Optional: add `hearth-spring-boot-starter` to `spring.factories` (Boot 2) or
 * `AutoConfiguration.imports` (Boot 3) to enable zero-config autoconfiguration.
 */
@AutoConfiguration
@EnableConfigurationProperties(HearthProperties::class)
@ConditionalOnProperty(prefix = "hearth", name = ["issuer-url"])
class HearthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun hearthClient(props: HearthProperties): HearthClient {
        if (props.issuerUrl.isBlank()) {
            throw ConfigurationError("hearth.issuer-url must be set")
        }
        return HearthClient(
            issuerUrl = props.issuerUrl,
            clientId = props.clientId,
            clientSecret = props.clientSecret,
            jwksTtl = props.jwksTtlMs,
            introspectionEndpointOverride = props.introspectionEndpoint,
            httpTimeoutMs = props.httpTimeoutMs,
            expectedAudience = if (props.verifyAudience) props.clientId else null,
        )
    }

    @Bean
    @ConditionalOnMissingBean
    fun hearthBearerTokenFilter(client: HearthClient): HearthBearerTokenFilter =
        HearthBearerTokenFilter(client)
}
