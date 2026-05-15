plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    `java-library`
    `maven-publish`
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Kotlin coroutines
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // JSON serialization
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // JWT + JWKS verification (nimbus-jose-jwt is the JVM standard)
    api("com.nimbusds:nimbus-jose-jwt:9.40")

    // OkHttp for HTTP transport (coroutine-compatible via suspendCoroutine bridge)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // SLF4J for logging (implementation detail, not exposed)
    implementation("org.slf4j:slf4j-api:2.0.13")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.slf4j:slf4j-simple:2.0.13")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "hearth-core"
            from(components["java"])
            pom {
                name.set("Hearth Core SDK")
                description.set("Official Kotlin/JVM SDK for Hearth identity server")
                url.set("https://github.com/anthropics/hearth")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
            }
        }
    }
}
