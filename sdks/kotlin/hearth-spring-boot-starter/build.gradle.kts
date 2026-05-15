plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    kotlin("plugin.spring")
    id("io.spring.dependency-management")
    `java-library`
    `maven-publish`
}

kotlin {
    jvmToolchain(17)
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:3.3.5")
    }
}

dependencies {
    api(project(":hearth-core"))

    // Spring Boot — provided at runtime by the host app, not bundled.
    compileOnly("org.springframework.boot:spring-boot-autoconfigure")
    compileOnly("org.springframework:spring-webmvc")
    compileOnly("jakarta.servlet:jakarta.servlet-api")

    // Annotation processor for @ConfigurationProperties metadata
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation(kotlin("test"))
    testImplementation("org.springframework.boot:spring-boot-test")
    testImplementation("org.springframework.boot:spring-boot-starter-web")
    testImplementation("org.springframework:spring-test")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "hearth-spring-boot-starter"
            from(components["java"])
            pom {
                name.set("Hearth Spring Boot Starter")
                description.set("Spring Boot autoconfiguration for the Hearth Kotlin SDK")
                url.set("https://github.com/anthropics/hearth")
            }
        }
    }
}
