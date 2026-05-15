plugins {
    kotlin("jvm") version "2.0.21" apply false
    kotlin("plugin.serialization") version "2.0.21" apply false
    kotlin("plugin.spring") version "2.0.21" apply false
    id("org.springframework.boot") version "3.4.13" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
}

group = "io.hearth"
version = "0.1.0"

subprojects {
    group = rootProject.group
    version = rootProject.version

    repositories {
        mavenCentral()
    }
}
