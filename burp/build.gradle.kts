plugins {
    java
}

group = "com.pablodlz.arsenal"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.5")
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

tasks.register<Jar>("extensionJar") {
    archiveBaseName.set("arsenal-phantom-success")
    from(sourceSets.main.get().output)
    manifest { attributes("Implementation-Version" to project.version) }
}

tasks.named("build") { dependsOn("extensionJar") }
