import org.gradle.launcher.daemon.configuration.DaemonBuildOptions.JvmArgsOption

plugins {
    kotlin("jvm") version "2.1.10"
}

group = "bios9"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("io.mockk:mockk:1.13.17")
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
}

tasks.test {
    jvmArgs("-XX:+EnableDynamicAgentLoading")
    useJUnitPlatform()
}