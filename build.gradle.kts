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
    implementation(files("libs/taplinx/classic-4.0.0-RELEASE.jar"))
    implementation(files("libs/taplinx/desfire-4.0.0-RELEASE.jar"))
    implementation(files("libs/taplinx/plus-4.0.0-RELEASE.jar"))
    implementation(files("libs/taplinx/librarymanager-4.0.0-RELEASE.jar"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
}

tasks.test {
    jvmArgs("-XX:+EnableDynamicAgentLoading")
    useJUnitPlatform()
}