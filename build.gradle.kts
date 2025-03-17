plugins {
  kotlin("jvm") version "2.1.10"
  id("com.ncorti.ktfmt.gradle") version "0.22.0"
}

group = "bios9"

version = "1.0-SNAPSHOT"

repositories { mavenCentral() }

dependencies {
  testImplementation(kotlin("test"))
  testImplementation("io.mockk:mockk:1.13.17")
  implementation("co.touchlab:kermit:2.0.5")
}

tasks.test {
  jvmArgs("-XX:+EnableDynamicAgentLoading")
  useJUnitPlatform()
}
