import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val rustCrateDir = rootProject.layout.projectDirectory.dir("../rust/tapsmith-android")
val generatedJniLibsDir = layout.buildDirectory.dir("generated/jniLibs/rust")
val androidMinSdk = 24
val androidRustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
val androidSdkDir = androidSdkDirFromLocalProperties()
val androidNdkDir = androidNdkDirFromEnvironment() ?: androidSdkDir?.latestNdkDir()

android {
    namespace = "bios9.tapsmith"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "bios9.tapsmith"
        minSdk = androidMinSdk
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs(generatedJniLibsDir.get().asFile)
        }
    }
}

tasks.register<Exec>("cargoBuildAndroid") {
    group = "build"
    description = "Builds the Rust JNI library for Android ABIs into generated jniLibs."
    workingDir = rustCrateDir.asFile
    androidSdkDir?.let { sdk -> environment("ANDROID_HOME", sdk.absolutePath) }
    androidNdkDir?.let { ndk -> environment("ANDROID_NDK_HOME", ndk.absolutePath) }
    commandLine(
        listOf(
            "cargo",
            "ndk",
            "--platform",
            androidMinSdk.toString(),
        ) + androidRustAbis.flatMap { abi -> listOf("--target", abi) } + listOf(
            "--output-dir",
            generatedJniLibsDir.get().asFile.absolutePath,
            "build",
            "--release",
        )
    )
}

if (providers.gradleProperty("buildRustAndroid").map(String::toBoolean).getOrElse(false)) {
    tasks.named("preBuild") {
        dependsOn("cargoBuildAndroid")
    }
}

fun androidSdkDirFromLocalProperties(): File? {
    val localProperties = rootProject.file("local.properties")
    if (!localProperties.isFile) {
        return null
    }
    val properties = Properties()
    localProperties.inputStream().use(properties::load)
    return properties.getProperty("sdk.dir")?.let(::File)
}

fun androidNdkDirFromEnvironment(): File? =
    providers.environmentVariable("ANDROID_NDK_HOME").orNull?.let(::File)

fun File.latestNdkDir(): File? =
    resolve("ndk")
        .listFiles()
        ?.filter(File::isDirectory)
        ?.maxByOrNull(File::getName)

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
