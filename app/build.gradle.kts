plugins {
    id("unknown-android-application")
}

/**
 * The launcher icon artwork is stored as chunked base64 text (see icon-src/)
 * so the repository stays reviewable in plain text; this task reassembles the
 * chunks and materialises the real WebP drawable during the build.
 */
val launcherIconResDir = layout.buildDirectory.dir("generated/launcher-icon")

val decodeLauncherIcon =
    tasks.register("decodeLauncherIcon") {
        val inputDir = layout.projectDirectory.dir("icon-src")
        val output = launcherIconResDir.get().dir("drawable-nodpi").file("ic_launcher_foreground.webp")
        inputs.dir(inputDir)
        outputs.file(output)
        doLast {
            val parts =
                inputDir.asFile
                    .listFiles { file -> file.name.matches(Regex("ic_launcher_foreground\\.part-\\d+")) }
                    .orEmpty()
                    .sortedBy { it.name }
            require(parts.isNotEmpty()) { "launcher icon chunks missing in icon-src/" }
            val encoded = parts.joinToString("") { it.readText().trim() }
            val bytes = java.util.Base64.getMimeDecoder().decode(encoded)
            output.asFile.parentFile.mkdirs()
            output.asFile.writeBytes(bytes)
        }
    }

android {
    namespace = "com.unknown.security"

    defaultConfig {
        applicationId = "com.unknown.security"
        versionCode = 1
        versionName = "1.0.0"
    }

    buildFeatures {
        buildConfig = true
    }

    sourceSets["main"].res.srcDir(launcherIconResDir.get().asFile)

    signingConfigs {
        create("release") {
            val storeFilePath = providers.environmentVariable("UNKNOWN_SIGNING_STORE").orNull
            val storePassword = providers.environmentVariable("UNKNOWN_SIGNING_STORE_PASSWORD").orNull
            val keyAlias = providers.environmentVariable("UNKNOWN_SIGNING_KEY_ALIAS").orNull
            val keyPassword = providers.environmentVariable("UNKNOWN_SIGNING_KEY_PASSWORD").orNull
            if (storeFilePath != null && storePassword != null && keyAlias != null && keyPassword != null) {
                storeFile = rootProject.file(storeFilePath)
                this.storePassword = storePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            val config = signingConfigs.getByName("release")
            if (config.storeFile != null) {
                signingConfig = config
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(decodeLauncherIcon)
}

dependencies {
    implementation(project(":core:common"))
    implementation(project(":core:model"))
    implementation(project(":core:persistence"))
    implementation(project(":core:designsystem"))
    implementation(project(":domain:engine"))
    implementation(project(":service:platform"))
    implementation(project(":service:accessibility"))
    implementation(project(":service:shizuku"))
    implementation(project(":service:root"))
    implementation(project(":service:deviceadmin"))
    implementation(project(":data:repository"))
    implementation(project(":feature:home"))
    implementation(project(":feature:scan"))
    implementation(project(":feature:shield"))
    implementation(project(":feature:rules"))
    implementation(project(":feature:settings"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
}
