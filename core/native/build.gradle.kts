plugins {
    id("unknown-android-library")
    // Kotlin support is built into AGP 9 — do NOT apply kotlin.android here.
}

android {
    namespace = "com.unknown.security.core.nativelib"
    ndkVersion = "27.2.12479018"

    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments += "-DUNKNOWN_NATIVE_BUILD_TESTS=OFF"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation(project(":core:model"))
}
