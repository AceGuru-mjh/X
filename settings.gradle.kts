pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "unknown-security"

include(":core:common")
include(":core:model")
include(":core:native")
include(":core:persistence")
include(":core:designsystem")
include(":domain:engine")
include(":service:platform")
include(":service:accessibility")
include(":service:shizuku")
include(":service:root")
include(":service:deviceadmin")
include(":data:repository")
include(":feature:home")
include(":feature:scan")
include(":feature:shield")
include(":feature:rules")
include(":feature:settings")
include(":app")
