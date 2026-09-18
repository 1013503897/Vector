// Gradle 9 forbids changing Ant's default excludes during the build. Gradle 9.3.1 bundles
// Ant 1.10.15, whose native default excludes include **/.gitattributes; a config-time
// DirectoryScanner init (reached while configuring the Android modules, e.g. :daemon) restores
// that native set, which diverges from Gradle's curated baseline (no .gitattributes) and aborts
// with "Cannot change default excludes during the build". Bless the native set as the
// settings-provided baseline via the supported PatternSpecFactory API (the mechanism the error
// message itself points to), so the later config-time state matches and no change is flagged.
run {
    org.apache.tools.ant.DirectoryScanner.addDefaultExclude("**/.gitattributes")
    org.gradle.api.tasks.util.internal.PatternSpecFactory.INSTANCE
        .setDefaultExcludesFromSettings(org.apache.tools.ant.DirectoryScanner.getDefaultExcludes())
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Vector"

include(
    ":app",
    ":daemon",
    ":dex2oat",
    ":external:axml",
    ":external:apache",
    ":hiddenapi:stubs",
    ":hiddenapi:bridge",
    ":legacy",
    ":services:manager-service",
    ":services:daemon-service",
    ":xposed",
    ":zygisk",
)
