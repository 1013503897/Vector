import org.apache.tools.ant.DirectoryScanner

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

// Gradle 9.3+ forbids changing Ant's default excludes during the build and requires them to be
// configured in the settings script. Depending on the daemon's JVM state, AGP/Kotlin (via lazy
// Ant DirectoryScanner initialization) may add the git-file patterns during project configuration,
// which triggers:
//   "Cannot change default excludes during the build. They were changed from [...] to
//    [... **/.gitattributes ...]. Configure default excludes in the settings script instead."
// Pin the modern git-file patterns here so the build-time set is already complete and never changes
// during configuration. addDefaultExclude is idempotent, so this is a no-op when the bundled Ant
// already contains them.
DirectoryScanner.addDefaultExclude("**/.gitattributes")
DirectoryScanner.addDefaultExclude("**/.gitignore")
DirectoryScanner.addDefaultExclude("**/.gitmodules")

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
