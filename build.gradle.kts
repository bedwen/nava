plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

val verifyArchitecture = tasks.register<Exec>("verifyArchitecture") {
    group = "verification"
    description = "Runs Gate 1 deterministic architecture, allowlist, isolation, and English/ASCII guards."
    workingDir = layout.projectDirectory.asFile
    commandLine("bash", "scripts/verify_architecture.sh")
}

subprojects {
    tasks.configureEach {
        if (name == "preBuild" || name == "check") {
            dependsOn(verifyArchitecture)
        }
    }
}
