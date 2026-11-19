package com.nava.domain.ai

/**
 * Pinned model specification for offline SHA-256 verified `.litertlm` provisioning
 * without `android.permission.INTERNET` (PLAN.md Section 1.1 Law 3 and Section 4.3).
 */
data class PinnedModelSpec(
    val modelId: String,
    val fileName: String,
    val expectedSha256Hex: String,
    val expectedSizeBytes: Long,
    val minRamTier: RamTier
) {
    init {
        require(modelId.isNotBlank()) { "PinnedModelSpec modelId must not be blank" }
        validateModelFileName(fileName, owner = "PinnedModelSpec")
        require(isValidSha256Hex(expectedSha256Hex)) {
            "PinnedModelSpec expectedSha256Hex must be a 64-character hex SHA-256 digest"
        }
        require(expectedSizeBytes > 0L) {
            "PinnedModelSpec expectedSizeBytes must be positive, got $expectedSizeBytes"
        }
    }
}

/**
 * Metadata for an offline `.litertlm` model bundle already copied into app-private storage
 * and verified against its SHA-256 digest.
 */
data class ProvisionedModelInfo(
    val modelId: String,
    val fileName: String,
    val absolutePath: String,
    val sha256Hex: String,
    val sizeBytes: Long,
    val verifiedAtEpochMs: Long
) {
    init {
        require(modelId.isNotBlank()) { "ProvisionedModelInfo modelId must not be blank" }
        validateModelFileName(fileName, owner = "ProvisionedModelInfo")
        require(absolutePath.isNotBlank()) { "ProvisionedModelInfo absolutePath must not be blank" }
        require('\u0000' !in absolutePath) {
            "ProvisionedModelInfo absolutePath must not contain NUL"
        }
        require(absolutePath.split('/', '\\').none { it == ".." }) {
            "ProvisionedModelInfo absolutePath must not contain parent directory traversal"
        }
        require(isValidSha256Hex(sha256Hex)) {
            "ProvisionedModelInfo sha256Hex must be a 64-character hex SHA-256 digest"
        }
        require(sizeBytes > 0L) {
            "ProvisionedModelInfo sizeBytes must be positive, got $sizeBytes"
        }
        require(verifiedAtEpochMs >= 0L) {
            "ProvisionedModelInfo verifiedAtEpochMs must be non-negative, got $verifiedAtEpochMs"
        }
    }
}

/**
 * Streaming copy and SHA-256 verification progress snapshot during offline SAF model import.
 */
data class ProvisioningProgress(
    val bytesCopied: Long,
    val totalBytes: Long
) {
    init {
        require(bytesCopied >= 0L) {
            "ProvisioningProgress bytesCopied must be non-negative, got $bytesCopied"
        }
        require(totalBytes >= 0L) {
            "ProvisioningProgress totalBytes must be non-negative, got $totalBytes"
        }
        require(totalBytes == 0L || bytesCopied <= totalBytes) {
            "ProvisioningProgress bytesCopied ($bytesCopied) must not exceed totalBytes ($totalBytes)"
        }
    }

    /** Normalized completion ratio in `[0f, 1f]`, or `0f` when [totalBytes] is unknown (`0L`). */
    val fraction: Float
        get() = if (totalBytes > 0L) {
            (bytesCopied.toDouble() / totalBytes.toDouble()).toFloat().coerceIn(0f, 1f)
        } else {
            0f
        }
}

/**
 * Pure Kotlin port for offline `.litertlm` model storage inspection, SHA-256 verification,
 * and lifecycle cleanup in app-private storage (`filesDir/models/`).
 */
interface ModelProvisionerPort {
    /** Returns the absolute path of the app-private models directory (`filesDir/models/`). */
    fun modelsDirectoryPath(): String

    /** Finds a previously provisioned and verified model by its [fileName], or `null` if absent. */
    suspend fun findProvisionedModel(fileName: String): ProvisionedModelInfo?

    /** Lists all provisioned `.litertlm` models currently present in app-private storage. */
    suspend fun listProvisionedModels(): List<ProvisionedModelInfo>

    /** Streams the file at [absolutePath] and verifies its SHA-256 digest matches [expectedSha256Hex]. */
    suspend fun verifyFileIntegrity(absolutePath: String, expectedSha256Hex: String): Boolean

    /** Deletes a provisioned model file by [fileName]; returns `true` if a file was removed. */
    suspend fun deleteProvisionedModel(fileName: String): Boolean
}

private const val MODEL_FILE_EXTENSION: String = ".litertlm"
private const val SHA256_HEX_LENGTH: Int = 64

private fun validateModelFileName(fileName: String, owner: String) {
    require(fileName.isNotBlank()) { "$owner fileName must not be blank" }
    require(fileName.endsWith(MODEL_FILE_EXTENSION) && fileName.length > MODEL_FILE_EXTENSION.length) {
        "$owner fileName must have a non-empty stem ending in '$MODEL_FILE_EXTENSION'"
    }
    require('/' !in fileName && '\\' !in fileName) {
        "$owner fileName must not contain path separators"
    }
    require(".." !in fileName) {
        "$owner fileName must not contain '..'"
    }
    require('\u0000' !in fileName) {
        "$owner fileName must not contain NUL"
    }
}

private fun isValidSha256Hex(value: String): Boolean {
    if (value.length != SHA256_HEX_LENGTH) return false
    for (ch in value) {
        val isHex = ch in '0'..'9' || ch in 'a'..'f' || ch in 'A'..'F'
        if (!isHex) return false
    }
    return true
}
