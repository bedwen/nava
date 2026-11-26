package com.nava.app.di

import com.nava.core.ai.provisioning.SafModelProvisioner
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.RamTier
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.locale.QualityTier
import com.nava.domain.locale.SupportedLanguageCatalog

/**
 * Recommendation descriptor emitted when the user's active language has
 * [QualityTier.LOW_RESOURCE_E2B_WARNING] on Gemma 4 E2B and the device qualifies for E4B
 * ([RamTier.TIER_2_HIGH], `totalMem >= 12 GB`, PLAN.md Section 6.1).
 */
data class ModelQualitySuggestion(
    val currentModelId: String,
    val suggestedModelSpec: PinnedModelSpec,
    val languageEntry: LanguageEntry
)

/**
 * Roles for models provisioned in Nava's multi-model architecture.
 */
enum class PinnedModelRole {
    PRIMARY_LLM,
    FUNCTION_ROUTER,
    SEMANTIC_EMBEDDING
}

/**
 * Official pinned `.litertlm` model catalog for offline SHA-256 verified SAF provisioning
 * and RAM-tier model selection (PLAN.md Sections 1.1 Law 3, 2.3, 4.3, and 6.1).
 */
object PinnedModelCatalog {

    const val MODEL_ID_GEMMA4_E2B: String = "gemma-4-E2B-it"
    const val MODEL_ID_GEMMA4_E4B: String = "gemma-4-E4B-it"

    const val FILE_NAME_GEMMA4_E2B: String = "gemma-4-E2B-it.litertlm"
    const val FILE_NAME_GEMMA4_E4B: String = "gemma-4-E4B-it.litertlm"

    /** Verified `.litertlm` bundle size upper bound for 4-bit quantized Gemma 4 E2B (~2.59 GB). */
    const val SIZE_BYTES_GEMMA4_E2B: Long = 2_650_000_000L

    /** Verified `.litertlm` bundle size for 4-bit quantized Gemma 4 E4B (3,659,530,240 bytes). */
    const val SIZE_BYTES_GEMMA4_E4B: Long = 3_659_530_240L

    /** Pinned SHA-256 hex digest for official `gemma-4-E2B-it.litertlm` bundle. */
    const val SHA256_GEMMA4_E2B: String =
        "181938105e0eefd105961417e8da75903eacda102c4fce9ce90f50b97139a63c"

    /** Pinned SHA-256 hex digest for official `gemma-4-E4B-it.litertlm` bundle. */
    const val SHA256_GEMMA4_E4B: String =
        "0b2a8980ce155fd97673d8e820b4d29d9c7d99b8fa6806f425d969b145bd52e0"

    const val MODEL_ID_EMBEDDING_GEMMA: String = "embeddinggemma-2-740m"
    const val MODEL_ID_EMBEDDING_GEMMA_270M: String = "embeddinggemma-2-text-270m"
    const val MODEL_ID_MOBILE_ACTIONS: String = "mobile-actions-270m"

    const val FILE_NAME_EMBEDDING_GEMMA: String = "embeddinggemma-2-740m.litertlm"
    const val FILE_NAME_EMBEDDING_GEMMA_270M: String = "embeddinggemma-2-text-270m.litertlm"
    const val FILE_NAME_MOBILE_ACTIONS: String = "mobile-actions_q8_ekv1024.litertlm"

    const val SIZE_BYTES_EMBEDDING_GEMMA: Long = 510_000_000L
    const val SIZE_BYTES_EMBEDDING_GEMMA_270M: Long = 164_626_432L
    const val SIZE_BYTES_MOBILE_ACTIONS: Long = 298_000_000L

    const val SHA256_EMBEDDING_GEMMA: String =
        "e7a8a2204b91e0f96e92960e84a09a89212e1633dcb7575a9bf3378b4df77f4c"

    const val SHA256_EMBEDDING_GEMMA_270M: String =
        "2d079ee2f6f066b1f368e8d7c819f55214eaef1d0513b312321901f30ab286fb"

    const val SHA256_MOBILE_ACTIONS: String =
        "92109695f911d1872fa8ae07c1e3ff0ed70f2c3d1690d410ec6db8587c2ab409"

    val GEMMA_4_E2B_SPEC: PinnedModelSpec = PinnedModelSpec(
        modelId = MODEL_ID_GEMMA4_E2B,
        fileName = FILE_NAME_GEMMA4_E2B,
        expectedSha256Hex = SHA256_GEMMA4_E2B,
        expectedSizeBytes = SIZE_BYTES_GEMMA4_E2B,
        minRamTier = RamTier.TIER_0_LOW_MEMORY
    )

    val GEMMA_4_E4B_SPEC: PinnedModelSpec = PinnedModelSpec(
        modelId = MODEL_ID_GEMMA4_E4B,
        fileName = FILE_NAME_GEMMA4_E4B,
        expectedSha256Hex = SHA256_GEMMA4_E4B,
        expectedSizeBytes = SIZE_BYTES_GEMMA4_E4B,
        minRamTier = RamTier.TIER_1_STANDARD
    )

    val EMBEDDING_GEMMA_SPEC: PinnedModelSpec = PinnedModelSpec(
        modelId = MODEL_ID_EMBEDDING_GEMMA,
        fileName = FILE_NAME_EMBEDDING_GEMMA,
        expectedSha256Hex = SHA256_EMBEDDING_GEMMA,
        expectedSizeBytes = SIZE_BYTES_EMBEDDING_GEMMA,
        minRamTier = RamTier.TIER_1_STANDARD
    )

    val EMBEDDING_GEMMA_270M_SPEC: PinnedModelSpec = PinnedModelSpec(
        modelId = MODEL_ID_EMBEDDING_GEMMA_270M,
        fileName = FILE_NAME_EMBEDDING_GEMMA_270M,
        expectedSha256Hex = SHA256_EMBEDDING_GEMMA_270M,
        expectedSizeBytes = SIZE_BYTES_EMBEDDING_GEMMA_270M,
        minRamTier = RamTier.TIER_0_LOW_MEMORY
    )

    val MOBILE_ACTIONS_SPEC: PinnedModelSpec = PinnedModelSpec(
        modelId = MODEL_ID_MOBILE_ACTIONS,
        fileName = FILE_NAME_MOBILE_ACTIONS,
        expectedSha256Hex = SHA256_MOBILE_ACTIONS,
        expectedSizeBytes = SIZE_BYTES_MOBILE_ACTIONS,
        minRamTier = RamTier.TIER_0_LOW_MEMORY
    )

    /** Primary official pinned Gemma 4 `.litertlm` specifications in deterministic order. */
    val ALL_SPECS: List<PinnedModelSpec> = listOf(
        GEMMA_4_E2B_SPEC,
        GEMMA_4_E4B_SPEC
    )

    /** Optional power-user add-on `.litertlm` models (semantic memory & fast mobile actions). */
    val ADDON_SPECS: List<PinnedModelSpec> = listOf(
        MOBILE_ACTIONS_SPEC,
        EMBEDDING_GEMMA_270M_SPEC,
        EMBEDDING_GEMMA_SPEC
    )

    /** Finds a [PinnedModelSpec] by its [modelId] (case-insensitive), or returns `null`. */
    fun findByModelId(modelId: String?): PinnedModelSpec? {
        if (modelId.isNullOrBlank()) return null
        val trimmed = modelId.trim()
        return (ALL_SPECS + ADDON_SPECS).firstOrNull { it.modelId.equals(trimmed, ignoreCase = true) }
    }

    /** Finds a [PinnedModelSpec] by its `.litertlm` [fileName] (case-insensitive), or returns `null`. */
    fun findByFileName(fileName: String?): PinnedModelSpec? {
        if (fileName.isNullOrBlank()) return null
        val trimmed = fileName.trim()
        return (ALL_SPECS + ADDON_SPECS).firstOrNull { it.fileName.equals(trimmed, ignoreCase = true) }
    }

    /**
     * Returns the default recommended [PinnedModelSpec] for [ramTier] (PLAN.md Section 2.3):
     * Always defaults to [GEMMA_4_E2B_SPEC] across all RAM tiers for optimal battery, thermals,
     * and responsive on-device reasoning.
     */
    fun recommendedSpecForRamTier(ramTier: RamTier): PinnedModelSpec {
        return GEMMA_4_E2B_SPEC
    }

    /**
     * Resolves the operational [PinnedModelRole] slot for [modelId].
     */
    fun roleForModelId(modelId: String?): PinnedModelRole {
        if (modelId.isNullOrBlank()) return PinnedModelRole.PRIMARY_LLM
        val trimmed = modelId.trim()
        return when {
            trimmed.equals(MODEL_ID_MOBILE_ACTIONS, ignoreCase = true) ||
                trimmed.contains("mobile-actions", ignoreCase = true) -> PinnedModelRole.FUNCTION_ROUTER

            trimmed.startsWith("embeddinggemma", ignoreCase = true) ||
                trimmed.contains("embedding", ignoreCase = true) -> PinnedModelRole.SEMANTIC_EMBEDDING

            else -> PinnedModelRole.PRIMARY_LLM
        }
    }

    /**
     * Returns all models eligible to run on a device with [ramTier].
     * Tier 2 devices (`>= 12 GB`) may run either `E4B` or the `E2B` battery-saver profile.
     */
    fun eligibleSpecsForRamTier(ramTier: RamTier): List<PinnedModelSpec> {
        return ALL_SPECS.filter { spec -> spec.minRamTier.ordinal <= ramTier.ordinal }
    }

    /**
     * Returns the minimum internal `filesDir/models/` free space required before starting an
     * offline SAF copy of [spec] (`expectedSizeBytes + 256 MiB headroom`).
     */
    fun requiredInternalFreeBytesForImport(spec: PinnedModelSpec): Long {
        return spec.expectedSizeBytes + SafModelProvisioner.SAFETY_HEADROOM_BYTES
    }

    /**
     * Returns the total temporary 2x storage footprint across external download + internal copy
     * during SAF import (`2 * expectedSizeBytes + 256 MiB headroom`, PLAN.md Section 1.1 Law 3).
     */
    fun temporaryTwoTimesStorageBytes(spec: PinnedModelSpec): Long {
        return (spec.expectedSizeBytes * 2L) + SafModelProvisioner.SAFETY_HEADROOM_BYTES
    }

    /**
     * Returns `true` when Nava should suggest upgrading from Gemma 4 `E2B` to `E4B`:
     * - Device RAM is [RamTier.TIER_2_HIGH] (`totalMem >= 12 GB`),
     * - Currently selected/active model is `E2B`, and
     * - The active [languageEntry] is classified as [QualityTier.LOW_RESOURCE_E2B_WARNING]
     *   (PLAN.md Section 6.1).
     */
    fun shouldSuggestE4bUpgrade(
        activeModelId: String?,
        ramTier: RamTier,
        languageEntry: LanguageEntry?
    ): Boolean {
        if (ramTier != RamTier.TIER_2_HIGH) return false
        if (languageEntry?.qualityTier != QualityTier.LOW_RESOURCE_E2B_WARNING) return false
        val cleanedId = activeModelId?.trim().orEmpty()
        return cleanedId.equals(MODEL_ID_GEMMA4_E2B, ignoreCase = true)
    }

    /**
     * Evaluates whether an `E2B -> E4B` quality suggestion banner should be presented for
     * [activeLanguageTag] on a device of [ramTier] with [activeModelId], querying [catalog]
     * in a 100% data-driven manner (zero hardcoded language lists).
     */
    suspend fun evaluateQualitySuggestion(
        activeModelId: String?,
        ramTier: RamTier,
        activeLanguageTag: String,
        catalog: SupportedLanguageCatalog
    ): ModelQualitySuggestion? {
        val entry = catalog.findByTag(activeLanguageTag) ?: return null
        if (!shouldSuggestE4bUpgrade(activeModelId, ramTier, entry)) {
            return null
        }
        return ModelQualitySuggestion(
            currentModelId = MODEL_ID_GEMMA4_E2B,
            suggestedModelSpec = GEMMA_4_E4B_SPEC,
            languageEntry = entry
        )
    }
}
