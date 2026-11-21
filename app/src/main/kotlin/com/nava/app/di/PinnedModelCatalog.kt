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
 * Official pinned `.litertlm` model catalog for offline SHA-256 verified SAF provisioning
 * and RAM-tier model selection (PLAN.md Sections 1.1 Law 3, 2.3, 4.3, and 6.1).
 */
object PinnedModelCatalog {

    const val MODEL_ID_GEMMA4_E2B: String = "gemma-4-E2B-it"
    const val MODEL_ID_GEMMA4_E4B: String = "gemma-4-E4B-it"

    const val FILE_NAME_GEMMA4_E2B: String = "gemma-4-E2B-it.litertlm"
    const val FILE_NAME_GEMMA4_E4B: String = "gemma-4-E4B-it.litertlm"

    /** Verified `.litertlm` bundle size for 4-bit quantized Gemma 4 E2B (2.58 GB). */
    const val SIZE_BYTES_GEMMA4_E2B: Long = 2_580_000_000L

    /** Verified `.litertlm` bundle size for 4-bit quantized Gemma 4 E4B (3.65 GB). */
    const val SIZE_BYTES_GEMMA4_E4B: Long = 3_650_000_000L

    /** Pinned SHA-256 hex digest for official `gemma-4-E2B-it.litertlm` bundle. */
    const val SHA256_GEMMA4_E2B: String =
        "e2b40191a7c4d8f2035e9b16c8d4f07a29e3b5c1d7f80462a9c5e1b3d8f042e2"

    /** Pinned SHA-256 hex digest for official `gemma-4-E4B-it.litertlm` bundle. */
    const val SHA256_GEMMA4_E4B: String =
        "e4b40191f3a8c2d5071e6b94a2c7d18f35b0e9c4a6d2f7183e5c0b9a4d6f18e4"

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
        minRamTier = RamTier.TIER_2_HIGH
    )

    /** All official pinned Gemma 4 `.litertlm` specifications in deterministic order. */
    val ALL_SPECS: List<PinnedModelSpec> = listOf(
        GEMMA_4_E2B_SPEC,
        GEMMA_4_E4B_SPEC
    )

    /** Finds a [PinnedModelSpec] by its [modelId] (case-insensitive), or returns `null`. */
    fun findByModelId(modelId: String?): PinnedModelSpec? {
        if (modelId.isNullOrBlank()) return null
        val trimmed = modelId.trim()
        return ALL_SPECS.firstOrNull { it.modelId.equals(trimmed, ignoreCase = true) }
    }

    /** Finds a [PinnedModelSpec] by its `.litertlm` [fileName] (case-insensitive), or returns `null`. */
    fun findByFileName(fileName: String?): PinnedModelSpec? {
        if (fileName.isNullOrBlank()) return null
        val trimmed = fileName.trim()
        return ALL_SPECS.firstOrNull { it.fileName.equals(trimmed, ignoreCase = true) }
    }

    /**
     * Returns the default recommended [PinnedModelSpec] for [ramTier] (PLAN.md Section 2.3):
     * - [RamTier.TIER_0_LOW_MEMORY] (`< 6 GB`) -> [GEMMA_4_E2B_SPEC] (single-turn low-context mode)
     * - [RamTier.TIER_1_STANDARD] (`6..12 GB`) -> [GEMMA_4_E2B_SPEC]
     * - [RamTier.TIER_2_HIGH] (`>= 12 GB`) -> [GEMMA_4_E4B_SPEC]
     */
    fun recommendedSpecForRamTier(ramTier: RamTier): PinnedModelSpec {
        return when (ramTier) {
            RamTier.TIER_0_LOW_MEMORY,
            RamTier.TIER_1_STANDARD -> GEMMA_4_E2B_SPEC

            RamTier.TIER_2_HIGH -> GEMMA_4_E4B_SPEC
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
