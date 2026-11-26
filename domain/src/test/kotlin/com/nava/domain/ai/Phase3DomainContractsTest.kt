package com.nava.domain.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class Phase3DomainContractsTest {

    private val validSha256Lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    private val validSha256Upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

    @Test
    fun cachedActionTemplate_validConstructionSucceeds() {
        val template = CachedActionTemplate(
            languageCode = "en",
            canonicalSkeleton = "wake me up at \$TIME_0",
            toolNames = listOf("set_alarm"),
            toolSchemaVersions = mapOf("set_alarm" to 1),
            serializedPlanTemplate = "call:set_alarm{time:\$TIME_0}",
            lastUsedEpochSec = 1_700_000_000L
        )
        assertEquals("en", template.languageCode)
        assertEquals(listOf("set_alarm"), template.toolNames)
    }

    @Test
    fun cachedActionTemplate_rejectsInvalidFields() {
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(languageCode = "   ")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(canonicalSkeleton = "")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(languageCode = "en\u0000extra")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(canonicalSkeleton = "set alarm\u0000injected")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(toolNames = emptyList())
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(toolNames = listOf("set_alarm", " "))
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(serializedPlanTemplate = "\t")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(toolSchemaVersions = mapOf("" to 1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(toolSchemaVersions = mapOf("set_alarm" to 0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            validCachedTemplate(toolSchemaVersions = mapOf("set_alarm" to -3))
        }
    }

    @Test
    fun pinnedModelSpec_validConstructionSucceeds() {
        val lower = PinnedModelSpec(
            modelId = "gemma-4-e2b-it",
            fileName = "gemma-4-e2b-it.litertlm",
            expectedSha256Hex = validSha256Lower,
            expectedSizeBytes = 2_147_483_648L,
            minRamTier = RamTier.TIER_1_STANDARD
        )
        val upper = lower.copy(expectedSha256Hex = validSha256Upper)
        assertEquals("gemma-4-e2b-it.litertlm", lower.fileName)
        assertEquals(validSha256Upper, upper.expectedSha256Hex)
    }

    @Test
    fun pinnedModelSpec_rejectsInvalidFields() {
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(modelId = "")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = "gemma-4-e2b-it.bin")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = ".litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = "subdir/gemma.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = "subdir\\gemma.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = "..gemma.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(fileName = "gemma\u0000.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(expectedSha256Hex = validSha256Lower.dropLast(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(expectedSha256Hex = validSha256Lower + "0")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(expectedSha256Hex = "g" + validSha256Lower.drop(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(expectedSizeBytes = 0L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            validPinnedModelSpec(expectedSizeBytes = -10L)
        }
    }

    @Test
    fun provisionedModelInfo_validConstructionAndInvariantChecks() {
        val info = ProvisionedModelInfo(
            modelId = "gemma-4-e2b-it",
            fileName = "gemma-4-e2b-it.litertlm",
            absolutePath = "/data/user/0/com.nava/files/models/gemma-4-e2b-it.litertlm",
            sha256Hex = validSha256Lower,
            sizeBytes = 2_000_000_000L,
            verifiedAtEpochMs = 1_700_000_000_000L
        )
        assertEquals(2_000_000_000L, info.sizeBytes)

        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(modelId = " ")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(fileName = "model.tflite")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(fileName = "../model.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(absolutePath = "")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(absolutePath = "/data/files/models/\u0000model.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(absolutePath = "/data/files/../models/model.litertlm")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(sha256Hex = "not-a-sha256")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(sizeBytes = 0L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            validProvisionedInfo(verifiedAtEpochMs = -1L)
        }
    }

    @Test
    fun provisioningProgress_validatesBoundsAndFraction() {
        val half = ProvisioningProgress(bytesCopied = 50L, totalBytes = 100L)
        assertEquals(0.5f, half.fraction, 0.0001f)

        val unknownTotal = ProvisioningProgress(bytesCopied = 1024L, totalBytes = 0L)
        assertEquals(0f, unknownTotal.fraction, 0.0001f)

        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningProgress(bytesCopied = -1L, totalBytes = 100L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningProgress(bytesCopied = 0L, totalBytes = -1L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningProgress(bytesCopied = 101L, totalBytes = 100L)
        }
    }

    @Test
    fun ramTier_usesUniversalE2bDefaultAndOptimalContextTokens() {
        assertEquals("gemma-4-E2B-it", RamTier.TIER_0_LOW_MEMORY.recommendedModelTag)
        assertEquals("gemma-4-E2B-it", RamTier.TIER_1_STANDARD.recommendedModelTag)
        assertEquals("gemma-4-E2B-it", RamTier.TIER_2_HIGH.recommendedModelTag)

        assertEquals(1024, RamTier.TIER_0_LOW_MEMORY.defaultContextTokens)
        assertEquals(4096, RamTier.TIER_1_STANDARD.defaultContextTokens)
        assertEquals(4096, RamTier.TIER_2_HIGH.defaultContextTokens)

        assertEquals(1024, RamTier.TIER_0_LOW_MEMORY.e2bOptimalContextTokens)
        assertEquals(2048, RamTier.TIER_1_STANDARD.e2bOptimalContextTokens)
        assertEquals(2048, RamTier.TIER_2_HIGH.e2bOptimalContextTokens)
    }

    @Test
    fun resolutionTier_ordersFunctionGemmaBetweenCacheAndGemma3() {
        assertTrue(ResolutionTier.TIER_1_RULE.ordinal < ResolutionTier.TIER_2_CACHE.ordinal)
        assertTrue(ResolutionTier.TIER_2_CACHE.ordinal < ResolutionTier.TIER_2_5_FUNCTION_GEMMA.ordinal)
        assertTrue(ResolutionTier.TIER_2_5_FUNCTION_GEMMA.ordinal < ResolutionTier.TIER_3_GEMMA.ordinal)
    }

    @Test
    fun embeddingPort_cosineSimilarityHandlesValidAndDegenerateVectors() {
        assertEquals(1f, EmbeddingPort.cosineSimilarity(floatArrayOf(1f, 2f, 3f), floatArrayOf(2f, 4f, 6f)), 1e-5f)
        assertEquals(0f, EmbeddingPort.cosineSimilarity(floatArrayOf(1f, 0f), floatArrayOf(0f, 1f)), 1e-5f)
        assertEquals(-1f, EmbeddingPort.cosineSimilarity(floatArrayOf(1f, -2f), floatArrayOf(-1f, 2f)), 1e-5f)
        assertEquals(0f, EmbeddingPort.cosineSimilarity(floatArrayOf(1f, 2f), floatArrayOf(1f)), 1e-5f)
        assertEquals(0f, EmbeddingPort.cosineSimilarity(floatArrayOf(), floatArrayOf()), 1e-5f)
        assertEquals(0f, EmbeddingPort.cosineSimilarity(floatArrayOf(0f, 0f), floatArrayOf(1f, 1f)), 1e-5f)
        assertEquals(0f, EmbeddingPort.cosineSimilarity(floatArrayOf(Float.NaN, 1f), floatArrayOf(1f, 1f)), 1e-5f)
    }

    private fun validCachedTemplate(
        languageCode: String = "en",
        canonicalSkeleton: String = "set alarm at \$TIME_0",
        toolNames: List<String> = listOf("set_alarm"),
        toolSchemaVersions: Map<String, Int> = mapOf("set_alarm" to 1),
        serializedPlanTemplate: String = "call:set_alarm{time:\$TIME_0}",
        lastUsedEpochSec: Long = 100L
    ): CachedActionTemplate = CachedActionTemplate(
        languageCode = languageCode,
        canonicalSkeleton = canonicalSkeleton,
        toolNames = toolNames,
        toolSchemaVersions = toolSchemaVersions,
        serializedPlanTemplate = serializedPlanTemplate,
        lastUsedEpochSec = lastUsedEpochSec
    )

    private fun validPinnedModelSpec(
        modelId: String = "gemma-4-e2b-it",
        fileName: String = "gemma-4-e2b-it.litertlm",
        expectedSha256Hex: String = validSha256Lower,
        expectedSizeBytes: Long = 1024L,
        minRamTier: RamTier = RamTier.TIER_1_STANDARD
    ): PinnedModelSpec = PinnedModelSpec(
        modelId = modelId,
        fileName = fileName,
        expectedSha256Hex = expectedSha256Hex,
        expectedSizeBytes = expectedSizeBytes,
        minRamTier = minRamTier
    )

    private fun validProvisionedInfo(
        modelId: String = "gemma-4-e2b-it",
        fileName: String = "gemma-4-e2b-it.litertlm",
        absolutePath: String = "/data/user/0/com.nava/files/models/gemma-4-e2b-it.litertlm",
        sha256Hex: String = validSha256Lower,
        sizeBytes: Long = 1024L,
        verifiedAtEpochMs: Long = 1000L
    ): ProvisionedModelInfo = ProvisionedModelInfo(
        modelId = modelId,
        fileName = fileName,
        absolutePath = absolutePath,
        sha256Hex = sha256Hex,
        sizeBytes = sizeBytes,
        verifiedAtEpochMs = verifiedAtEpochMs
    )
}
