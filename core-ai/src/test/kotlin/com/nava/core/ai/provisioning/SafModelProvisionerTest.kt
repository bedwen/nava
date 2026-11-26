package com.nava.core.ai.provisioning

import com.nava.core.ai.testing.FakeStorageSpaceProvider
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.ProvisioningProgress
import com.nava.domain.ai.RamTier
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

class SafModelProvisionerTest {

    private lateinit var modelsDir: File

    @Before
    fun setUp() {
        modelsDir = Files.createTempDirectory("nava_saf_models").toFile()
    }

    @After
    fun tearDown() {
        modelsDir.deleteRecursively()
    }

    @Test
    fun importsVerifiesListsAndDeletesModelOffline() = runTest {
        val payload = "gemma4-e2b-quantized-mock-weights".repeat(256).toByteArray()
        val expectedSha = sha256Hex(payload)
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = expectedSha,
            expectedSizeBytes = payload.size.toLong(),
            minRamTier = RamTier.TIER_0_LOW_MEMORY
        )
        val storage = FakeStorageSpaceProvider(
            availableBytesValue = payload.size.toLong() + SafModelProvisioner.SAFETY_HEADROOM_BYTES + 1024L
        )
        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = storage,
            clockMs = { 1_700_000_000_000L }
        )

        val progressEvents = mutableListOf<ProvisioningProgress>()
        val info = provisioner.importFromStream(
            inputStream = ByteArrayInputStream(payload),
            sourceSizeBytes = payload.size.toLong(),
            pinnedSpec = spec,
            onProgress = { progressEvents.add(it) }
        )

        assertEquals("gemma-4-E2B-it", info.modelId)
        assertEquals(expectedSha, info.sha256Hex)
        assertEquals(payload.size.toLong(), info.sizeBytes)
        assertTrue(progressEvents.isNotEmpty())
        assertEquals(payload.size.toLong(), progressEvents.last().bytesCopied)
        assertEquals(1.0f, progressEvents.last().fraction, 1e-4f)

        val found = provisioner.findProvisionedModel(spec.fileName)
        assertNotNull(found)
        assertEquals(expectedSha, found!!.sha256Hex)

        val listed = provisioner.listProvisionedModels()
        assertEquals(1, listed.size)
        assertTrue(provisioner.verifyFileIntegrity(info.absolutePath, expectedSha))
        assertFalse(provisioner.verifyFileIntegrity(info.absolutePath, "0".repeat(64)))

        assertTrue(provisioner.deleteProvisionedModel(spec.fileName))
        assertNull(provisioner.findProvisionedModel(spec.fileName))
    }

    @Test
    fun reusesInMemoryDigestCacheWithoutSidecarFilesAndStillHashesFreshOnVerify() = runTest {
        val payload = "cached-gemma4-e2b-weights".repeat(64).toByteArray()
        val expectedSha = sha256Hex(payload)
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = expectedSha,
            expectedSizeBytes = payload.size.toLong(),
            minRamTier = RamTier.TIER_1_STANDARD
        )
        val storage = FakeStorageSpaceProvider(
            availableBytesValue = payload.size.toLong() + SafModelProvisioner.SAFETY_HEADROOM_BYTES + 1024L
        )
        val provisioner = SafModelProvisioner(modelsDir, storage, clockMs = { 1_700_000_000_000L })

        val imported = provisioner.importFromStream(
            inputStream = ByteArrayInputStream(payload),
            sourceSizeBytes = payload.size.toLong(),
            pinnedSpec = spec
        )

        // Ensure zero sidecar files exist in modelsDir
        val filesAfterImport = modelsDir.listFiles()?.toList().orEmpty()
        assertEquals(1, filesAfterImport.size)
        assertTrue(filesAfterImport.single().name.endsWith(".litertlm"))

        // Tamper in-place keeping the exact same size and lastModified timestamp
        val targetFile = File(imported.absolutePath)
        val originalMtime = targetFile.lastModified()
        val tampered = payload.copyOf().apply { this[0] = (this[0].toInt() xor 0x01).toByte() }
        targetFile.writeBytes(tampered)
        targetFile.setLastModified(originalMtime)

        // findProvisionedModel / listProvisionedModels use metadata-keyed in-memory digest cache
        assertEquals(expectedSha, provisioner.findProvisionedModel(spec.fileName)!!.sha256Hex)
        assertEquals(expectedSha, provisioner.listProvisionedModels().single().sha256Hex)

        // verifyFileIntegrity MUST ALWAYS hash fresh from disk and detect tampering!
        assertFalse(provisioner.verifyFileIntegrity(imported.absolutePath, expectedSha))

        // Changing size or mtime invalidates cache entry
        val updatedPayload = payload + byteArrayOf(0x42)
        targetFile.writeBytes(updatedPayload)
        targetFile.setLastModified(originalMtime + 1000L)
        assertEquals(sha256Hex(updatedPayload), provisioner.findProvisionedModel(spec.fileName)!!.sha256Hex)
    }

    @Test
    fun rejectsInsufficientTwoTimesStorageHeadroom() = runTest {
        val payload = ByteArray(4096) { 0x5A }
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E4B-it",
            fileName = "gemma-4-E4B-it.litertlm",
            expectedSha256Hex = sha256Hex(payload),
            expectedSizeBytes = payload.size.toLong(),
            minRamTier = RamTier.TIER_2_HIGH
        )
        val insufficientStorage = FakeStorageSpaceProvider(
            availableBytesValue = SafModelProvisioner.SAFETY_HEADROOM_BYTES - 1L
        )
        val provisioner = SafModelProvisioner(modelsDir, insufficientStorage)

        try {
            provisioner.importFromStream(
                inputStream = ByteArrayInputStream(payload),
                sourceSizeBytes = payload.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected IllegalStateException when available storage < required 2x headroom")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message.orEmpty().contains("Insufficient storage"))
        }
        assertEquals(0, modelsDir.listFiles()?.size ?: 0)
    }

    @Test
    fun sha256MismatchThrowsSecurityExceptionAndLeavesZeroTempOrFinalFiles() = runTest {
        val payload = "corrupted-or-tampered-model-bytes".toByteArray()
        val wrongSha = "a".repeat(64)
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = wrongSha,
            expectedSizeBytes = payload.size.toLong(),
            minRamTier = RamTier.TIER_0_LOW_MEMORY
        )
        val storage = FakeStorageSpaceProvider(
            availableBytesValue = SafModelProvisioner.SAFETY_HEADROOM_BYTES + 1_000_000L
        )
        val provisioner = SafModelProvisioner(modelsDir, storage)

        try {
            provisioner.importFromStream(
                inputStream = ByteArrayInputStream(payload),
                sourceSizeBytes = payload.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected SecurityException on SHA-256 mismatch")
        } catch (_: SecurityException) {
            // Expected
        }

        val leftoverFiles = modelsDir.listFiles()?.toList().orEmpty()
        assertTrue("Expected zero leftover .tmp or .litertlm files, got $leftoverFiles", leftoverFiles.isEmpty())
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val chars = CharArray(digest.size * 2)
        val hex = "0123456789abcdef"
        for (i in digest.indices) {
            val v = digest[i].toInt() and 0xFF
            chars[i * 2] = hex[v ushr 4]
            chars[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(chars)
    }
}
