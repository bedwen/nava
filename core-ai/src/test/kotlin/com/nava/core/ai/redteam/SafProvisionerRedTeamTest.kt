package com.nava.core.ai.redteam

import com.nava.core.ai.provisioning.SafModelProvisioner
import com.nava.core.ai.provisioning.StorageSpaceProvider
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.RamTier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest

/**
 * Independent Gate 2 adversarial security suite for [SafModelProvisioner]:
 * path traversal, non-`.litertlm` extensions, SHA-256 1-bit tamper rejection,
 * existing-model preservation on failed re-import, 2x storage headroom & overflow defense,
 * mid-stream IOException cleanup, and symlink/traversal containment in `verifyFileIntegrity`
 * (PLAN.md Sections 1.1 Law 3, 4.3, 8.3).
 */
class SafProvisionerRedTeamTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun pathTraversalNulAndNonLitertlmExtensionsAreRejectedWithZeroFilesWritten() = runTest {
        val sandboxRoot = tempFolder.newFolder("sandbox")
        val modelsDir = File(sandboxRoot, "models")
        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(4L * 1024L * 1024L * 1024L)
        )
        val validSha = sha256Hex("model-bytes".toByteArray())

        val maliciousNames = listOf(
            "../evil.litertlm",
            "sub/model.litertlm",
            "sub\\model.litertlm",
            "..\\evil.litertlm",
            "model.litertlm\u0000.txt",
            "model\u0000.litertlm",
            "payload.apk",
            "libevil.so",
            "weights.bin",
            ".litertlm",
            "   "
        )

        for (badName in maliciousNames) {
            // 1. PinnedModelSpec rejects bad file names immediately.
            try {
                PinnedModelSpec(
                    modelId = "bad",
                    fileName = badName,
                    expectedSha256Hex = validSha,
                    expectedSizeBytes = 11L,
                    minRamTier = RamTier.TIER_1_STANDARD
                )
                fail("PinnedModelSpec MUST reject malicious fileName '$badName'")
            } catch (_: IllegalArgumentException) {
                // Expected
            } catch (_: SecurityException) {
                // Expected
            }

            // 2. findProvisionedModel MUST also reject malicious file names directly.
            try {
                provisioner.findProvisionedModel(badName)
                fail("findProvisionedModel MUST reject malicious fileName '$badName'")
            } catch (_: IllegalArgumentException) {
                // Expected
            } catch (_: SecurityException) {
                // Expected
            }

            // 3. deleteProvisionedModel MUST also reject malicious file names directly.
            try {
                provisioner.deleteProvisionedModel(badName)
                fail("deleteProvisionedModel MUST reject malicious fileName '$badName'")
            } catch (_: IllegalArgumentException) {
                // Expected
            } catch (_: SecurityException) {
                // Expected
            }
        }

        // Verify zero files were written outside or inside modelsDir.
        val outsideFiles = sandboxRoot.listFiles()?.filter { it != modelsDir } ?: emptyList()
        assertTrue("No files may exist outside modelsDir: $outsideFiles", outsideFiles.isEmpty())
        val insideFiles = modelsDir.listFiles()?.toList() ?: emptyList()
        assertTrue("No files may exist inside modelsDir: $insideFiles", insideFiles.isEmpty())
    }

    @Test
    fun singleBitSha256MismatchDeletesTempFileAndPreservesExistingValidModel() = runTest {
        val modelsDir = tempFolder.newFolder("models_sha")
        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(8L * 1024L * 1024L * 1024L),
            clockMs = { 1_700_000_000_000L }
        )

        val validBytes = ByteArray(8192) { idx -> ((idx * 31) and 0xFF).toByte() }
        val validSha = sha256Hex(validBytes)
        val flippedBytes = validBytes.copyOf().apply {
            this[4096] = (this[4096].toInt() xor 0x01).toByte()
        }

        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = validSha,
            expectedSizeBytes = validBytes.size.toLong(),
            minRamTier = RamTier.TIER_1_STANDARD
        )

        // 1. Fresh import with 1-bit flip MUST throw SecurityException and leave ZERO files.
        try {
            provisioner.importFromStream(
                inputStream = ByteArrayInputStream(flippedBytes),
                sourceSizeBytes = flippedBytes.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected SecurityException on 1-bit SHA-256 mismatch")
        } catch (_: SecurityException) {
            // Expected
        }
        assertTrue(
            "modelsDir must contain ZERO .litertlm or .tmp files after failed initial import",
            modelsDir.listFiles().isNullOrEmpty()
        )

        // 2. Import valid model successfully.
        val installed = provisioner.importFromStream(
            inputStream = ByteArrayInputStream(validBytes),
            sourceSizeBytes = validBytes.size.toLong(),
            pinnedSpec = spec
        )
        assertEquals(validSha, installed.sha256Hex)
        val installedFile = File(installed.absolutePath)
        assertTrue(installedFile.exists())

        // 3. Re-import with 1-bit tampered stream MUST fail AND leave existing valid model intact!
        try {
            provisioner.importFromStream(
                inputStream = ByteArrayInputStream(flippedBytes),
                sourceSizeBytes = flippedBytes.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected SecurityException on tampered re-import")
        } catch (_: SecurityException) {
            // Expected
        }

        assertTrue("Existing verified model MUST remain intact", installedFile.exists())
        assertArrayEquals("Existing model bytes MUST NOT be overwritten", validBytes, installedFile.readBytes())
        assertFalse(
            "No .tmp artifact may remain after failed re-import",
            modelsDir.listFiles()!!.any { it.name.endsWith(".tmp") }
        )
    }

    @Test
    fun insufficientStorageAndIntegerOverflowFailBeforeWritingAnyBytes() = runTest {
        val modelsDir = tempFolder.newFolder("models_storage")
        val payload = ByteArray(4096) { 0x5A }
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = sha256Hex(payload),
            expectedSizeBytes = payload.size.toLong(),
            minRamTier = RamTier.TIER_1_STANDARD
        )

        // Available bytes is 1 byte short of (size + 256 MiB safety headroom).
        val shortBytes = payload.size.toLong() + SafModelProvisioner.SAFETY_HEADROOM_BYTES - 1L
        val provisionerShort = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(shortBytes)
        )
        val probeStream1 = ReadCountingInputStream(payload)
        try {
            provisionerShort.importFromStream(
                inputStream = probeStream1,
                sourceSizeBytes = payload.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected IllegalStateException when availableBytes < size + 256 MiB")
        } catch (_: IllegalStateException) {
            // Expected
        }
        assertEquals("Stream MUST NOT be read when storage headroom is insufficient", 0, probeStream1.readCalls)
        assertTrue("Zero files may be created when storage check fails", modelsDir.listFiles().isNullOrEmpty())

        // Adversarial ContentProvider reporting sourceSizeBytes = Long.MAX_VALUE MUST NOT overflow
        // `effectiveSizeBytes + SAFETY_HEADROOM_BYTES` to negative and bypass the storage check!
        val provisionerTiny = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(1024L)
        )
        val probeStream2 = ReadCountingInputStream(payload)
        try {
            provisionerTiny.importFromStream(
                inputStream = probeStream2,
                sourceSizeBytes = Long.MAX_VALUE,
                pinnedSpec = spec
            )
            fail("Long.MAX_VALUE sourceSizeBytes MUST throw IllegalStateException (integer overflow bypass prevented)")
        } catch (_: IllegalStateException) {
            // Expected
        } catch (_: IllegalArgumentException) {
            // Also acceptable
        }
        assertEquals("Stream MUST NOT be read on overflowing sourceSizeBytes", 0, probeStream2.readCalls)
        assertTrue("Zero files may be created on overflowing sourceSizeBytes", modelsDir.listFiles().isNullOrEmpty())
    }

    @Test
    fun midStreamIoExceptionDeletesTempFileAndLeavesZeroPartialArtifacts() = runTest {
        val modelsDir = tempFolder.newFolder("models_ioerr")
        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(4L * 1024L * 1024L * 1024L)
        )

        val expectedPayload = ByteArray(16_384) { (it and 0xFF).toByte() }
        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = sha256Hex(expectedPayload),
            expectedSizeBytes = expectedPayload.size.toLong(),
            minRamTier = RamTier.TIER_1_STANDARD
        )

        val failingStream = object : InputStream() {
            private var emitted = 0
            override fun read(): Int = throw IOException("Simulated single-byte read error")
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (emitted == 0) {
                    val chunk = minOf(len, 4096)
                    for (i in 0 until chunk) {
                        b[off + i] = expectedPayload[i]
                    }
                    emitted += chunk
                    return chunk
                }
                throw IOException("Simulated SAF stream disconnect mid-copy")
            }
        }

        try {
            provisioner.importFromStream(
                inputStream = failingStream,
                sourceSizeBytes = expectedPayload.size.toLong(),
                pinnedSpec = spec
            )
            fail("Expected IOException from truncated/failing SAF stream")
        } catch (_: IOException) {
            // Expected
        }

        assertTrue(
            "modelsDir must contain ZERO partial .tmp or .litertlm artifacts after mid-stream IOException",
            modelsDir.listFiles().isNullOrEmpty()
        )
    }

    @Test
    fun verifyFileIntegrityRejectsSymlinkEscapesPathTraversalSiblingPrefixAndTamperedFiles() = runTest {
        val root = tempFolder.newFolder("integrity_root")
        val modelsDir = File(root, "models").apply { mkdirs() }
        val siblingEvilDir = File(root, "models_evil").apply { mkdirs() }

        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(4L * 1024L * 1024L * 1024L)
        )

        val bytes = "authentic-gemma4-weights".toByteArray()
        val digest = sha256Hex(bytes)

        // Valid model inside modelsDir -> MUST pass
        val legitimateFile = File(modelsDir, "gemma-4-E2B-it.litertlm").apply { writeBytes(bytes) }
        assertTrue(provisioner.verifyFileIntegrity(legitimateFile.absolutePath, digest))

        // 1. Outside file accessed via path traversal `models/../outside.litertlm` -> MUST fail
        val outsideFile = File(root, "outside.litertlm").apply { writeBytes(bytes) }
        val traversalPath = modelsDir.absolutePath + File.separator + ".." + File.separator + "outside.litertlm"
        assertFalse(
            "Path traversal outside modelsDir MUST be rejected",
            provisioner.verifyFileIntegrity(traversalPath, digest)
        )

        // 2. Sibling directory with matching string prefix (`models_evil/evil.litertlm`) -> MUST fail
        val siblingFile = File(siblingEvilDir, "evil.litertlm").apply { writeBytes(bytes) }
        assertFalse(
            "Sibling directory prefix bypass MUST be rejected",
            provisioner.verifyFileIntegrity(siblingFile.absolutePath, digest)
        )

        // 3. Symlink inside modelsDir pointing to outsideFile -> MUST fail
        val symlinkFile = File(modelsDir, "symlink_escape.litertlm")
        Files.createSymbolicLink(symlinkFile.toPath(), outsideFile.toPath())
        assertFalse(
            "Symlink inside modelsDir escaping outside MUST be rejected",
            provisioner.verifyFileIntegrity(symlinkFile.absolutePath, digest)
        )

        // 4. Non-.litertlm file inside modelsDir -> MUST fail
        val nonModelFile = File(modelsDir, "not_a_model.bin").apply { writeBytes(bytes) }
        assertFalse(
            "Non-.litertlm file MUST be rejected by verifyFileIntegrity",
            provisioner.verifyFileIntegrity(nonModelFile.absolutePath, digest)
        )

        // 5. Path with NUL byte -> MUST fail
        assertFalse(
            "NUL byte in path MUST be rejected",
            provisioner.verifyFileIntegrity(legitimateFile.absolutePath + "\u0000", digest)
        )

        // 6. Tampered file (1-bit flip) -> MUST fail
        val tampered = bytes.copyOf().apply { this[0] = (this[0].toInt() xor 0x01).toByte() }
        legitimateFile.writeBytes(tampered)
        assertFalse(
            "Tampered file inside modelsDir MUST fail SHA-256 verification",
            provisioner.verifyFileIntegrity(legitimateFile.absolutePath, digest)
        )
    }

    @Test
    fun concurrentImportsForSameModelSerializeCleanlyWithoutTmpCorruption() = runTest {
        val modelsDir = tempFolder.newFolder("models_concurrent")
        val provisioner = SafModelProvisioner(
            modelsDir = modelsDir,
            storageSpaceProvider = FixedStorageProvider(8L * 1024L * 1024L * 1024L),
            clockMs = { 1_700_000_000_000L }
        )

        val validBytes = ByteArray(256 * 1024) { idx -> ((idx * 17 + 3) and 0xFF).toByte() }
        val validSha = sha256Hex(validBytes)
        val corruptedBytes = validBytes.copyOf().apply {
            this[100_000] = (this[100_000].toInt() xor 0x01).toByte()
        }

        val spec = PinnedModelSpec(
            modelId = "gemma-4-E2B-it",
            fileName = "gemma-4-E2B-it.litertlm",
            expectedSha256Hex = validSha,
            expectedSizeBytes = validBytes.size.toLong(),
            minRamTier = RamTier.TIER_1_STANDARD
        )

        val outcomes = coroutineScope {
            listOf(
                async(Dispatchers.Default) {
                    runCatching {
                        provisioner.importFromStream(
                            inputStream = ChunkedByteArrayInputStream(validBytes, chunkSize = 8192),
                            sourceSizeBytes = validBytes.size.toLong(),
                            pinnedSpec = spec
                        )
                    }
                },
                async(Dispatchers.Default) {
                    runCatching {
                        provisioner.importFromStream(
                            inputStream = ChunkedByteArrayInputStream(corruptedBytes, chunkSize = 8192),
                            sourceSizeBytes = corruptedBytes.size.toLong(),
                            pinnedSpec = spec
                        )
                    }
                },
                async(Dispatchers.Default) {
                    runCatching {
                        provisioner.importFromStream(
                            inputStream = ChunkedByteArrayInputStream(validBytes, chunkSize = 8192),
                            sourceSizeBytes = validBytes.size.toLong(),
                            pinnedSpec = spec
                        )
                    }
                },
                async(Dispatchers.Default) {
                    runCatching {
                        provisioner.importFromStream(
                            inputStream = ChunkedByteArrayInputStream(validBytes, chunkSize = 8192),
                            sourceSizeBytes = validBytes.size.toLong(),
                            pinnedSpec = spec
                        )
                    }
                }
            ).awaitAll()
        }

        // Index 1 is the corrupted stream and MUST fail with SecurityException.
        val corruptedOutcome = outcomes[1]
        assertTrue("Corrupted concurrent stream MUST fail", corruptedOutcome.isFailure)
        assertTrue(
            "Corrupted concurrent stream MUST throw SecurityException, got ${corruptedOutcome.exceptionOrNull()}",
            corruptedOutcome.exceptionOrNull() is SecurityException
        )

        // Indices 0, 2, 3 are valid streams and MUST all succeed cleanly.
        for (validIdx in listOf(0, 2, 3)) {
            val outcome = outcomes[validIdx]
            assertTrue(
                "Valid concurrent stream $validIdx MUST succeed, got ${outcome.exceptionOrNull()}",
                outcome.isSuccess
            )
            val info = outcome.getOrThrow()
            assertEquals(validSha, info.sha256Hex)
            assertEquals(validBytes.size.toLong(), info.sizeBytes)
        }

        val dirEntries = modelsDir.listFiles()?.toList() ?: emptyList()
        assertFalse(
            "Zero .tmp files may remain after concurrent imports: $dirEntries",
            dirEntries.any { it.name.endsWith(".tmp") }
        )
        val finalFile = File(modelsDir, spec.fileName)
        assertTrue("Final verified .litertlm model file must exist", finalFile.exists() && finalFile.isFile)
        assertTrue(
            "Final .litertlm model file MUST pass verifyFileIntegrity after concurrent imports",
            provisioner.verifyFileIntegrity(finalFile.absolutePath, validSha)
        )
    }

    private class ChunkedByteArrayInputStream(
        private val data: ByteArray,
        private val chunkSize: Int
    ) : InputStream() {
        private var pos: Int = 0

        override fun read(): Int {
            return if (pos < data.size) data[pos++].toInt() and 0xFF else -1
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (pos >= data.size) return -1
            val toCopy = minOf(len, chunkSize, data.size - pos)
            System.arraycopy(data, pos, b, off, toCopy)
            pos += toCopy
            return toCopy
        }
    }

    private class FixedStorageProvider(private val bytes: Long) : StorageSpaceProvider {
        override fun availableBytes(directory: File): Long = bytes
    }

    private class ReadCountingInputStream(data: ByteArray) : InputStream() {
        private val delegate = ByteArrayInputStream(data)
        var readCalls: Int = 0

        override fun read(): Int {
            readCalls++
            return delegate.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            readCalls++
            return delegate.read(b, off, len)
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val hex = "0123456789abcdef"
        val chars = CharArray(digest.size * 2)
        for (i in digest.indices) {
            val v = digest[i].toInt() and 0xFF
            chars[i * 2] = hex[v ushr 4]
            chars[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(chars)
    }
}
