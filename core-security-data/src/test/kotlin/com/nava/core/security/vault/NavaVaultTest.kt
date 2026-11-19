package com.nava.core.security.vault

import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import java.io.File
import java.io.FileNotFoundException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

@OptIn(ExperimentalCoroutinesApi::class)
class NavaVaultTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun firstTimeAndSubsequentUnlockReadWriteListDeleteAndLock() = runTest {
        val vaultDir = File(tempFolder.root, "vault")
        val keyProvider = InMemorySoftwareKeyProvider()
        var nowMs = 1_000_000L
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            sessionTimeoutMs = 60_000L,
            clockMs = { nowMs },
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        assertFalse(vault.isUnlocked())
        try {
            vault.listNoteIds()
            fail("Expected SecurityException when listing locked vault")
        } catch (_: SecurityException) {
            // Expected
        }

        val initCipher = vault.prepareUnlockCipher()
        vault.unlockWithAuthenticatedCipher(initCipher)
        assertTrue(vault.isUnlocked())

        val secretPayload = "Private Vault Entry".toByteArray(Charsets.UTF_8)
        vault.writeNote("passport_info", secretPayload)
        vault.writeNote("alpha_note", "Alpha".toByteArray(Charsets.UTF_8))

        assertEquals(listOf("alpha_note", "passport_info"), vault.listNoteIds())

        val readBack = vault.readNote("passport_info")
        assertArrayEquals("Private Vault Entry".toByteArray(Charsets.UTF_8), readBack)

        val scopedResult = vault.withDecryptedNote("alpha_note") { bytes ->
            bytes.toString(Charsets.UTF_8)
        }
        assertEquals("Alpha", scopedResult)

        vault.lock()
        assertFalse(vault.isUnlocked())
        assertTrue(readBack.all { it == 0.toByte() })

        try {
            vault.readNote("passport_info")
            fail("Expected SecurityException when reading locked vault")
        } catch (_: SecurityException) {
            // Expected
        }

        val secondVault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            sessionTimeoutMs = 60_000L,
            clockMs = { nowMs },
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val unlockCipher = secondVault.prepareUnlockCipher()
        secondVault.unlockWithAuthenticatedCipher(unlockCipher)
        assertTrue(secondVault.isUnlocked())

        val persisted = secondVault.readNote("passport_info")
        assertArrayEquals("Private Vault Entry".toByteArray(Charsets.UTF_8), persisted)

        secondVault.deleteNote("alpha_note")
        assertEquals(listOf("passport_info"), secondVault.listNoteIds())

        try {
            secondVault.readNote("missing_note")
            fail("Expected FileNotFoundException for missing note")
        } catch (_: FileNotFoundException) {
            // Expected
        }

        secondVault.close()
        assertFalse(secondVault.isUnlocked())
    }

    @Test
    fun unlockWithBiometricPromptCryptoObjectOnJvm() = runTest {
        val vaultDir = File(tempFolder.root, "vault_crypto_obj")
        val keyProvider = InMemorySoftwareKeyProvider()
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val cryptoObject = vault.prepareUnlockCryptoObject()
        assertNotNull(cryptoObject.cipher)
        vault.unlockWithCryptoObject(cryptoObject)
        assertTrue(vault.isUnlocked())

        vault.writeNote("biometric_note", "Verified".toByteArray(Charsets.UTF_8))
        val text = vault.withDecryptedNote("biometric_note") { it.toString(Charsets.UTF_8) }
        assertEquals("Verified", text)
        vault.lock()
    }

    @Test
    fun sessionTimeoutAutomaticallyLocksVaultAndZeroizesPlaintext() = runTest {
        val vaultDir = File(tempFolder.root, "vault_timeout")
        val keyProvider = InMemorySoftwareKeyProvider()
        var nowMs = 5_000L
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            sessionTimeoutMs = 10_000L,
            clockMs = { nowMs },
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val cipher = vault.prepareUnlockCipher()
        vault.unlockWithAuthenticatedCipher(cipher)
        vault.writeNote("note1", "Sensitive".toByteArray(Charsets.UTF_8))

        val buffer = vault.readNote("note1")
        assertEquals("Sensitive", buffer.toString(Charsets.UTF_8))

        nowMs += 10_000L
        assertTrue(vault.isUnlocked())

        nowMs += 1L
        assertFalse(vault.isUnlocked())
        assertTrue(buffer.all { it == 0.toByte() })

        try {
            vault.writeNote("note2", "Blocked".toByteArray(Charsets.UTF_8))
            fail("Expected SecurityException after session timeout")
        } catch (_: SecurityException) {
            // Expected
        }
    }
}
