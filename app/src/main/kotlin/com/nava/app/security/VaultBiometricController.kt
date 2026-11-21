package com.nava.app.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.nava.core.security.vault.NavaVault
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * Localized labels displayed in the Android [BiometricPrompt] dialog for Nava Secure Vault.
 */
data class BiometricPromptLabels(
    val title: String = DEFAULT_TITLE,
    val subtitle: String = DEFAULT_SUBTITLE,
    val negativeButtonText: String = DEFAULT_NEGATIVE_BUTTON
) {
    init {
        require(title.isNotBlank()) { "BiometricPromptLabels title must not be blank" }
        require(negativeButtonText.isNotBlank()) {
            "BiometricPromptLabels negativeButtonText must not be blank"
        }
    }

    companion object {
        const val DEFAULT_TITLE: String = "Unlock Nava Secure Vault"
        const val DEFAULT_SUBTITLE: String =
            "Authenticate with strong biometrics to decrypt Nava Vault"
        const val DEFAULT_NEGATIVE_BUTTON: String = "Cancel"
    }
}

/**
 * Outcome returned by [BiometricPromptGateway.authenticate].
 */
sealed interface BiometricPromptGatewayOutcome {
    data class Authenticated(
        val cryptoObject: BiometricPrompt.CryptoObject
    ) : BiometricPromptGatewayOutcome

    data object Cancelled : BiometricPromptGatewayOutcome

    data class Error(
        val errorCode: Int,
        val message: String
    ) : BiometricPromptGatewayOutcome
}

/**
 * Typed outcome of [VaultBiometricController.unlock].
 */
sealed interface VaultUnlockResult {
    data object Unlocked : VaultUnlockResult
    data object Cancelled : VaultUnlockResult
    data class Failed(val errorCode: Int, val reason: String) : VaultUnlockResult
}

/**
 * Abstraction over AndroidX [BiometricPrompt] (`BIOMETRIC_STRONG`) enabling deterministic JVM unit
 * testing of hardware-bound [BiometricPrompt.CryptoObject] unlock flows.
 */
interface BiometricPromptGateway {
    suspend fun authenticate(
        activity: FragmentActivity?,
        cryptoObject: BiometricPrompt.CryptoObject,
        labels: BiometricPromptLabels
    ): BiometricPromptGatewayOutcome
}

/**
 * Production AndroidX [BiometricPrompt] implementation enforcing
 * [BiometricManager.Authenticators.BIOMETRIC_STRONG] and hardware-bound [BiometricPrompt.CryptoObject].
 */
class AndroidBiometricPromptGateway : BiometricPromptGateway {

    override suspend fun authenticate(
        activity: FragmentActivity?,
        cryptoObject: BiometricPrompt.CryptoObject,
        labels: BiometricPromptLabels
    ): BiometricPromptGatewayOutcome {
        if (activity == null) {
            return BiometricPromptGatewayOutcome.Error(
                errorCode = VaultBiometricController.ERROR_ACTIVITY_REQUIRED,
                message = "FragmentActivity is required to display BiometricPrompt"
            )
        }
        return withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { continuation ->
                val executor = ContextCompat.getMainExecutor(activity)
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!continuation.isActive) return
                        val authenticatedCrypto = result.cryptoObject
                        if (authenticatedCrypto == null || authenticatedCrypto.cipher == null) {
                            continuation.resume(
                                BiometricPromptGatewayOutcome.Error(
                                    errorCode = VaultBiometricController.ERROR_CRYPTO_OBJECT_MISSING,
                                    message = "BiometricPrompt succeeded without an authenticated CryptoObject"
                                )
                            )
                        } else {
                            continuation.resume(
                                BiometricPromptGatewayOutcome.Authenticated(authenticatedCrypto)
                            )
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!continuation.isActive) return
                        if (isUserCancellationCode(errorCode)) {
                            continuation.resume(BiometricPromptGatewayOutcome.Cancelled)
                        } else {
                            continuation.resume(
                                BiometricPromptGatewayOutcome.Error(
                                    errorCode = errorCode,
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                }

                val prompt = BiometricPrompt(activity, executor, callback)
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(labels.title)
                    .setSubtitle(labels.subtitle)
                    .setNegativeButtonText(labels.negativeButtonText)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(true)
                    .build()

                continuation.invokeOnCancellation {
                    runCatching { prompt.cancelAuthentication() }
                }

                prompt.authenticate(promptInfo, cryptoObject)
            }
        }
    }

    private fun isUserCancellationCode(errorCode: Int): Boolean {
        return errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
            errorCode == BiometricPrompt.ERROR_CANCELED
    }
}

/**
 * Coordinates hardware-bound `BiometricPrompt` (`BIOMETRIC_STRONG`) authentication with
 * [NavaVault.prepareUnlockCryptoObject], [NavaVault.unlockWithCryptoObject], and immediate RAM
 * zeroization on [lock] (PLAN.md Section 5.2).
 */
class VaultBiometricController(
    private val navaVault: NavaVault,
    private val promptGateway: BiometricPromptGateway = AndroidBiometricPromptGateway()
) {

    private val controllerMutex = Mutex()
    private val _isVaultUnlockedFlow = MutableStateFlow(false)

    /** Reactive state reflecting whether [NavaVault] is currently unlocked in memory. */
    val isVaultUnlockedFlow: StateFlow<Boolean> = _isVaultUnlockedFlow.asStateFlow()

    /**
     * Queries [NavaVault.isUnlocked] (which also enforces session timeout auto-lock) and
     * synchronizes [isVaultUnlockedFlow].
     */
    suspend fun refreshUnlockState(): Boolean {
        val unlocked = navaVault.isUnlocked()
        _isVaultUnlockedFlow.value = unlocked
        return unlocked
    }

    /**
     * Prepares a hardware-bound [BiometricPrompt.CryptoObject] from [NavaVault], prompts the user
     * for `BIOMETRIC_STRONG` authentication on [activity], and unlocks [NavaVault] on success.
     *
     * Fails closed (calling [NavaVault.lock] to zeroize RAM) on cancellation, error, or exception.
     */
    suspend fun unlock(
        activity: FragmentActivity,
        labels: BiometricPromptLabels = BiometricPromptLabels()
    ): VaultUnlockResult {
        return unlockInternal(activity = activity, labels = labels)
    }

    /**
     * Overload accepting a nullable [FragmentActivity] for JVM unit tests configured with a custom
     * [BiometricPromptGateway].
     */
    suspend fun unlockWithGateway(
        activity: FragmentActivity? = null,
        labels: BiometricPromptLabels = BiometricPromptLabels()
    ): VaultUnlockResult {
        return unlockInternal(activity = activity, labels = labels)
    }

    /**
     * Unlocks [NavaVault] directly with an already-authenticated [BiometricPrompt.CryptoObject].
     */
    suspend fun unlockWithCryptoObject(
        cryptoObject: BiometricPrompt.CryptoObject
    ): VaultUnlockResult = controllerMutex.withLock {
        try {
            navaVault.unlockWithCryptoObject(cryptoObject)
            val unlocked = navaVault.isUnlocked()
            _isVaultUnlockedFlow.value = unlocked
            if (unlocked) {
                VaultUnlockResult.Unlocked
            } else {
                navaVault.lock()
                _isVaultUnlockedFlow.value = false
                VaultUnlockResult.Failed(
                    errorCode = ERROR_CRYPTO_UNWRAP_FAILED,
                    reason = "Vault remained locked after CryptoObject unwrap"
                )
            }
        } catch (e: CancellationException) {
            navaVault.lock()
            _isVaultUnlockedFlow.value = false
            throw e
        } catch (e: Exception) {
            navaVault.lock()
            _isVaultUnlockedFlow.value = false
            VaultUnlockResult.Failed(
                errorCode = ERROR_CRYPTO_UNWRAP_FAILED,
                reason = e.message ?: "Failed to unlock Nava Vault with CryptoObject"
            )
        }
    }

    /**
     * Immediately locks [NavaVault], overwriting the in-memory DEK and all tracked decrypted
     * `ByteArray` buffers with `0x00` (`SecureMemory.zeroize`), and updates [isVaultUnlockedFlow]
     * to `false`.
     */
    suspend fun lock() = controllerMutex.withLock {
        navaVault.lock()
        _isVaultUnlockedFlow.value = false
    }

    private suspend fun unlockInternal(
        activity: FragmentActivity?,
        labels: BiometricPromptLabels
    ): VaultUnlockResult = controllerMutex.withLock {
        try {
            val preparedCrypto = navaVault.prepareUnlockCryptoObject()
            when (val outcome = promptGateway.authenticate(activity, preparedCrypto, labels)) {
                is BiometricPromptGatewayOutcome.Authenticated -> {
                    navaVault.unlockWithCryptoObject(outcome.cryptoObject)
                    val unlocked = navaVault.isUnlocked()
                    _isVaultUnlockedFlow.value = unlocked
                    if (unlocked) {
                        VaultUnlockResult.Unlocked
                    } else {
                        navaVault.lock()
                        _isVaultUnlockedFlow.value = false
                        VaultUnlockResult.Failed(
                            errorCode = ERROR_CRYPTO_UNWRAP_FAILED,
                            reason = "Vault failed to unlock after authentication"
                        )
                    }
                }

                BiometricPromptGatewayOutcome.Cancelled -> {
                    navaVault.lock()
                    _isVaultUnlockedFlow.value = false
                    VaultUnlockResult.Cancelled
                }

                is BiometricPromptGatewayOutcome.Error -> {
                    navaVault.lock()
                    _isVaultUnlockedFlow.value = false
                    VaultUnlockResult.Failed(
                        errorCode = outcome.errorCode,
                        reason = outcome.message
                    )
                }
            }
        } catch (e: CancellationException) {
            navaVault.lock()
            _isVaultUnlockedFlow.value = false
            throw e
        } catch (e: Exception) {
            navaVault.lock()
            _isVaultUnlockedFlow.value = false
            VaultUnlockResult.Failed(
                errorCode = ERROR_CRYPTO_PREPARE_FAILED,
                reason = e.message ?: "Failed to prepare or complete biometric unlock"
            )
        }
    }

    companion object {
        const val ERROR_ACTIVITY_REQUIRED: Int = -1001
        const val ERROR_CRYPTO_OBJECT_MISSING: Int = -1002
        const val ERROR_CRYPTO_PREPARE_FAILED: Int = -1003
        const val ERROR_CRYPTO_UNWRAP_FAILED: Int = -1004
    }
}
