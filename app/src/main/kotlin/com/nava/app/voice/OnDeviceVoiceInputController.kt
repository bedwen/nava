package com.nava.app.voice

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import com.nava.domain.security.Gemma4InputSanitizer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * State machine for 100% offline on-device voice recognition (PLAN.md Sections 2.3, 4.2, and 6.4).
 */
sealed interface VoiceInputState {
    data object Idle : VoiceInputState

    data class Listening(
        val localeTag: String
    ) : VoiceInputState

    data class PartialTranscript(
        val text: String,
        val localeTag: String
    ) : VoiceInputState

    data class FinalTranscript(
        val text: String,
        val localeTag: String
    ) : VoiceInputState

    /**
     * Explicit state surfaced when on-device speech recognition or the offline language pack for
     * [localeTag] is not installed on the device. Nava never falls back to network speech services.
     */
    data class OfflinePackMissing(
        val localeTag: String
    ) : VoiceInputState

    data class Error(
        val errorCode: Int,
        val message: String,
        val localeTag: String
    ) : VoiceInputState
}

/**
 * Immutable configuration for an offline speech recognition session.
 *
 * Security invariant: [preferOffline] must always be `true`; Nava holds zero `INTERNET` permission
 * and forbids cloud speech recognition fallback.
 */
data class OnDeviceSpeechConfig(
    val localeTag: String,
    val preferOffline: Boolean = true,
    val partialResults: Boolean = true,
    val languageModel: String = RecognizerIntent.LANGUAGE_MODEL_FREE_FORM
) {
    init {
        require(localeTag.isNotBlank()) { "OnDeviceSpeechConfig localeTag must not be blank" }
        require(preferOffline) {
            "Nava forbids online speech recognition; EXTRA_PREFER_OFFLINE must be true"
        }
    }
}

/**
 * Callback contract between [OnDeviceSpeechRecognizerGateway] and [OnDeviceVoiceInputController].
 */
interface OnDeviceSpeechListener {
    fun onReadyForSpeech()
    fun onPartialTranscript(text: String)
    fun onFinalTranscript(text: String)
    fun onOfflinePackMissing(localeTag: String)
    fun onError(errorCode: Int, message: String)
}

/**
 * JVM-testable gateway wrapping Android API 31+ [SpeechRecognizer.createOnDeviceSpeechRecognizer]
 * and [SpeechRecognizer.isOnDeviceRecognitionAvailable].
 */
interface OnDeviceSpeechRecognizerGateway {
    fun isOnDeviceRecognitionAvailable(): Boolean
    fun startListening(config: OnDeviceSpeechConfig, listener: OnDeviceSpeechListener)
    fun stopListening()
    fun cancel()
    fun destroy()
}

/**
 * Production Android API 31+ implementation of [OnDeviceSpeechRecognizerGateway].
 *
 * Invariants (PLAN.md Sections 2.3 & 6.4):
 * - Checks [SpeechRecognizer.isOnDeviceRecognitionAvailable] before creating a recognizer.
 * - Instantiates strictly via [SpeechRecognizer.createOnDeviceSpeechRecognizer] (never the
 *   network-capable `createSpeechRecognizer`).
 * - Always sets [RecognizerIntent.EXTRA_PREFER_OFFLINE] = `true`.
 * - Maps missing offline pack / network error codes directly to
 *   [OnDeviceSpeechListener.onOfflinePackMissing] with zero network fallback.
 */
class AndroidOnDeviceSpeechRecognizerGateway(
    private val context: Context
) : OnDeviceSpeechRecognizerGateway {

    private var activeRecognizer: SpeechRecognizer? = null

    override fun isOnDeviceRecognitionAvailable(): Boolean {
        return runCatching {
            SpeechRecognizer.isOnDeviceRecognitionAvailable(context)
        }.getOrDefault(false)
    }

    override fun startListening(
        config: OnDeviceSpeechConfig,
        listener: OnDeviceSpeechListener
    ) {
        require(config.preferOffline) {
            "EXTRA_PREFER_OFFLINE must be true for on-device recognition"
        }
        if (!isOnDeviceRecognitionAvailable()) {
            listener.onOfflinePackMissing(config.localeTag)
            return
        }

        destroy()

        val recognizer = try {
            SpeechRecognizer.createOnDeviceSpeechRecognizer(context)
        } catch (_: Exception) {
            listener.onOfflinePackMissing(config.localeTag)
            return
        }
        activeRecognizer = recognizer

        recognizer.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                listener.onReadyForSpeech()
            }

            override fun onBeginningOfSpeech() = Unit

            override fun onRmsChanged(rmsdB: Float) = Unit

            override fun onBufferReceived(buffer: ByteArray?) = Unit

            override fun onEndOfSpeech() = Unit

            override fun onError(error: Int) {
                if (isOfflinePackOrNetworkBlockedError(error)) {
                    listener.onOfflinePackMissing(config.localeTag)
                } else {
                    listener.onError(error, describeSpeechError(error))
                }
            }

            override fun onResults(results: Bundle?) {
                val transcript = extractFirstTranscript(results)
                listener.onFinalTranscript(transcript)
            }

            override fun onPartialResults(partialResults: Bundle?) {
                val partial = extractFirstTranscript(partialResults)
                if (partial.isNotEmpty()) {
                    listener.onPartialTranscript(partial)
                }
            }

            override fun onEvent(eventType: Int, params: Bundle?) = Unit
        })

        val recognizerIntent = buildOfflineRecognizerIntent(config)
        recognizer.startListening(recognizerIntent)
    }

    override fun stopListening() {
        runCatching { activeRecognizer?.stopListening() }
    }

    override fun cancel() {
        runCatching { activeRecognizer?.cancel() }
    }

    override fun destroy() {
        val current = activeRecognizer
        activeRecognizer = null
        if (current != null) {
            runCatching { current.destroy() }
        }
    }

    internal fun buildOfflineRecognizerIntent(config: OnDeviceSpeechConfig): Intent {
        return Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, config.languageModel)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, config.localeTag)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_PREFERENCE, config.localeTag)
            putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, config.partialResults)
        }
    }

    private fun extractFirstTranscript(bundle: Bundle?): String {
        val candidates = bundle?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
        return candidates?.firstOrNull()?.trim().orEmpty()
    }

    companion object {
        internal fun isOfflinePackOrNetworkBlockedError(errorCode: Int): Boolean {
            return errorCode == SpeechRecognizer.ERROR_LANGUAGE_NOT_SUPPORTED ||
                errorCode == SpeechRecognizer.ERROR_LANGUAGE_UNAVAILABLE ||
                errorCode == SpeechRecognizer.ERROR_NETWORK ||
                errorCode == SpeechRecognizer.ERROR_NETWORK_TIMEOUT ||
                errorCode == SpeechRecognizer.ERROR_SERVER
        }

        internal fun describeSpeechError(errorCode: Int): String {
            return when (errorCode) {
                SpeechRecognizer.ERROR_AUDIO -> "Audio recording error"
                SpeechRecognizer.ERROR_CLIENT -> "On-device speech client error"
                SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "RECORD_AUDIO permission missing"
                SpeechRecognizer.ERROR_NO_MATCH -> "No speech match recognized"
                SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "On-device speech recognizer is busy"
                SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> "No speech input detected"
                else -> "On-device speech recognition error ($errorCode)"
            }
        }
    }
}

/**
 * Controller managing 100% offline on-device voice recognition via [OnDeviceSpeechRecognizerGateway].
 *
 * Security & privacy invariants:
 * - Zero network fallback: if on-device recognition or the requested locale's offline model pack
 *   is unavailable, transitions deterministically to [VoiceInputState.OfflinePackMissing].
 * - Sanitizes all partial and final transcripts via [Gemma4InputSanitizer.sanitize] before
 *   emitting them to UI or intent resolution consumers.
 */
class OnDeviceVoiceInputController(
    private val gateway: OnDeviceSpeechRecognizerGateway
) {

    constructor(context: Context) : this(
        AndroidOnDeviceSpeechRecognizerGateway(context.applicationContext)
    )

    private val stateLock = Any()
    private val _stateFlow = MutableStateFlow<VoiceInputState>(VoiceInputState.Idle)

    /** Reactive stream of the current [VoiceInputState]. */
    val stateFlow: StateFlow<VoiceInputState> = _stateFlow.asStateFlow()

    /** Returns true if the device supports on-device offline speech recognition. */
    fun isOnDeviceRecognitionAvailable(): Boolean {
        return gateway.isOnDeviceRecognitionAvailable()
    }

    /**
     * Starts an offline voice recognition session for [localeTag] (`EXTRA_PREFER_OFFLINE = true`).
     *
     * Immediately transitions to [VoiceInputState.OfflinePackMissing] if offline recognition
     * is unavailable on the device.
     */
    fun startListening(localeTag: String = DEFAULT_LOCALE_TAG): VoiceInputState {
        val cleanLocale = sanitizeLocaleTag(localeTag)
        synchronized(stateLock) {
            if (!gateway.isOnDeviceRecognitionAvailable()) {
                val missingState = VoiceInputState.OfflinePackMissing(cleanLocale)
                _stateFlow.value = missingState
                return missingState
            }

            val listeningState = VoiceInputState.Listening(cleanLocale)
            _stateFlow.value = listeningState

            val config = OnDeviceSpeechConfig(
                localeTag = cleanLocale,
                preferOffline = true,
                partialResults = true
            )

            gateway.startListening(
                config = config,
                listener = object : OnDeviceSpeechListener {
                    override fun onReadyForSpeech() {
                        synchronized(stateLock) {
                            if (_stateFlow.value !is VoiceInputState.OfflinePackMissing) {
                                _stateFlow.value = VoiceInputState.Listening(cleanLocale)
                            }
                        }
                    }

                    override fun onPartialTranscript(text: String) {
                        val sanitized = sanitizeTranscriptSafely(text)
                        synchronized(stateLock) {
                            if (sanitized.isNotEmpty()) {
                                _stateFlow.value = VoiceInputState.PartialTranscript(
                                    text = sanitized,
                                    localeTag = cleanLocale
                                )
                            }
                        }
                    }

                    override fun onFinalTranscript(text: String) {
                        val sanitized = sanitizeTranscriptSafely(text)
                        synchronized(stateLock) {
                            _stateFlow.value = VoiceInputState.FinalTranscript(
                                text = sanitized,
                                localeTag = cleanLocale
                            )
                        }
                    }

                    override fun onOfflinePackMissing(localeTag: String) {
                        val safeMissingTag = sanitizeLocaleTag(localeTag)
                        synchronized(stateLock) {
                            _stateFlow.value = VoiceInputState.OfflinePackMissing(safeMissingTag)
                        }
                    }

                    override fun onError(errorCode: Int, message: String) {
                        synchronized(stateLock) {
                            if (AndroidOnDeviceSpeechRecognizerGateway.isOfflinePackOrNetworkBlockedError(errorCode)) {
                                _stateFlow.value = VoiceInputState.OfflinePackMissing(cleanLocale)
                            } else {
                                _stateFlow.value = VoiceInputState.Error(
                                    errorCode = errorCode,
                                    message = Gemma4InputSanitizer.stripInvisibleControls(message).trim(),
                                    localeTag = cleanLocale
                                )
                            }
                        }
                    }
                }
            )
            return _stateFlow.value
        }
    }

    /** Signals the active recognizer to finish capturing audio and emit final results. */
    fun stopListening() {
        synchronized(stateLock) {
            gateway.stopListening()
        }
    }

    /** Cancels any active session and resets [stateFlow] to [VoiceInputState.Idle]. */
    fun cancel() {
        synchronized(stateLock) {
            gateway.cancel()
            _stateFlow.value = VoiceInputState.Idle
        }
    }

    /** Destroys underlying platform speech recognizer resources and resets to [VoiceInputState.Idle]. */
    fun destroy() {
        synchronized(stateLock) {
            gateway.destroy()
            _stateFlow.value = VoiceInputState.Idle
        }
    }

    private fun sanitizeLocaleTag(rawTag: String): String {
        val stripped = Gemma4InputSanitizer.stripInvisibleControls(rawTag)
            .trim()
            .replace('_', '-')
        return stripped.ifEmpty { DEFAULT_LOCALE_TAG }
    }

    private fun sanitizeTranscriptSafely(rawText: String): String {
        return try {
            Gemma4InputSanitizer.sanitize(rawText).trim()
        } catch (_: SecurityException) {
            ""
        }
    }

    companion object {
        const val DEFAULT_LOCALE_TAG: String = "en"
    }
}
