package com.nava.app.assistant

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.InteractiveNotificationRequest
import java.util.Locale

/**
 * Supported presentation modes when launching Nava's main activity or modal assistant sheet.
 */
enum class AssistantOpenMode(val modeValue: String) {
    CONFIRMATION(AssistantIntentContract.OPEN_MODE_CONFIRMATION),
    VOICE(AssistantIntentContract.OPEN_MODE_VOICE),
    QUICK_SHEET(AssistantIntentContract.OPEN_MODE_QUICK_SHEET);

    companion object {
        fun fromModeValue(raw: String?): AssistantOpenMode? {
            if (raw.isNullOrBlank()) return null
            val cleaned = Gemma4InputSanitizer.stripInvisibleControls(raw).trim().uppercase(Locale.US)
            return values().firstOrNull { it.modeValue == cleaned }
        }
    }
}

/**
 * Pure Kotlin representation of an explicit activity launch specification.
 * Decouples component, action, flags, and extras verification from Android framework [Intent]
 * stubs during pure JVM unit testing.
 */
data class AssistantComponentSpec(
    val packageName: String,
    val className: String,
    val action: String,
    val openMode: AssistantOpenMode,
    val flags: Int,
    val stringExtras: Map<String, String>,
    val booleanExtras: Map<String, Boolean>
)

/**
 * Sanitized extras extracted from an incoming confirmation notification [Intent].
 *
 * Security note: These extras are untrusted lookup hints only. `PendingConfirmationStore` must
 * resolve them strictly against already-registered in-memory confirmation items or verified
 * `RuleCapabilityGrant` records from `RuleGrantPort`.
 */
data class ConfirmationIntentExtras(
    val requestId: String? = null,
    val ruleId: String? = null,
    val taskId: String? = null,
    val requiresBiometric: Boolean = false,
    val hasUntrustedHighRiskSlot: Boolean = false,
    val openMode: AssistantOpenMode = AssistantOpenMode.CONFIRMATION
) {
    fun hasAnyIdentifier(): Boolean {
        return !requestId.isNullOrBlank() || !ruleId.isNullOrBlank() || !taskId.isNullOrBlank()
    }
}

/**
 * Canonical actions, extras, activity component names, and explicit [Intent] / [PendingIntent]
 * builders connecting `:feature-automations` notification bridges, Quick Settings tiles, and
 * voice assistant sessions to `:app` screens.
 *
 * Security invariants:
 * - Every constructed [Intent] sets an explicit [ComponentName] inside Nava's package.
 * - Every constructed [PendingIntent] includes [PendingIntent.FLAG_IMMUTABLE].
 */
object AssistantIntentContract {

    const val DEFAULT_PACKAGE_NAME: String = "com.nava.app"
    const val MAIN_ACTIVITY_CLASS_NAME: String = "com.nava.app.MainActivity"
    const val ASSISTANT_SHEET_ACTIVITY_CLASS_NAME: String =
        "com.nava.app.assistant.NavaAssistantSheetActivity"

    const val ACTION_OPEN_CONFIRMATION: String = "com.nava.action.OPEN_CONFIRMATION"
    const val ACTION_OPEN_ASSISTANT_SHEET: String = "com.nava.action.OPEN_ASSISTANT_SHEET"
    const val ACTION_OPEN_VOICE: String = "com.nava.action.OPEN_VOICE"

    const val EXTRA_REQUEST_ID: String = AutomationNotificationBridge.EXTRA_REQUEST_ID
    const val EXTRA_RULE_ID: String = AutomationNotificationBridge.EXTRA_RULE_ID
    const val EXTRA_TASK_ID: String = AutomationNotificationBridge.EXTRA_TASK_ID
    const val EXTRA_REQUIRES_BIOMETRIC: String = AutomationNotificationBridge.EXTRA_REQUIRES_BIOMETRIC
    const val EXTRA_UNTRUSTED_HIGH_RISK: String = AutomationNotificationBridge.EXTRA_UNTRUSTED_HIGH_RISK
    const val EXTRA_OPEN_MODE: String = "com.nava.extra.OPEN_MODE"

    const val OPEN_MODE_CONFIRMATION: String = "CONFIRMATION"
    const val OPEN_MODE_VOICE: String = "VOICE"
    const val OPEN_MODE_QUICK_SHEET: String = "QUICK_SHEET"

    const val DEFAULT_ACTIVITY_FLAGS: Int =
        Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP

    const val PENDING_INTENT_FLAGS: Int =
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT

    /**
     * Builds a pure Kotlin [AssistantComponentSpec] for an [InteractiveNotificationRequest].
     */
    fun buildConfirmationSpec(
        request: InteractiveNotificationRequest,
        packageName: String = DEFAULT_PACKAGE_NAME,
        useSheetActivity: Boolean = false
    ): AssistantComponentSpec {
        val safePkg = validatePackageName(packageName)
        val targetClass = if (useSheetActivity) {
            ASSISTANT_SHEET_ACTIVITY_CLASS_NAME
        } else {
            MAIN_ACTIVITY_CLASS_NAME
        }
        val stringExtras = LinkedHashMap<String, String>()
        stringExtras[EXTRA_OPEN_MODE] = OPEN_MODE_CONFIRMATION
        stringExtras[EXTRA_REQUEST_ID] = sanitizeExtraIdentifier(request.requestId)
        request.ruleId?.takeIf { it.isNotBlank() }?.let {
            stringExtras[EXTRA_RULE_ID] = sanitizeExtraIdentifier(it)
        }
        request.taskId?.takeIf { it.isNotBlank() }?.let {
            stringExtras[EXTRA_TASK_ID] = sanitizeExtraIdentifier(it)
        }

        val booleanExtras = linkedMapOf(
            EXTRA_REQUIRES_BIOMETRIC to request.requiresBiometric,
            EXTRA_UNTRUSTED_HIGH_RISK to request.hasUntrustedHighRiskSlot
        )

        return AssistantComponentSpec(
            packageName = safePkg,
            className = targetClass,
            action = ACTION_OPEN_CONFIRMATION,
            openMode = AssistantOpenMode.CONFIRMATION,
            flags = DEFAULT_ACTIVITY_FLAGS,
            stringExtras = stringExtras,
            booleanExtras = booleanExtras
        )
    }

    /**
     * Builds a pure Kotlin [AssistantComponentSpec] for opening the modal assistant sheet
     * (e.g. from `NavaQuickSettingsTileService` or `NavaVoiceInteractionSession`).
     */
    fun buildAssistantSheetSpec(
        openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET,
        packageName: String = DEFAULT_PACKAGE_NAME,
        requestId: String? = null
    ): AssistantComponentSpec {
        val safePkg = validatePackageName(packageName)
        val action = when (openMode) {
            AssistantOpenMode.CONFIRMATION -> ACTION_OPEN_CONFIRMATION
            AssistantOpenMode.VOICE -> ACTION_OPEN_VOICE
            AssistantOpenMode.QUICK_SHEET -> ACTION_OPEN_ASSISTANT_SHEET
        }
        val stringExtras = LinkedHashMap<String, String>()
        stringExtras[EXTRA_OPEN_MODE] = openMode.modeValue
        requestId?.takeIf { it.isNotBlank() }?.let {
            stringExtras[EXTRA_REQUEST_ID] = sanitizeExtraIdentifier(it)
        }
        return AssistantComponentSpec(
            packageName = safePkg,
            className = ASSISTANT_SHEET_ACTIVITY_CLASS_NAME,
            action = action,
            openMode = openMode,
            flags = DEFAULT_ACTIVITY_FLAGS,
            stringExtras = stringExtras,
            booleanExtras = emptyMap()
        )
    }

    /**
     * Builds a pure Kotlin [AssistantComponentSpec] for launching Nava directly in offline voice mode.
     */
    fun buildVoiceSpec(
        packageName: String = DEFAULT_PACKAGE_NAME,
        useSheetActivity: Boolean = true
    ): AssistantComponentSpec {
        val safePkg = validatePackageName(packageName)
        val targetClass = if (useSheetActivity) {
            ASSISTANT_SHEET_ACTIVITY_CLASS_NAME
        } else {
            MAIN_ACTIVITY_CLASS_NAME
        }
        return AssistantComponentSpec(
            packageName = safePkg,
            className = targetClass,
            action = ACTION_OPEN_VOICE,
            openMode = AssistantOpenMode.VOICE,
            flags = DEFAULT_ACTIVITY_FLAGS,
            stringExtras = mapOf(EXTRA_OPEN_MODE to OPEN_MODE_VOICE),
            booleanExtras = emptyMap()
        )
    }

    /**
     * Builds an explicit Android [Intent] targeting [MAIN_ACTIVITY_CLASS_NAME] (or
     * [ASSISTANT_SHEET_ACTIVITY_CLASS_NAME] when [useSheetActivity] is true) for an interactive
     * confirmation request.
     */
    fun buildConfirmationIntent(
        context: Context,
        request: InteractiveNotificationRequest,
        useSheetActivity: Boolean = false
    ): Intent {
        val pkg = runCatching { context.packageName }.getOrNull().orEmpty().ifBlank { DEFAULT_PACKAGE_NAME }
        return buildConfirmationIntent(
            packageName = pkg,
            request = request,
            useSheetActivity = useSheetActivity
        )
    }

    /**
     * Builds an explicit Android [Intent] for an [InteractiveNotificationRequest] using [packageName].
     */
    fun buildConfirmationIntent(
        packageName: String,
        request: InteractiveNotificationRequest,
        useSheetActivity: Boolean = false
    ): Intent {
        val spec = buildConfirmationSpec(
            request = request,
            packageName = packageName,
            useSheetActivity = useSheetActivity
        )
        return toAndroidIntent(spec)
    }

    /**
     * Builds an immutable [PendingIntent] (`FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT`) for
     * [AndroidAutomationNotificationBridge] interactive confirmation notifications.
     */
    fun buildConfirmationPendingIntent(
        context: Context,
        request: InteractiveNotificationRequest,
        useSheetActivity: Boolean = false
    ): PendingIntent {
        val intent = buildConfirmationIntent(
            context = context,
            request = request,
            useSheetActivity = useSheetActivity
        )
        return PendingIntent.getActivity(
            context,
            request.notificationId,
            intent,
            PENDING_INTENT_FLAGS
        )
    }

    /**
     * Builds an explicit Android [Intent] targeting [ASSISTANT_SHEET_ACTIVITY_CLASS_NAME].
     */
    fun buildAssistantSheetIntent(
        context: Context,
        openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET,
        requestId: String? = null
    ): Intent {
        val pkg = runCatching { context.packageName }.getOrNull().orEmpty().ifBlank { DEFAULT_PACKAGE_NAME }
        val spec = buildAssistantSheetSpec(
            openMode = openMode,
            packageName = pkg,
            requestId = requestId
        )
        return toAndroidIntent(spec)
    }

    /**
     * Builds an explicit Android [Intent] for launching Nava in offline voice input mode.
     */
    fun buildVoiceIntent(
        context: Context,
        useSheetActivity: Boolean = true
    ): Intent {
        val pkg = runCatching { context.packageName }.getOrNull().orEmpty().ifBlank { DEFAULT_PACKAGE_NAME }
        val spec = buildVoiceSpec(
            packageName = pkg,
            useSheetActivity = useSheetActivity
        )
        return toAndroidIntent(spec)
    }

    /**
     * Converts a pure [AssistantComponentSpec] into an explicit Android [Intent].
     */
    fun toAndroidIntent(spec: AssistantComponentSpec): Intent {
        return Intent(spec.action).apply {
            component = ComponentName(spec.packageName, spec.className)
            flags = spec.flags
            for ((k, v) in spec.stringExtras) {
                putExtra(k, v)
            }
            for ((k, v) in spec.booleanExtras) {
                putExtra(k, v)
            }
        }
    }

    /**
     * Extracts and sanitizes [ConfirmationIntentExtras] from an Android [Intent].
     * Returns null if [intent] is null or contains smuggled control tokens.
     */
    fun extractConfirmationExtras(intent: Intent?): ConfirmationIntentExtras? {
        if (intent == null) return null
        return runCatching {
            val map = LinkedHashMap<String, Any?>()
            map[EXTRA_REQUEST_ID] = intent.getStringExtra(EXTRA_REQUEST_ID)
            map[EXTRA_RULE_ID] = intent.getStringExtra(EXTRA_RULE_ID)
            map[EXTRA_TASK_ID] = intent.getStringExtra(EXTRA_TASK_ID)
            map[EXTRA_OPEN_MODE] = intent.getStringExtra(EXTRA_OPEN_MODE)
            map[EXTRA_REQUIRES_BIOMETRIC] = intent.getBooleanExtra(EXTRA_REQUIRES_BIOMETRIC, false)
            map[EXTRA_UNTRUSTED_HIGH_RISK] = intent.getBooleanExtra(EXTRA_UNTRUSTED_HIGH_RISK, false)
            extractConfirmationExtrasFromMap(map)
        }.getOrNull()
    }

    /**
     * Pure-Kotlin extraction and validation of [ConfirmationIntentExtras] from a raw extra map.
     * Rejects control-token smuggling, NUL bytes, or excessive identifier lengths by returning null.
     */
    fun extractConfirmationExtrasFromMap(rawExtras: Map<String, Any?>): ConfirmationIntentExtras? {
        val requestId = sanitizeOptionalExtraId(rawExtras[EXTRA_REQUEST_ID] as? String) ?: return null
        val ruleId = sanitizeOptionalExtraId(rawExtras[EXTRA_RULE_ID] as? String) ?: return null
        val taskId = sanitizeOptionalExtraId(rawExtras[EXTRA_TASK_ID] as? String) ?: return null

        val rawMode = (rawExtras[EXTRA_OPEN_MODE] as? String)?.trim()
        val resolvedMode = if (rawMode.isNullOrEmpty()) {
            AssistantOpenMode.CONFIRMATION
        } else {
            AssistantOpenMode.fromModeValue(rawMode) ?: return null
        }

        val requiresBiometric = (rawExtras[EXTRA_REQUIRES_BIOMETRIC] as? Boolean) ?: false
        val untrustedHighRisk = (rawExtras[EXTRA_UNTRUSTED_HIGH_RISK] as? Boolean) ?: false

        return ConfirmationIntentExtras(
            requestId = requestId.takeIf { it.isNotEmpty() },
            ruleId = ruleId.takeIf { it.isNotEmpty() },
            taskId = taskId.takeIf { it.isNotEmpty() },
            requiresBiometric = requiresBiometric,
            hasUntrustedHighRiskSlot = untrustedHighRisk,
            openMode = resolvedMode
        )
    }

    /**
     * Resolves the requested [AssistantOpenMode] from an Android [Intent].
     */
    fun extractOpenMode(intent: Intent?): AssistantOpenMode? {
        if (intent == null) return null
        return runCatching {
            val modeExtra = intent.getStringExtra(EXTRA_OPEN_MODE)
            AssistantOpenMode.fromModeValue(modeExtra) ?: when (intent.action) {
                ACTION_OPEN_CONFIRMATION -> AssistantOpenMode.CONFIRMATION
                ACTION_OPEN_VOICE -> AssistantOpenMode.VOICE
                ACTION_OPEN_ASSISTANT_SHEET -> AssistantOpenMode.QUICK_SHEET
                else -> null
            }
        }.getOrNull()
    }

    private fun validatePackageName(packageName: String): String {
        val trimmed = packageName.trim()
        require(trimmed.isNotEmpty() && SAFE_PACKAGE_REGEX.matches(trimmed)) {
            "Invalid explicit component package name: '$packageName'"
        }
        return trimmed
    }

    private fun sanitizeExtraIdentifier(raw: String): String {
        val sanitized = sanitizeOptionalExtraId(raw)
        require(!sanitized.isNullOrEmpty()) { "Intent extra identifier must be non-blank and safe" }
        return sanitized
    }

    /**
     * Returns empty string when [raw] is null/blank, the sanitized identifier when valid,
     * or `null` when [raw] contains NUL bytes, line breaks, or control-token smuggling.
     */
    private fun sanitizeOptionalExtraId(raw: String?): String? {
        if (raw == null) return ""
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ""
        if (trimmed.length > MAX_IDENTIFIER_LENGTH) return null
        if ('\u0000' in trimmed || '\n' in trimmed || '\r' in trimmed) return null
        val sanitized = try {
            Gemma4InputSanitizer.sanitize(trimmed).trim()
        } catch (_: SecurityException) {
            return null
        }
        if (sanitized != trimmed || sanitized.isEmpty()) return null
        return sanitized
    }

    private const val MAX_IDENTIFIER_LENGTH: Int = 256
    private val SAFE_PACKAGE_REGEX: Regex =
        Regex("^[a-zA-Z][a-zA-Z0-9_]*(?:\\.[a-zA-Z][a-zA-Z0-9_]*)+$")
}
