package com.nava.feature.automations.common

import android.Manifest
import android.app.NotificationManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.AlarmClock
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.util.Locale

/**
 * Result returned by platform gateways when dispatching an allowlisted Android Intent
 * or invoking a system manager API.
 */
sealed interface PlatformDispatchResult {
    data class Dispatched(val detail: String = "") : PlatformDispatchResult
    data class MissingPermission(val permission: String) : PlatformDispatchResult
    data class Unavailable(val reason: String) : PlatformDispatchResult
}

/**
 * Thin, JVM-testable abstraction over allowlisted Android `Intent` dispatches and runtime/special
 * permission checks (PLAN.md Sections 5.4 & 5.7).
 *
 * Security invariants:
 * - Only fixed allowlisted system actions (`ACTION_SET_ALARM`, `ACTION_SET_TIMER`, `ACTION_SENDTO`
 *   with `smsto:`, `ACTION_DIAL` / `ACTION_CALL` with `tel:`, and verified launcher intents) exist.
 * - `ACTION_VIEW` and arbitrary `http://` / `https://` URLs are never exposed or constructed.
 */
interface AutomationIntentGateway {
    fun hasRuntimePermission(permission: String): Boolean

    fun isNotificationPolicyAccessGranted(): Boolean

    fun isNotificationListenerEnabled(): Boolean

    fun dispatchSetAlarm(
        hour: Int,
        minute: Int,
        label: String? = null,
        skipUi: Boolean = false
    ): PlatformDispatchResult

    fun dispatchSetTimer(
        durationSeconds: Int,
        label: String? = null,
        skipUi: Boolean = false
    ): PlatformDispatchResult

    fun dispatchSmsDraft(
        recipient: String,
        body: String
    ): PlatformDispatchResult

    fun dispatchDial(phoneNumber: String): PlatformDispatchResult

    fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult

    fun resolveLaunchablePackage(appNameOrPackage: String): String?

    fun dispatchLaunchApp(packageName: String): PlatformDispatchResult
}

/**
 * Production Android SDK implementation of [AutomationIntentGateway].
 */
class AndroidAutomationIntentGateway(
    private val context: Context
) : AutomationIntentGateway {

    override fun hasRuntimePermission(permission: String): Boolean {
        if (permission.isBlank()) return false
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    override fun isNotificationPolicyAccessGranted(): Boolean {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false
        return manager.isNotificationPolicyAccessGranted
    }

    override fun isNotificationListenerEnabled(): Boolean {
        val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
        return context.packageName in enabledPackages
    }

    override fun dispatchSetAlarm(
        hour: Int,
        minute: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult {
        if (hour !in 0..23 || minute !in 0..59) {
            return PlatformDispatchResult.Unavailable("Invalid alarm time $hour:$minute")
        }
        val intent = Intent(AlarmClock.ACTION_SET_ALARM).apply {
            putExtra(AlarmClock.EXTRA_HOUR, hour)
            putExtra(AlarmClock.EXTRA_MINUTES, minute)
            putExtra(AlarmClock.EXTRA_SKIP_UI, skipUi)
            if (!label.isNullOrBlank()) {
                putExtra(AlarmClock.EXTRA_MESSAGE, label.trim())
            }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return startAllowlistedActivity(intent, "clock_alarm")
    }

    override fun dispatchSetTimer(
        durationSeconds: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult {
        if (durationSeconds <= 0) {
            return PlatformDispatchResult.Unavailable("Timer duration must be positive")
        }
        val intent = Intent(AlarmClock.ACTION_SET_TIMER).apply {
            putExtra(AlarmClock.EXTRA_LENGTH, durationSeconds)
            putExtra(AlarmClock.EXTRA_SKIP_UI, skipUi)
            if (!label.isNullOrBlank()) {
                putExtra(AlarmClock.EXTRA_MESSAGE, label.trim())
            }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return startAllowlistedActivity(intent, "clock_timer")
    }

    override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult {
        val cleanedRecipient = recipient.trim()
        if (!isValidDialableNumber(cleanedRecipient)) {
            return PlatformDispatchResult.Unavailable("Invalid SMS recipient")
        }
        val smsUri = Uri.fromParts("smsto", cleanedRecipient, null)
        val intent = Intent(Intent.ACTION_SENDTO, smsUri).apply {
            putExtra("sms_body", body)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return startAllowlistedActivity(intent, "sms_draft")
    }

    override fun dispatchDial(phoneNumber: String): PlatformDispatchResult {
        val cleanedNumber = phoneNumber.trim()
        if (!isValidDialableNumber(cleanedNumber)) {
            return PlatformDispatchResult.Unavailable("Invalid phone number")
        }
        val telUri = Uri.fromParts("tel", cleanedNumber, null)
        val intent = Intent(Intent.ACTION_DIAL, telUri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return startAllowlistedActivity(intent, "dialer")
    }

    override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult {
        if (!hasRuntimePermission(Manifest.permission.CALL_PHONE)) {
            return PlatformDispatchResult.MissingPermission(Manifest.permission.CALL_PHONE)
        }
        val cleanedNumber = phoneNumber.trim()
        if (!isValidDialableNumber(cleanedNumber)) {
            return PlatformDispatchResult.Unavailable("Invalid phone number")
        }
        val telUri = Uri.fromParts("tel", cleanedNumber, null)
        val intent = Intent(Intent.ACTION_CALL, telUri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return startAllowlistedActivity(intent, "direct_call")
    }

    override fun resolveLaunchablePackage(appNameOrPackage: String): String? {
        val trimmed = appNameOrPackage.trim()
        if (trimmed.isEmpty()) return null
        val pm = context.packageManager

        if (isValidPackageName(trimmed)) {
            if (pm.getLaunchIntentForPackage(trimmed) != null) {
                return trimmed
            }
        }

        val launcherQuery = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val candidates = pm.queryIntentActivities(launcherQuery, 0)
        val targetLower = trimmed.lowercase(Locale.ROOT)
        for (info in candidates) {
            val pkg = info.activityInfo?.packageName ?: continue
            if (!isValidPackageName(pkg)) continue
            val label = info.loadLabel(pm).toString().trim().lowercase(Locale.ROOT)
            if (label.isEmpty()) continue
            if (label == targetLower) {
                return pkg
            }
        }
        return null
    }

    override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult {
        val cleanedPkg = packageName.trim()
        if (!isValidPackageName(cleanedPkg)) {
            return PlatformDispatchResult.Unavailable("Invalid package name '$cleanedPkg'")
        }
        val launchIntent = context.packageManager.getLaunchIntentForPackage(cleanedPkg)
            ?: return PlatformDispatchResult.Unavailable("No launchable activity for '$cleanedPkg'")
        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return startAllowlistedActivity(launchIntent, cleanedPkg)
    }

    private fun startAllowlistedActivity(intent: Intent, detail: String): PlatformDispatchResult {
        return try {
            val resolved = intent.resolveActivity(context.packageManager)
            if (resolved == null) {
                PlatformDispatchResult.Unavailable("No activity available for $detail")
            } else {
                context.startActivity(intent)
                PlatformDispatchResult.Dispatched(detail)
            }
        } catch (_: SecurityException) {
            PlatformDispatchResult.MissingPermission(intent.action ?: detail)
        } catch (_: ActivityNotFoundException) {
            PlatformDispatchResult.Unavailable("Activity not found for $detail")
        }
    }

    companion object {
        private val SAFE_DIALABLE_REGEX: Regex = Regex("""^[+0-9*#()\- ]{1,64}$""")
        private val ANDROID_PACKAGE_REGEX: Regex = Regex(
            """^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$"""
        )

        fun isValidDialableNumber(value: String): Boolean {
            val trimmed = value.trim()
            return trimmed.isNotEmpty() &&
                SAFE_DIALABLE_REGEX.matches(trimmed) &&
                trimmed.any { it.isDigit() }
        }

        fun isValidPackageName(value: String): Boolean {
            val trimmed = value.trim()
            return trimmed.isNotEmpty() && ANDROID_PACKAGE_REGEX.matches(trimmed)
        }
    }
}
