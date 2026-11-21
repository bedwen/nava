package com.nava.app.assistant

import android.content.ComponentName
import android.content.Context
import android.service.voice.VoiceInteractionService

/**
 * System voice interaction service entry point for Nava (PLAN.md Section 2.3.4).
 *
 * Declared in AndroidManifest.xml with:
 * - android:permission="android.permission.BIND_VOICE_INTERACTION"
 * - android:exported="true"
 * - intent-filter android.service.voice.VoiceInteractionService
 * - meta-data android.voice_interaction pointing to @xml/nava_voice_interaction_service
 *
 * Security & Platform Invariants:
 * - Zero network socket usage (No-INTERNET Law 3).
 * - Zero SYSTEM_ALERT_WINDOW usage.
 */
open class NavaVoiceInteractionService : VoiceInteractionService() {

    override fun onReady() {
        super.onReady()
    }

    override fun onShutdown() {
        super.onShutdown()
    }

    companion object {
        /**
         * Checks whether Nava's voice interaction service is currently selected as the active
         * assistant service in Android system settings.
         */
        fun isServiceActive(context: Context): Boolean {
            return try {
                val component = ComponentName(context, NavaVoiceInteractionService::class.java)
                isActive(context, component)
            } catch (_: Exception) {
                false
            }
        }
    }
}
