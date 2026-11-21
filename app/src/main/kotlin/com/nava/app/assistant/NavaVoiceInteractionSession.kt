package com.nava.app.assistant

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.voice.VoiceInteractionSession

/**
 * System voice interaction session managing assistant activation events (PLAN.md Section 2.3.4).
 *
 * Lifecycle & Security Invariants:
 * - Directs execution to [NavaAssistantSheetActivity] via [AssistantIntentContract.buildAssistantSheetIntent]
 *   with [AssistantOpenMode.QUICK_SHEET] (or [AssistantOpenMode.VOICE]).
 * - Never uses SYSTEM_ALERT_WINDOW (overlay permission).
 * - Never accesses network sockets (No-INTERNET Law 3).
 * - Cleanly hides the session window to prevent overlay visual artifacts.
 */
open class NavaVoiceInteractionSession(
    context: Context
) : VoiceInteractionSession(context) {

    override fun onShow(args: Bundle?, showFlags: Int) {
        super.onShow(args, showFlags)
        launchAssistantSheet(AssistantOpenMode.QUICK_SHEET)
        runCatching { hide() }
    }

    override fun onHandleAssist(state: AssistState) {
        super.onHandleAssist(state)
    }

    override fun onHide() {
        super.onHide()
    }

    override fun onDestroy() {
        super.onDestroy()
    }

    /**
     * Launches the explicit [NavaAssistantSheetActivity] using [AssistantIntentContract].
     */
    fun launchAssistantSheet(openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET) {
        val launchIntent = buildSheetIntent(context, openMode)
        try {
            startAssistantActivity(launchIntent)
        } catch (_: Exception) {
            try {
                context.startActivity(launchIntent)
            } catch (_: Exception) {
                // Handled gracefully in headless test stubs
            }
        }
    }

    companion object {
        /**
         * Builds the explicit sheet intent targeting NavaAssistantSheetActivity.
         */
        fun buildSheetIntent(
            context: Context,
            openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET
        ): Intent {
            return AssistantIntentContract.buildAssistantSheetIntent(
                context = context,
                openMode = openMode
            )
        }

        /**
         * Pure specification descriptor for testing without Android framework mocks.
         */
        fun buildSheetSpec(
            openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET,
            packageName: String = AssistantIntentContract.DEFAULT_PACKAGE_NAME
        ): AssistantComponentSpec {
            return AssistantIntentContract.buildAssistantSheetSpec(
                openMode = openMode,
                packageName = packageName
            )
        }
    }
}
