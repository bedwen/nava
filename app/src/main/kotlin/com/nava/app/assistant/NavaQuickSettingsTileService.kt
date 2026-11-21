package com.nava.app.assistant

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.nava.app.R

/**
 * Quick Settings Tile service opening Nava's modal assistant sheet activity directly from
 * the Android Quick Settings panel (PLAN.md Section 2.3.4).
 *
 * Security & Platform Invariants:
 * - Uses [AssistantIntentContract.buildAssistantSheetIntent] targeting explicit internal component
 *   `com.nava.app.assistant.NavaAssistantSheetActivity`.
 * - PendingIntent incorporates [PendingIntent.FLAG_IMMUTABLE].
 * - On API 34+ (Android 14+), invokes `startActivityAndCollapse(PendingIntent)`.
 * - On API 31-33 (Android 12-13), falls back to `startActivityAndCollapse(Intent)`.
 * - Never uses SYSTEM_ALERT_WINDOW.
 * - Never accesses network sockets (No-INTERNET Law 3).
 */
open class NavaQuickSettingsTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onTileAdded() {
        super.onTileAdded()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        launchAssistantSheet()
    }

    /**
     * Updates the tile label, subtitle (API 29+), and active/inactive state cleanly.
     */
    fun updateTileState() {
        val tile = qsTile ?: return
        try {
            tile.label = getString(R.string.tile_assistant_label)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.tile_assistant_description)
            }
            tile.state = Tile.STATE_INACTIVE
            tile.updateTile()
        } catch (_: Exception) {
            // Handled gracefully in headless test stubs
        }
    }

    /**
     * Opens [NavaAssistantSheetActivity] and collapses the notification shade.
     */
    fun launchAssistantSheet(openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET) {
        val launchIntent = AssistantIntentContract.buildAssistantSheetIntent(this, openMode)
        val pendingIntent = createAssistantSheetPendingIntent(this, openMode)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                startActivityAndCollapse(pendingIntent)
            } catch (_: Exception) {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(launchIntent)
            }
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launchIntent)
        }
    }

    companion object {
        const val TILE_REQUEST_CODE: Int = 1001

        /**
         * Builds the immutable [PendingIntent] for launching NavaAssistantSheetActivity from the QS tile.
         */
        fun createAssistantSheetPendingIntent(
            context: Context,
            openMode: AssistantOpenMode = AssistantOpenMode.QUICK_SHEET,
            requestCode: Int = TILE_REQUEST_CODE
        ): PendingIntent {
            val intent = AssistantIntentContract.buildAssistantSheetIntent(context, openMode)
            val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            return PendingIntent.getActivity(context, requestCode, intent, flags)
        }

        /**
         * Pure specification descriptor for testing without Android framework mocks.
         */
        fun buildTileLaunchSpec(
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
