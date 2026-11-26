package com.nava.feature.automations.common

import android.content.Context
import android.content.Intent
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.view.KeyEvent

/** Media transport commands sent as media key events to the active media session. */
enum class MediaCommand {
    PLAY_PAUSE,
    PLAY,
    PAUSE,
    NEXT,
    PREVIOUS
}

/** Fixed system settings panels Nava may open (mirrors the outbound policy allowlist). */
enum class SettingsPanelKind(val policyTarget: String) {
    INTERNET("internet"),
    WIFI("wifi"),
    BLUETOOTH("bluetooth"),
    VOLUME("volume");

    companion object {
        fun fromSlot(raw: String): SettingsPanelKind? {
            val key = raw.trim().lowercase(java.util.Locale.ROOT)
            return entries.firstOrNull { it.policyTarget == key }
        }
    }
}

/**
 * Thin, JVM-testable abstraction over the flashlight, media keys, and system settings panels.
 * None of these need a runtime permission, send data anywhere, or accept free-form targets.
 */
interface DeviceControlPlatformGateway {
    fun setFlashlight(enabled: Boolean): PlatformDispatchResult
    fun sendMediaCommand(command: MediaCommand): PlatformDispatchResult
    fun openSettingsPanel(panel: SettingsPanelKind): PlatformDispatchResult
}

/** Production Android implementation of [DeviceControlPlatformGateway]. */
class AndroidDeviceControlPlatformGateway(
    private val context: Context
) : DeviceControlPlatformGateway {

    override fun setFlashlight(enabled: Boolean): PlatformDispatchResult {
        val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
            ?: return PlatformDispatchResult.Unavailable("CameraManager unavailable")
        return try {
            val torchId = cameraManager.cameraIdList.firstOrNull { id ->
                cameraManager.getCameraCharacteristics(id)
                    .get(CameraCharacteristics.FLASH_INFO_AVAILABLE) == true
            } ?: return PlatformDispatchResult.Unavailable("No camera with a flash unit")
            cameraManager.setTorchMode(torchId, enabled)
            PlatformDispatchResult.Dispatched(if (enabled) "on" else "off")
        } catch (e: Exception) {
            PlatformDispatchResult.Unavailable(e.message ?: "Failed to toggle flashlight")
        }
    }

    override fun sendMediaCommand(command: MediaCommand): PlatformDispatchResult {
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            ?: return PlatformDispatchResult.Unavailable("AudioManager unavailable")
        val keyCode = when (command) {
            MediaCommand.PLAY_PAUSE -> KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE
            MediaCommand.PLAY -> KeyEvent.KEYCODE_MEDIA_PLAY
            MediaCommand.PAUSE -> KeyEvent.KEYCODE_MEDIA_PAUSE
            MediaCommand.NEXT -> KeyEvent.KEYCODE_MEDIA_NEXT
            MediaCommand.PREVIOUS -> KeyEvent.KEYCODE_MEDIA_PREVIOUS
        }
        return try {
            val now = SystemClock.uptimeMillis()
            audioManager.dispatchMediaKeyEvent(KeyEvent(now, now, KeyEvent.ACTION_DOWN, keyCode, 0))
            audioManager.dispatchMediaKeyEvent(KeyEvent(now, now, KeyEvent.ACTION_UP, keyCode, 0))
            PlatformDispatchResult.Dispatched(command.name)
        } catch (e: RuntimeException) {
            PlatformDispatchResult.Unavailable(e.message ?: "Failed to send media key")
        }
    }

    override fun openSettingsPanel(panel: SettingsPanelKind): PlatformDispatchResult {
        val action = when (panel) {
            SettingsPanelKind.INTERNET -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Settings.Panel.ACTION_INTERNET_CONNECTIVITY
            } else {
                Settings.ACTION_WIRELESS_SETTINGS
            }
            SettingsPanelKind.WIFI -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Settings.Panel.ACTION_WIFI
            } else {
                Settings.ACTION_WIFI_SETTINGS
            }
            SettingsPanelKind.BLUETOOTH -> Settings.ACTION_BLUETOOTH_SETTINGS
            SettingsPanelKind.VOLUME -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Settings.Panel.ACTION_VOLUME
            } else {
                Settings.ACTION_SOUND_SETTINGS
            }
        }
        return try {
            context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            PlatformDispatchResult.Dispatched(panel.policyTarget)
        } catch (e: RuntimeException) {
            PlatformDispatchResult.Unavailable(e.message ?: "Settings panel unavailable")
        }
    }
}
