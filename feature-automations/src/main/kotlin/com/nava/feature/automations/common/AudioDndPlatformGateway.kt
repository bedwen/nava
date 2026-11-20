package com.nava.feature.automations.common

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.media.AudioManager
import kotlin.math.roundToInt

/**
 * Supported Android audio streams controlled by `AudioDndTool` (`set_volume`).
 */
enum class AudioStreamKind {
    MEDIA,
    RING,
    ALARM,
    NOTIFICATION,
    SYSTEM
}

/**
 * Do Not Disturb interruption filter modes controlled by `AudioDndTool` (`set_dnd`).
 */
enum class DndFilterMode {
    ALL,
    PRIORITY,
    NONE,
    ALARMS_ONLY
}

/**
 * Thin, JVM-testable abstraction over Android `AudioManager` and `NotificationManager`
 * DND interruption filter controls.
 */
interface AudioDndPlatformGateway {
    fun isNotificationPolicyAccessGranted(): Boolean

    fun setInterruptionFilter(mode: DndFilterMode): PlatformDispatchResult

    fun setStreamVolumePercent(stream: AudioStreamKind, percent: Int): PlatformDispatchResult

    fun getStreamVolumePercent(stream: AudioStreamKind): Int
}

/**
 * Production Android SDK implementation of [AudioDndPlatformGateway].
 */
class AndroidAudioDndPlatformGateway(
    private val context: Context
) : AudioDndPlatformGateway {

    override fun isNotificationPolicyAccessGranted(): Boolean {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false
        return manager.isNotificationPolicyAccessGranted
    }

    override fun setInterruptionFilter(mode: DndFilterMode): PlatformDispatchResult {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return PlatformDispatchResult.Unavailable("NotificationManager unavailable")
        if (!manager.isNotificationPolicyAccessGranted) {
            return PlatformDispatchResult.MissingPermission(Manifest.permission.ACCESS_NOTIFICATION_POLICY)
        }
        val filter = when (mode) {
            DndFilterMode.ALL -> NotificationManager.INTERRUPTION_FILTER_ALL
            DndFilterMode.PRIORITY -> NotificationManager.INTERRUPTION_FILTER_PRIORITY
            DndFilterMode.NONE -> NotificationManager.INTERRUPTION_FILTER_NONE
            DndFilterMode.ALARMS_ONLY -> NotificationManager.INTERRUPTION_FILTER_ALARMS
        }
        return try {
            manager.setInterruptionFilter(filter)
            PlatformDispatchResult.Dispatched(mode.name)
        } catch (_: SecurityException) {
            PlatformDispatchResult.MissingPermission(Manifest.permission.ACCESS_NOTIFICATION_POLICY)
        } catch (e: RuntimeException) {
            PlatformDispatchResult.Unavailable(e.message ?: "Failed to update interruption filter")
        }
    }

    override fun setStreamVolumePercent(
        stream: AudioStreamKind,
        percent: Int
    ): PlatformDispatchResult {
        if (percent !in 0..100) {
            return PlatformDispatchResult.Unavailable("Volume percent must be in 0..100")
        }
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            ?: return PlatformDispatchResult.Unavailable("AudioManager unavailable")
        val streamType = toAndroidStream(stream)
        val minVol = audioManager.getStreamMinVolume(streamType)
        val maxVol = audioManager.getStreamMaxVolume(streamType)
        val targetIndex = minVol + ((maxVol - minVol) * (percent / 100.0)).roundToInt()
        return try {
            audioManager.setStreamVolume(streamType, targetIndex.coerceIn(minVol, maxVol), 0)
            PlatformDispatchResult.Dispatched("${stream.name}:$percent")
        } catch (_: SecurityException) {
            PlatformDispatchResult.MissingPermission(Manifest.permission.ACCESS_NOTIFICATION_POLICY)
        } catch (e: RuntimeException) {
            PlatformDispatchResult.Unavailable(e.message ?: "Failed to set stream volume")
        }
    }

    override fun getStreamVolumePercent(stream: AudioStreamKind): Int {
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            ?: return 0
        val streamType = toAndroidStream(stream)
        val minVol = audioManager.getStreamMinVolume(streamType)
        val maxVol = audioManager.getStreamMaxVolume(streamType)
        if (maxVol <= minVol) return 0
        val current = audioManager.getStreamVolume(streamType)
        return (((current - minVol).toDouble() / (maxVol - minVol).toDouble()) * 100.0)
            .roundToInt()
            .coerceIn(0, 100)
    }

    private fun toAndroidStream(stream: AudioStreamKind): Int = when (stream) {
        AudioStreamKind.MEDIA -> AudioManager.STREAM_MUSIC
        AudioStreamKind.RING -> AudioManager.STREAM_RING
        AudioStreamKind.ALARM -> AudioManager.STREAM_ALARM
        AudioStreamKind.NOTIFICATION -> AudioManager.STREAM_NOTIFICATION
        AudioStreamKind.SYSTEM -> AudioManager.STREAM_SYSTEM
    }
}
