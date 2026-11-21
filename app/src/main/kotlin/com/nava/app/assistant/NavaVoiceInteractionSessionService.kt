package com.nava.app.assistant

import android.os.Bundle
import android.service.voice.VoiceInteractionSession
import android.service.voice.VoiceInteractionSessionService

/**
 * Bound session service for voice interaction sessions (PLAN.md Section 2.3.4).
 *
 * Declared in AndroidManifest.xml with:
 * - android:permission="android.permission.BIND_VOICE_INTERACTION"
 * - android:exported="false"
 */
open class NavaVoiceInteractionSessionService : VoiceInteractionSessionService() {

    override fun onNewSession(args: Bundle?): VoiceInteractionSession {
        return NavaVoiceInteractionSession(this)
    }
}
