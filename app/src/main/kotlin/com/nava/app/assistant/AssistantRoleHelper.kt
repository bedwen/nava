package com.nava.app.assistant

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent

/**
 * Gateway abstraction decoupling [RoleManager] framework interactions for pure JVM testing.
 */
interface AssistantRoleManagerGateway {
    fun isAssistantRoleAvailable(): Boolean
    fun isAssistantRoleHeld(): Boolean
    fun createRequestAssistantRoleIntent(): Intent?
}

/**
 * Android framework implementation of [AssistantRoleManagerGateway] utilizing system [RoleManager].
 */
class AndroidAssistantRoleManagerGateway(
    private val context: Context
) : AssistantRoleManagerGateway {

    private val roleManager: RoleManager?
        get() = context.getSystemService(RoleManager::class.java)

    override fun isAssistantRoleAvailable(): Boolean {
        return try {
            roleManager?.isRoleAvailable(RoleManager.ROLE_ASSISTANT) ?: false
        } catch (_: Exception) {
            false
        }
    }

    override fun isAssistantRoleHeld(): Boolean {
        return try {
            roleManager?.isRoleHeld(RoleManager.ROLE_ASSISTANT) ?: false
        } catch (_: Exception) {
            false
        }
    }

    override fun createRequestAssistantRoleIntent(): Intent? {
        return try {
            roleManager?.createRequestRoleIntent(RoleManager.ROLE_ASSISTANT)
        } catch (_: Exception) {
            null
        }
    }
}

/**
 * Helper wrapping [RoleManager.ROLE_ASSISTANT] status checks and role request intent creation.
 *
 * Security Invariant (PLAN.md Section 2.3.4):
 * - Nava integrates via official [RoleManager.ROLE_ASSISTANT] and modal sheet activity.
 * - SYSTEM_ALERT_WINDOW (overlay permission) is STRICTLY FORBIDDEN and never used.
 */
class AssistantRoleHelper(
    private val gateway: AssistantRoleManagerGateway
) {
    constructor(context: Context) : this(AndroidAssistantRoleManagerGateway(context))

    /**
     * Checks whether [RoleManager.ROLE_ASSISTANT] is available on this device.
     */
    fun isAssistantRoleAvailable(): Boolean = gateway.isAssistantRoleAvailable()

    /**
     * Checks whether Nava currently holds the [RoleManager.ROLE_ASSISTANT] role.
     */
    fun isAssistantRoleHeld(): Boolean = gateway.isAssistantRoleHeld()

    /**
     * Creates an [Intent] prompting the user to set Nava as the default system assistant,
     * or null if the role is unavailable.
     */
    fun createRequestAssistantRoleIntent(): Intent? = gateway.createRequestAssistantRoleIntent()

    companion object {
        const val ROLE_ASSISTANT: String = RoleManager.ROLE_ASSISTANT
    }
}
