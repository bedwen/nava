package com.nava.domain.usecase

import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The one-tap grant on a denial card must change only the denied target, never a preset or a
 * custom profile shared with other targets, and must respect structural level rules.
 */
class SetCapabilityForTargetTest {

    private class InMemoryEvaluator : PermissionEvaluatorPort {
        val profiles = linkedMapOf(PermissionProfile.DEFAULT_DENY_PROFILE_ID to PermissionProfile.defaultDeny())
        val assignments = mutableMapOf<String, String>()

        override suspend fun getProfileForTarget(targetId: String): PermissionProfile {
            val id = assignments[targetId] ?: PermissionProfile.DEFAULT_DENY_PROFILE_ID
            return profiles[id] ?: PermissionProfile.defaultDeny()
        }

        override suspend fun evaluateCapability(targetId: String, capability: AtomicCapability): ConfirmationLevel =
            getProfileForTarget(targetId).levelFor(capability)

        override suspend fun listProfiles(): List<PermissionProfile> = profiles.values.toList()

        override suspend fun saveProfile(profile: PermissionProfile) {
            profiles[profile.id] = profile
        }

        override suspend fun assignTargetToProfile(targetId: String, profileId: String) {
            assignments[targetId] = profileId
        }

        override suspend fun deleteProfile(profileId: String) {
            profiles.remove(profileId)
        }
    }

    private class RecordingAudit : AuditLogPort {
        val entries = ArrayList<AuditLogEntry>()
        override suspend fun record(entry: AuditLogEntry) {
            entries.add(entry)
        }
        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
    }

    @Test
    fun grantOnDefaultDenyForksPerTargetProfileAndLeavesOthersDenied() = runBlocking {
        val evaluator = InMemoryEvaluator()
        val audit = RecordingAudit()
        val useCase = ManageProfilesUseCase(evaluator, audit)

        useCase.setCapabilityForTarget("system.clock", AtomicCapability.CREATE_DRAFT, ConfirmationLevel.AUTO, 1_000L)

        assertEquals(ConfirmationLevel.AUTO, evaluator.evaluateCapability("system.clock", AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.DISABLED, evaluator.evaluateCapability("system.calendar", AtomicCapability.CREATE_DRAFT))
        assertEquals(
            ConfirmationLevel.DISABLED,
            evaluator.profiles.getValue(PermissionProfile.DEFAULT_DENY_PROFILE_ID).levelFor(AtomicCapability.CREATE_DRAFT)
        )
        assertEquals(ManageProfilesUseCase.perTargetProfileId("system.clock"), evaluator.assignments["system.clock"])
        assertTrue(audit.entries.any { it.decision == "TARGET_ASSIGNED" && it.targetId == "system.clock" })
    }

    @Test
    fun grantNeverWidensASharedCustomProfile() = runBlocking {
        val evaluator = InMemoryEvaluator()
        val shared = PermissionProfile(
            id = "custom_shared",
            name = "Shared",
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = AtomicCapability.entries.associateWith { ConfirmationLevel.DISABLED }
        )
        evaluator.profiles[shared.id] = shared
        evaluator.assignments["system.clock"] = shared.id
        evaluator.assignments["system.sms"] = shared.id
        val useCase = ManageProfilesUseCase(evaluator, RecordingAudit())

        useCase.setCapabilityForTarget("system.clock", AtomicCapability.CREATE_DRAFT, ConfirmationLevel.PROMPT_CARD, 2_000L)

        assertEquals(ConfirmationLevel.PROMPT_CARD, evaluator.evaluateCapability("system.clock", AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.DISABLED, evaluator.evaluateCapability("system.sms", AtomicCapability.CREATE_DRAFT))
        assertNotEquals(shared.id, evaluator.assignments["system.clock"])

        // A second grant reuses the target's own profile instead of forking again.
        useCase.setCapabilityForTarget("system.clock", AtomicCapability.DATA_READ, ConfirmationLevel.AUTO, 3_000L)
        assertEquals(ConfirmationLevel.PROMPT_CARD, evaluator.evaluateCapability("system.clock", AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.AUTO, evaluator.evaluateCapability("system.clock", AtomicCapability.DATA_READ))
    }

    @Test
    fun autoIsRejectedForModifyDeleteSend() {
        val evaluator = InMemoryEvaluator()
        val useCase = ManageProfilesUseCase(evaluator, RecordingAudit())
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                useCase.setCapabilityForTarget(
                    "system.sms",
                    AtomicCapability.MODIFY_DELETE_SEND,
                    ConfirmationLevel.AUTO,
                    1_000L
                )
            }
        }
        assertEquals(1, evaluator.profiles.size)
    }
}
