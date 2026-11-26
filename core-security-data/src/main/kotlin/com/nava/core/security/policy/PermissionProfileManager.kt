package com.nava.core.security.policy

import com.nava.core.security.crypto.KeyUnavailability
import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Default-Deny orthogonal [PermissionProfile] manager persisted in [EncryptedSqliteStore].
 *
 * Security invariants (PLAN.md Section 5.1 & Iron Law 5):
 * - Every unknown, blank, or unassigned target resolves to [PermissionProfile.defaultDeny].
 * - Built-in presets in [PermissionProfile.IMMUTABLE_PRESET_IDS] are always available and can
 *   never be overwritten, modified, or deleted.
 * - Deleting a custom profile automatically resets all targets bound to it back to Default-Deny.
 */
class PermissionProfileManager(
    private val store: EncryptedSqliteStore,
    private val clockEpochSec: () -> Long = { System.currentTimeMillis() / 1000L }
) : PermissionEvaluatorPort {

    private val policyMutex = Mutex()

    /**
     * Last profile successfully resolved from [store] per target, used ONLY when the
     * `nava_db_master_key` is transiently unavailable (device locked,
     * `setUnlockedDeviceRequired(true)`). Without it, every background caller (notification
     * listener, routines) silently resolved to Default-Deny while the screen was locked.
     *
     * Every mutation goes through this manager, so entries can never be stale relative to the
     * database: each successful write bumps [resolutionCacheVersion] and clears the cache.
     * A cache miss while locked still fails closed (the original exception propagates).
     */
    private val lastKnownProfileByTarget = ConcurrentHashMap<String, PermissionProfile>()
    private val resolutionCacheVersion = AtomicLong(0L)
    private val warmedAtVersion = AtomicLong(-1L)

    private val builtInPresets: Map<String, PermissionProfile> = linkedMapOf(
        PermissionProfile.DEFAULT_DENY_PROFILE_ID to PermissionProfile.defaultDeny(),
        PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID to PermissionProfile.notificationSummaryOnly(),
        PermissionProfile.SAFE_DRAFT_PROFILE_ID to PermissionProfile.safeDraftAndCommunication(),
        PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID to PermissionProfile.trustedSystemAutomation(),
        PermissionProfile.BIOMETRIC_HIGH_SECURITY_PROFILE_ID to PermissionProfile.biometricHighSecurity()
    )

    override suspend fun getProfileForTarget(targetId: String): PermissionProfile {
        if (targetId.isBlank() || NULL_CHAR in targetId) {
            return PermissionProfile.defaultDeny()
        }
        val versionAtStart = resolutionCacheVersion.get()
        val resolved = try {
            resolveProfileFromStore(targetId)
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            if (KeyUnavailability.isTransient(e)) {
                lastKnownProfileByTarget[targetId]?.let { return it }
            }
            throw e
        }
        if (resolutionCacheVersion.get() == versionAtStart) {
            lastKnownProfileByTarget[targetId] = resolved
            warmResolutionCacheIfCold(versionAtStart)
        }
        return resolved
    }

    /**
     * After the first successful (unlocked) resolution, snapshots every explicit target binding so
     * targets first seen while the device is locked are still evaluated against the user's choice.
     */
    private suspend fun warmResolutionCacheIfCold(version: Long) {
        if (warmedAtVersion.get() == version) return
        val snapshot = HashMap<String, PermissionProfile>()
        try {
            for ((profileId, targets) in loadTargetsGroupedByProfile()) {
                val profile = findProfileById(profileId) ?: PermissionProfile.defaultDeny()
                for (target in targets) {
                    snapshot[target] = profile
                }
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (_: Exception) {
            return
        }
        if (resolutionCacheVersion.get() == version) {
            lastKnownProfileByTarget.putAll(snapshot)
            warmedAtVersion.set(version)
        }
    }

    private fun invalidateResolutionCache() {
        resolutionCacheVersion.incrementAndGet()
        lastKnownProfileByTarget.clear()
    }

    private suspend fun resolveProfileFromStore(targetId: String): PermissionProfile {
        val bindingHmac = store.computeBlindIndex(DOMAIN_TARGET, targetId)
        val bindingRow = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS,
            lookupHmac = bindingHmac
        ) ?: return PermissionProfile.defaultDeny()

        val binding = decodeBindingAndZeroize(bindingRow)
        if (binding.targetId != targetId) {
            return PermissionProfile.defaultDeny()
        }
        return findProfileById(binding.profileId) ?: PermissionProfile.defaultDeny()
    }

    override suspend fun evaluateCapability(
        targetId: String,
        capability: AtomicCapability
    ): ConfirmationLevel {
        return getProfileForTarget(targetId).levelFor(capability)
    }

    override suspend fun listProfiles(): List<PermissionProfile> {
        val bindingsByProfile = loadTargetsGroupedByProfile()
        val customRows = store.listAllDecrypted(EncryptedTableSchema.TABLE_PERMISSION_PROFILES)
        val customProfiles = try {
            val decodedList = ArrayList<PermissionProfile>(customRows.size)
            for (row in customRows) {
                val decoded = decodeProfileAndZeroize(row)
                if (decoded.id in PermissionProfile.IMMUTABLE_PRESET_IDS) {
                    continue
                }
                val assigned = bindingsByProfile[decoded.id].orEmpty()
                decodedList.add(decoded.copy(assignedTargets = assigned))
            }
            decodedList
        } finally {
            for (row in customRows) {
                row.zeroize()
            }
        }
        customProfiles.sortWith(compareBy<PermissionProfile> { it.createdAtEpochSec }.thenBy { it.id })

        val allProfiles = ArrayList<PermissionProfile>(builtInPresets.size + customProfiles.size)
        for ((presetId, presetProfile) in builtInPresets) {
            val assigned = bindingsByProfile[presetId].orEmpty()
            allProfiles.add(presetProfile.copy(assignedTargets = assigned))
        }
        allProfiles.addAll(customProfiles)
        return allProfiles
    }

    override suspend fun saveProfile(profile: PermissionProfile) {
        if (profile.id in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            throw SecurityException("Built-in preset profile '${profile.id}' is immutable")
        }
        if (profile.preset != PermissionProfilePreset.CUSTOM) {
            throw SecurityException(
                "Custom persisted profile '${profile.id}' must use PermissionProfilePreset.CUSTOM"
            )
        }
        require(NULL_CHAR !in profile.id) { "profile.id must not contain null characters" }
        policyMutex.withLock {
            val now = clockEpochSec()
            val persistedProfile = profile.copy(
                createdAtEpochSec = if (profile.createdAtEpochSec > 0L) profile.createdAtEpochSec else now,
                updatedAtEpochSec = if (profile.updatedAtEpochSec > 0L) profile.updatedAtEpochSec else now
            )
            val encoded = encodeProfile(persistedProfile)
            SecureMemory.withZeroizedBytes(encoded) { payload ->
                val lookupHmac = store.computeBlindIndex(DOMAIN_PROFILE, persistedProfile.id)
                store.upsertEncryptedByBlindIndex(
                    tableName = EncryptedTableSchema.TABLE_PERMISSION_PROFILES,
                    lookupHmac = lookupHmac,
                    plaintext = payload,
                    epochSec = persistedProfile.updatedAtEpochSec,
                    schemaVersion = PROFILE_SCHEMA_VERSION
                )
            }
            invalidateResolutionCache()
        }
    }

    override suspend fun assignTargetToProfile(targetId: String, profileId: String) {
        require(targetId.isNotBlank() && NULL_CHAR !in targetId) {
            "targetId must be non-blank and must not contain null characters"
        }
        require(profileId.isNotBlank() && NULL_CHAR !in profileId) {
            "profileId must be non-blank and must not contain null characters"
        }
        policyMutex.withLock {
            val targetProfile = findProfileById(profileId)
                ?: throw IllegalArgumentException("PermissionProfile '$profileId' does not exist")

            val now = clockEpochSec()
            val binding = TargetBinding(
                targetId = targetId,
                profileId = targetProfile.id,
                updatedAtEpochSec = now
            )
            val encoded = encodeBinding(binding)
            SecureMemory.withZeroizedBytes(encoded) { payload ->
                val lookupHmac = store.computeBlindIndex(DOMAIN_TARGET, targetId)
                store.upsertEncryptedByBlindIndex(
                    tableName = EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS,
                    lookupHmac = lookupHmac,
                    plaintext = payload,
                    epochSec = now,
                    schemaVersion = BINDING_SCHEMA_VERSION
                )
            }
            invalidateResolutionCache()
        }
    }

    override suspend fun deleteProfile(profileId: String) {
        require(profileId.isNotBlank() && NULL_CHAR !in profileId) {
            "profileId must be non-blank and must not contain null characters"
        }
        if (profileId in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            throw SecurityException("Built-in preset profile '$profileId' cannot be deleted")
        }
        policyMutex.withLock {
            val profileHmac = store.computeBlindIndex(DOMAIN_PROFILE, profileId)
            store.deleteByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_PERMISSION_PROFILES,
                lookupHmac = profileHmac
            )
            // Invalidate immediately: a cached binding must never outlive its deleted profile.
            invalidateResolutionCache()

            val bindingRows = store.listAllDecrypted(EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS)
            val affectedRowIds = try {
                val ids = ArrayList<Long>()
                for (row in bindingRows) {
                    val binding = decodeBindingAndZeroize(row)
                    if (binding.profileId == profileId) {
                        ids.add(row.rowId)
                    }
                }
                ids
            } finally {
                for (row in bindingRows) {
                    row.zeroize()
                }
            }
            try {
                for (rowId in affectedRowIds) {
                    store.deleteByRowId(
                        tableName = EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS,
                        rowId = rowId
                    )
                }
            } finally {
                invalidateResolutionCache()
            }
        }
    }

    /**
     * Fast Default-Deny check for `NotificationListenerService.onNotificationPosted()` to drop
     * disallowed packages in memory before any text extraction, storage, or logging.
     */
    suspend fun isNotificationReadEnabled(packageName: String): Boolean {
        if (packageName.isBlank() || NULL_CHAR in packageName) return false
        return evaluateCapability(packageName, AtomicCapability.NOTIFICATION_READ).isAllowed
    }

    private suspend fun findProfileById(profileId: String): PermissionProfile? {
        if (profileId.isBlank() || NULL_CHAR in profileId) return null
        builtInPresets[profileId]?.let { return it }
        val profileHmac = store.computeBlindIndex(DOMAIN_PROFILE, profileId)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_PERMISSION_PROFILES,
            lookupHmac = profileHmac
        ) ?: return null
        val decoded = decodeProfileAndZeroize(row)
        return if (decoded.id == profileId && decoded.id !in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            decoded
        } else {
            null
        }
    }

    private suspend fun loadTargetsGroupedByProfile(): Map<String, Set<String>> {
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS)
        return try {
            val grouped = LinkedHashMap<String, MutableSet<String>>()
            for (row in rows) {
                val binding = decodeBindingAndZeroize(row)
                grouped.getOrPut(binding.profileId) { LinkedHashSet() }.add(binding.targetId)
            }
            grouped
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    private fun encodeProfile(profile: PermissionProfile): ByteArray {
        val capabilitiesAsStrings = LinkedHashMap<String, String>(profile.capabilities.size)
        for ((capability, level) in profile.capabilities) {
            capabilitiesAsStrings[capability.name] = level.name
        }
        return StructuredPayloadCodec.encode(formatVersion = PROFILE_SCHEMA_VERSION) {
            writeString(profile.id)
            writeString(profile.name)
            writeString(profile.preset.name)
            writeStringMap(capabilitiesAsStrings)
            writeLong(profile.createdAtEpochSec)
            writeLong(profile.updatedAtEpochSec)
        }
    }

    private fun decodeProfileAndZeroize(row: DecryptedRow): PermissionProfile {
        return try {
            StructuredPayloadCodec.decode(
                bytes = row.plaintext,
                expectedVersion = PROFILE_SCHEMA_VERSION
            ) {
                val id = readString()
                val name = readString()
                val preset = PermissionProfilePreset.valueOf(readString())
                val rawCaps = readStringMap()
                val capabilities = LinkedHashMap<AtomicCapability, ConfirmationLevel>(rawCaps.size)
                for ((capName, levelName) in rawCaps) {
                    capabilities[AtomicCapability.valueOf(capName)] = ConfirmationLevel.valueOf(levelName)
                }
                val createdAt = readLong()
                val updatedAt = readLong()
                PermissionProfile(
                    id = id,
                    name = name,
                    preset = preset,
                    capabilities = capabilities,
                    createdAtEpochSec = createdAt,
                    updatedAtEpochSec = updatedAt
                )
            }
        } finally {
            row.zeroize()
        }
    }

    private fun encodeBinding(binding: TargetBinding): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = BINDING_SCHEMA_VERSION) {
            writeString(binding.targetId)
            writeString(binding.profileId)
            writeLong(binding.updatedAtEpochSec)
        }
    }

    private fun decodeBindingAndZeroize(row: DecryptedRow): TargetBinding {
        return try {
            StructuredPayloadCodec.decode(
                bytes = row.plaintext,
                expectedVersion = BINDING_SCHEMA_VERSION
            ) {
                TargetBinding(
                    targetId = readString(),
                    profileId = readString(),
                    updatedAtEpochSec = readLong()
                )
            }
        } finally {
            row.zeroize()
        }
    }

    private data class TargetBinding(
        val targetId: String,
        val profileId: String,
        val updatedAtEpochSec: Long
    )

    companion object {
        private const val DOMAIN_PROFILE: String = "profile"
        private const val DOMAIN_TARGET: String = "target"
        private const val PROFILE_SCHEMA_VERSION: Int = 1
        private const val BINDING_SCHEMA_VERSION: Int = 1
        private const val NULL_CHAR: Char = '\u0000'
    }
}
