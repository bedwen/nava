package com.nava.app.di

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.Uri
import com.nava.app.assistant.AssistantIntentContract
import com.nava.app.diagnostics.LogcatLlmTurnDiagnosticsSink
import com.nava.app.locale.AndroidPlatformLocaleBridge
import com.nava.app.locale.AppLocaleManager
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.locale.FallbackEnglishMessageTemplateProvider
import com.nava.app.locale.InMemoryPlatformLocaleBridge
import com.nava.app.locale.LocaleDateTimeFormatter
import com.nava.app.locale.MessageTemplateProvider
import com.nava.app.locale.NavaMessageRenderer
import com.nava.app.locale.PlatformLocaleBridge
import com.nava.app.reminders.MorningBriefingPreferencesStore
import com.nava.app.security.AndroidBiometricPromptGateway
import com.nava.app.security.BiometricPromptGateway
import com.nava.app.security.BiometricPromptGatewayOutcome
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.security.PendingConfirmationStore
import com.nava.app.security.VaultBiometricController
import com.nava.app.ui.theme.ThemePreferenceStore
import com.nava.app.voice.AndroidOnDeviceSpeechRecognizerGateway
import com.nava.app.voice.OnDeviceSpeechConfig
import com.nava.app.voice.OnDeviceSpeechListener
import com.nava.app.voice.OnDeviceSpeechRecognizerGateway
import com.nava.app.voice.OnDeviceVoiceInputController
import com.nava.core.ai.embedding.AndroidLiteRtEmbeddingRuntimeAdapter
import com.nava.core.ai.embedding.EmbeddingNoteSemanticRanker
import com.nava.core.ai.embedding.EmbeddingRuntimeAdapter
import com.nava.core.ai.embedding.LiteRtEmbeddingEngine
import com.nava.core.ai.engine.AndroidLiteRtRuntimeAdapter
import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.LiteRtRuntimeAdapter
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.engine.RuntimeTurnConfig
import com.nava.core.ai.lifecycle.AndroidDeviceHardwareStatusProvider
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.DeviceHardwareStatusProvider
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.locale.AndroidAssetTextReader
import com.nava.core.ai.locale.AndroidTextClassifierAdapter
import com.nava.core.ai.locale.AssetLocaleRulePackLoader
import com.nava.core.ai.locale.AssetSupportedLanguageCatalog
import com.nava.core.ai.locale.AssetTextReader
import com.nava.core.ai.locale.ClasspathAssetTextReader
import com.nava.core.ai.locale.DirectoryAssetTextReader
import com.nava.core.ai.locale.OnDeviceLanguageDetector
import com.nava.core.ai.locale.PlatformLanguageClassifier
import com.nava.core.ai.locale.SeedLocaleNormalizers
import com.nava.core.ai.parser.MicroDslParser
import com.nava.core.ai.provisioning.AndroidStatFsStorageSpaceProvider
import com.nava.core.ai.provisioning.SafModelProvisioner
import com.nava.core.ai.provisioning.StorageSpaceProvider
import com.nava.core.ai.pruner.DynamicToolPruner
import com.nava.core.ai.router.CacheIntentResolver
import com.nava.core.ai.router.FunctionGemmaIntentResolver
import com.nava.core.ai.router.GemmaIntentResolver
import com.nava.core.ai.router.RuleIntentResolver
import com.nava.core.security.crypto.AesGcmCryptoEngine
import com.nava.core.security.crypto.AndroidKeystoreKeyProvider
import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.HmacSha256Engine
import com.nava.core.security.dao.ActionCacheDao
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.dao.EncryptedNoteDao
import com.nava.core.security.dao.ScheduledReminderDao
import com.nava.core.security.firewall.BlindSlotExtractor
import com.nava.core.security.firewall.OutboundChannelPolicy
import com.nava.core.security.firewall.SecurityFirewall
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.AndroidSqliteOpenHelperBackend
import com.nava.core.security.storage.EncryptedRowStorage
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.RawEncryptedRow
import com.nava.core.security.vault.NavaVault
import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.RamTier
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.ReminderSchedulerPort
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LocaleNormalizerRegistry
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.CompileRuleUseCase
import com.nava.domain.usecase.ExecutePlanUseCase
import com.nava.domain.usecase.ManageProfilesUseCase
import com.nava.domain.usecase.ProcessQueryUseCase
import com.nava.feature.automations.alarm.AlarmTimerTool
import com.nava.feature.automations.applaunch.AppLaunchTool
import com.nava.feature.automations.audio.AudioDndTool
import com.nava.feature.automations.background.BackgroundTaskContinuationManager
import com.nava.feature.automations.background.BackgroundTaskWorkScheduler
import com.nava.feature.automations.background.WorkManagerBackgroundTaskScheduler
import com.nava.feature.automations.briefing.DailyBriefingBuilder
import com.nava.feature.automations.briefing.DailyBriefingTool
import com.nava.feature.automations.calendar.CalendarTool
import com.nava.feature.automations.call.CallIntentTool
import com.nava.feature.automations.common.AndroidAudioDndPlatformGateway
import com.nava.feature.automations.common.AndroidAutomationIntentGateway
import com.nava.feature.automations.common.AndroidAutomationNotificationBridge
import com.nava.feature.automations.common.AndroidCalendarPlatformGateway
import com.nava.feature.automations.common.AndroidSafPlatformGateway
import com.nava.feature.automations.common.AudioDndPlatformGateway
import com.nava.feature.automations.common.AudioStreamKind
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.CalendarEventDraft
import com.nava.feature.automations.common.CalendarEventPatch
import com.nava.feature.automations.common.CalendarEventRecord
import com.nava.feature.automations.common.CalendarGatewayResult
import com.nava.feature.automations.common.CalendarPlatformGateway
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.DndFilterMode
import com.nava.feature.automations.common.ForegroundNotificationSpec
import com.nava.feature.automations.common.InteractiveNotificationRequest
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.SafDocumentEntry
import com.nava.feature.automations.common.SafGatewayResult
import com.nava.feature.automations.common.SafPlatformGateway
import com.nava.feature.automations.notes.NotesSearchTool
import com.nava.feature.automations.notes.NotesVaultTool
import com.nava.feature.automations.notification.InMemoryNotificationInbox
import com.nava.feature.automations.notification.NotificationServiceBinding
import com.nava.feature.automations.notification.NotificationSummaryTool
import com.nava.feature.automations.reminder.ReminderAlarmScheduler
import com.nava.feature.automations.reminder.ReminderTools
import com.nava.feature.automations.routine.AutomationWorkerRegistry
import com.nava.feature.automations.routine.ProposeRoutineTool
import com.nava.feature.automations.routine.RoutineExecutor
import com.nava.feature.automations.routine.RoutineWorkScheduler
import com.nava.feature.automations.routine.WorkManagerRoutineScheduler
import com.nava.feature.automations.saf.SafDirectoryTool
import com.nava.feature.automations.sms.SmsDraftTool
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt

/**
 * Pure Kotlin Manual Constructor Dependency Injection Composition Root for Nava (`:app`)
 * (PLAN.md Section 1.1 Law 4, Section 2, and Section 9 Phase 5).
 *
 * Performance & Cold-Start Invariant (`< 400 ms`, PLAN.md Section 2.3):
 * - All heavy components are `lazy`.
 * - Construction of [AppContainer] and [NavaApplication.onCreate] NEVER loads `.litertlm` weights,
 *   NEVER initializes `LiteRT-LM` native engines, and NEVER computes SHA-256 digests over multi-GB
 *   model bundles on the main thread.
 * - Active model path resolution and integrity verification execute asynchronously on
 *   `Dispatchers.IO` inside [resolveActiveModelPath] only when Tier 3 inference is invoked.
 */
class AppContainer internal constructor(
    val appContext: Context?,
    private val templateProviderFactory: (Context) -> MessageTemplateProvider = {
        FallbackEnglishMessageTemplateProvider()
    },
    private val templateProviderOverride: MessageTemplateProvider? = null,
    private val keyProviderOverride: CryptoKeyProvider? = null,
    private val rowStorageOverride: EncryptedRowStorage? = null,
    private val vaultDirOverride: File? = null,
    private val modelsDirOverride: File? = null,
    private val storageSpaceProviderOverride: StorageSpaceProvider? = null,
    private val assetTextReaderOverride: AssetTextReader? = null,
    private val platformLanguageClassifierOverride: PlatformLanguageClassifier? = null,
    private val hardwareStatusProviderOverride: DeviceHardwareStatusProvider? = null,
    private val liteRtRuntimeAdapterOverride: LiteRtRuntimeAdapter? = null,
    private val functionRuntimeAdapterOverride: LiteRtRuntimeAdapter? = null,
    private val embeddingRuntimeAdapterOverride: EmbeddingRuntimeAdapter? = null,
    private val embeddingPortOverride: EmbeddingPort? = null,
    private val intentGatewayOverride: AutomationIntentGateway? = null,
    private val audioDndGatewayOverride: AudioDndPlatformGateway? = null,
    private val calendarGatewayOverride: CalendarPlatformGateway? = null,
    private val safGatewayOverride: SafPlatformGateway? = null,
    private val notificationBridgeOverride: AutomationNotificationBridge? = null,
    private val routineWorkSchedulerOverride: RoutineWorkScheduler? = null,
    private val backgroundTaskWorkSchedulerOverride: BackgroundTaskWorkScheduler? = null,
    private val reminderSchedulerOverride: ReminderSchedulerPort? = null,
    private val platformLocaleBridgeOverride: PlatformLocaleBridge? = null,
    private val preferencesStorageGatewayOverride: PreferencesStorageGateway? = null,
    private val biometricPromptGatewayOverride: BiometricPromptGateway? = null,
    private val speechRecognizerGatewayOverride: OnDeviceSpeechRecognizerGateway? = null,
    private val modelImportHandlerOverride: (suspend (BackgroundTaskRequest.ModelImportContinuation) -> Boolean)? = null,
    private val verifyModelSha256OnResolve: Boolean = false,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val appScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
) {

    /**
     * Production constructor wired from [NavaApplication].
     *
     * Exposes [templateProviderFactory] (defaulting to `{ FallbackEnglishMessageTemplateProvider() }`)
     * so Wave 2 can wire `AndroidResourceMessageTemplateProvider` cleanly in [NavaApplication].
     */
    constructor(
        context: Context,
        templateProviderFactory: (Context) -> MessageTemplateProvider = {
            FallbackEnglishMessageTemplateProvider()
        }
    ) : this(
        appContext = context.applicationContext,
        templateProviderFactory = templateProviderFactory
    )

    private fun requireContext(): Context {
        return requireNotNull(appContext) {
            "Android Context is required when platform override is not provided"
        }
    }

    // -------------------------------------------------------------------------
    // 1. Security, Cryptography, EncryptedSqliteStore, Vault & Firewall
    // -------------------------------------------------------------------------

    val keyProvider: CryptoKeyProvider by lazy {
        keyProviderOverride ?: AndroidKeystoreKeyProvider()
    }

    val rowStorage: EncryptedRowStorage by lazy {
        rowStorageOverride ?: AndroidSqliteOpenHelperBackend(requireContext())
    }

    val aesGcmEngine: AesGcmCryptoEngine by lazy {
        AesGcmCryptoEngine()
    }

    val hmacEngine: HmacSha256Engine by lazy {
        HmacSha256Engine()
    }

    val encryptedSqliteStore: EncryptedSqliteStore by lazy {
        EncryptedSqliteStore(
            storage = rowStorage,
            keyProvider = keyProvider,
            aesGcmEngine = aesGcmEngine,
            hmacEngine = hmacEngine,
            dispatcher = ioDispatcher
        )
    }

    val actionCacheDao: ActionCacheDao by lazy {
        ActionCacheDao(store = encryptedSqliteStore)
    }

    val auditLogDao: AuditLogDao by lazy {
        AuditLogDao(store = encryptedSqliteStore)
    }

    val encryptedNoteDao: EncryptedNoteDao by lazy {
        EncryptedNoteDao(store = encryptedSqliteStore)
    }

    val scheduledReminderDao: ScheduledReminderDao by lazy {
        ScheduledReminderDao(store = encryptedSqliteStore)
    }

    val permissionProfileManager: PermissionProfileManager by lazy {
        PermissionProfileManager(
            store = encryptedSqliteStore,
            clockEpochSec = { clockMs() / 1000L }
        )
    }

    val ruleCapabilityGrantManager: RuleCapabilityGrantManager by lazy {
        RuleCapabilityGrantManager(
            store = encryptedSqliteStore,
            keyProvider = keyProvider,
            hmacEngine = hmacEngine
        )
    }

    val navaVault: NavaVault by lazy {
        val dir = vaultDirOverride ?: File(requireContext().filesDir, VAULT_DIR_NAME)
        NavaVault(
            vaultDir = dir,
            keyProvider = keyProvider,
            aesGcmEngine = aesGcmEngine,
            clockMs = clockMs,
            dispatcher = ioDispatcher
        )
    }

    val outboundChannelPolicy: OutboundChannelPolicy by lazy {
        OutboundChannelPolicy()
    }

    val securityFirewall: SecurityFirewall by lazy {
        SecurityFirewall(
            permissionEvaluator = permissionProfileManager,
            ruleGrantManager = ruleCapabilityGrantManager,
            auditLog = auditLogDao,
            outboundPolicy = outboundChannelPolicy,
            clockMs = clockMs
        )
    }

    // -------------------------------------------------------------------------
    // 2. Multilingual Catalog, Rule Packs, Normalization & Language Detection
    // -------------------------------------------------------------------------

    val assetTextReader: AssetTextReader by lazy {
        assetTextReaderOverride ?: AndroidAssetTextReader(requireContext().assets)
    }

    val supportedLanguageCatalog: AssetSupportedLanguageCatalog by lazy {
        AssetSupportedLanguageCatalog(assetReader = assetTextReader)
    }

    val localeRulePackLoader: AssetLocaleRulePackLoader by lazy {
        AssetLocaleRulePackLoader(assetReader = assetTextReader)
    }

    val localeNormalizerRegistry: LocaleNormalizerRegistry by lazy {
        SeedLocaleNormalizers.createRegistry()
    }

    val textNormalizer: GenericTextNormalizer by lazy {
        GenericTextNormalizer(registry = localeNormalizerRegistry)
    }

    val platformLanguageClassifier: PlatformLanguageClassifier? by lazy {
        platformLanguageClassifierOverride ?: appContext?.let { AndroidTextClassifierAdapter(it) }
    }

    val languageDetector: OnDeviceLanguageDetector by lazy {
        OnDeviceLanguageDetector(
            catalog = supportedLanguageCatalog,
            platformClassifier = platformLanguageClassifier,
            textNormalizer = textNormalizer
        )
    }

    // -------------------------------------------------------------------------
    // 3. Hardware Telemetry, Thermal Lifecycle, SAF Model Provisioning & LiteRT-LM
    // -------------------------------------------------------------------------

    val hardwareStatusProvider: DeviceHardwareStatusProvider by lazy {
        hardwareStatusProviderOverride ?: AndroidDeviceHardwareStatusProvider(requireContext())
    }

    val thermalModelLifecycleManager: ThermalModelLifecycleManager by lazy {
        ThermalModelLifecycleManager(
            hardwareStatusProvider = hardwareStatusProvider,
            scope = appScope
        )
    }

    val multiModelCoordinator: MultiModelCoordinator by lazy {
        MultiModelCoordinator(hardwareStatusProvider)
    }

    val storageSpaceProvider: StorageSpaceProvider by lazy {
        storageSpaceProviderOverride ?: AndroidStatFsStorageSpaceProvider()
    }

    val safModelProvisioner: SafModelProvisioner by lazy {
        val dir = modelsDirOverride ?: File(requireContext().filesDir, SafModelProvisioner.MODELS_DIR_NAME)
        SafModelProvisioner(
            modelsDir = dir,
            storageSpaceProvider = storageSpaceProvider,
            clockMs = clockMs
        )
    }

    val liteRtRuntimeAdapter: LiteRtRuntimeAdapter by lazy {
        liteRtRuntimeAdapterOverride ?: AndroidLiteRtRuntimeAdapter(context = requireContext())
    }

    val liteRtLlmEngine: LiteRtLlmEngine by lazy {
        LiteRtLlmEngine(
            modelPathProvider = { resolveActiveModelPath() },
            lifecycleManager = thermalModelLifecycleManager,
            runtimeAdapter = liteRtRuntimeAdapter,
            clockMs = clockMs,
            coordinator = multiModelCoordinator,
            modelSlot = ModelSlot.PRIMARY_LLM
        )
    }

    val llmEngine: LlmEnginePort
        get() = liteRtLlmEngine

    val embeddingRuntimeAdapter: EmbeddingRuntimeAdapter by lazy {
        embeddingRuntimeAdapterOverride ?: if (appContext != null) {
            AndroidLiteRtEmbeddingRuntimeAdapter(requireContext())
        } else {
            NoOpTestEmbeddingRuntimeAdapter()
        }
    }

    val liteRtEmbeddingEngine: LiteRtEmbeddingEngine by lazy {
        LiteRtEmbeddingEngine(
            modelPathProvider = { resolveActiveEmbeddingModelPath() },
            lifecycleManager = thermalModelLifecycleManager,
            runtimeAdapter = embeddingRuntimeAdapter,
            coordinator = multiModelCoordinator
        )
    }

    val embeddingPort: EmbeddingPort by lazy {
        embeddingPortOverride ?: liteRtEmbeddingEngine
    }

    val embeddingNoteSemanticRanker: EmbeddingNoteSemanticRanker by lazy {
        EmbeddingNoteSemanticRanker(embeddingPort)
    }

    val functionRuntimeAdapter: LiteRtRuntimeAdapter by lazy {
        functionRuntimeAdapterOverride ?: if (appContext != null) {
            AndroidLiteRtRuntimeAdapter(context = requireContext(), useGpuBackend = false)
        } else {
            NoOpTestLiteRtRuntimeAdapter()
        }
    }

    val functionGemmaEngine: LiteRtLlmEngine by lazy {
        LiteRtLlmEngine(
            modelPathProvider = { resolveActiveFunctionModelPath() },
            lifecycleManager = thermalModelLifecycleManager,
            runtimeAdapter = functionRuntimeAdapter,
            clockMs = clockMs,
            coordinator = multiModelCoordinator,
            modelSlot = ModelSlot.FUNCTION_ROUTER
        )
    }

    val blindSlotExtractor: BlindSlotExtractor by lazy {
        BlindSlotExtractor(llmEngine = llmEngine)
    }

    val dynamicToolPruner: DynamicToolPruner by lazy {
        DynamicToolPruner()
    }

    val microDslParser: MicroDslParser by lazy {
        MicroDslParser()
    }

    // -------------------------------------------------------------------------
    // 4. Three-Tier Hybrid Intent Router
    // -------------------------------------------------------------------------

    val ruleIntentResolver: RuleIntentResolver by lazy {
        RuleIntentResolver(
            rulePackLoader = localeRulePackLoader,
            securityFirewall = securityFirewall,
            textNormalizer = textNormalizer
        )
    }

    val cacheIntentResolver: CacheIntentResolver by lazy {
        CacheIntentResolver(
            actionCachePort = actionCacheDao,
            securityFirewall = securityFirewall,
            textNormalizer = textNormalizer
        )
    }

    val functionGemmaIntentResolver: FunctionGemmaIntentResolver by lazy {
        FunctionGemmaIntentResolver(
            functionEngine = functionGemmaEngine,
            isModelAvailable = { resolveActiveFunctionModelPath() != null },
            lifecycleManager = thermalModelLifecycleManager,
            coordinator = multiModelCoordinator,
            toolPruner = dynamicToolPruner,
            microDslParser = microDslParser,
            securityFirewall = securityFirewall,
            rulePackLoader = localeRulePackLoader,
            embeddingPort = embeddingPort
        )
    }

    /**
     * Developer-only Tier 3 diagnostics sink. Non-null ONLY in debuggable builds
     * (`ApplicationInfo.FLAG_DEBUGGABLE`), so release builds never log utterances or model output.
     */
    val llmDiagnosticsSink: LogcatLlmTurnDiagnosticsSink? by lazy {
        val debuggable = appContext?.applicationInfo?.let { info ->
            (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } ?: false
        if (debuggable) LogcatLlmTurnDiagnosticsSink() else null
    }

    val gemmaIntentResolver: GemmaIntentResolver by lazy {
        GemmaIntentResolver(
            llmEngine = llmEngine,
            lifecycleManager = thermalModelLifecycleManager,
            toolPruner = dynamicToolPruner,
            microDslParser = microDslParser,
            securityFirewall = securityFirewall,
            rulePackLoader = localeRulePackLoader,
            diagnosticsSink = llmDiagnosticsSink,
            embeddingPort = embeddingPort,
            personalMemory = personalFactDao
        )
    }

    val intentResolvers: List<IntentResolver> by lazy {
        listOf(
            ruleIntentResolver,
            cacheIntentResolver,
            functionGemmaIntentResolver,
            gemmaIntentResolver
        )
    }

    // -------------------------------------------------------------------------
    // 5. Platform Gateways & All 21 Atomic NavaTool Adapters in ToolRegistry
    // -------------------------------------------------------------------------

    val intentGateway: AutomationIntentGateway by lazy {
        intentGatewayOverride ?: AndroidAutomationIntentGateway(requireContext())
    }

    val audioDndGateway: AudioDndPlatformGateway by lazy {
        audioDndGatewayOverride ?: AndroidAudioDndPlatformGateway(requireContext())
    }

    val deviceControlGateway: com.nava.feature.automations.common.DeviceControlPlatformGateway by lazy {
        val ctx = appContext
        if (ctx != null) {
            com.nava.feature.automations.common.AndroidDeviceControlPlatformGateway(ctx)
        } else {
            object : com.nava.feature.automations.common.DeviceControlPlatformGateway {
                private val unavailable =
                    com.nava.feature.automations.common.PlatformDispatchResult.Unavailable("No Android context")
                override fun setFlashlight(enabled: Boolean) = unavailable
                override fun sendMediaCommand(command: com.nava.feature.automations.common.MediaCommand) = unavailable
                override fun openSettingsPanel(panel: com.nava.feature.automations.common.SettingsPanelKind) = unavailable
            }
        }
    }

    /** Encrypted store of facts the user asked Nava to remember. */
    val personalFactDao: com.nava.core.security.dao.PersonalFactDao by lazy {
        com.nava.core.security.dao.PersonalFactDao(encryptedSqliteStore)
    }

    val calendarGateway: CalendarPlatformGateway by lazy {
        calendarGatewayOverride ?: AndroidCalendarPlatformGateway(requireContext())
    }

    val safGateway: SafPlatformGateway by lazy {
        safGatewayOverride ?: AndroidSafPlatformGateway(requireContext())
    }

    val notificationInbox: InMemoryNotificationInbox by lazy {
        InMemoryNotificationInbox()
    }

    val alarmTimerTool: AlarmTimerTool by lazy {
        AlarmTimerTool(
            intentGateway = intentGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao,
            clock = clockMs
        )
    }

    val calendarTool: CalendarTool by lazy {
        CalendarTool(
            calendarGateway = calendarGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao,
            clock = clockMs
        )
    }

    val audioDndTool: AudioDndTool by lazy {
        AudioDndTool(
            audioDndGateway = audioDndGateway,
            auditLog = auditLogDao,
            clock = clockMs
        )
    }

    val smsDraftTool: SmsDraftTool by lazy {
        SmsDraftTool(
            intentGateway = intentGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao
        )
    }

    val callIntentTools: List<NavaTool> by lazy {
        CallIntentTool.createAll(
            intentGateway = intentGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao
        )
    }

    val notesVaultTools: List<NavaTool> by lazy {
        NotesVaultTool.createAll(
            noteStorage = encryptedNoteDao,
            vaultPort = navaVault,
            auditLog = auditLogDao
        )
    }

    val notesSearchTool: NotesSearchTool by lazy {
        NotesSearchTool(
            noteStorage = encryptedNoteDao,
            permissionEvaluator = permissionProfileManager,
            auditLog = auditLogDao,
            semanticRanker = embeddingNoteSemanticRanker,
            clock = clockMs
        )
    }

    val safDirectoryTools: List<NavaTool> by lazy {
        SafDirectoryTool.createAll(
            safGateway = safGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao
        )
    }

    val appLaunchTool: AppLaunchTool by lazy {
        AppLaunchTool(
            intentGateway = intentGateway,
            firewall = securityFirewall,
            auditLog = auditLogDao,
            clock = clockMs,
            permissionEvaluator = permissionProfileManager
        )
    }

    val notificationSummaryTool: NotificationSummaryTool by lazy {
        NotificationSummaryTool(
            inbox = notificationInbox,
            permissionEvaluator = permissionProfileManager,
            auditLog = auditLogDao,
            intentGateway = intentGateway
        )
    }

    val reminderAlarmScheduler: ReminderSchedulerPort by lazy {
        reminderSchedulerOverride
            ?: appContext?.let { ReminderAlarmScheduler(it) }
            ?: object : ReminderSchedulerPort {
                override fun scheduleReminder(reminder: ScheduledReminder): Boolean = true
                override fun cancelReminder(reminderId: String) = Unit
                override fun scheduleMorningBriefing(hour: Int, minute: Int, nowEpochMs: Long): Long? =
                    ReminderAlarmScheduler.computeNextDailyTriggerEpochMs(hour, minute, nowEpochMs)
                override fun cancelMorningBriefing() = Unit
            }
    }

    val notificationWatcherDao: com.nava.core.security.dao.NotificationWatcherDao by lazy {
        com.nava.core.security.dao.NotificationWatcherDao(encryptedSqliteStore)
    }

    /**
     * Single watcher access point for the engine, tools and UI: keeps a lock-screen snapshot that
     * every mutation refreshes, so nothing can bypass it with a direct DAO write.
     */
    val notificationWatcherPort: com.nava.feature.automations.notification.CachingNotificationWatcherPort by lazy {
        com.nava.feature.automations.notification.CachingNotificationWatcherPort(notificationWatcherDao)
    }

    val notificationWatcherEngine: com.nava.feature.automations.notification.NotificationWatcherEngine by lazy {
        com.nava.feature.automations.notification.NotificationWatcherEngine(
            watcherPort = notificationWatcherPort,
            alertPort = com.nava.domain.automation.NotificationWatcherAlertPort { watcher, sourcePkg, title, snippet ->
                appContext?.let { ctx ->
                    com.nava.app.reminders.ReminderNotificationPoster.postWatcherAlertNotification(
                        context = ctx,
                        watcher = watcher,
                        sourcePackageName = sourcePkg,
                        title = title,
                        snippet = snippet
                    )
                }
            },
            clockMs = clockMs
        )
    }

    val notificationWatcherTools: List<NavaTool> by lazy {
        com.nava.feature.automations.notification.NotificationWatcherTools.createAll(
            watcherPort = notificationWatcherPort,
            auditLog = auditLogDao,
            clockMs = clockMs
        )
    }

    val reminderTools: List<NavaTool> by lazy {
        ReminderTools.createAll(
            reminderPort = scheduledReminderDao,
            schedulerPort = reminderAlarmScheduler,
            auditLog = auditLogDao,
            clock = clockMs
        )
    }

    val proposeRoutineTool: ProposeRoutineTool by lazy {
        ProposeRoutineTool(
            ruleGrantPort = ruleCapabilityGrantManager,
            toolRegistryProvider = { toolRegistry },
            auditLog = auditLogDao,
            clock = clockMs
        )
    }

    val dailyBriefingBuilder: DailyBriefingBuilder by lazy {
        DailyBriefingBuilder(
            reminderPort = scheduledReminderDao,
            notificationInbox = notificationInbox,
            permissionEvaluator = permissionProfileManager,
            calendarGateway = calendarGateway
        )
    }

    val dailyBriefingTool: DailyBriefingTool by lazy {
        DailyBriefingTool(
            builder = dailyBriefingBuilder,
            auditLog = auditLogDao,
            configProvider = { morningBriefingPreferencesStore.currentConfig() },
            clock = clockMs
        )
    }

    /** Reactive signal set by [com.nava.app.MainActivity] when the user taps "Summarize with Nava" on a Morning Briefing notification. */
    val briefingSummaryRequested: MutableStateFlow<Boolean> = MutableStateFlow(false)

    /**
     * Open/Closed [ToolRegistry] populated with all atomic [NavaTool] adapters.
     */
    val toolRegistry: ToolRegistry by lazy {
        ToolRegistry(
            initialTools = buildList {
                addAll(alarmTimerTool.allTools())        // 2: set_alarm, set_timer
                addAll(reminderTools)                    // 2: schedule_reminder, cancel_reminder
                addAll(calendarTool.allTools())          // 3: calendar_query, calendar_create, calendar_modify
                addAll(notesVaultTools)                  // 6: notes_read/create/delete, vault_read/write/delete
                add(notesSearchTool)                     // 1: notes_search
                add(smsDraftTool)                        // 1: create_sms_draft
                addAll(callIntentTools)                  // 2: dial_call, place_call
                add(notificationSummaryTool)             // 1: summarize_notifications
                addAll(notificationWatcherTools)         // 2: create_notification_watcher, manage_notification_watchers
                add(dailyBriefingTool)                   // 1: daily_briefing
                addAll(audioDndTool.allTools())          // 2: set_dnd, set_volume
                add(appLaunchTool)                       // 1: launch_app
                addAll(safDirectoryTools)                // 3: saf_read, saf_write, saf_delete
                add(proposeRoutineTool)                  // 1: propose_routine
                add(com.nava.feature.automations.memory.RememberFactTool(personalFactDao, auditLogDao))
                add(com.nava.feature.automations.memory.RecallFactsTool(personalFactDao, auditLogDao))
                add(com.nava.feature.automations.memory.ForgetFactTool(personalFactDao, auditLogDao))
                add(com.nava.feature.automations.device.FlashlightTool(deviceControlGateway, auditLogDao))
                add(com.nava.feature.automations.device.MediaControlTool(deviceControlGateway, auditLogDao))
                add(
                    com.nava.feature.automations.device.SettingsPanelTool(
                        deviceControlGateway,
                        securityFirewall,
                        auditLogDao
                    )
                )
            }
        )
    }

    // -------------------------------------------------------------------------
    // 6. All 4 Domain UseCases
    // -------------------------------------------------------------------------

    val processQueryUseCase: ProcessQueryUseCase by lazy {
        ProcessQueryUseCase(
            resolvers = intentResolvers,
            toolRegistry = toolRegistry,
            languageDetector = languageDetector,
            textNormalizer = textNormalizer
        )
    }

    val executePlanUseCase: ExecutePlanUseCase by lazy {
        ExecutePlanUseCase(
            toolRegistry = toolRegistry,
            securityFirewall = securityFirewall,
            auditLog = auditLogDao
        )
    }

    val manageProfilesUseCase: ManageProfilesUseCase by lazy {
        ManageProfilesUseCase(
            permissionEvaluator = permissionProfileManager,
            auditLog = auditLogDao
        )
    }

    val compileRuleUseCase: CompileRuleUseCase by lazy {
        CompileRuleUseCase(
            ruleGrantPort = ruleCapabilityGrantManager,
            toolRegistry = toolRegistry,
            auditLog = auditLogDao
        )
    }

    // -------------------------------------------------------------------------
    // 7. Localization, Onboarding, Biometrics, Confirmations & Offline Voice
    // -------------------------------------------------------------------------

    val bidiTextFormatter: BidiTextFormatter by lazy {
        BidiTextFormatter()
    }

    val localeDateTimeFormatter: LocaleDateTimeFormatter by lazy {
        LocaleDateTimeFormatter()
    }

    val messageTemplateProvider: MessageTemplateProvider by lazy {
        templateProviderOverride
            ?: appContext?.let { templateProviderFactory(it) }
            ?: FallbackEnglishMessageTemplateProvider()
    }

    val messageRenderer: NavaMessageRenderer by lazy {
        NavaMessageRenderer(
            templateProvider = messageTemplateProvider,
            bidiFormatter = bidiTextFormatter,
            dateTimeFormatter = localeDateTimeFormatter
        )
    }

    val platformLocaleBridge: PlatformLocaleBridge by lazy {
        platformLocaleBridgeOverride ?: AndroidPlatformLocaleBridge(requireContext())
    }

    val appLocaleManager: AppLocaleManager by lazy {
        AppLocaleManager(
            catalog = supportedLanguageCatalog,
            platformBridge = platformLocaleBridge
        )
    }

    val preferencesStorageGateway: PreferencesStorageGateway by lazy {
        preferencesStorageGatewayOverride ?: SharedPreferencesStorageGateway(requireContext())
    }

    val onboardingStateStore: OnboardingStateStore by lazy {
        OnboardingStateStore(storage = preferencesStorageGateway)
    }

    val themePreferenceStore: ThemePreferenceStore by lazy {
        ThemePreferenceStore(storage = preferencesStorageGateway)
    }

    val morningBriefingPreferencesStore: MorningBriefingPreferencesStore by lazy {
        MorningBriefingPreferencesStore(storage = preferencesStorageGateway)
    }

    val biometricPromptGateway: BiometricPromptGateway by lazy {
        biometricPromptGatewayOverride ?: AndroidBiometricPromptGateway()
    }

    val vaultBiometricController: VaultBiometricController by lazy {
        VaultBiometricController(
            navaVault = navaVault,
            promptGateway = biometricPromptGateway
        )
    }

    val speechRecognizerGateway: OnDeviceSpeechRecognizerGateway by lazy {
        speechRecognizerGatewayOverride ?: AndroidOnDeviceSpeechRecognizerGateway(requireContext())
    }

    val voiceInputController: OnDeviceVoiceInputController by lazy {
        OnDeviceVoiceInputController(gateway = speechRecognizerGateway)
    }

    val pendingConfirmationStore: PendingConfirmationStore by lazy {
        PendingConfirmationStore(
            ruleGrantPort = ruleCapabilityGrantManager,
            ruleSealVerifier = { grant -> ruleCapabilityGrantManager.verifySeal(grant) },
            backgroundTaskManagerProvider = { backgroundTaskContinuationManager },
            clockMs = clockMs
        )
    }

    // -------------------------------------------------------------------------
    // 8. Notifications, WorkManager Schedulers, RoutineExecutor & Background Continuation
    // -------------------------------------------------------------------------

    val notificationBridge: AutomationNotificationBridge by lazy {
        notificationBridgeOverride ?: AndroidAutomationNotificationBridge(
            context = requireContext(),
            messageRenderer = { userMessage ->
                messageRenderer.render(userMessage, appLocaleManager.currentLocale())
            },
            interactiveContentIntentFactory = { request ->
                appContext?.let { ctx ->
                    AssistantIntentContract.buildConfirmationPendingIntent(ctx, request)
                }
            },
            smallIconResId = com.nava.app.R.drawable.ic_stat_nava
        )
    }

    val routineWorkScheduler: RoutineWorkScheduler by lazy {
        routineWorkSchedulerOverride ?: WorkManagerRoutineScheduler(requireContext())
    }

    val routineExecutor: RoutineExecutor by lazy {
        RoutineExecutor(
            ruleGrantPort = ruleCapabilityGrantManager,
            securityFirewall = securityFirewall,
            toolRegistry = toolRegistry,
            auditLog = auditLogDao,
            notificationBridge = notificationBridge,
            scheduler = routineWorkScheduler
        )
    }

    val backgroundTaskWorkScheduler: BackgroundTaskWorkScheduler by lazy {
        backgroundTaskWorkSchedulerOverride ?: WorkManagerBackgroundTaskScheduler(requireContext())
    }

    val backgroundTaskContinuationManager: BackgroundTaskContinuationManager by lazy {
        BackgroundTaskContinuationManager(
            executePlanUseCase = executePlanUseCase,
            auditLog = auditLogDao,
            notificationBridge = notificationBridge,
            scheduler = backgroundTaskWorkScheduler,
            modelProvisioner = safModelProvisioner,
            modelImportHandler = modelImportHandlerOverride ?: { request ->
                handleModelImportContinuation(request)
            }
        )
    }

    // -------------------------------------------------------------------------
    // 9. Async Active Model Path Resolution & Platform Service Bindings
    // -------------------------------------------------------------------------

    private data class VerifiedModelCache(
        val canonicalPath: String,
        val sizeBytes: Long,
        val lastModifiedMs: Long,
        val expectedSha256Hex: String
    )

    private val modelResolveMutex = Mutex()
    private val verifiedModelsById = ConcurrentHashMap<String, VerifiedModelCache>()

    private fun modelIntegrityPrefKey(modelId: String): String = "model_integrity_hmac_$modelId"

    private fun computeModelIntegrityStamp(
        canonicalPath: String,
        sizeBytes: Long,
        lastModifiedMs: Long,
        spec: PinnedModelSpec
    ): String? {
        return runCatching {
            hmacEngine.computeBlindIndex(
                keyProvider.getOrCreateBlindIndexKey(),
                MODEL_INTEGRITY_HMAC_DOMAIN,
                spec.modelId,
                canonicalPath,
                sizeBytes.toString(),
                lastModifiedMs.toString(),
                spec.expectedSha256Hex.lowercase(Locale.ROOT)
            )
        }.getOrNull()
    }

    private suspend fun verifyOrUseCachedModelIntegrity(
        candidateFile: File,
        spec: PinnedModelSpec
    ): Boolean {
        if (!verifyModelSha256OnResolve) {
            return true
        }
        val canonicalPath = runCatching { candidateFile.canonicalPath }.getOrNull() ?: return false
        val sizeBytes = candidateFile.length()
        val lastModifiedMs = candidateFile.lastModified()
        val expectedShaLower = spec.expectedSha256Hex.lowercase(Locale.ROOT)

        val memCached = verifiedModelsById[spec.modelId]
        if (memCached != null &&
            memCached.canonicalPath == canonicalPath &&
            memCached.sizeBytes == sizeBytes &&
            memCached.lastModifiedMs == lastModifiedMs &&
            memCached.expectedSha256Hex == expectedShaLower
        ) {
            return true
        }

        val prefKey = modelIntegrityPrefKey(spec.modelId)
        val storedStamp = preferencesStorageGateway.getString(prefKey, null)
        if (!storedStamp.isNullOrBlank()) {
            val expectedStamp = computeModelIntegrityStamp(
                canonicalPath = canonicalPath,
                sizeBytes = sizeBytes,
                lastModifiedMs = lastModifiedMs,
                spec = spec
            )
            if (expectedStamp != null &&
                MessageDigest.isEqual(
                    storedStamp.toByteArray(Charsets.UTF_8),
                    expectedStamp.toByteArray(Charsets.UTF_8)
                )
            ) {
                verifiedModelsById[spec.modelId] = VerifiedModelCache(
                    canonicalPath = canonicalPath,
                    sizeBytes = sizeBytes,
                    lastModifiedMs = lastModifiedMs,
                    expectedSha256Hex = expectedShaLower
                )
                return true
            }
        }

        val valid = safModelProvisioner.verifyFileIntegrity(
            absolutePath = candidateFile.absolutePath,
            expectedSha256Hex = spec.expectedSha256Hex
        )
        if (!valid) {
            verifiedModelsById.remove(spec.modelId)
            preferencesStorageGateway.putString(prefKey, null)
            return false
        }

        computeModelIntegrityStamp(
            canonicalPath = canonicalPath,
            sizeBytes = sizeBytes,
            lastModifiedMs = lastModifiedMs,
            spec = spec
        )?.let { freshStamp ->
            preferencesStorageGateway.putString(prefKey, freshStamp)
        }
        verifiedModelsById[spec.modelId] = VerifiedModelCache(
            canonicalPath = canonicalPath,
            sizeBytes = sizeBytes,
            lastModifiedMs = lastModifiedMs,
            expectedSha256Hex = expectedShaLower
        )
        return true
    }

    /**
     * Asynchronously resolves the active provisioned `.litertlm` model path on [ioDispatcher]
     * without blocking app cold start (`< 400 ms` invariant, Requirement 10).
     *
     * Resolution priority:
     * 1. User-selected model ID persisted in [OnboardingStateStore].
     * 2. Default recommended model for [ThermalModelLifecycleManager.currentRamTier].
     * 3. Any other provisioned official model in [PinnedModelCatalog.ALL_SPECS].
     */
    suspend fun resolveActiveModelPath(): String? = withContext(ioDispatcher) {
        modelResolveMutex.withLock {
            val modelsDir = File(safModelProvisioner.modelsDirectoryPath())
            if (!modelsDir.exists() || !modelsDir.isDirectory) {
                return@withLock null
            }

            val selectedModelId = onboardingStateStore.getSelectedModelId()
            val ramTier = thermalModelLifecycleManager.currentRamTier()
            val candidateSpecs = buildCandidateModelSpecList(selectedModelId, ramTier)

            for (spec in candidateSpecs) {
                val candidateFile = File(modelsDir, spec.fileName)
                if (!candidateFile.exists() || !candidateFile.isFile || candidateFile.length() <= 0L) {
                    continue
                }
                if (!verifyOrUseCachedModelIntegrity(candidateFile, spec)) {
                    continue
                }
                return@withLock candidateFile.absolutePath
            }

            null
        }
    }

    /**
     * Binds [NotificationServiceBinding] and [AutomationWorkerRegistry] to this container's
     * instances so Android's `NavaNotificationListenerService` and `WorkManager` workers
     * delegate to the active security boundary.
     */
    fun bindPlatformServices() {
        NotificationServiceBinding.bind(
            evaluatorPort = permissionProfileManager,
            inboxPort = notificationInbox,
            onLiveIngested = { captured ->
                notificationWatcherEngine.onLiveNotificationIngested(captured)
            }
        )
        // Warm the lock-screen watcher snapshot while the store is readable.
        appScope.launch {
            notificationWatcherPort.warmUp()
        }
        appContext?.let { NotificationServiceBinding.requestRebindIfUnbound(it) }
        AutomationWorkerRegistry.bind(
            routineExecutor = routineExecutor,
            backgroundTaskManager = backgroundTaskContinuationManager,
            notificationBridge = notificationBridge
        )
    }

    /**
     * Unbinds static platform service hooks and closes vault/storage resources.
     */
    suspend fun shutdown() {
        NotificationServiceBinding.unbind()
        AutomationWorkerRegistry.unbind()
        runCatching { vaultBiometricController.lock() }
        runCatching { liteRtLlmEngine.unloadModel() }
        runCatching { functionGemmaEngine.unloadModel() }
        runCatching { embeddingPort.unloadEmbeddingModel() }
        runCatching { encryptedSqliteStore.close() }
    }

    fun isFunctionRouterEnabled(): Boolean {
        return preferencesStorageGateway.getString(KEY_FUNCTION_ROUTER_ENABLED, "true") != "false"
    }

    suspend fun setFunctionRouterEnabled(enabled: Boolean) {
        preferencesStorageGateway.putString(KEY_FUNCTION_ROUTER_ENABLED, enabled.toString())
        if (!enabled) {
            runCatching { functionGemmaEngine.unloadModel() }
        }
    }

    fun isSemanticEmbeddingEnabled(): Boolean {
        return preferencesStorageGateway.getString(KEY_SEMANTIC_EMBEDDING_ENABLED, "true") != "false"
    }

    suspend fun setSemanticEmbeddingEnabled(enabled: Boolean) {
        preferencesStorageGateway.putString(KEY_SEMANTIC_EMBEDDING_ENABLED, enabled.toString())
        if (!enabled) {
            runCatching { embeddingPort.unloadEmbeddingModel() }
        }
    }

    /**
     * Resolves the provisioned function-calling model path (`mobile-actions_q8_ekv1024.litertlm`).
     */
    suspend fun resolveActiveFunctionModelPath(): String? = withContext(ioDispatcher) {
        if (!isFunctionRouterEnabled()) {
            return@withContext null
        }
        val modelsDir = File(safModelProvisioner.modelsDirectoryPath())
        if (!modelsDir.exists() || !modelsDir.isDirectory) {
            return@withContext null
        }
        val selectedId = onboardingStateStore.getSelectedFunctionModelId()
        val specs = listOfNotNull(
            PinnedModelCatalog.findByModelId(selectedId),
            PinnedModelCatalog.MOBILE_ACTIONS_SPEC
        ).distinctBy { it.modelId }

        for (spec in specs) {
            val candidateFile = File(modelsDir, spec.fileName)
            if (!candidateFile.exists() || !candidateFile.isFile || candidateFile.length() <= 0L) {
                continue
            }
            if (!verifyOrUseCachedModelIntegrity(candidateFile, spec)) {
                continue
            }
            return@withContext candidateFile.absolutePath
        }
        null
    }

    /**
     * Resolves the provisioned semantic embedding model path (`embeddinggemma-2-*.litertlm`).
     */
    suspend fun resolveActiveEmbeddingModelPath(): String? = withContext(ioDispatcher) {
        if (!isSemanticEmbeddingEnabled()) {
            return@withContext null
        }
        val modelsDir = File(safModelProvisioner.modelsDirectoryPath())
        if (!modelsDir.exists() || !modelsDir.isDirectory) {
            return@withContext null
        }
        val selectedId = onboardingStateStore.getSelectedEmbeddingModelId()
        val specs = listOfNotNull(
            PinnedModelCatalog.findByModelId(selectedId),
            PinnedModelCatalog.EMBEDDING_GEMMA_270M_SPEC,
            PinnedModelCatalog.EMBEDDING_GEMMA_SPEC
        ).distinctBy { it.modelId }

        for (spec in specs) {
            val candidateFile = File(modelsDir, spec.fileName)
            if (!candidateFile.exists() || !candidateFile.isFile || candidateFile.length() <= 0L) {
                continue
            }
            if (!verifyOrUseCachedModelIntegrity(candidateFile, spec)) {
                continue
            }
            return@withContext candidateFile.absolutePath
        }
        null
    }

    private fun buildCandidateModelSpecList(
        selectedModelId: String?,
        ramTier: RamTier
    ): List<PinnedModelSpec> {
        val ordered = ArrayList<PinnedModelSpec>(3)
        val seenIds = LinkedHashSet<String>(3)

        fun addIfAbsent(spec: PinnedModelSpec?) {
            if (spec != null && PinnedModelCatalog.ALL_SPECS.any { it.modelId == spec.modelId } && seenIds.add(spec.modelId)) {
                ordered.add(spec)
            }
        }

        addIfAbsent(PinnedModelCatalog.findByModelId(selectedModelId))
        addIfAbsent(PinnedModelCatalog.recommendedSpecForRamTier(ramTier))
        for (spec in PinnedModelCatalog.ALL_SPECS) {
            addIfAbsent(spec)
        }
        return ordered
    }

    private suspend fun handleModelImportContinuation(
        request: BackgroundTaskRequest.ModelImportContinuation
    ): Boolean {
        val catalogSpec = PinnedModelCatalog.findByModelId(request.expectedModelId)
        val effectiveSpec = catalogSpec?.copy(
            expectedSha256Hex = request.expectedSha256Hex
        ) ?: PinnedModelSpec(
            modelId = request.expectedModelId,
            fileName = "${request.expectedModelId}${SafModelProvisioner.LITERTLM_EXTENSION}",
            expectedSha256Hex = request.expectedSha256Hex,
            expectedSizeBytes = PinnedModelCatalog.SIZE_BYTES_GEMMA4_E4B,
            minRamTier = RamTier.TIER_0_LOW_MEMORY
        )

        return if (request.sourceUri.startsWith("content://")) {
            val ctx = appContext ?: return false
            val imported = safModelProvisioner.importFromSafUri(
                context = ctx,
                sourceUri = Uri.parse(request.sourceUri),
                pinnedSpec = effectiveSpec
            )
            onboardingStateStore.assignImportedModelByRole(imported.modelId)
            val importedFile = File(imported.absolutePath)
            val canonicalPath = runCatching { importedFile.canonicalPath }.getOrNull()
            if (canonicalPath != null) {
                val lastMod = importedFile.lastModified()
                computeModelIntegrityStamp(
                    canonicalPath = canonicalPath,
                    sizeBytes = imported.sizeBytes,
                    lastModifiedMs = lastMod,
                    spec = effectiveSpec
                )?.let { freshStamp ->
                    preferencesStorageGateway.putString(modelIntegrityPrefKey(effectiveSpec.modelId), freshStamp)
                }
                verifiedModelsById[effectiveSpec.modelId] = VerifiedModelCache(
                    canonicalPath = canonicalPath,
                    sizeBytes = imported.sizeBytes,
                    lastModifiedMs = lastMod,
                    expectedSha256Hex = effectiveSpec.expectedSha256Hex.lowercase(Locale.ROOT)
                )
            }
            true
        } else {
            val valid = safModelProvisioner.verifyFileIntegrity(
                absolutePath = request.sourceUri,
                expectedSha256Hex = request.expectedSha256Hex
            )
            if (valid) {
                onboardingStateStore.assignImportedModelByRole(effectiveSpec.modelId)
            }
            valid
        }
    }

    companion object {
        const val VAULT_DIR_NAME: String = "vault"
        private const val MODEL_INTEGRITY_HMAC_DOMAIN: String = "nava_model_integrity_v1"
        private const val KEY_FUNCTION_ROUTER_ENABLED: String = "addon_function_router_enabled"
        private const val KEY_SEMANTIC_EMBEDDING_ENABLED: String = "addon_semantic_embedding_enabled"

        /**
         * Clean testing factory creating a self-contained [AppContainer] wired with real
         * `:domain`, `:core-security-data`, `:core-ai`, and `:feature-automations` logic over
         * in-memory storage, software keys, and deterministic test gateways for Wave 2 ViewModel
         * tests and Gate 2 Red-Team suites.
         */
        fun createForTesting(
            context: Context? = null,
            templateProvider: MessageTemplateProvider = FallbackEnglishMessageTemplateProvider(),
            keyProvider: CryptoKeyProvider = InMemoryTestKeyProvider(),
            rowStorage: EncryptedRowStorage = InMemoryTestRowStorage(),
            vaultDir: File = Files.createTempDirectory("nava_test_vault").toFile(),
            modelsDir: File = Files.createTempDirectory("nava_test_models").toFile(),
            storageSpaceProvider: StorageSpaceProvider = FixedTestStorageSpaceProvider(),
            assetTextReader: AssetTextReader = resolveDefaultTestAssetReader(),
            platformLanguageClassifier: PlatformLanguageClassifier? = null,
            hardwareStatusProvider: DeviceHardwareStatusProvider = FixedTestHardwareStatusProvider(),
            liteRtRuntimeAdapter: LiteRtRuntimeAdapter = NoOpTestLiteRtRuntimeAdapter(),
            functionRuntimeAdapter: LiteRtRuntimeAdapter = NoOpTestLiteRtRuntimeAdapter(),
            embeddingRuntimeAdapter: EmbeddingRuntimeAdapter = NoOpTestEmbeddingRuntimeAdapter(),
            embeddingPort: EmbeddingPort = NoOpTestEmbeddingPort(),
            intentGateway: AutomationIntentGateway = NoOpTestAutomationIntentGateway(),
            audioDndGateway: AudioDndPlatformGateway = NoOpTestAudioDndPlatformGateway(),
            calendarGateway: CalendarPlatformGateway = NoOpTestCalendarPlatformGateway(),
            safGateway: SafPlatformGateway = NoOpTestSafPlatformGateway(),
            notificationBridge: AutomationNotificationBridge = NoOpTestNotificationBridge(),
            routineWorkScheduler: RoutineWorkScheduler = NoOpTestRoutineWorkScheduler(),
            backgroundTaskWorkScheduler: BackgroundTaskWorkScheduler = NoOpTestBackgroundTaskWorkScheduler(),
            platformLocaleBridge: PlatformLocaleBridge = InMemoryPlatformLocaleBridge(),
            preferencesStorageGateway: PreferencesStorageGateway = InMemoryPreferencesStorageGateway(),
            biometricPromptGateway: BiometricPromptGateway = AutoApproveTestBiometricPromptGateway(),
            speechRecognizerGateway: OnDeviceSpeechRecognizerGateway = OfflineMissingTestSpeechRecognizerGateway(),
            modelImportHandler: (suspend (BackgroundTaskRequest.ModelImportContinuation) -> Boolean)? = null,
            verifyModelSha256OnResolve: Boolean = false,
            clockMs: () -> Long = System::currentTimeMillis,
            ioDispatcher: CoroutineDispatcher = Dispatchers.Unconfined,
            appScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        ): AppContainer {
            return AppContainer(
                appContext = context,
                templateProviderOverride = templateProvider,
                keyProviderOverride = keyProvider,
                rowStorageOverride = rowStorage,
                vaultDirOverride = vaultDir,
                modelsDirOverride = modelsDir,
                storageSpaceProviderOverride = storageSpaceProvider,
                assetTextReaderOverride = assetTextReader,
                platformLanguageClassifierOverride = platformLanguageClassifier,
                hardwareStatusProviderOverride = hardwareStatusProvider,
                liteRtRuntimeAdapterOverride = liteRtRuntimeAdapter,
                functionRuntimeAdapterOverride = functionRuntimeAdapter,
                embeddingRuntimeAdapterOverride = embeddingRuntimeAdapter,
                embeddingPortOverride = embeddingPort,
                intentGatewayOverride = intentGateway,
                audioDndGatewayOverride = audioDndGateway,
                calendarGatewayOverride = calendarGateway,
                safGatewayOverride = safGateway,
                notificationBridgeOverride = notificationBridge,
                routineWorkSchedulerOverride = routineWorkScheduler,
                backgroundTaskWorkSchedulerOverride = backgroundTaskWorkScheduler,
                platformLocaleBridgeOverride = platformLocaleBridge,
                preferencesStorageGatewayOverride = preferencesStorageGateway,
                biometricPromptGatewayOverride = biometricPromptGateway,
                speechRecognizerGatewayOverride = speechRecognizerGateway,
                modelImportHandlerOverride = modelImportHandler,
                verifyModelSha256OnResolve = verifyModelSha256OnResolve,
                clockMs = clockMs,
                ioDispatcher = ioDispatcher,
                appScope = appScope
            )
        }

        fun resolveDefaultTestAssetReader(): AssetTextReader {
            val candidates = listOf(
                File("core-ai/src/main/assets"),
                File("../core-ai/src/main/assets")
            )
            val existingDir = candidates.firstOrNull { it.exists() && it.isDirectory }
            return if (existingDir != null) {
                DirectoryAssetTextReader(existingDir)
            } else {
                ClasspathAssetTextReader()
            }
        }
    }
}

/**
 * Software JCA [CryptoKeyProvider] for JVM unit and integration tests.
 */
class InMemoryTestKeyProvider : CryptoKeyProvider {
    private val lock = Any()
    private var dbMasterKey: SecretKey? = null
    private var blindIndexKey: SecretKey? = null
    private var vaultBiometricKey: SecretKey? = null

    override fun getOrCreateDbMasterKey(): SecretKey = synchronized(lock) {
        dbMasterKey ?: generateKey("AES").also { dbMasterKey = it }
    }

    override fun getOrCreateBlindIndexKey(): SecretKey = synchronized(lock) {
        blindIndexKey ?: generateKey("HmacSHA256").also { blindIndexKey = it }
    }

    override fun getOrCreateVaultBiometricKey(): SecretKey = synchronized(lock) {
        vaultBiometricKey ?: generateKey("AES").also { vaultBiometricKey = it }
    }

    override fun isStrongBoxBacked(alias: String): Boolean = false

    private fun generateKey(algorithm: String): SecretKey {
        val generator = KeyGenerator.getInstance(algorithm)
        generator.init(256)
        return generator.generateKey()
    }
}

/**
 * In-memory [EncryptedRowStorage] for JVM unit and integration tests.
 */
class InMemoryTestRowStorage : EncryptedRowStorage {
    private val lock = Any()
    private val tables = LinkedHashMap<String, MutableList<RawEncryptedRow>>()
    private val sequences = LinkedHashMap<String, Long>()
    private var txDepth = 0

    init {
        for (table in EncryptedTableSchema.ALLOWED_TABLES) {
            tables[table] = mutableListOf()
            sequences[table] = 0L
        }
    }

    override fun allocateRowId(tableName: String): Long {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            val next = (sequences[valid] ?: 0L) + 1L
            sequences[valid] = next
            next
        }
    }

    override fun insertRow(tableName: String, row: RawEncryptedRow) {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        synchronized(lock) {
            val rows = tables.getValue(valid)
            check(rows.none { it.rowId == row.rowId }) { "Duplicate rowId ${row.rowId}" }
            rows.add(copyRow(row))
        }
    }

    override fun upsertByLookupHmac(tableName: String, row: RawEncryptedRow) {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        synchronized(lock) {
            val rows = tables.getValue(valid)
            rows.removeAll { it.lookupHmac == row.lookupHmac || it.rowId == row.rowId }
            rows.add(copyRow(row))
        }
    }

    override fun findByLookupHmac(tableName: String, lookupHmac: String): RawEncryptedRow? {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(valid)
                .asSequence()
                .filter { it.lookupHmac == lookupHmac }
                .sortedWith(RECENT_ORDER)
                .firstOrNull()
                ?.let(::copyRow)
        }
    }

    override fun findByRowId(tableName: String, rowId: Long): RawEncryptedRow? {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(valid).firstOrNull { it.rowId == rowId }?.let(::copyRow)
        }
    }

    override fun listRows(tableName: String): List<RawEncryptedRow> {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(valid).sortedBy { it.rowId }.map(::copyRow)
        }
    }

    override fun listRecent(tableName: String, limit: Int): List<RawEncryptedRow> {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        return synchronized(lock) {
            tables.getValue(valid).sortedWith(RECENT_ORDER).take(limit).map(::copyRow)
        }
    }

    override fun listRecentByLookupHmac(
        tableName: String,
        lookupHmac: String,
        limit: Int
    ): List<RawEncryptedRow> {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        return synchronized(lock) {
            tables.getValue(valid)
                .asSequence()
                .filter { it.lookupHmac == lookupHmac }
                .sortedWith(RECENT_ORDER)
                .take(limit)
                .map(::copyRow)
                .toList()
        }
    }

    override fun deleteByLookupHmac(tableName: String, lookupHmac: String): Boolean {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(valid).removeAll { it.lookupHmac == lookupHmac }
        }
    }

    override fun deleteByRowId(tableName: String, rowId: Long): Boolean {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(valid).removeAll { it.rowId == rowId }
        }
    }

    override fun deleteOlderThanMaxCount(tableName: String, maxEntries: Int): Int {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        require(maxEntries >= 0) { "maxEntries must be non-negative" }
        return synchronized(lock) {
            val rows = tables.getValue(valid)
            if (rows.size <= maxEntries) return@synchronized 0
            val evictCount = rows.size - maxEntries
            val evictIds = rows.sortedWith(LRU_ORDER).take(evictCount).mapTo(HashSet()) { it.rowId }
            rows.removeAll { it.rowId in evictIds }
            evictIds.size
        }
    }

    override fun touchUpdatedEpochSec(
        tableName: String,
        rowId: Long,
        updatedEpochSec: Long
    ): Boolean {
        val valid = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            val rows = tables.getValue(valid)
            val idx = rows.indexOfFirst { it.rowId == rowId }
            if (idx < 0) return@synchronized false
            rows[idx] = rows[idx].copy(updatedEpochSec = updatedEpochSec)
            true
        }
    }

    override fun <T> withTransaction(block: () -> T): T {
        return synchronized(lock) {
            val outermost = txDepth == 0
            val tableSnap = if (outermost) {
                tables.mapValuesTo(LinkedHashMap()) { (_, v) -> v.mapTo(mutableListOf(), ::copyRow) }
            } else {
                null
            }
            val seqSnap = if (outermost) HashMap(sequences) else null
            txDepth++
            try {
                block()
            } catch (t: Throwable) {
                if (outermost && tableSnap != null && seqSnap != null) {
                    tables.clear()
                    tables.putAll(tableSnap)
                    sequences.clear()
                    sequences.putAll(seqSnap)
                }
                throw t
            } finally {
                txDepth--
            }
        }
    }

    override fun close() = Unit

    private fun copyRow(row: RawEncryptedRow): RawEncryptedRow {
        return row.copy(payloadBlob = row.payloadBlob.copyOf())
    }

    companion object {
        private val RECENT_ORDER: Comparator<RawEncryptedRow> =
            compareByDescending<RawEncryptedRow> { it.updatedEpochSec }
                .thenByDescending { it.rowId }

        private val LRU_ORDER: Comparator<RawEncryptedRow> =
            compareBy<RawEncryptedRow> { it.updatedEpochSec }
                .thenBy { it.rowId }
    }
}

internal class FixedTestStorageSpaceProvider(
    private val availableBytes: Long = 16L * 1024L * 1024L * 1024L
) : StorageSpaceProvider {
    override fun availableBytes(directory: File): Long = availableBytes
}

internal class FixedTestHardwareStatusProvider(
    private val snapshot: DeviceHardwareSnapshot = DeviceHardwareSnapshot(
        totalRamBytes = 8L * 1024L * 1024L * 1024L,
        thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
        batteryLevelPercent = 85
    )
) : DeviceHardwareStatusProvider {
    override fun readSnapshot(): DeviceHardwareSnapshot = snapshot
}

internal class NoOpTestLiteRtRuntimeAdapter : LiteRtRuntimeAdapter {
    private var loaded = false

    override fun isLoaded(): Boolean = loaded

    override suspend fun ensureMasterPrefix(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int
    ) {
        loaded = true
    }

    override fun runClonedTurn(
        systemPrefixId: String,
        config: RuntimeTurnConfig
    ): Flow<RuntimeStreamDelta> = emptyFlow()

    override suspend fun unload() {
        loaded = false
    }
}

internal class NoOpTestEmbeddingPort : EmbeddingPort {
    override suspend fun isEmbeddingModelAvailable(): Boolean = false
    override suspend fun embedQuery(query: String): FloatArray? = null
    override suspend fun embedDocument(title: String, text: String): FloatArray? = null
    override suspend fun unloadEmbeddingModel() {}
}

internal class NoOpTestEmbeddingRuntimeAdapter : EmbeddingRuntimeAdapter {
    private var loaded = false
    override fun isLoaded(): Boolean = loaded
    override suspend fun ensureLoaded(modelPath: String) {
        loaded = true
    }
    override suspend fun computeEmbedding(formattedInput: String): FloatArray? = null
    override suspend fun unload() {
        loaded = false
    }
}

internal class NoOpTestAutomationIntentGateway : AutomationIntentGateway {
    override fun hasRuntimePermission(permission: String): Boolean = true
    override fun isNotificationPolicyAccessGranted(): Boolean = true
    override fun isNotificationListenerEnabled(): Boolean = true
    override fun dispatchSetAlarm(
        hour: Int,
        minute: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult = PlatformDispatchResult.Dispatched("alarm:$hour:$minute")

    override fun dispatchSetTimer(
        durationSeconds: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult = PlatformDispatchResult.Dispatched("timer:$durationSeconds")

    override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult =
        PlatformDispatchResult.Dispatched("sms:$recipient")

    override fun dispatchDial(phoneNumber: String): PlatformDispatchResult =
        PlatformDispatchResult.Dispatched("dial:$phoneNumber")

    override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult =
        PlatformDispatchResult.Dispatched("call:$phoneNumber")

    override fun resolveLaunchablePackage(appNameOrPackage: String): String? =
        if (AndroidAutomationIntentGateway.isValidPackageName(appNameOrPackage)) {
            appNameOrPackage.trim()
        } else {
            "com.example.${appNameOrPackage.trim().lowercase(Locale.US).replace(" ", "")}"
        }

    override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult =
        PlatformDispatchResult.Dispatched("launch:$packageName")
}

internal class NoOpTestAudioDndPlatformGateway : AudioDndPlatformGateway {
    private val volumes = LinkedHashMap<AudioStreamKind, Int>()
    override fun isNotificationPolicyAccessGranted(): Boolean = true
    override fun setInterruptionFilter(mode: DndFilterMode): PlatformDispatchResult =
        PlatformDispatchResult.Dispatched(mode.name)

    override fun setStreamVolumePercent(
        stream: AudioStreamKind,
        percent: Int
    ): PlatformDispatchResult {
        volumes[stream] = percent
        return PlatformDispatchResult.Dispatched("${stream.name}:$percent")
    }

    override fun getStreamVolumePercent(stream: AudioStreamKind): Int = volumes[stream] ?: 50
}

internal class NoOpTestCalendarPlatformGateway : CalendarPlatformGateway {
    override suspend fun queryEvents(
        startEpochMs: Long,
        endEpochMs: Long,
        limit: Int
    ): CalendarGatewayResult<List<CalendarEventRecord>> = CalendarGatewayResult.Success(emptyList())

    override suspend fun createEvent(draft: CalendarEventDraft): CalendarGatewayResult<Long> =
        CalendarGatewayResult.Success(1L)

    override suspend fun updateEvent(
        eventId: Long,
        patch: CalendarEventPatch
    ): CalendarGatewayResult<Boolean> = CalendarGatewayResult.Success(true)

    override suspend fun deleteEvent(eventId: Long): CalendarGatewayResult<Boolean> =
        CalendarGatewayResult.Success(true)
}

internal class NoOpTestSafPlatformGateway : SafPlatformGateway {
    override fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean = false
    override fun listPersistedTreeUris(): Set<String> = emptySet()
    override suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>> =
        SafGatewayResult.GrantMissing(treeUri)

    override suspend fun readDocument(
        treeUri: String,
        fileName: String,
        maxBytes: Int
    ): SafGatewayResult<ByteArray> = SafGatewayResult.GrantMissing(treeUri)

    override suspend fun writeDocument(
        treeUri: String,
        fileName: String,
        mimeType: String,
        content: ByteArray,
        overwrite: Boolean
    ): SafGatewayResult<SafDocumentEntry> = SafGatewayResult.GrantMissing(treeUri)

    override suspend fun deleteDocument(
        treeUri: String,
        fileName: String
    ): SafGatewayResult<Boolean> = SafGatewayResult.GrantMissing(treeUri)
}

internal class NoOpTestNotificationBridge : AutomationNotificationBridge {
    override fun postCompletionNotification(request: CompletionNotificationRequest) = Unit
    override fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest) = Unit
    override fun cancelNotification(notificationId: Int) = Unit
    override fun createForegroundNotificationSpec(
        taskId: String,
        message: UserMessage
    ): ForegroundNotificationSpec {
        return ForegroundNotificationSpec(
            notificationId = 1,
            channelId = AutomationNotificationBridge.CHANNEL_FOREGROUND_TASK,
            taskId = taskId,
            message = message
        )
    }
}

internal class NoOpTestRoutineWorkScheduler : RoutineWorkScheduler {
    override suspend fun schedule(grant: RuleCapabilityGrant) = Unit
    override suspend fun cancel(ruleId: String) = Unit
    override suspend fun cancelAll() = Unit
}

internal class NoOpTestBackgroundTaskWorkScheduler : BackgroundTaskWorkScheduler {
    override suspend fun schedule(request: BackgroundTaskRequest) = Unit
    override suspend fun cancel(taskId: String) = Unit
}

internal class AutoApproveTestBiometricPromptGateway : BiometricPromptGateway {
    override suspend fun authenticate(
        activity: FragmentActivity?,
        cryptoObject: BiometricPrompt.CryptoObject,
        labels: BiometricPromptLabels
    ): BiometricPromptGatewayOutcome {
        return BiometricPromptGatewayOutcome.Authenticated(cryptoObject)
    }
}

internal class OfflineMissingTestSpeechRecognizerGateway : OnDeviceSpeechRecognizerGateway {
    override fun isOnDeviceRecognitionAvailable(): Boolean = false
    override fun startListening(config: OnDeviceSpeechConfig, listener: OnDeviceSpeechListener) {
        listener.onOfflinePackMissing(config.localeTag)
    }

    override fun stopListening() = Unit
    override fun cancel() = Unit
    override fun destroy() = Unit
}
