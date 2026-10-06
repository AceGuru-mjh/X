package com.unknown.security.data.repository

import android.content.Context
import com.unknown.security.core.model.AppRiskReport
import com.unknown.security.core.model.EnginePolicy
import com.unknown.security.core.model.EventAction
import com.unknown.security.core.model.EventKind
import com.unknown.security.core.model.GuardStats
import com.unknown.security.core.model.GuardTier
import com.unknown.security.core.model.InterceptionEvent
import com.unknown.security.core.model.PackageSnapshot
import com.unknown.security.core.model.ScanVerdict
import com.unknown.security.core.model.VerdictLevel
import com.unknown.security.core.persistence.EventStore
import com.unknown.security.core.persistence.RuleStore
import com.unknown.security.core.persistence.SettingsStore
import com.unknown.security.core.persistence.WhitelistStore
import com.unknown.security.domain.engine.DetectionEngine
import com.unknown.security.domain.engine.PolicyResolver
import com.unknown.security.service.accessibility.AccessibilityBus
import com.unknown.security.service.accessibility.AccessibilitySignal
import com.unknown.security.service.accessibility.AccessibilityStatus
import com.unknown.security.service.deviceadmin.DeviceAdminGate
import com.unknown.security.service.platform.AppInventory
import com.unknown.security.service.platform.PackageChangeEvent
import com.unknown.security.service.platform.PackageChangeKind
import com.unknown.security.service.platform.PackageEventReceiver
import com.unknown.security.service.platform.UsageForegroundWatcher
import com.unknown.security.service.root.RootShell
import com.unknown.security.service.root.RootState
import com.unknown.security.service.shizuku.ShizukuGate
import com.unknown.security.service.shizuku.ShizukuState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.Calendar

/** UI-facing alert request — rendered by the app shell as notification/overlay. */
data class AlertRequest(
    val packageName: String,
    val appLabel: String,
    val verdict: ScanVerdict,
    val actionLabel: String,
)

/** Live requirement status for a tier — drives the setup guide UI. */
data class TierRequirementStatus(
    val tier: GuardTier,
    val accessibilityOk: Boolean,
    val shizukuOk: Boolean,
    val rootOk: Boolean,
    val deviceOwnerOk: Boolean,
) {
    val satisfied: Boolean
        get() =
            (!tier.requiresAccessibility || accessibilityOk) &&
                (!tier.requiresShizuku || shizukuOk) &&
                (!tier.requiresRoot || rootOk) &&
                (!tier.requiresDeviceOwner || deviceOwnerOk)
}

/**
 * Orchestrates the whole guard: settings + rules + events + every privilege
 * channel. Single source of truth for the UI and the foreground service.
 */
class GuardRepository(
    private val context: Context,
    private val scope: CoroutineScope,
    val settings: SettingsStore,
    val rules: RuleStore,
    val events: EventStore,
    val whitelist: WhitelistStore,
    val inventory: AppInventory,
    val shizukuGate: ShizukuGate,
    val rootShell: RootShell,
    val deviceAdminGate: DeviceAdminGate,
) {
    private val engine = DetectionEngine()
    private val resolver = PolicyResolver()
    private val router = TierActionRouter(context, shizukuGate, rootShell, deviceAdminGate)
    private val receiver = PackageEventReceiver()
    private val usageWatcher = UsageForegroundWatcher(context, scope)

    private val _alerts = MutableSharedFlow<AlertRequest>(extraBufferCapacity = 16)
    val alerts: SharedFlow<AlertRequest> = _alerts.asSharedFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    private val _scanReports = MutableStateFlow<List<AppRiskReport>>(emptyList())
    val scanReports: StateFlow<List<AppRiskReport>> = _scanReports.asStateFlow()

    private val _lastScanMillis = MutableStateFlow(0L)
    val lastScanMillis: StateFlow<Long> = _lastScanMillis.asStateFlow()

    private val _watchedApps = MutableStateFlow(0)
    val watchedApps: StateFlow<Int> get() = _watchedApps.asStateFlow()

    private var started = false
    private val watchJobs = mutableListOf<Job>()

    val tier: StateFlow<GuardTier> =
        settings.tierFlow
            .stateIn(scope, SharingStarted.Eagerly, GuardTier.STANDARD)

    val policy: StateFlow<EnginePolicy> =
        settings.policyFlow
            .stateIn(scope, SharingStarted.Eagerly, EnginePolicy())

    val guardEnabled: StateFlow<Boolean> =
        settings.guardEnabledFlow
            .stateIn(scope, SharingStarted.Eagerly, true)

    val ruleSet = rules.ruleSet
    val eventLog = events.events
    val whitelistEntries = whitelist.entries

    val stats: StateFlow<GuardStats> =
        combine(
            eventLog,
            tier,
            _watchedApps,
        ) { log, currentTier, size ->
            val today = startOfDay()
            GuardStats(
                watchedApps = size,
                eventsToday = log.count { it.timestampMillis >= today },
                totalThreats = log.count { it.level == VerdictLevel.DANGEROUS },
                totalBlocked = log.count { it.action != EventAction.ALLOWED && it.action != EventAction.NO_ACTION },
                activeTierKey = currentTier.key,
            )
        }.stateIn(scope, SharingStarted.WhileSubscribed(5_000), GuardStats())

    val foreground: StateFlow<String?> = AccessibilityBus.foreground

    init {
        scope.launch {
            rules.reload()
            events.loadRecent()
            whitelist.load()
            _watchedApps.value =
                runCatching {
                    inventory.allPackages(includeSystem = true).size
                }.getOrDefault(0)
        }
        policy
            .onEach {
                AccessibilityBus.dialogControlEnabled = it.dialogControlEnabled
                AccessibilityBus.emergencyPressesRequired = it.emergencyVolumePresses
                AccessibilityBus.emergencyWindowMillis = it.emergencyWindowMillis
            }.launchIn(scope)
        settings.tierFlow.onEach { applyTierSideEffects(it) }.launchIn(scope)
    }

    /** Starts the live pipeline (package events, accessibility, foreground watch). */
    fun start() {
        if (started) return
        started = true
        receiver.register(context)

        watchJobs +=
            receiver.events
                .onEach { onPackageChange(it) }
                .launchIn(scope)

        watchJobs +=
            AccessibilityBus.signals
                .onEach { onAccessibilitySignal(it) }
                .launchIn(scope)

        if (policy.value.foregroundWatchEnabled) {
            usageWatcher.start()
        }
    }

    fun stop() {
        started = false
        watchJobs.forEach { it.cancel() }
        watchJobs.clear()
        receiver.unregister(context)
        usageWatcher.stop()
    }

    suspend fun setTier(newTier: GuardTier) {
        settings.setTier(newTier)
        if (newTier.requiresRoot) rootShell.resetProbe()
        applyTierSideEffects(newTier)
    }

    suspend fun setGuardEnabled(enabled: Boolean) = settings.setGuardEnabled(enabled)

    suspend fun setPolicy(newPolicy: EnginePolicy) = settings.setPolicy(newPolicy)

    private suspend fun applyTierSideEffects(tier: GuardTier) {
        if (deviceAdminGate.isDeviceOwner) {
            deviceAdminGate.setInstallBlocked(tier.requiresDeviceOwner)
        }
        if (tier.requiresRoot) rootShell.checkAvailability()
    }

    private suspend fun onPackageChange(change: PackageChangeEvent) {
        when (change.kind) {
            PackageChangeKind.REMOVED -> {
                record(
                    packageName = change.packageName,
                    kind = EventKind.UNINSTALLED,
                    verdict = ScanVerdict.clean(change.packageName),
                    action = EventAction.NO_ACTION,
                    note = "应用已卸载",
                )
                return
            }

            PackageChangeKind.ADDED, PackageChangeKind.REPLACED -> {
                Unit
            }
        }

        val snapshot = inventory.snapshot(change.packageName, computeHash = true) ?: return
        val verdict = evaluate(snapshot)
        val decision = resolver.resolve(verdict, policy.value, tier.value, snapshot.isSystemApp)
        val kind = if (change.kind == PackageChangeKind.REPLACED) EventKind.REPLACE else EventKind.INSTALL

        var actionTaken = decision.action
        var note = decision.reason

        val intent =
            when (decision.action) {
                EventAction.REMOVED -> DisposalIntent.UNINSTALL
                EventAction.FROZEN -> DisposalIntent.FREEZE
                else -> null
            }
        if (intent != null) {
            val result = router.execute(intent, change.packageName)
            if (result.success) {
                note = "${decision.reason}（${channelLabel(result.channel)}：${result.detail}）"
            } else {
                actionTaken = EventAction.WARNED
                note = "${decision.reason} · 自动处置失败：${result.detail}"
            }
        }

        record(change.packageName, kind, verdict, actionTaken, note)
        if (verdict.level != VerdictLevel.CLEAN && !verdict.whitelisted) {
            _alerts.tryEmit(
                AlertRequest(
                    packageName = change.packageName,
                    appLabel = snapshot.label,
                    verdict = verdict,
                    actionLabel = actionTaken.label,
                ),
            )
        }
    }

    private suspend fun onAccessibilitySignal(signal: AccessibilitySignal) {
        when (signal) {
            is AccessibilitySignal.ForegroundChanged -> {
                maybeAlertForeground(signal.packageName)
            }

            is AccessibilitySignal.InstallerDialogShown -> {
                record(
                    packageName = signal.installerPackage,
                    kind = EventKind.INSTALL_DIALOG,
                    verdict = ScanVerdict.clean(signal.installerPackage),
                    action = EventAction.NO_ACTION,
                    note = "检测到安装确认弹窗",
                )
            }

            is AccessibilitySignal.DialogCancelled -> {
                record(
                    packageName = signal.installerPackage,
                    kind = EventKind.INSTALL_DIALOG,
                    verdict = ScanVerdict.clean(signal.installerPackage),
                    action = EventAction.DIALOG_CANCELED,
                    note = "已自动取消安装弹窗（无障碍接管）",
                )
            }

            is AccessibilitySignal.EmergencyTriggered -> {
                runEmergencySweep()
            }

            AccessibilitySignal.ServiceStopped -> {
                Unit
            }
        }
    }

    private suspend fun maybeAlertForeground(packageName: String) {
        if (!policy.value.foregroundWatchEnabled) return
        if (packageName == context.packageName) return
        val snapshot = inventory.snapshot(packageName, computeHash = false) ?: return
        val verdict = evaluate(snapshot)
        if (verdict.level == VerdictLevel.DANGEROUS && !verdict.whitelisted) {
            record(packageName, EventKind.FOREGROUND, verdict, EventAction.WARNED, "风险应用进入前台")
            _alerts.tryEmit(
                AlertRequest(
                    packageName = packageName,
                    appLabel = snapshot.label,
                    verdict = verdict,
                    actionLabel = EventAction.WARNED.label,
                ),
            )
        }
    }

    /** Full-device scan; publishes reports sorted worst-first. */
    suspend fun scanAll(includeSystem: Boolean = true): List<AppRiskReport> {
        _scanning.value = true
        try {
            val allowed = whitelist.packageNames
            val ruleSetSnapshot = rules.ruleSet.value
            val reports =
                inventory
                    .allPackages(includeSystem)
                    .map { snapshot ->
                        AppRiskReport(snapshot, engine.evaluate(snapshot, ruleSetSnapshot, allowed))
                    }.sortedWith(
                        compareByDescending<AppRiskReport> { it.verdict.score }
                            .thenBy { it.snapshot.label },
                    )
            _scanReports.value = reports
            _watchedApps.value = reports.size
            _lastScanMillis.value = System.currentTimeMillis()
            return reports
        } finally {
            _scanning.value = false
        }
    }

    /** Emergency escape: full scan + force-stop every dangerous app. */
    suspend fun runEmergencySweep() {
        val reports = scanAll()
        val dangerous = reports.filter { it.verdict.level == VerdictLevel.DANGEROUS && !it.verdict.whitelisted }
        record(
            packageName = context.packageName,
            kind = EventKind.EMERGENCY,
            verdict = ScanVerdict.clean(context.packageName),
            action = EventAction.NO_ACTION,
            note = "紧急触发：命中 ${dangerous.size} 个危险应用",
        )
        dangerous.forEach { report ->
            val result = router.execute(DisposalIntent.FORCE_STOP, report.snapshot.packageName)
            record(
                packageName = report.snapshot.packageName,
                kind = EventKind.EMERGENCY,
                verdict = report.verdict,
                action = if (result.success) EventAction.FORCE_STOPPED else EventAction.WARNED,
                note = "紧急处置：${result.detail}",
            )
        }
    }

    /** Manual disposal from UI (scan results / event detail). */
    suspend fun actManually(
        packageName: String,
        intent: DisposalIntent,
    ): DisposalResult {
        val result = router.execute(intent, packageName)
        record(
            packageName = packageName,
            kind = EventKind.MANUAL_SCAN,
            verdict = ScanVerdict.clean(packageName),
            action =
                when (intent) {
                    DisposalIntent.UNINSTALL -> EventAction.REMOVED
                    DisposalIntent.FREEZE -> EventAction.FROZEN
                    DisposalIntent.HIDE -> EventAction.HIDDEN
                    DisposalIntent.FORCE_STOP -> EventAction.FORCE_STOPPED
                },
            note = "手动处置（${channelLabel(result.channel)}）：${result.detail}",
        )
        return result
    }

    fun evaluate(snapshot: PackageSnapshot): ScanVerdict = engine.evaluate(snapshot, rules.ruleSet.value, whitelist.packageNames)

    suspend fun addToWhitelist(
        packageName: String,
        note: String = "",
    ) = whitelist.add(packageName, note)

    suspend fun removeFromWhitelist(packageName: String) = whitelist.remove(packageName)

    /** Requirement matrix for every tier — powers the tier setup UI. */
    fun tierStatuses(): List<TierRequirementStatus> {
        val accessibilityOk = AccessibilityStatus.isServiceEnabled(context)
        val shizukuOk = shizukuGate.state.value == ShizukuState.READY
        val rootOk = rootShell.state.value == RootState.AVAILABLE
        val deviceOwnerOk = deviceAdminGate.isDeviceOwner
        return GuardTier.entries.map { tier ->
            TierRequirementStatus(
                tier = tier,
                accessibilityOk = accessibilityOk,
                shizukuOk = shizukuOk,
                rootOk = rootOk,
                deviceOwnerOk = deviceOwnerOk,
            )
        }
    }

    private suspend fun record(
        packageName: String,
        kind: EventKind,
        verdict: ScanVerdict,
        action: EventAction,
        note: String,
    ) {
        val event =
            InterceptionEvent(
                id = events.newId(),
                timestampMillis = System.currentTimeMillis(),
                packageName = packageName,
                appLabel = inventory.appLabel(packageName),
                kind = kind,
                level = verdict.level,
                score = verdict.score,
                matchedRuleNames = verdict.matchedRules.map { it.ruleName },
                action = action,
                tierKey = tier.value.key,
                note = note,
            )
        events.append(event)
    }

    private fun startOfDay(): Long =
        Calendar
            .getInstance()
            .apply {
                set(Calendar.HOUR_OF_DAY, 0)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }.timeInMillis

    private fun channelLabel(channel: ExecutionChannel): String =
        when (channel) {
            ExecutionChannel.SHIZUKU -> "Shizuku"
            ExecutionChannel.ROOT -> "Root"
            ExecutionChannel.DEVICE_POLICY -> "设备策略"
            ExecutionChannel.PLATFORM -> "系统确认"
            ExecutionChannel.NONE -> "无通道"
        }
}
