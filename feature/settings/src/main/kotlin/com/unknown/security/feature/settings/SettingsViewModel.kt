package com.unknown.security.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.unknown.security.core.model.EnginePolicy
import com.unknown.security.core.model.ThemeMode
import com.unknown.security.core.model.ThreatSeverity
import com.unknown.security.data.repository.GuardRepository
import com.unknown.security.data.repository.TierRequirementStatus
import com.unknown.security.service.deviceadmin.DeviceAdminState
import com.unknown.security.service.root.RootState
import com.unknown.security.service.shizuku.ShizukuState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(
    private val repository: GuardRepository,
) : ViewModel() {
    val tier = repository.tier
    val policy = repository.policy
    val shizukuState = repository.shizukuGate.state
    val rootState = repository.rootShell.state

    val themeMode: StateFlow<ThemeMode> =
        repository.settings.themeModeFlow
            .stateIn(viewModelScope, SharingStarted.Eagerly, ThemeMode.SYSTEM)

    private val _deviceAdminState = MutableStateFlow(DeviceAdminState.NOT_PROVISIONED)
    val deviceAdminState: StateFlow<DeviceAdminState> = _deviceAdminState.asStateFlow()

    private val _requirements = MutableStateFlow<List<TierRequirementStatus>>(emptyList())
    val requirements: StateFlow<List<TierRequirementStatus>> = _requirements.asStateFlow()

    val provisioningCommand: String get() = repository.deviceAdminGate.provisioningCommand

    init {
        refresh()
    }

    fun refresh() {
        _requirements.value = repository.tierStatuses()
        _deviceAdminState.value = repository.deviceAdminGate.state()
        repository.shizukuGate.refreshState()
    }

    fun updatePolicy(mutate: (EnginePolicy) -> EnginePolicy) {
        viewModelScope.launch {
            repository.setPolicy(mutate(repository.policy.value))
        }
    }

    fun setAutoThreshold(severity: ThreatSeverity) {
        updatePolicy { it.copy(autoActThreshold = severity) }
    }

    fun setEmergencyPresses(presses: Int) {
        updatePolicy { it.copy(emergencyVolumePresses = presses) }
    }

    fun setThemeMode(mode: ThemeMode) {
        viewModelScope.launch { repository.settings.setThemeMode(mode) }
    }

    /** Re-opens the first-run guide on the next navigation to the root UI. */
    fun reopenOnboarding() {
        viewModelScope.launch { repository.settings.setOnboardingCompleted(false) }
    }

    fun clearEvents() {
        viewModelScope.launch { repository.events.clear() }
    }

    fun requestShizukuPermission() {
        viewModelScope.launch {
            repository.shizukuGate.requestPermission()
            refresh()
        }
    }

    fun probeRoot() {
        viewModelScope.launch {
            repository.rootShell.resetProbe()
            repository.rootShell.checkAvailability()
            refresh()
        }
    }
}
