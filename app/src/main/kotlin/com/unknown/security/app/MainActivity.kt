package com.unknown.security.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.HealthAndSafety
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.unknown.security.app.di.AppContainer
import com.unknown.security.app.guard.GuardService
import com.unknown.security.app.onboarding.OnboardingFlow
import com.unknown.security.core.designsystem.GlassBottomNavBar
import com.unknown.security.core.designsystem.GlassScaffold
import com.unknown.security.core.designsystem.GlassTab
import com.unknown.security.core.designsystem.UnknownTheme
import com.unknown.security.core.model.ThemeMode
import com.unknown.security.feature.home.HomeScreen
import com.unknown.security.feature.rules.RulesScreen
import com.unknown.security.feature.scan.ScanScreen
import com.unknown.security.feature.settings.SettingsScreen
import com.unknown.security.feature.shield.ShieldScreen
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val container = (application as UnknownApp).container

        setContent {
            val themeMode by container.settings.themeModeFlow.collectAsState(initial = ThemeMode.SYSTEM)
            val onboardingCompleted by container.settings.onboardingCompletedFlow.collectAsState(initial = null)
            val scope = rememberCoroutineScope()

            UnknownTheme(
                darkTheme =
                    when (themeMode) {
                        ThemeMode.SYSTEM -> isSystemInDarkTheme()
                        ThemeMode.LIGHT -> false
                        ThemeMode.DARK -> true
                    },
            ) {
                GuardLifecycle(container)
                when (onboardingCompleted) {
                    // DataStore not loaded yet — render the bare glass background.
                    null -> {
                        Unit
                    }

                    false -> {
                        OnboardingFlow(
                            container = container,
                            onFinished = {
                                scope.launch { container.settings.setOnboardingCompleted(true) }
                            },
                        )
                    }

                    true -> {
                        UnknownRoot(container)
                    }
                }
            }
        }
    }

    @Composable
    private fun GuardLifecycle(container: AppContainer) {
        val activity = this
        LaunchedEffect(container) {
            container.settings.guardEnabledFlow.collect { enabled ->
                if (enabled) {
                    runCatching {
                        activity.startForegroundService(Intent(activity, GuardService::class.java))
                    }
                } else {
                    activity.stopService(Intent(activity, GuardService::class.java))
                }
            }
        }
    }
}

@Composable
private fun UnknownRoot(container: AppContainer) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    val repository = container.repository

    val tabs =
        listOf(
            GlassTab("守护", Icons.Rounded.HealthAndSafety),
            GlassTab("扫描", Icons.Rounded.Radar),
            GlassTab("拦截", Icons.Rounded.History),
            GlassTab("规则", Icons.Rounded.Gavel),
            GlassTab("设置", Icons.Rounded.Settings),
        )

    GlassScaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            GlassBottomNavBar(
                tabs = tabs,
                selected = selectedTab,
                onSelect = { selectedTab = it },
            )
        },
    ) {
        when (selectedTab) {
            0 -> {
                HomeScreen(
                    repository = repository,
                    onScan = { selectedTab = 1 },
                    onShield = { selectedTab = 2 },
                )
            }

            1 -> {
                ScanScreen(repository = repository)
            }

            2 -> {
                ShieldScreen(repository = repository)
            }

            3 -> {
                RulesScreen(repository = repository)
            }

            4 -> {
                SettingsScreen(repository = repository)
            }
        }
    }
}
