package com.unknown.security.app.onboarding

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccessibilityNew
import androidx.compose.material.icons.rounded.BatterySaver
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.HealthAndSafety
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.QueryStats
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.unknown.security.app.di.AppContainer
import com.unknown.security.app.permission.PermissionChecks
import com.unknown.security.core.designsystem.GlassButton
import com.unknown.security.core.designsystem.GlassCard
import com.unknown.security.core.designsystem.GlassChip
import com.unknown.security.core.designsystem.GlassScaffold
import com.unknown.security.core.designsystem.GlassTopBar
import com.unknown.security.service.shizuku.ShizukuState
import kotlinx.coroutines.launch

private enum class StepKind { WELCOME, NOTIFICATIONS, USAGE_ACCESS, OVERLAY, ACCESSIBILITY, SHIZUKU, BATTERY, DONE }

private data class OnboardingStep(
    val kind: StepKind,
    val title: String,
    val subtitle: String,
    val points: List<String> = emptyList(),
    val icon: ImageVector,
    val optional: Boolean = false,
    val granted: Boolean? = null,
    val actionLabel: String? = null,
    val action: (() -> Unit)? = null,
)

/**
 * First-run guide: introduces the guard concept, then walks the user through
 * every permission channel one page at a time. Each page shows the live grant
 * status (refreshed whenever the app resumes) and jumps straight to the right
 * system screen. Finishing the flow persists the completion flag; the guide
 * can be re-opened any time from Settings.
 */
@Composable
fun OnboardingFlow(
    container: AppContainer,
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var refreshTick by remember { mutableIntStateOf(0) }

    // Re-check every permission when returning from a system settings screen.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_RESUME) refreshTick++
            }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val notificationLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
            refreshTick++
        }

    val shizukuState by container.shizukuGate.state.collectAsState()

    @Suppress("UNUSED_EXPRESSION")
    refreshTick // reading the tick makes every status below refresh on change

    val steps =
        buildList {
            add(
                OnboardingStep(
                    kind = StepKind.WELCOME,
                    title = "欢迎使用 Unknown 守护",
                    subtitle = "多层权限引擎驱动的病毒拦截与防护",
                    icon = Icons.Rounded.HealthAndSafety,
                    points =
                        listOf(
                            "安装监听：新装 / 更新的应用实时风险判定",
                            "八档守卫层级：从无权限到设备所有者，按设备条件选择",
                            "拦截、冻结、隐藏、弹窗接管，全链路自动处置",
                            "接下来将逐项引导你开启所需权限",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.NOTIFICATIONS,
                    title = "通知权限",
                    subtitle = "威胁告警与守护状态的通知通道",
                    icon = Icons.Rounded.Notifications,
                    granted = PermissionChecks.notificationsGranted(context),
                    actionLabel = "授权通知",
                    action = {
                        if (Build.VERSION.SDK_INT >= 33) {
                            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    },
                    points =
                        listOf(
                            "命中风险应用时第一时间推送高优先级告警",
                            "前台守护服务通过常驻通知保活",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.USAGE_ACCESS,
                    title = "使用情况访问",
                    subtitle = "无无障碍时的前台应用监控基线",
                    icon = Icons.Rounded.QueryStats,
                    optional = true,
                    granted = PermissionChecks.usageAccessGranted(context),
                    actionLabel = "去系统设置开启",
                    action = { PermissionChecks.openSystemSettings(context, PermissionChecks.usageAccessIntent()) },
                    points =
                        listOf(
                            "轮询前台应用，危险应用上台即刻告警",
                            "与无障碍通道互为备份，建议开启",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.OVERLAY,
                    title = "悬浮窗权限",
                    subtitle = "在任意界面之上弹出风险警示",
                    icon = Icons.Rounded.Layers,
                    optional = true,
                    granted = PermissionChecks.overlayGranted(context),
                    actionLabel = "去系统设置开启",
                    action = { PermissionChecks.openSystemSettings(context, PermissionChecks.overlayIntent(context)) },
                    points =
                        listOf(
                            "风险应用安装 / 上台时悬浮警示，不被遮挡",
                            "可在「设置 → 引擎策略」中随时关闭悬浮告警",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.ACCESSIBILITY,
                    title = "无障碍服务",
                    subtitle = "实时前台监控与安装弹窗接管的眼睛",
                    icon = Icons.Rounded.AccessibilityNew,
                    optional = true,
                    granted = PermissionChecks.accessibilityGranted(context),
                    actionLabel = "去系统设置开启",
                    action = { PermissionChecks.openSystemSettings(context, PermissionChecks.accessibilityIntent()) },
                    points =
                        listOf(
                            "实时获知前台应用，零延迟告警",
                            "安装确认弹窗自动点取消，拦截静默安装",
                            "连按音量键触发全盘紧急体检",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.SHIZUKU,
                    title = "Shizuku（可选）",
                    subtitle = "adb 级特权：强停 / 静默卸载 / 冻结 / 隐藏",
                    icon = Icons.Rounded.Terminal,
                    optional = true,
                    granted = shizukuState == ShizukuState.READY,
                    actionLabel =
                        when (shizukuState) {
                            ShizukuState.READY -> "已就绪"
                            ShizukuState.UNAUTHORIZED, ShizukuState.ASKING -> "请求 Shizuku 授权"
                            else -> "了解 Shizuku"
                        },
                    action = {
                        when (shizukuState) {
                            ShizukuState.UNAUTHORIZED, ShizukuState.ASKING -> {
                                scope.launch {
                                    container.shizukuGate.requestPermission()
                                    refreshTick++
                                }
                            }

                            else -> {
                                PermissionChecks.openSystemSettings(
                                    context,
                                    android.content
                                        .Intent(
                                            android.content.Intent.ACTION_VIEW,
                                            android.net.Uri.parse("https://shizuku.rikka.app"),
                                        ),
                                )
                            }
                        }
                    },
                    points =
                        listOf(
                            "无需 root 即可执行系统级处置",
                            "需要先安装并启动 Shizuku 应用",
                            "没有它也可以使用标准 / 无障碍层级",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.BATTERY,
                    title = "关闭电池优化",
                    subtitle = "防止系统杀死后台守护服务",
                    icon = Icons.Rounded.BatterySaver,
                    optional = true,
                    granted = PermissionChecks.batteryOptimizationIgnored(context),
                    actionLabel = "去系统设置关闭",
                    action = { PermissionChecks.openSystemSettings(context, PermissionChecks.batteryOptimizationIntent()) },
                    points =
                        listOf(
                            "部分厂商系统会激进清理后台进程",
                            "加入白名单后守护服务更稳定",
                        ),
                ),
            )
            add(
                OnboardingStep(
                    kind = StepKind.DONE,
                    title = "一切就绪",
                    subtitle = "权限汇总如下，未开启的可在设置中随时补齐",
                    icon = Icons.Rounded.CheckCircle,
                ),
            )
        }

    val pagerState = rememberPagerState(pageCount = { steps.size })

    GlassScaffold(
        modifier = modifier,
        topBar = {
            GlassTopBar(
                title = "新手引导",
                subtitle = "第 ${pagerState.currentPage + 1} / ${steps.size} 步",
            )
        },
        bottomBar = {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
                    .padding(bottom = 28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                PageIndicator(
                    count = steps.size,
                    current = pagerState.currentPage,
                )
                Spacer(Modifier.height(16.dp))
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (pagerState.currentPage < steps.size - 1) {
                        GlassButton(onClick = onFinished) {
                            Text("跳过", color = MaterialTheme.colorScheme.onSurface)
                        }
                    }
                    GlassButton(
                        onClick = {
                            if (pagerState.currentPage >= steps.size - 1) {
                                onFinished()
                            } else {
                                scope.launch { pagerState.animateScrollToPage(pagerState.currentPage + 1) }
                            }
                        },
                        emphasized = true,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(
                            text = if (pagerState.currentPage >= steps.size - 1) "开始守护" else "下一步",
                            color = MaterialTheme.colorScheme.onPrimary,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }
        },
    ) {
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.fillMaxSize(),
        ) { page ->
            OnboardingPage(
                step = steps[page],
                summary =
                    if (steps[page].kind == StepKind.DONE) {
                        steps.filter { it.granted != null }
                    } else {
                        emptyList()
                    },
            )
        }
    }
}

@Composable
private fun OnboardingPage(
    step: OnboardingStep,
    summary: List<OnboardingStep>,
) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
            .padding(top = 96.dp, bottom = 150.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier
                .size(96.dp)
                .clip(CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            GlassCard(Modifier.fillMaxSize(), cornerRadius = 48.dp) {}
            Icon(
                imageVector = step.icon,
                contentDescription = step.title,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(44.dp),
            )
        }
        Spacer(Modifier.height(20.dp))
        Text(
            text = step.title,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = step.subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))

        if (step.granted != null) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                GlassChip(
                    text = if (step.granted) "已授权" else "未开启",
                    tint = if (step.granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                )
                if (step.optional) {
                    GlassChip(text = "可选")
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        if (step.points.isNotEmpty()) {
            GlassCard(Modifier.fillMaxWidth()) {
                Column(
                    Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    step.points.forEach { point ->
                        Row(verticalAlignment = Alignment.Top) {
                            Text(
                                text = "·",
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Bold,
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = point,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }

        if (step.action != null && step.granted != true) {
            GlassButton(onClick = step.action, emphasized = true) {
                Text(
                    text = step.actionLabel ?: "去授权",
                    color = MaterialTheme.colorScheme.onPrimary,
                    fontWeight = FontWeight.Bold,
                )
            }
        }

        if (summary.isNotEmpty()) {
            GlassCard(Modifier.fillMaxWidth()) {
                Column(
                    Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    summary.forEach { item ->
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = item.title,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            GlassChip(
                                text = if (item.granted == true) "已授权" else "未开启",
                                tint =
                                    if (item.granted == true) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.error
                                    },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PageIndicator(
    count: Int,
    current: Int,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        repeat(count) { index ->
            val active = index == current
            Box(
                Modifier
                    .size(if (active) 8.dp else 6.dp)
                    .clip(CircleShape)
                    .background(
                        if (active) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                        },
                    ),
            )
        }
    }
}
