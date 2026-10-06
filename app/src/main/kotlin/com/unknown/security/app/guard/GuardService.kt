package com.unknown.security.app.guard

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.unknown.security.R
import com.unknown.security.app.MainActivity
import com.unknown.security.app.UnknownApp
import com.unknown.security.app.di.AppContainer
import com.unknown.security.app.overlay.OverlayAlertController
import com.unknown.security.core.model.VerdictLevel
import com.unknown.security.data.repository.AlertRequest
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Foreground guard service: owns the live interception pipeline and renders
 * alerts (high-priority notifications + optional overlay) when threats are detected.
 */
class GuardService : Service() {
    private lateinit var container: AppContainer
    private lateinit var overlay: OverlayAlertController

    override fun onCreate() {
        super.onCreate()
        container = UnknownApp.container(this)
        overlay = OverlayAlertController(this)
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        startAsForeground()
        container.repository.start()

        container.applicationScope.launch {
            container.repository.alerts.collectLatest { alert ->
                val policy = container.repository.policy.value
                if (policy.notificationsEnabled) {
                    showAlertNotification(alert)
                }
                if (policy.overlayAlertsEnabled) {
                    overlay.show(alert)
                }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        overlay.dismiss()
        container.repository.stop()
        super.onDestroy()
    }

    private fun startAsForeground() {
        val notification =
            buildStatusNotification(
                subtitle = getString(R.string.guard_notification_running),
            )
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                STATUS_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(STATUS_NOTIFICATION_ID, notification)
        }
    }

    private fun buildStatusNotification(subtitle: String): Notification {
        val launchIntent =
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        return NotificationCompat
            .Builder(this, UnknownApp.CHANNEL_GUARD)
            .setSmallIcon(R.drawable.ic_stat_guard)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(subtitle)
            .setOngoing(true)
            .setContentIntent(launchIntent)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun showAlertNotification(alert: AlertRequest) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val launchIntent =
            PendingIntent.getActivity(
                this,
                1,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        val icon =
            when (alert.verdict.level) {
                VerdictLevel.CLEAN -> R.drawable.ic_stat_guard
                VerdictLevel.SUSPICIOUS -> R.drawable.ic_stat_guard
                VerdictLevel.DANGEROUS -> R.drawable.ic_stat_guard
            }
        val notification =
            NotificationCompat
                .Builder(this, UnknownApp.CHANNEL_ALERT)
                .setSmallIcon(icon)
                .setContentTitle(
                    getString(R.string.alert_title, alert.verdict.level.label, alert.appLabel),
                ).setContentText(
                    getString(R.string.alert_body, alert.actionLabel, alert.verdict.score) +
                        alert.verdict.matchedRules.joinToString("、") { it.ruleName },
                ).setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(launchIntent)
                .build()
        manager.notify(alert.packageName.hashCode(), notification)
    }

    companion object {
        private const val STATUS_NOTIFICATION_ID = 47001

        fun start(context: Context) {
            context.startForegroundService(Intent(context, GuardService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, GuardService::class.java))
        }
    }
}
