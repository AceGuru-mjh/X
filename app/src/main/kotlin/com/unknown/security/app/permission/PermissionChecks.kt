package com.unknown.security.app.permission

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.os.Process
import android.provider.Settings
import com.unknown.security.service.accessibility.AccessibilityStatus

/**
 * Live status checks and system-settings intents for every runtime / special
 * access permission the guard relies on. Used by the onboarding flow and
 * re-checked whenever the app resumes.
 */
object PermissionChecks {
    /** POST_NOTIFICATIONS — runtime permission since API 33. */
    fun notificationsGranted(context: Context): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    /** PACKAGE_USAGE_STATS — special access granted in system settings. */
    fun usageAccessGranted(context: Context): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode =
            runCatching {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                )
            }.getOrDefault(AppOpsManager.MODE_ERRORED)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** SYSTEM_ALERT_WINDOW — special access granted in system settings. */
    fun overlayGranted(context: Context): Boolean = Settings.canDrawOverlays(context)

    /** Accessibility service enabled in system settings. */
    fun accessibilityGranted(context: Context): Boolean = AccessibilityStatus.isServiceEnabled(context)

    /** Battery optimisation exemption (keeps the foreground guard alive). */
    fun batteryOptimizationIgnored(context: Context): Boolean {
        val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return power.isIgnoringBatteryOptimizations(context.packageName)
    }

    fun usageAccessIntent(): Intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)

    fun overlayIntent(context: Context): Intent =
        Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:${context.packageName}"))

    fun accessibilityIntent(): Intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)

    fun batteryOptimizationIntent(): Intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

    fun openSystemSettings(
        context: Context,
        intent: Intent,
    ) {
        runCatching {
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }
}
