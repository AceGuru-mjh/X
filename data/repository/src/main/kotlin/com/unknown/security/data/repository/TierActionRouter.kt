package com.unknown.security.data.repository

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.unknown.security.core.common.AppResult
import com.unknown.security.core.common.ShellOutcome
import com.unknown.security.service.deviceadmin.DeviceAdminGate
import com.unknown.security.service.root.RootShell
import com.unknown.security.service.shizuku.ShizukuGate

/** Intent of a disposal action — the router decides the execution channel. */
enum class DisposalIntent { FORCE_STOP, UNINSTALL, FREEZE, HIDE }

/** Channel that executed a disposal. */
enum class ExecutionChannel { SHIZUKU, ROOT, DEVICE_POLICY, PLATFORM, NONE }

data class DisposalResult(
    val intent: DisposalIntent,
    val packageName: String,
    val channel: ExecutionChannel,
    val success: Boolean,
    val detail: String,
)

/**
 * Resolves *how* to perform a privileged action for the current tier:
 * Shizuku (adb shell) is preferred when available, root is the fallback,
 * device policy covers hide/block capabilities.
 */
class TierActionRouter(
    private val context: Context,
    private val shizukuGate: ShizukuGate,
    private val rootShell: RootShell,
    private val deviceAdminGate: DeviceAdminGate,
) {
    suspend fun execute(
        intent: DisposalIntent,
        packageName: String,
    ): DisposalResult {
        val shizukuReady = shizukuGate.state.value == com.unknown.security.service.shizuku.ShizukuState.READY
        val rootReady =
            rootShell.state.value == com.unknown.security.service.root.RootState.AVAILABLE ||
                rootShell.checkAvailability()

        if (intent == DisposalIntent.HIDE && deviceAdminGate.isAdminActive) {
            val result = deviceAdminGate.setHidden(packageName, true)
            return DisposalResult(
                intent,
                packageName,
                ExecutionChannel.DEVICE_POLICY,
                result is AppResult.Ok,
                (result as? AppResult.Ok)?.let { "已通过设备策略隐藏" } ?: (result as? AppResult.Err)?.error?.message ?: "",
            )
        }

        val command =
            when (intent) {
                DisposalIntent.FORCE_STOP -> "am force-stop $packageName"
                DisposalIntent.UNINSTALL -> "pm uninstall --user 0 $packageName"
                DisposalIntent.FREEZE -> "pm disable-user --user 0 $packageName"
                DisposalIntent.HIDE -> "pm hide --user 0 $packageName"
            }

        if (shizukuReady) {
            val outcome = shizukuGate.exec(command)
            return DisposalResult(
                intent,
                packageName,
                ExecutionChannel.SHIZUKU,
                outcome is AppResult.Ok && (outcome as AppResult.Ok).value.isSuccess,
                describe(outcome),
            )
        }

        if (rootReady) {
            val outcome = rootShell.exec(command)
            return DisposalResult(
                intent,
                packageName,
                ExecutionChannel.ROOT,
                outcome is AppResult.Ok && (outcome as AppResult.Ok).value.isSuccess,
                describe(outcome),
            )
        }

        // Standard tier fallback: REQUEST_DELETE_PACKAGES lets us hand the
        // uninstall to the system, which asks the user for confirmation.
        if (intent == DisposalIntent.UNINSTALL) {
            return platformUninstall(intent, packageName)
        }

        return DisposalResult(
            intent,
            packageName,
            ExecutionChannel.NONE,
            false,
            "无可用特权通道（Shizuku 未就绪且 root 不可用）",
        )
    }

    private fun platformUninstall(
        intent: DisposalIntent,
        packageName: String,
    ): DisposalResult =
        runCatching {
            val uninstall =
                Intent(Intent.ACTION_DELETE, Uri.fromParts("package", packageName, null))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(uninstall)
        }.fold(
            onSuccess = {
                DisposalResult(intent, packageName, ExecutionChannel.PLATFORM, true, "已调起系统卸载确认")
            },
            onFailure = {
                DisposalResult(
                    intent,
                    packageName,
                    ExecutionChannel.PLATFORM,
                    false,
                    "系统卸载入口不可用：${it.message}",
                )
            },
        )

    private fun describe(outcome: AppResult<ShellOutcome>): String =
        when (outcome) {
            is AppResult.Ok -> {
                if (outcome.value.isSuccess) {
                    "exit=0 · ${outcome.value.durationMillis}ms"
                } else {
                    "exit=${outcome.value.exitCode} · ${outcome.value.trimmedOutput.take(160)}"
                }
            }

            is AppResult.Err -> {
                outcome.error.message
            }
        }
}
