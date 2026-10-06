package com.unknown.security.app.overlay

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import com.unknown.security.app.MainActivity
import com.unknown.security.data.repository.AlertRequest

/**
 * Renders threat alerts as a floating overlay window (SYSTEM_ALERT_WINDOW).
 * Used when the user enabled overlay alerts — the warning is visible even
 * above the installer / risk app UI that triggered it.
 */
class OverlayAlertController(
    private val context: Context,
) {
    private val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private val dismissRunnable = Runnable { dismiss() }
    private var currentView: View? = null

    fun canShow(): Boolean = Settings.canDrawOverlays(context)

    fun show(alert: AlertRequest) {
        if (!canShow()) return
        handler.post {
            dismissInternal()
            val view = buildView(alert)
            val density = context.resources.displayMetrics.density
            val params =
                WindowManager
                    .LayoutParams(
                        WindowManager.LayoutParams.MATCH_PARENT,
                        WindowManager.LayoutParams.WRAP_CONTENT,
                        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                        android.graphics.PixelFormat.TRANSLUCENT,
                    ).apply {
                        gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
                        x = 0
                        y = (density * 24).toInt()
                    }
            runCatching {
                windowManager.addView(view, params)
                currentView = view
                handler.postDelayed(dismissRunnable, AUTO_DISMISS_MILLIS)
            }
        }
    }

    fun dismiss() {
        handler.post { dismissInternal() }
    }

    private fun dismissInternal() {
        handler.removeCallbacks(dismissRunnable)
        currentView?.let { view ->
            runCatching { windowManager.removeView(view) }
        }
        currentView = null
    }

    private fun buildView(alert: AlertRequest): View {
        val density = context.resources.displayMetrics.density

        fun Int.dp(): Int = (this * density).toInt()

        val cardBackground =
            GradientDrawable().apply {
                cornerRadius = 22.dp().toFloat()
                setColor(BACKGROUND_COLOR)
                setStroke(1.dp(), BORDER_COLOR)
            }

        val title =
            TextView(context).apply {
                text = "【${alert.verdict.level.label}】${alert.appLabel}"
                setTextColor(Color.WHITE)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
        val body =
            TextView(context).apply {
                text =
                    "已执行：${alert.actionLabel} · 风险评分 ${alert.verdict.score}" +
                    alert.verdict.matchedRules.joinToString("、") { it.ruleName }
                setTextColor(MUTED_COLOR)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            }
        val hint =
            TextView(context).apply {
                text = "点击查看详情 · ${AUTO_DISMISS_MILLIS / 1000} 秒后自动关闭"
                setTextColor(MUTED_COLOR)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            }

        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            this.background = cardBackground
            val horizontal = 20.dp()
            val vertical = 14.dp()
            setPadding(horizontal, vertical, horizontal, vertical)
            addView(title)
            addView(
                body,
                LinearLayout
                    .LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = 6.dp() },
            )
            addView(
                hint,
                LinearLayout
                    .LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = 8.dp() },
            )
            setOnClickListener {
                runCatching {
                    context.startActivity(
                        Intent(context, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                }
                dismiss()
            }
        }
    }

    private companion object {
        const val AUTO_DISMISS_MILLIS = 6_000L
        const val BACKGROUND_COLOR = 0xF21B2721.toInt()
        const val BORDER_COLOR = 0x662DD4A7
        const val MUTED_COLOR = 0xFFB4C4BB.toInt()
    }
}
