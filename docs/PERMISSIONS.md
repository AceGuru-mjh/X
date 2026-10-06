# 权限清单与利用审计

本文件审计 `app/src/main/AndroidManifest.xml` 声明的每一项权限：**声明位置、
实际用途、代码落点、用户引导入口**。原则：凡声明，必使用；凡使用，必可在
引导页或设置页中追踪。

## Manifest 权限

| 权限 | 用途 | 代码落点 | 用户入口 |
|---|---|---|---|
| `POST_NOTIFICATIONS` | 威胁告警通知 + 前台守护服务常驻通知 | `GuardService.showAlertNotification()`（遵循「通知告警」开关）| 引导页第 2 步 · 设置 → 系统权限 |
| `FOREGROUND_SERVICE` / `FOREGROUND_SERVICE_SPECIAL_USE` | 前台守护服务，驱动实时拦截流水线 | `GuardService.startAsForeground()` | 首页守护开关 |
| `RECEIVE_BOOT_COMPLETED` | 开机自启守护服务 | `BootReceiver` | 自动生效 |
| `QUERY_ALL_PACKAGES` | 全量应用清单，支撑全盘扫描 | `AppInventory.allPackages()` | 扫描页 |
| `PACKAGE_USAGE_STATS` | 无无障碍时的前台应用监控基线 | `UsageForegroundWatcher` | 引导页第 3 步 · 设置 → 系统权限 |
| `SYSTEM_ALERT_WINDOW` | 在任意界面之上弹出风险悬浮警示 | `OverlayAlertController`（遵循「悬浮窗告警」开关）| 引导页第 4 步 · 设置 → 系统权限 |
| `REQUEST_DELETE_PACKAGES` | 标准层级下的卸载回退：调起系统卸载确认 | `TierActionRouter.platformUninstall()` | 扫描结果 → 卸载 |

## 特殊通道（非 manifest 权限，但属特权能力）

| 通道 | 用途 | 代码落点 | 用户入口 |
|---|---|---|---|
| 无障碍服务 | 前台监控 / 安装弹窗接管 / 音量键紧急触发 | `UnknownAccessibilityService` + `AccessibilityBus` | 引导页第 5 步 · 设置 → 权限通道 |
| Shizuku（adb 特权） | 强停 / 静默卸载 / 冻结 / 隐藏 | `ShizukuGate` + `ShizukuShellService` | 引导页第 6 步 · 设置 → 权限通道 |
| Root | 同上，经 `su` 执行 | `RootShell` | 设置 → 权限通道 |
| 设备所有者 | 系统级安装阻断 / 隐藏应用 | `DeviceAdminGate` | 设置 → 权限通道（adb 配置） |
| 电池优化白名单 | 防止守护服务被后台清理 | 系统设置跳转 | 引导页第 7 步 · 设置 → 系统权限 |

## 审计结论

- 上一版遗留问题：`SYSTEM_ALERT_WINDOW` 与 `REQUEST_DELETE_PACKAGES` 曾只声明未使用
  —— 现已分别由悬浮告警与系统卸载回退落地。
- `EnginePolicy.notificationsEnabled` / `overlayAlertsEnabled` 两个策略开关此前在 UI 中
  不可见且服务侧未读取 —— 现已加入设置页并在 `GuardService` 中生效。
- 所有需要用户手动开启的权限均可在「新手引导」中逐项完成，引导完成后仍可在
  「设置 → 系统权限 / 权限通道」中查看实时状态并跳转系统设置。
