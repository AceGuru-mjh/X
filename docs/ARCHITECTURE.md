# Architecture

Unknown Security 采用**完全分层、模块化**的架构：领域逻辑是纯 Kotlin，权限通道彼此隔离，
UI 与业务彻底解耦。整体自下而上分为五层。

```
┌────────────────────────────────────────────────────────────────┐
│  app            应用壳：导航 / DI 装配 / 前台守护服务 / 悬浮告警 │
├────────────────────────────────────────────────────────────────┤
│  feature/*      界面层：home · scan · shield · rules · settings │
│  core/designsystem  全局液态玻璃设计系统                          │
├────────────────────────────────────────────────────────────────┤
│  data/repository  仓库层：编排引擎、存储与各权限通道               │
├────────────────────────────────────────────────────────────────┤
│  domain/engine   检测引擎：规则匹配 + 评分 + 处置策略（纯 Kotlin）│
│  core/native     原生检测核心：C++17 匹配热路径（可选加速）    │
│  core/model      领域模型：守卫层级 / 能力 / 规则 / 事件          │
│  core/persistence 存储：DataStore + JSON 规则/事件/白名单         │
├────────────────────────────────────────────────────────────────┤
│  service/*       权限通道层：platform · accessibility · shizuku  │
│                 root · deviceadmin                              │
│  core/common     公共基础：Result / Dispatchers / Logger         │
└────────────────────────────────────────────────────────────────┘
```

## 守卫层级（GuardTier）与能力矩阵

八档层级 = 四种权限通道的组合：

| 层级 | 无障碍 | Shizuku | Root | 设备所有者 | 独有能力 |
|---|---|---|---|---|---|
| STANDARD | | | | | 安装监听、应用清单 |
| ACCESSIBLE | ✓ | | | | + 前台监控、弹窗接管 |
| SHIZUKU | | ✓ | | | + 强停/静默卸载/冻结/隐藏 |
| ACCESSIBLE_SHIZUKU | ✓ | ✓ | | | 以上全部 |
| ROOT | | | ✓ | | + 强停/静默卸载/冻结/隐藏 |
| ACCESSIBLE_ROOT | ✓ | | ✓ | | 以上全部 |
| DEVICE_OWNER | | | | ✓ | + 安装阻断、隐藏 |
| ACCESSIBLE_DEVICE_OWNER | ✓ | | | ✓ | 以上全部 |

能力（`GuardCapability`）：`INSTALL_MONITOR` · `APP_INVENTORY` · `FOREGROUND_WATCH` ·
`INSTALL_DIALOG_CONTROL` · `FORCE_STOP` · `SILENT_UNINSTALL` · `HIDE_APP` · `FREEZE_APP` ·
`BLOCK_INSTALL`。

仓库层的 **TierActionRouter** 依据当前层级把「意图」（如"卸载风险应用"）路由到具体通道：
Shizuku 层走 adb shell（uid 2000），Root 层走 `su`，设备所有者层走 `DevicePolicyManager`。

## 拦截流水线

```
事件源（安装广播 / 无障碍前台事件 / 弹窗检测 / 紧急触发 / 手动扫描）
        │
        ▼
AppInventory.snapshot(pkg)  ──▶ DetectionEngine.evaluate(snapshot, ruleSet, whitelist)
        │                                     │
        │                              ScanVerdict(level, score, matched)
        ▼                                     ▼
TierActionRouter.resolve(verdict, policy, tier) ──▶ 决策：放行 / 警示 / 拦截 / 处置
        │
        ▼
InterceptionEvent 落盘 + 通知 / 悬浮告警 / 统计
```

## 检测引擎

规则类型（`DetectionRule`，全部可序列化）：

- `PackageNameRule` — 包名精确 / 正则匹配
- `LabelKeywordRule` — 应用名关键词
- `PermissionComboRule` — 权限组合启发式（如 短信 + 联系人 + 悬浮窗 + 无障碍）
- `ApkHashRule` — APK SHA-256 精确锁定
- `TargetSdkRule` — 极低 targetSdk + 敏感权限的规避行为

评分：命中规则按 `ThreatSeverity`（LOW 10 / MEDIUM 25 / HIGH 50 / CRITICAL 100）累加，
映射到 `VerdictLevel`（CLEAN / SUSPICIOUS / DANGEROUS），再由 `EnginePolicy`
（自动处置阈值等）决定动作。

### 原生检测核心（core/native）

规则匹配的热路径可选下沉到 C++17 原生核心（JNI 桥 + `libunknown_native.so`）：
Aho-Corasick 关键词自动机、权限组合稠密位图、流式 SHA-256、轻量正则与
精确包名 / 哈希开放寻址表。纯 Kotlin 引擎仍是语义权威；设备无匹配 ABI 时
`NativeRuleSet.compile()` 返回 null，引擎自动回退纯 Kotlin 路径。
协议、线程模型与本地测试方法详见 [NATIVE_ENGINE.md](NATIVE_ENGINE.md)。

## 存储设计

- **DataStore Preferences** — 选定层级、引擎策略（JSON 序列化）、开关项
- **JSON 规则库** — 内置种子规则（assets）与用户规则合并，可导入导出
- **NDJSON 事件流** — 拦截事件追加写，环形截断保留最近 500 条
- **白名单** — JSON 文件，命中即跳过自动处置

## 液态玻璃设计系统

`core/designsystem` 提供全局玻璃组件（脚手架 / 卡片 / 按钮 / 导航栏 / 弹层 / 徽章），
全部基于液态玻璃效果库（折射 + 振感 + 色散）实现——不是简单半透明，也不是普通毛玻璃。
背景层通过 `layerBackdrop` 记录为采样源，玻璃组件实时折射其下方真实内容。

## CI

GitHub Actions 对每个 PR 执行三项检查：

1. **gradle wrapper validation** — wrapper 完整性
2. **ktlint** — 代码风格
3. **gradle build (assemble)** — 全模块编译 + 产物上传

## 分层提交计划

本仓库按五个堆叠 PR 交付：

1. `layer/01-foundation` — 构建系统、CI、公共基础与领域模型
2. `layer/02-engine` — 持久化与检测引擎
3. `layer/03-services` — 五个权限通道服务
4. `layer/04-ui` — 液态玻璃设计系统、全部界面与应用壳
5. `layer/05-hardening` — 文档、清单与 CI 加固
