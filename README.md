# Unknown Security

> Android 应用风险拦截与防护 — 多层权限引擎 · 全局液态玻璃界面

**Unknown Security** 是一个专注于「病毒拦截」的 Android 安全工具：以**多种权限层级**
组织拦截能力，用户按设备条件选择合适的守卫档位。

## 核心特性

- **8 档守卫层级**：标准 / 无障碍 / Shizuku / 无障碍+Shizuku / Root / 无障碍+Root / 设备所有者 / 无障碍+设备所有者
- **实时拦截引擎**：安装监听 → 规则匹配（包名 / 关键词 / 权限组合 / 哈希 / 目标SDK）→ 自动处置
- **C++17 原生检测核心**：Aho-Corasick 关键词匹配 + 权限组合位图 + 流式 SHA-256 + 轻量正则，稳态零分配，不可用时自动回退纯 Kotlin 引擎
- **处置能力矩阵**：强停 / 静默卸载 / 冻结 / 隐藏 / 安装阻断 / 弹窗接管
- **全局液态玻璃 UI**：基于 Compose 与液态玻璃效果库构建，非 WebView、非毛玻璃
- **可扩展规则库**：内置种子规则 + 用户自定义规则，支持导入导出
- **紧急触发**：连按音量键触发全盘体检与紧急处置

## 架构

完全模块化的 Kotlin / Jetpack Compose 工程（详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)）：

```
app/                 应用壳：导航、DI 装配、前台守护服务、悬浮告警
core/                common · model · native(C++17) · persistence · designsystem
domain/engine/       检测引擎（纯 Kotlin，可独立测试；native 热路径见 docs/NATIVE_ENGINE.md）
service/             platform · accessibility · shizuku · root · deviceadmin
data/repository/     仓库层：编排引擎、存储与各权限通道
feature/             home · scan · shield · rules · settings
```

## 构建

| 项 | 版本 |
|---|---|
| JDK | 21 |
| Gradle | 9.7.1（仓库自带 wrapper） |
| Android Gradle Plugin | 9.3.2 |
| Kotlin | 2.4.10 |
| NDK / CMake | 27.2.12479018 / 3.22.1（仅 core/native 需要） |
| compileSdk / targetSdk / minSdk | 37 / 37 / 26 |

```bash
./gradlew assembleDebug     # 调试包
./gradlew assemble          # 全模块（含 libunknown_native.so）
```

原生核心可在主机上独立构建与测试（无需 Android SDK）：

```bash
cmake -S core/native/src/main/cpp -B build-host -DUNKNOWN_NATIVE_BUILD_TESTS=ON
cmake --build build-host --parallel && ctest --test-dir build-host --output-on-failure
```

CI（GitHub Actions）会在每个 PR 上执行 wrapper 校验、ktlint 与全量构建；
native-ci 另跑主机单测与 NDK 双 ABI 交叉编译。

## 许可

- 本仓库自有代码：**GNU AGPL-3.0**（见 [LICENSE](LICENSE)）
- 第三方组件（液态玻璃效果库、Shizuku、AndroidX 等）见
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，其版权与许可声明一律保留

## 免责声明

本项目按「现状」提供，不提供任何担保。涉及无障碍服务、adb 特权与 root
等高权限能力，请只在自有设备上、在了解其行为的前提下使用，并遵守所在地区法律法规。
