# Native Detection Core（core/native）

> C++17 检测引擎热路径核心 + JNI 桥 —— 为 Unknown Security 的规则匹配流水线提供
> 零依赖、零分配（稳态）的原生加速能力。

## 定位

`domain/engine` 的纯 Kotlin 检测引擎仍是语义权威（source of truth）；`core/native`
是可选的**热路径加速器**：把「编译规则集 + 逐包评估」这段最热的路径下沉到 C++。

```
Kotlin (core/model)                     C++17 (core/native)
─────────────────────                   ──────────────────────────────────
DetectionRule ──encodeRules──▶ 行协议 ──▶ CompiledRuleSet::compile()
                                            ├─ Aho-Corasick 自动机（全部关键词）
                                            ├─ 权限稠密位图（PermissionIndex）
                                            ├─ 精确包名 / SHA-256 开放寻址表
                                            └─ RegexLite 轻量正则（编译期校验）

PackageSnapshot ──encodeSnapshot─▶ 行协议 ──▶ evaluate()
                                            │  ① 精确包名表探测
                                            │  ② 正则包名规则
                                            │  ③ 一次 Aho-Corasick 标签扫描
                                            │  ④ 快照权限位图 + 危险权限标记
                                            │  ⑤ PermissionCombo 位图判定
                                            │  ⑥ SHA-256 折叠小写后查表
                                            │  ⑦ TargetSdk 阈值判定
                                            ▼
ScanVerdict ◀──decodeVerdict── String[] ◀── Verdict{level, score, matches[]}
```

Kotlin 侧入口：`NativeRuleSet.compile(rules)` / `evaluate(snapshot)` /
`NativeVerdict.toScanVerdict(packageName)`。`NativeSha256` 提供流式原生哈希，
可用于 APK 摘要。

## 规则覆盖

| core/model 规则 | native 实现 | 语义 |
|---|---|---|
| `PackageNameRule`（非正则） | 开放寻址哈希表 | 包名字节级精确相等 |
| `PackageNameRule`（正则） | `RegexLite` | 非锚定搜索；支持 `.` `*` `+` `?` `{m,n}` `[]` `()` `\|` `\d\w\s` `^$`；步数 + 递归深度双重预算，病态模式快速返回不匹配 |
| `LabelKeywordRule` | Aho-Corasick | 一次扫描命中全部关键词；关键词在编译期统一折叠为小写形式（大小写不敏感，详情亦显示折叠形式）；UTF-8 字节精确匹配（中文关键词可用） |
| `PermissionComboRule` | 稠密位图 | `required` 全含且 `\|anyOf ∩ snapshot\| ≥ anyOfCount`（`anyOfCount ≤ 0` 时只看 required） |
| `ApkHashRule` | 哈希表 | 双侧折叠为小写 hex 后比较；未知摘要（空串）跳过 |
| `TargetSdkRule` | 整数比较 | `targetSdk ≤ maxTargetSdk` 且（如要求）请求了危险权限 |

危险权限表是内置的精选清单（`permission_index.cpp`），覆盖 SMS / 联系人 / 定位 /
存储 / 摄像头 / 麦克风 / 悬浮窗 / 无障碍 / `QUERY_ALL_PACKAGES` 等典型高危项，
供 TargetSdkRule 的规避启发式使用。

## 评分与判定（与 ARCHITECTURE.md 对齐）

- 命中规则按 `ThreatSeverity` 累加：LOW 10 / MEDIUM 25 / HIGH 50 / CRITICAL 100
- `score == 0` → CLEAN；`1..49` → SUSPICIOUS；`≥ 50` → DANGEROUS
- 匹配列表按严重度降序稳定排列（计数放置，无比较器排序）
- 是否自动处置仍由 Kotlin 侧 `EnginePolicy.autoActScore` 决定 —— native 只裁决、不动作
- 白名单判断在 Kotlin 侧（评估之前），native 保持纯匹配器

## Kotlin ↔ C++ 行协议

紧凑、可读、零反射。字段分隔 `\x1F`（US），列表分隔 `\x1E`（RS），规则按行。
编解码见 `NativeRuleCodec`；协议在两侧都有严格校验，坏输入以带行号/规则 ID 的
`IllegalArgumentException` 报错。

```text
规则行（类型码 | id | name | severity(0-3) | 类型专属字段…）
P ␟ id ␟ name ␟ sev ␟ pattern ␟ isRegex(0/1)
K ␟ id ␟ name ␟ sev ␟ keyword1 ␞ keyword2 …
C ␟ id ␟ name ␟ sev ␟ required(␞) ␟ anyOf(␞) ␟ anyOfCount
H ␟ id ␟ name ␟ sev ␟ sha256Hex
T ␟ id ␟ name ␟ sev ␟ maxTargetSdk ␟ requireDangerous(0/1)

快照行
packageName ␟ label ␟ targetSdk ␟ perm1 ␞ perm2 … ␟ sha256Hex(空=未知)

裁决输出（String[]，首元素为表头）
level(0-2) ␟ score ␟ matchCount
id ␟ name ␟ severity(0-3) ␟ detail
…
```

限制：规则 blob ≤ 1 MiB、≤ 50000 条、单个关键词 / 哈希 / 权限字符串遵循上述
协议上限；超出即编译期报错。自由文本字段（label、id、name、关键词）会剥离
协议控制字符。

## 内存与线程模型

- **编译期**：规则 blob 被整体复制进 `CompiledRuleSet` 的私有 arena，所有
  string_view 指向这份稳定存储 —— 无逐字符串拷贝，无悬垂视图
- **稳态零分配**：`evaluate()` 只读写调用方提供的 `EvalScratch`（命中位图、
  快照权限位图、匹配缓冲）。JNI 桥为每个 Java 线程持有 thread-local scratch，
  首次调用预热后不再触碰分配器
- **线程安全**：`CompiledRuleSet` 编译后不可变，可被多线程并发 `evaluate()`；
  每线程一个 scratch
- **句柄安全**：JNI 句柄带魔数校验，非法 / 已关闭句柄以
  `IllegalArgumentException` 报错而非崩溃；不重复 close 由 Kotlin 层的
  [AutoCloseable] 单线程生命周期约定保证
- **异常屏障**：所有 JNI 入口包裹 C++ 异常屏障，`bad_alloc` 等被转换为
  Java 异常，绝不穿越 `extern "C"` 边界
- `Verdict.matches` 指向 scratch 内的缓冲，有效期到下一次 `evaluate()` ——
  JNI 出口处立即转成 Java `String[]`，不暴露该约束

## 构建与测试

Android 侧由 Gradle `externalNativeBuild`（CMake 3.22.1 / NDK 27.2.12479018）
编出 `libunknown_native.so`，全 ABI。核心不依赖任何 Android 头文件，可在任意
主机上独立构建：

```bash
# 主机单测（零第三方依赖，CTest 驱动 6 个测试二进制）
cmake -S core/native/src/main/cpp -B build-host \
      -DUNKNOWN_NATIVE_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-host --parallel
ctest --test-dir build-host --output-on-failure

# NDK 交叉编译（CI 同款）
cmake -S core/native/src/main/cpp -B build-arm64 \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_SDK_ROOT/ndk/27.2.12479018/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
```

测试覆盖：NIST SHA-256 向量（含百万 'a' 与分块流式）、教科书 Aho-Corasick
（ushers / 重叠 / 大小写 / 中文）、正则（锚定 / 量词 / 类 / 逃逸 / 语法错误 /
病态模式双重预算）、权限索引（intern 去重 / 再哈希 / 危险权限表）、协议
（5 字段快照 / 损坏输入拒绝）、引擎端到端（六类规则全命中 / 评分聚合 /
严重度排序 / scratch 复用 / 重复键分组 / 编译期错误文案）。

CI：`native-ci` 对每个 PR 与 feat 分支运行 host 测试 + arm64-v8a / armeabi-v7a
NDK 交叉编译（产物上传为 artifact）；`android-ci` 的 assemble 任务额外安装
NDK 以完成全模块构建。

## 与 domain/engine 的集成约定（layer/02）

1. `NativeRuleSet.compile(enabledRules)` 返回 `null` ⇒ 回退纯 Kotlin 引擎
   （设备无匹配 ABI 时优雅降级，绝不崩溃）
2. 规则集变更（导入 / 编辑 / 开关）时重新 compile —— 编译本身是毫秒级
3. 每次扫描调用 `evaluate(snapshot)`，结果 `toScanVerdict(pkg)` 直接进入
   `TierActionRouter` 之后的既有流水线
4. APK 摘要可用 `NativeSha256` 流式计算，或沿用 `java.security.MessageDigest`
   —— 两者结果一致（FIPS 180-4）

## 许可

本模块为仓库自有代码，随仓库整体以 **GNU AGPL-3.0** 提供；无任何第三方依赖。
