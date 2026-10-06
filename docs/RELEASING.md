# 发布与签名

每次 PR 合并进 `main` 后，release 工作流会自动：

1. 构建 `:app:assembleRelease`；
2. 使用仓库内置密钥库（`app/keystore/release.keystore.part-*`，alias `meng411722`）签名；
3. 用 apksigner 校验签名，并创建带 APK 与 SHA-256 校验和的 GitHub Release
   （tag 形如 `v1.0.0-build123`）。

> 工作流文件位于 `ci/release.yml`。因推送 API 的 token 缺少 `workflow`
> scope，未能直接写入 `.github/workflows/`。启用方式：把
> `ci/release.yml` 移动为 `.github/workflows/release.yml`（网页端或本地
> git 操作均可），即可生效。

如需换成私有签名身份，把自有 keystore 以 base64 存入仓库 Secret
`SIGNING_KEYSTORE_BASE64` 即可（CI 优先使用），详见
[../app/keystore/README.md](../app/keystore/README.md)。

## 本地手动签名发布包

```bash
export UNKNOWN_SIGNING_STORE=/path/to/release.keystore
export UNKNOWN_SIGNING_STORE_PASSWORD=meng411722
export UNKNOWN_SIGNING_KEY_ALIAS=meng411722
export UNKNOWN_SIGNING_KEY_PASSWORD=meng411722
./gradlew :app:assembleRelease
```

未提供上述环境变量时，release 构建退化为未签名包，不影响本地调试。

## 应用图标

图标源图以分块 base64 存于 `app/icon-src/`，构建期由 `:app:decodeLauncherIcon`
重组解码为 WebP 自适应图标前景，详见 [../app/icon-src/README.md](../app/icon-src/README.md)。
