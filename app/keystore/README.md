# Release keystore

`release.keystore.part-*` 是发布签名密钥库（PKCS12）的分块 base64 文本，
由 release 工作流在构建时重组并解码使用，保证每次
Release 的签名一致、可覆盖安装升级：

```bash
cat app/keystore/release.keystore.part-* | base64 -d > release.keystore
```

- alias：`meng411722`
- store / key password：`meng411722`
- 算法：RSA 2048 · SHA256withRSA · 有效期 30 年

如需更换为私有密钥：把自有 keystore 以 base64 存入仓库 Secret
`SIGNING_KEYSTORE_BASE64`（CI 会优先使用），并相应调整密码配置。
