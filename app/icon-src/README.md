# Launcher icon source

`ic_launcher_foreground.part-*` 是应用图标（288px WebP）的分块 base64 文本，
构建期由 `:app:decodeLauncherIcon` 重组解码为
`drawable-nodpi/ic_launcher_foreground.webp`，被
`mipmap-anydpi-v26/ic_launcher.xml` 引用。

重新切分（替换图标后）：

```bash
base64 -w0 ic_launcher_foreground.webp > icon.b64
fold -w 1240 icon.b64 | awk '{print > ("ic_launcher_foreground.part-" sprintf("%02d", NR-1))}'
```
