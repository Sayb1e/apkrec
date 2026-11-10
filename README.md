# apkrec

APK 逆向快速侦察器：一条命令回答「该看哪个 dex、哪条字符串在什么偏移、哪里像密钥/密文」。

只依赖 Python 3 标准库（GUI 用 Tkinter），Windows / macOS / Linux 通用。

![界面](docs/screenshot.png)

## 它解决什么

反编译一个 APK 时，90% 的时间花在「找该看哪儿」：多个 dex 里哪个是业务代码、字符串池里哪几条像密钥、密文长什么样。apkrec 把这些压成一次操作：

```
$ python apkrec.py app.apk

dex               总类数     业务类      占比   判定
classes.dex      9243       4      0%   lib
classes2.dex      319       7      2%
classes3.dex       61      61    100%   ← 业务代码
classes4.dex        4       4    100%   (小模块)
classes5.dex     5214       0      0%   lib

业务包  com.example.reversegame   (61 个类, classes3.dex)

敏感字符串
  [HIGH    ] base64:base64  ×1
      classes3.dex  #736  0x0014615  ii5pccS1mAt2A0kpVV64zA==:C8Vw3Xoy...
  [MEDIUM  ] 16 字符 key   ×1
      classes3.dex  #613  0x0013DF2  a_sd.9/1m2)d]_+=
  [INFO    ] crypto API   ×7
      classes3.dex  #185  0x000EA97  AES
```

## 用法

### CLI

```bash
python apkrec.py app.apk                        # 概览（默认）
python apkrec.py app.apk --json                 # 机器可读
python apkrec.py app.apk strings "flag|key"     # 字符串池过滤
python apkrec.py app.apk strings -d classes3.dex -u -m 200
python apkrec.py app.apk find "a_sd"            # dex + 资源一起搜
python apkrec.py app.apk hex classes3.dex 0x14615 -c 128
python apkrec.py app.apk report -o report.md    # Markdown 报告
```

| 子命令 | 说明 |
|---|---|
| `overview` | dex 分布、业务包、敏感字符串、建议命令（默认） |
| `strings [pattern]` | 字符串池过滤，`-d` 限定 dex，`-u` 去重，`-m` 显示上限 |
| `find <pattern>` | 代码串 + 资源串一起搜 |
| `hex <dex> <offset>` | 按偏移看 hex，并标出命中的行 |
| `report` | 输出 Markdown 报告（UTF-8 BOM，Windows 编辑器不乱码） |

### GUI

```bash
python apkrec_gui.py app.apk
```

- 左侧列出每个 dex 的类数/业务类数，默认自动选中业务 dex
- 中间表格按严重度着色：`FLAG` 红 / `IV:CT` 橙 / `KEY` 黄 / `API` 蓝
- 选中一条即看完整字符串与对应偏移的 hex（命中行高亮）
- 双击复制，可导出 Markdown 报告
- Windows 高 DPI 已适配（per-monitor aware）

## 判定逻辑

| 项 | 做法 |
|---|---|
| 业务 dex | 解析 `class_defs`，按库前缀白名单（`Landroidx/`、`Lkotlin/`、`Lcom/google/` …）算业务类占比，取业务类最多且占比 ≥50% 的 dex |
| `iv:ct` 密文 | `^[A-Za-z0-9+/=]{12,}:[A-Za-z0-9+/=]{20,}$` |
| 16 字节 key | 长度 16 + 含小写 + 含非常规符号，排除 `ALL_CAPS` 常量、文件名、Compose 的 `Name-hash` 形式，再按字符杂度打分 |
| 资源串 | UTF-8 解码后取连续可打印段，跳过图片/字体/so |

## 边界

- 不反编译、不做交叉引用、不自动解密。它只回答「该看哪儿」。
- 业务类判定依赖库前缀白名单；遇到单字母包名混淆的样本，请加 `--json` 看原始分布再人工判断。
- 16 字符 key 是启发式，会漏（key 含空格/非 ASCII）也会误报，只作候选排序，不当结论。
- 资源侧是原始可打印串扫描，不做 `resources.arsc` 结构解析。

## License

MIT
