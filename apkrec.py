#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apkrec.py - APK 逆向快速侦察器（只依赖 Python 3 标准库）

用法:
  python apkrec.py app.apk                       概览: 哪个 dex 是业务代码 + 敏感串 + 建议
  python apkrec.py app.apk --json                同上, 机器可读
  python apkrec.py app.apk strings "flag|key"    字符串池过滤
  python apkrec.py app.apk strings -d classes3.dex -u -m 200
  python apkrec.py app.apk find "a_sd"           代码串 + 资源串一起搜
  python apkrec.py app.apk hex classes3.dex 0x14615 -c 128
  python apkrec.py app.apk report -o report.md

设计取舍: 不做反编译、不做解密、不做 xref。只把"该看哪儿"压缩到一条命令。
"""
import sys, os, re, json, struct, zipfile, argparse
from collections import Counter

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors='backslashreplace')
    except Exception:
        pass

# 公认的库前缀: 用来把"业务类"和"库类"分开
LIB_PREFIXES = (
    'Landroid/', 'Landroidx/', 'Lkotlin/', 'Lkotlinx/', 'Lorg/', 'Lcom/google/',
    'Ljava/', 'Ljavax/', 'Ldalvik/', 'Lokhttp3/', 'Lokio/', 'Lcom/squareup/',
    'Lcom/facebook/', 'Lcom/bumptech/', 'Lcom/airbnb/', 'Lio/', 'Lcom/tencent/',
    'Lcn/', 'Lcom/umeng/', 'Lcom/alibaba/', 'Lcom/blankj/', 'Ltop/', 'Lme/',
    'Lcom/zhihu/', 'Lcom/scwang/', 'Lcom/youth/', 'Lcom/google/android/',
)

KEY_BAD_EXT = ('.kt', '.java', '.class', '.xml', '.png', '.webp', '.json', '.txt',
               '.so', '.dex', '.apk', '.jar', '.js', '.html', '.kt.', '.md')


def looks_like_key(s):
    """16 字节可打印 key 的启发式: 混合大小写 + 符号, 排除常量名/文件名/标识符"""
    if len(s) != 16 or not re.fullmatch(r'[A-Za-z0-9_\.\+/\)\(\]\[\-=]{16}', s):
        return False
    if s.lower().endswith(KEY_BAD_EXT):      # AccountCircle.kt / AlertDialog.java
        return False
    if re.fullmatch(r'[A-Z_0-9]+', s):       # ALL_CAPS 常量
        return False
    if not re.search(r'[a-z]', s):           # 无小写
        return False
    if not re.search(r'[^A-Za-z0-9_.]', s):  # 没有任何非常规符号(下划线/点不算)
        return False
    return True


INTERESTING = [
    ('flag{...}',     re.compile(r'flag\{[^}\s]{4,}\}', re.I),                     'CRITICAL', None),
    ('base64:base64', re.compile(r'^[A-Za-z0-9+/=]{12,}:[A-Za-z0-9+/=]{20,}$'),    'HIGH',     None),
    ('32+ 位 hex',    re.compile(r'^[0-9a-fA-F]{32,}$'),                           'MEDIUM',   None),
    ('16 字符 key',   re.compile(r'^.{16}$'),                                      'MEDIUM',   looks_like_key),
    ('crypto API',    re.compile(r'\b(AES|DES|RSA|Cipher|SecretKeySpec|IvParameterSpec|MessageDigest)\b'), 'INFO', None),
    ('URL',           re.compile(r'https?://[^\s"\'<>]{6,}'),                       'INFO',     None),
    ('IPv4',          re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),                  'LOW',      None),
]

RES_ENTRY = re.compile(r'^(AndroidManifest\.xml|resources\.arsc|res/.+|assets/.+|lib/.+)$')
RES_SKIP_EXT = ('.png', '.webp', '.jpg', '.jpeg', '.gif', '.ttf', '.otf', '.ttc', '.mp3',
                '.ogg', '.wav', '.so', '.zip', '.jar', '.bin', '.dat', '.mp4', '.webm')


def uleb128(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


class Dex:
    """只解析两样东西: 字符串池 + 类描述符"""

    def __init__(self, name, data):
        self.name, self.data = name, data
        self.strings = self._strings()       # [(idx, off, utf16_len, text)]
        self.classes = self._classes()       # [Lcom/foo/Bar;]

    def _str_at(self, data, string_ids_off, sidx):
        so = struct.unpack_from('<I', data, string_ids_off + 4 * sidx)[0]
        _, p = uleb128(data, so)
        return data[p:data.index(b'\x00', p)]

    def _strings(self):
        d = self.data
        n, off = struct.unpack_from('<II', d, 0x38)      # string_ids_size/off
        out = []
        for i in range(n):
            so = struct.unpack_from('<I', d, off + 4 * i)[0]
            ulen, p = uleb128(d, so)
            raw = d[p:d.index(b'\x00', p)]
            try:
                text = raw.decode('utf-8', 'surrogatepass')
            except UnicodeDecodeError:
                text = raw.decode('latin1')
            out.append((i, so, ulen, text))
        return out

    def _classes(self):
        d = self.data
        ns, soff = struct.unpack_from('<II', d, 0x38)
        nt, toff = struct.unpack_from('<II', d, 0x40)    # type_ids
        nc, coff = struct.unpack_from('<II', d, 0x60)    # class_defs
        out = []
        for i in range(nc):
            cidx = struct.unpack_from('<I', d, coff + 32 * i)[0]
            sidx = struct.unpack_from('<I', d, toff + 4 * cidx)[0]
            out.append(self._str_at(d, soff, sidx).decode('utf-8', 'replace'))
        return out

    @property
    def app_classes(self):
        return [c for c in self.classes if not c.startswith(LIB_PREFIXES)]

    @property
    def ratio(self):
        return (len(self.app_classes) / len(self.classes)) if self.classes else 0.0


def open_apk(path):
    z = zipfile.ZipFile(path)
    names = [n for n in z.namelist() if re.match(r'classes\d*\.dex$', n)]
    names.sort(key=lambda n: (len(n), n))                # classes.dex, classes2.dex ...
    dexes = [Dex(n, z.read(n)) for n in names]
    return z, dexes


def resource_strings(z, minlen=4):
    """资源侧: AndroidManifest / res / assets 里的可打印串(UTF-8 解码后取连续段)"""
    out = []
    for name in sorted(z.namelist()):
        if name.endswith('/') or not RES_ENTRY.match(name):
            continue
        if name.lower().endswith(RES_SKIP_EXT):
            continue
        blob = z.read(name)
        if len(blob) > 4 * 1024 * 1024:      # 超大条目跳过, 免得拖慢
            continue
        text = blob.decode('utf-8', 'ignore')
        seen = set()
        for m in re.finditer(r'[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]{6,}', text):
            s = m.group().rstrip()
            if len(s) < minlen or s in seen:
                continue
            seen.add(s)
            out.append((name, m.start(), s))
    return out


def human_size(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f"{n:.0f}{u}" if u == 'B' else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def key_score(s):
    """key 候选评分: 字符越杂、带数字和符号越像密钥; 出现英文长单词则降权"""
    score = len(set(s))
    if re.search(r'\d', s):
        score += 2
    if re.search(r'[+/=)\]\[-]', s):
        score += 2
    if re.search(r'[a-z]{4,}', s):
        score -= 3
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*-\S+$', s):
        score -= 6      # Compose 生成的 Name-hash 形式
    return score


def group_hits(hits, kind):
    g = [h for h in hits if h['kind'] == kind]
    if kind.startswith('16 '):
        g = [h for h in g if key_score(h['text']) >= 15]
        g.sort(key=lambda h: -key_score(h['text']))
    return g


def scan_interesting(dexes):
    hits = []
    for dx in dexes:
        for idx, off, ulen, s in dx.strings:
            for label, pat, sev, pred in INTERESTING:
                if pat.search(s) and (pred is None or pred(s)):
                    hits.append(dict(dex=dx.name, idx=idx, off=off, sev=sev, kind=label, text=s))
                    break
    return hits


def cmd_overview(args):
    z, dexes = open_apk(args.apk)
    size = os.path.getsize(args.apk)
    total_classes = sum(len(d.classes) for d in dexes)
    primary = max(dexes, key=lambda d: (len(d.app_classes), d.ratio)) if dexes else None
    pkg = ''
    if primary and primary.app_classes:
        pkg = Counter('.'.join(c.lstrip('L').rstrip(';').split('/')[:3])
                      for c in primary.app_classes).most_common(1)[0][0]
    hits = scan_interesting(dexes)
    try:
        res = resource_strings(z)
    except Exception:
        res = []

    if args.json:
        print(json.dumps(dict(
            apk=os.path.abspath(args.apk), size=size, package=pkg,
            dexes=[dict(name=d.name, classes=len(d.classes), app_classes=len(d.app_classes),
                        ratio=round(d.ratio, 3)) for d in dexes],
            total_classes=total_classes,
            hits=[dict(dex=h['dex'], idx=h['idx'], off=h['off'], sev=h['sev'], kind=h['kind'], text=h['text']) for h in hits],
            resource_strings=len(res)), ensure_ascii=False, indent=2))
        return

    print(f"APK   {os.path.abspath(args.apk)}   {human_size(size)}   {len(dexes)} dex   {total_classes} 类\n")
    print(f"{'dex':<13}{'总类数':>8}{'业务类':>8}{'占比':>8}   判定")
    for d in dexes:
        mark = ''
        if d is primary:
            mark = '← 业务代码'
        elif len(d.classes) and d.ratio >= 0.5:
            mark = '(小模块)'
        elif len(d.classes) > 500:
            mark = 'lib'
        print(f"{d.name:<13}{len(d.classes):>8}{len(d.app_classes):>8}{d.ratio*100:>7.0f}%   {mark}")
    if pkg:
        print(f"\n业务包  {pkg}   ({len(primary.app_classes)} 个类, {primary.name})")

    print("\n敏感字符串")
    any_hit = False
    for label, pat, sev, _pred in INTERESTING:
        group = group_hits(hits, label)
        if not group:
            continue
        any_hit = True
        print(f"  [{sev:<8}] {label:<14} ×{len(group)}")
        for h in group[:5]:
            text = h['text'] if len(h['text']) <= 160 else h['text'][:160] + f" …[+{len(h['text'])-160}]"
            print(f"      {h['dex']:<13} #{h['idx']:<6} 0x{h['off']:07X}  {text}")
        if len(group) > 5:
            print(f"      … 还有 {len(group)-5} 条")
    if not any_hit:
        print("  (无)")

    print(f"\n资源串  {len(res)} 条 (AndroidManifest / resources.arsc / res / assets)")
    print("\n建议")
    if primary:
        print(f"  1) python {os.path.basename(sys.argv[0])} {args.apk} strings -d {primary.name} -u")
        for h in hits:
            if h['sev'] in ('CRITICAL', 'HIGH'):
                print(f"  ·  {h['dex']} 0x{h['off']:07X}  {h['kind']} -> "
                      f"hex {h['dex']} 0x{h['off']:07X} -c 128")
                break
    print(f"  2) python {os.path.basename(sys.argv[0])} {args.apk} find \"flag|key|iv\"")
    print(f"  3) python {os.path.basename(sys.argv[0])} {args.apk} report -o report.md")


def pick_dexes(dexes, sel):
    if not sel:
        return dexes
    return [d for d in dexes if d.name == sel or d.name.startswith(sel)]


def cmd_strings(args):
    z, dexes = open_apk(args.apk)
    pat = re.compile(args.pattern, re.I) if args.pattern else None
    shown = 0
    args._seen = set()
    for d in pick_dexes(dexes, args.dex):
        for idx, off, ulen, s in d.strings:
            if not s or (not args.all and not s.isprintable()):
                continue
            if pat and not pat.search(s):
                continue
            if args.uniq and s in args._seen:
                continue
            if args.uniq:
                args._seen.add(s)
            text = s if len(s) <= args.maxlen else s[:args.maxlen] + f" …[+{len(s)-args.maxlen}]"
            print(f"{d.name:<13} #{idx:<6} 0x{off:07X} u16={ulen:<4} {text}")
            shown += 1
            if args.limit and shown >= args.limit:
                print(f"# 已显示 {shown} 条(达到 --limit)", file=sys.stderr)
                return
    print(f"# 共 {shown} 条", file=sys.stderr)


def cmd_find(args):
    z, dexes = open_apk(args.apk)
    pat = re.compile(args.pattern, re.I)
    n = 0
    seen = set()
    for d in dexes:
        for idx, off, ulen, s in d.strings:
            if not s.isprintable() or not pat.search(s) or s in seen:
                continue
            seen.add(s)
            text = s if len(s) <= args.maxlen else s[:args.maxlen] + f" …[+{len(s)-args.maxlen}]"
            print(f"[dex] {d.name:<13} #{idx:<6} 0x{off:07X}  {text}")
            n += 1
    if args.resources:
        for name, off, s in resource_strings(z):
            if not pat.search(s) or s in seen:
                continue
            seen.add(s)
            text = s if len(s) <= args.maxlen else s[:args.maxlen] + f" …[+{len(s)-args.maxlen}]"
            print(f"[res] {name:<30} 0x{off:07X}  {text}")
            n += 1
    print(f"# {n} 条命中", file=sys.stderr)


def cmd_hex(args):
    z, dexes = open_apk(args.apk)
    ds = pick_dexes(dexes, args.dex)
    if not ds:
        sys.exit(f"没有这个 dex: {args.dex}")
    d = ds[0]
    off = int(args.offset, 0)
    start = max(0, off - args.before)
    end = min(len(d.data), off + args.count)
    print(f"# {d.name}  {len(d.data)} bytes, 区间 0x{start:X}-0x{end:X}, 目标 0x{off:X}\n")
    for p in range(start, end, 16):
        row = d.data[p:p + 16]
        hexs = ' '.join(f"{b:02X}" for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        mark = ' <==' if p <= off < p + 16 else ''
        print(f"{p:08X}  {hexs:<47}  |{asc}|{mark}")


def cmd_report(args):
    z, dexes = open_apk(args.apk)
    lines = []
    total = sum(len(d.classes) for d in dexes)
    primary = max(dexes, key=lambda d: (len(d.app_classes), d.ratio)) if dexes else None
    pkg = ''
    if primary and primary.app_classes:
        pkg = Counter('.'.join(c.lstrip('L').rstrip(';').split('/')[:3])
                      for c in primary.app_classes).most_common(1)[0][0]
    hits = scan_interesting(dexes)
    res = resource_strings(z)
    lines.append(f"# APK 侦察报告: {os.path.basename(args.apk)}\n")
    lines.append(f"- 文件: `{os.path.abspath(args.apk)}`")
    lines.append(f"- 大小: {human_size(os.path.getsize(args.apk))}")
    lines.append(f"- dex: {len(dexes)} 个, {total} 个类")
    lines.append(f"- 业务包: `{pkg}` (主要在 `{primary.name if primary else '?'}`)\n")
    lines.append("## dex 分布\n")
    lines.append("| dex | 类数 | 业务类 | 占比 |")
    lines.append("|---|---:|---:|---:|")
    for d in dexes:
        lines.append(f"| `{d.name}` | {len(d.classes)} | {len(d.app_classes)} | {d.ratio*100:.0f}% |")
    lines.append("\n## 敏感字符串\n")
    grouped = Counter(h['kind'] for h in hits)
    if not grouped:
        lines.append("_无_")
    for kind, cnt in grouped.items():
        sev = next(s for k, _, s, _p in INTERESTING if k == kind)
        lines.append(f"### {kind} ({sev}, {cnt} 条)\n")
        lines.append("| dex | # | 偏移 | 内容 |")
        lines.append("|---|---:|---|---|")
        for h in group_hits(hits, kind)[:20]:
            s = h['text'].replace('|', '\\|')
            s = s if len(s) <= 200 else s[:200] + '…'
            lines.append(f"| `{h['dex']}` | {h['idx']} | `0x{h['off']:07X}` | `{s}` |")
        lines.append("")
    lines.append("## 资源串\n")
    lines.append(f"共 {len(res)} 条, 例:\n")
    for name, off, s in res[:10]:
        lines.append(f"- `{name}` @ `0x{off:07X}`: {s[:120]}")
    out = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, 'w', encoding='utf-8-sig') as f:
            f.write(out)
        print(f"# 已写入 {args.out} ({len(out)} bytes)", file=sys.stderr)
    else:
        print(out)


def main():
    ap = argparse.ArgumentParser(description='APK 逆向快速侦察器')
    ap.add_argument('apk')
    ap.add_argument('--json', action='store_true', help='概览输出为 JSON')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('overview', help='概览(默认)')
    p.set_defaults(func=cmd_overview)

    p = sub.add_parser('strings', help='dex 字符串池过滤')
    p.add_argument('pattern', nargs='?')
    p.add_argument('-d', '--dex')
    p.add_argument('-u', '--uniq', action='store_true')
    p.add_argument('-m', '--maxlen', type=int, default=300)
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--all', action='store_true', help='包含不可打印串')
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser('find', help='代码串 + 资源串一起搜')
    p.add_argument('pattern')
    p.add_argument('--resources', action='store_true', default=True)
    p.add_argument('--no-resources', dest='resources', action='store_false')
    p.add_argument('-m', '--maxlen', type=int, default=300)
    p.set_defaults(func=cmd_find)

    p = sub.add_parser('hex', help='按 dex+偏移看 hex')
    p.add_argument('dex')
    p.add_argument('offset')
    p.add_argument('-c', '--count', type=int, default=128)
    p.add_argument('-b', '--before', type=int, default=32)
    p.set_defaults(func=cmd_hex)

    p = sub.add_parser('report', help='输出 Markdown 报告')
    p.add_argument('-o', '--out')
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    if not getattr(args, 'func', None):
        args.func = cmd_overview
    args.func(args)


if __name__ == '__main__':
    main()
