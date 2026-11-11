#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apkrec_gui.py - apkrec 的图形前端（Tkinter，零第三方依赖）

启动:  python apkrec_gui.py [app.apk]
自检:  python apkrec_gui.py --selftest app.apk     # 不开事件循环, 只验证加载与填充
"""
import os
import re
import sys
import time
import argparse
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apkrec as core
import ctypes
import locale


def _fix_stdout():
    """打包成 exe 后 stdout 编码会变, 统一成控制台代码页"""
    enc = 'utf-8'
    if sys.platform == 'win32':
        try:
            cp = ctypes.windll.kernel32.GetConsoleOutputCP() or ctypes.windll.kernel32.GetACP()
            enc = 'cp%d' % cp
        except Exception:
            enc = locale.getpreferredencoding(False)
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding=enc, errors='backslashreplace')
        except Exception:
            pass


_fix_stdout()


def _dpi_aware():
    """Windows 高分屏: 不开 DPI 感知会被系统位图拉伸, 文字发虚"""
    if sys.platform != 'win32':
        return
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

BG      = '#1e1f22'
PANEL   = '#2b2d30'
PANEL2  = '#313338'
FG      = '#dcddde'
FG_DIM  = '#9aa0a6'
ACCENT  = '#4e9cff'
SEL     = '#2f5f8f'
SEV_FG  = {'CRITICAL': '#ff6b6b', 'HIGH': '#ffa94d', 'MEDIUM': '#ffd43b', 'INFO': '#74c0fc', 'LOW': '#9aa0a6'}
TAG_OF  = {'flag{...}': 'FLAG', 'base64:base64': 'IV:CT', '32+ 位 hex': 'HEX',
           '16 字符 key': 'KEY', 'crypto API': 'API', 'URL': 'URL', 'IPv4': 'IP'}
ROW_LIMIT = 5000


def classify(s):
    """返回 (tag, severity); 不是敏感串返回 ('', '')"""
    for label, pat, sev, pred in core.INTERESTING:
        if pat.search(s) and (pred is None or pred(s)):
            tag = TAG_OF.get(label, label)
            if tag == 'KEY' and core.key_score(s) < 15:
                continue
            return tag, sev
    return '', ''


class App:
    def __init__(self, root, path=None):
        self.root = root
        self.scale = max(1.0, root.winfo_fpixels('1i') / 96.0)
        try:
            root.tk.call('tk', 'scaling', root.winfo_fpixels('1i') / 72.0)
        except tk.TclError:
            pass
        self.dexes = []
        self.dex_map = {}
        self.dex_bytes = {}
        self.res = []
        self.path = None
        self.loading = False
        self.rows = []
        self._build_style()
        self._build_ui()
        if path:
            self.load(path)

    # ---------- 样式 ----------
    def font(self, size, weight='normal'):
        return ('Microsoft YaHei UI', size, weight)

    def mono(self, size):
        return ('Consolas', size)

    def _build_style(self):
        st = ttk.Style(self.root)
        try:
            st.theme_use('clam')
        except tk.TclError:
            pass
        st.configure('.', background=BG, foreground=FG, fieldbackground=PANEL,
                     bordercolor='#3a3d42', lightcolor='#3a3d42', darkcolor='#3a3d42')
        st.configure('TFrame', background=BG)
        st.configure('TLabel', background=BG, foreground=FG)
        st.configure('Dim.TLabel', background=BG, foreground=FG_DIM)
        st.configure('Title.TLabel', background=BG, foreground=ACCENT, font=self.font(12, 'bold'))
        st.configure('TButton', background=PANEL2, foreground=FG, padding=(10, 4), borderwidth=0)
        st.map('TButton', background=[('active', '#3a3d42'), ('pressed', SEL)])
        st.configure('TCheckbutton', background=BG, foreground=FG)
        st.map('TCheckbutton', background=[('active', BG)])
        st.configure('TEntry', fieldbackground=PANEL2, foreground=FG, insertcolor=FG)
        st.configure('Treeview', font=self.font(10), background=PANEL, fieldbackground=PANEL, foreground=FG,
                     rowheight=max(24, int(26*self.scale)), borderwidth=0)
        st.configure('Treeview.Heading', background=PANEL2, foreground=FG_DIM,
                     relief='flat', padding=(8, 5), font=self.font(10, 'bold'))
        st.map('Treeview', background=[('selected', SEL)], foreground=[('selected', '#ffffff')])
        st.configure('TPanedwindow', background=BG)
        st.configure('Sash', background='#3a3d42', sashthickness=6)
        st.configure('Vertical.TScrollbar', background=PANEL2, troughcolor=BG, borderwidth=0, arrowsize=12)
        st.configure('Horizontal.TScrollbar', background=PANEL2, troughcolor=BG, borderwidth=0, arrowsize=12)
        st.configure('TNotebook', background=BG, borderwidth=0)
        st.configure('TNotebook.Tab', background=PANEL2, foreground=FG_DIM, padding=(12, 4))

    # ---------- 布局 ----------
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        top.pack(fill='x')
        ttk.Button(top, text='打开 APK', command=self.on_open).pack(side='left')
        self.path_var = tk.StringVar(value='未加载')
        ttk.Label(top, textvariable=self.path_var, style='Dim.TLabel').pack(side='left', padx=10)
        ttk.Button(top, text='导出报告', command=self.on_export).pack(side='right')

        bar = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        bar.pack(fill='x')
        ttk.Label(bar, text='搜索').pack(side='left')
        self.q = tk.StringVar()
        self.q.trace_add('write', lambda *_: self._debounce())
        e = ttk.Entry(bar, textvariable=self.q, width=42)
        e.pack(side='left', padx=6)
        e.bind('<Return>', lambda _e: self.refresh())
        self.regex = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text='正则', variable=self.regex, command=self.refresh).pack(side='left', padx=(4, 0))
        self.only_sens = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text='仅敏感', variable=self.only_sens, command=self.refresh).pack(side='left', padx=8)
        self.count_var = tk.StringVar(value='')
        ttk.Label(bar, textvariable=self.count_var, style='Dim.TLabel').pack(side='right')

        main = ttk.Panedwindow(self.root, orient='horizontal')
        main.pack(fill='both', expand=True, padx=10, pady=(0, 4))

        # 左: 来源
        left = ttk.Frame(main, width=int(280*self.scale))
        main.add(left, weight=0)
        ttk.Label(left, text='来源', style='Title.TLabel').pack(anchor='w', pady=(2, 6))
        self.src_tree = ttk.Treeview(left, show='tree', selectmode='extended', height=20)
        self.src_tree.pack(fill='both', expand=True)
        self.src_tree.column('#0', width=int(270*self.scale))
        self.src_tree.bind('<<TreeviewSelect>>', lambda _e: self.refresh())
        self.src_tree.insert('', 'end', iid='ALL', text='全部', open=True)

        # 右: 表 + 详情
        right = ttk.Panedwindow(main, orient='vertical')
        main.add(right, weight=1)
        tf = ttk.Frame(right)
        right.add(tf, weight=3)
        cols = ('src', 'idx', 'off', 'len', 'tag', 'text')
        self.table = ttk.Treeview(tf, columns=cols, show='headings', selectmode='browse')
        heads = {'src': ('来源', 120, 'w'), 'idx': ('#', 70, 'e'), 'off': ('偏移', 100, 'e'),
                 'len': ('u16', 56, 'e'), 'tag': ('标签', 66, 'center'), 'text': ('字符串', 900, 'w')}
        for c, (t, w, a) in heads.items():
            self.table.heading(c, text=t)
            self.table.column(c, width=int(w*self.scale), anchor=a, stretch=(c == 'text'))
        vs = ttk.Scrollbar(tf, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=vs.set)
        hsb = ttk.Scrollbar(tf, orient='horizontal', command=self.table.xview)
        self.table.configure(xscrollcommand=hsb.set)
        self.table.pack(side='top', fill='both', expand=True)
        hsb.pack(side='bottom', fill='x')
        vs.pack(side='right', fill='y')
        for sev, fg in SEV_FG.items():
            self.table.tag_configure(sev, foreground=fg)
        self.table.bind('<<TreeviewSelect>>', self.on_select)
        self.table.bind('<Double-1>', lambda _e: self.copy_selected())

        det = ttk.Frame(right)
        right.add(det, weight=2)
        ttk.Label(det, text='详情', style='Title.TLabel').pack(anchor='w', pady=(6, 4))
        self.detail = tk.Text(det, height=4, bg=PANEL, fg=FG, relief='flat', wrap='char',
                              insertbackground=FG, padx=8, pady=6, font=self.mono(10))
        self.detail.pack(fill='x')
        self.hexbox = tk.Text(det, height=10, bg='#17181a', fg='#c9d1d9', relief='flat',
                              insertbackground=FG, padx=8, pady=6, font=self.mono(10))
        hexwrap = ttk.Frame(det)
        hexwrap.pack(fill='both', expand=True, pady=(6, 0))
        hvs = ttk.Scrollbar(hexwrap, orient='vertical', command=self.hexbox.yview)
        self.hexbox.configure(yscrollcommand=hvs.set, height=10)
        self.hexbox.pack(side='left', fill='both', expand=True)
        hvs.pack(side='right', fill='y')
        self.hexbox.tag_configure('hit', background='#3a2a00', foreground='#ffd43b')

        bot = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        bot.pack(fill='x')
        self.status = tk.StringVar(value='就绪')
        ttk.Label(bot, textvariable=self.status, style='Dim.TLabel').pack(side='left')

    # ---------- 加载 ----------
    def on_open(self):
        p = filedialog.askopenfilename(title='选择 APK', filetypes=[('APK', '*.apk'), ('所有文件', '*.*')])
        if p:
            self.load(p)

    def load(self, path, blocking=False):
        self.path = path
        self.path_var.set(path)
        self.status.set(f'加载中… {os.path.basename(path)}')
        self.root.update_idletasks()
        if blocking:
            self._load_worker(path)
        else:
            threading.Thread(target=self._load_worker, args=(path,), daemon=True).start()

    def _load_worker(self, path):
        t0 = time.time()
        try:
            z, dexes = core.open_apk(path)
            res = core.resource_strings(z)
        except Exception as e:                                    # noqa: BLE001
            self.root.after(0, lambda: messagebox.showerror('加载失败', str(e)))
            return
        self.dexes, self.res = dexes, res
        self.dex_map = {d.name: d for d in dexes}
        self.dex_bytes = {d.name: d.data for d in dexes}
        self.elapsed = time.time() - t0
        self.root.after(0, self._populate_sources)

    def _populate_sources(self):
        for iid in self.src_tree.get_children(''):
            if iid != 'ALL':
                self.src_tree.delete(iid)
        total = sum(len(d.classes) for d in self.dexes)
        self.src_tree.item('ALL', text=f'全部   ({total} 类, {len(self.dexes)} dex)')
        for d in self.dexes:
            self.src_tree.insert('', 'end', iid=d.name,
                                 text=f'{d.name}   {len(d.classes)} 类 / 业务 {len(d.app_classes)}')
        self.src_tree.insert('', 'end', iid='资源', text=f'资源串   ({len(self.res)})')
        primary = max(self.dexes, key=lambda d: (len(d.app_classes), d.ratio)) if self.dexes else None
        self.src_tree.selection_set((primary.name,) if primary and primary.app_classes else ('ALL',))
        self.status.set(f'已加载 {os.path.basename(self.path)}  {self.elapsed:.1f}s  '
                        f'{len(self.dexes)} dex / {total} 类 / 资源串 {len(self.res)}')
        self.refresh()

    # ---------- 过滤与填充 ----------
    def _sources(self):
        sel = list(self.src_tree.selection())
        if not sel or 'ALL' in sel:
            return [d.name for d in self.dexes] + ['资源']
        return [s for s in sel if s in self.dex_map or s == '资源']

    def _pattern(self):
        txt = self.q.get().strip()
        if not txt:
            return None
        try:
            return re.compile(txt, re.I)
        except re.error:
            return None

    def _debounce(self):
        if hasattr(self, '_job'):
            self.root.after_cancel(self._job)
        self._job = self.root.after(250, self.refresh)

    def refresh(self):
        if not self.dexes:
            return
        pat = self._pattern()
        sens = self.only_sens.get()
        rows = []
        for name in self._sources():
            if name == '资源':
                for entry, off, s in self.res:
                    rows.append(('res:' + entry, '', off, '', s))
            else:
                d = self.dex_map[name]
                for idx, off, ulen, s in d.strings:
                    if not s:
                        continue
                    rows.append((name, idx, off, ulen, s))
        out = []
        for src, idx, off, ulen, s in rows:
            if pat and not pat.search(s):
                continue
            tag, sev = classify(s)
            if sens and not tag:
                continue
            out.append((src, idx, off, ulen, tag, sev, s))
            if len(out) >= ROW_LIMIT:
                break
        self.rows = out
        self._fill(out, truncated=len(out) >= ROW_LIMIT)
        self.count_var.set(f'{len(out)} 行' + (' (已截断)' if len(out) >= ROW_LIMIT else ''))

    def _fill(self, rows, truncated=False):
        tb = self.table
        tb.delete(*tb.get_children())
        for i, (src, idx, off, ulen, tag, sev, s) in enumerate(rows):
            text = s if len(s) <= 400 else s[:400] + f' …[+{len(s)-400}]'
            tb.insert('', 'end', iid=str(i),
                      values=(src, idx, f'0x{off:07X}', ulen, tag, text),
                      tags=(sev,))
        if rows:
            tb.selection_set('0')
        if truncated:
            self.status.set(f'结果超过 {ROW_LIMIT} 行, 已截断; 请用搜索或勾选来源收窄')

    # ---------- 交互 ----------
    def on_select(self, _e=None):
        sel = self.table.selection()
        if not sel:
            return
        src, idx, off, ulen, tag, sev, s = self.rows[int(sel[0])]
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', s)
        self.detail.configure(state='disabled')
        self._hex(src, off)

    def _hex(self, src, off, before=32, count=320):
        self.hexbox.delete('1.0', 'end')
        name = src[4:] if src.startswith('res:') else src
        data = self.dex_bytes.get(name)
        if data is None:
            self.hexbox.insert('1.0', '(资源条目, 无 dex 数据)')
            return
        start = max(0, off - before)
        end = min(len(data), off + count)
        lines = []
        for p in range(start, end, 16):
            row = data[p:p + 16]
            hexs = ' '.join(f'{b:02X}' for b in row)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            lines.append(f'{p:08X}  {hexs:<47}  |{asc}|' + ('   <==' if p <= off < p + 16 else ''))
        self.hexbox.insert('1.0', '\n'.join(lines))

    def copy_selected(self):
        sel = self.table.selection()
        if not sel:
            return
        s = self.rows[int(sel[0])][6]
        self.root.clipboard_clear()
        self.root.clipboard_append(s)
        self.status.set('已复制到剪贴板')

    def on_export(self):
        if not self.path:
            return
        out = filedialog.asksaveasfilename(defaultextension='.md',
                                           filetypes=[('Markdown', '*.md')],
                                           initialfile='apkrec-report.md')
        if not out:
            return
        ns = argparse.Namespace(apk=self.path, out=out)
        try:
            core.cmd_report(ns)
            self.status.set(f'报告已写入 {out}')
        except Exception as e:                                    # noqa: BLE001
            messagebox.showerror('导出失败', str(e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('apk', nargs='?')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    _dpi_aware()
    root = tk.Tk()
    root.title('apkrec — APK 侦察器')
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f'{int(sw*0.80)}x{int(sh*0.84)}+{int(sw*0.1)}+{int(sh*0.06)}')
    root.configure(bg=BG)
    app = App(root, path=None)
    if args.apk:
        app.load(args.apk, blocking=args.selftest)
    if args.selftest:
        for _ in range(200):
            root.update()
            time.sleep(0.01)
            if app.rows:
                break
        print(f'selftest: dex={len(app.dexes)} rows={len(app.table.get_children())} '
              f'sources={len(app.src_tree.get_children())} '
              f'scale={app.scale:.2f} screen={root.winfo_screenwidth()}x{root.winfo_screenheight()} '
              f'geom={root.geometry()}')
        root.destroy()
        return
    root.mainloop()


if __name__ == '__main__':
    main()
