import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import struct
import zlib
from pathlib import Path
import threading
import json

# ── 可选拖拽支持 ─────────────────────────────────────────────────────────────
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
    TkinterDnD = None


# ═══════════════════════════════════════════════════════════════════════════════
#  文件类型分类 —— 与浏览器版（HTML工具）完全一致
# ═══════════════════════════════════════════════════════════════════════════════

# 完全复制浏览器版的 TEXT_EXTS（纯文本/代码文件 → 拒绝洗码）
TEXT_EXTS = {
    ".txt", ".csv", ".json", ".xml", ".html", ".htm", ".css", ".js", ".ts", ".jsx", ".tsx",
    ".py", ".java", ".c", ".cpp", ".h", ".cs", ".rb", ".go", ".rs", ".swift", ".kt", ".php",
    ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".md",
    ".markdown", ".log", ".sql", ".vue", ".sass", ".scss", ".less", ".bat", ".ps1",
    ".r", ".m", ".tex", ".rst", ".env", ".gitignore", ".dockerfile", ".makefile",
    ".lock", ".editorconfig", ".babelrc", ".eslintrc", ".prettierrc"
}

# 完全复制浏览器版的 RISKY_EXTS（PDF/Office/压缩包/可执行等 → 允许但警告）
RISKY_EXTS = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
    ".exe", ".dll", ".apk", ".ipa", ".dmg", ".pkg", ".deb", ".rpm", ".msi",
    ".jar", ".war", ".ear", ".epub", ".odt", ".ods", ".odp", ".iso"
}

# 安全类型（媒体文件等 → 无警告直接洗码）
SAFE_TYPES: dict[str, set] = {
    "JPEG 图片": {".jpg", ".jpeg", ".jfif", ".jpe"},
    "GIF / BMP / ICO / WebP 图片": {".gif", ".bmp", ".ico", ".webp", ".avif", ".tiff", ".tif"},
    "视频文件": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".m4v", ".ts", ".mpg", ".mpeg", ".3gp", ".rm", ".rmvb"},
    "音频文件": {".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma", ".m4a", ".opus", ".ape", ".aiff"},
    "磁盘镜像": {".iso", ".img", ".vhd", ".vmdk"},
    "SQLite 数据库": {".db", ".sqlite", ".sqlite3"},
    "其他二进制": {".dat", ".raw", ".dump", ".pak", ".cab"},
}

PNG_EXTS = {".png"}


def classify_file(filepath: str) -> tuple[str, str]:
    """返回 (类型描述, 风险等级: 'safe' | 'png' | 'risky' | 'warning' | 'unknown')
    与浏览器版（HTML工具）的判断逻辑 100% 一致"""
    ext = Path(filepath).suffix.lower()

    # PNG 特殊处理（保留原 Python 工具的优雅注入方式）
    if ext in PNG_EXTS:
        return "PNG 图片", "png"

    # 文本/代码文件 → 拒绝（与浏览器版完全一致）
    if ext in TEXT_EXTS:
        return "纯文本 / 代码文件", "risky"

    # 高风险格式 → 警告但允许（与浏览器版完全一致）
    if ext in RISKY_EXTS:
        return "高风险格式 (PDF/Office/压缩包/可执行文件等)", "warning"

    # 安全媒体文件
    for cat, exts in SAFE_TYPES.items():
        if ext in exts:
            return cat, "safe"

    # 未知类型
    return f"未知类型 ({ext or '无扩展名'})", "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
#  哈希 & 洗码核心逻辑（保持不变，仅分类已对齐）
# ═══════════════════════════════════════════════════════════════════════════════

def compute_hashes(filepath: str) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _inject_png_chunk(data: bytes, payload: bytes) -> bytes:
    iend = b"IEND"
    pos = data.rfind(iend)
    if pos < 4:
        return data + payload
    insert_at = pos - 4
    chunk_type = b"wASH"
    crc = struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    chunk = struct.pack(">I", len(payload)) + chunk_type + payload + crc
    return data[:insert_at] + chunk + data[insert_at:]


def wash_file_data(filepath: str, risk_level: str) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    tag = b"\x00WASH\x00" + os.urandom(16)
    if risk_level == "png":
        return _inject_png_chunk(data, tag)
    else:
        # 其他类型统一在末尾追加（与浏览器版洗码方式一致）
        return data + tag


def hash_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  配置与主题（保持不变）
# ═══════════════════════════════════════════════════════════════════════════════

CONFIG_PATH = Path.home() / ".file_washer_config.json"

def load_config():
    try: return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except: return {"default_save_path": "", "theme": "dark"}

def save_config(cfg):
    try: CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except: pass

THEMES = {
    "dark": {
        "bg": "#0e1117", "surface": "#1a1d27", "surface2": "#22263a", "border": "#2e3352",
        "accent": "#5b8dee", "accent2": "#7c5cbf", "text": "#e8ecf0", "text_muted": "#7a869a",
        "success": "#4caf82", "warning": "#f0a84b", "error": "#e05c6e", "hash_bg": "#111520",
        "drop_bg": "#141824", "input_bg": "#111520", "button_text": "#ffffff",
    },
    "light": {
        "bg": "#f0f2f8", "surface": "#ffffff", "surface2": "#eaecf5", "border": "#d0d5e8",
        "accent": "#3b6fd4", "accent2": "#6e4fc2", "text": "#1a1d2e", "text_muted": "#6b748a",
        "success": "#1e9e60", "warning": "#c97d10", "error": "#c93050", "hash_bg": "#f5f7fd",
        "drop_bg": "#f8f9fe", "input_bg": "#f5f7fd", "button_text": "#ffffff",
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GUI 类（保持不变，仅分类已对齐）
# ═══════════════════════════════════════════════════════════════════════════════

class FileWasherApp:
    def __init__(self):
        self.config = load_config()
        self.theme_name = self.config.get("theme", "dark")
        self.T = THEMES[self.theme_name]

        self.source_path = ""
        self.risk_level = ""
        self.file_type_desc = ""
        self.original_hashes = {}
        self.washed_data = None
        self.washed_hashes = {}

        self.root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        self.root.title("文件洗码工具")
        self.root.geometry("1150x720")
        self.root.minsize(950, 580)

        self._build_ui()
        self._apply_theme()
        self.root.mainloop()

    def _build_ui(self):
        T, root = self.T, self.root
        # 顶栏
        self.header = tk.Frame(root, height=52); self.header.pack(fill="x")
        self.header.pack_propagate(False)
        self.lbl_title = tk.Label(self.header, text="⟨/⟩  文件洗码工具", font=("Menlo", 15, "bold"), anchor="w", padx=18)
        self.lbl_title.pack(side="left", fill="y")
        self.btn_theme = tk.Button(self.header, text="☀ 浅色", width=8, relief="flat", cursor="hand2", command=self._toggle_theme)
        self.btn_theme.pack(side="right", padx=14, pady=10)

        # 滚动容器
        self.canvas = tk.Canvas(root, highlightthickness=0, bd=0)
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.main_frame = tk.Frame(self.canvas)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")
        self.main_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))

        P = 20
        # 拖拽/选择
        self.drop_frame = tk.Frame(self.main_frame, height=120); self.drop_frame.pack(fill="x", padx=P, pady=(P, 10))
        self.drop_inner = tk.Frame(self.drop_frame, relief="flat", bd=0); self.drop_inner.pack(fill="both", expand=True)
        self.lbl_drop = tk.Label(self.drop_inner, text="📂  拖拽文件至此 或 点击选择", font=("Menlo", 12), cursor="hand2", pady=30)
        self.lbl_drop.pack(fill="both", expand=True)
        self.lbl_drop.bind("<Button-1>", lambda e: self._pick_file())
        if HAS_DND:
            for w in (self.drop_inner, self.lbl_drop):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self._on_drop)

        # 文件信息
        self.info_frame = tk.LabelFrame(self.main_frame, text="  文件信息  ", font=("Menlo", 10, "bold"), padx=14, pady=10)
        self.info_frame.pack(fill="x", padx=P, pady=(0, 10))
        def info_row(label):
            row = tk.Frame(self.info_frame); row.pack(fill="x", pady=2)
            tk.Label(row, text=label, font=("Menlo", 9), width=8, anchor="e").pack(side="left")
            val = tk.Label(row, font=("Menlo", 9), anchor="w", wraplength=800); val.pack(side="left", padx=(8, 0))
            return val
        self.val_path = info_row("路径")
        self.val_name = info_row("文件名")
        self.val_size = info_row("大小")
        self.val_type = info_row("类型")
        risk_row = tk.Frame(self.info_frame); risk_row.pack(fill="x", pady=(4, 0))
        tk.Label(risk_row, text="状态", font=("Menlo", 9), width=8, anchor="e").pack(side="left")
        self.lbl_risk = tk.Label(risk_row, text="—", font=("Menlo", 9, "bold"), padx=8, pady=2)
        self.lbl_risk.pack(side="left", padx=(8, 0))

        # 哈希对比区
        self.hashes_row = tk.Frame(self.main_frame); self.hashes_row.pack(fill="x", padx=P, pady=(0, 10))
        self.orig_frame = tk.LabelFrame(self.hashes_row, text="  原始哈希  ", font=("Menlo", 10, "bold"), padx=14, pady=10)
        self.new_frame = tk.LabelFrame(self.hashes_row, text="  洗码后哈希  ", font=("Menlo", 10, "bold"), padx=14, pady=10)
        self.orig_frame.pack(side="left", fill="both", expand=True, padx=0)
        self.new_frame.pack(side="left", fill="both", expand=True, padx=0)
        self.orig_hashes_widgets = self._build_hash_rows(self.orig_frame)
        self.new_hashes_widgets = self._build_hash_rows(self.new_frame)

        # 按钮与保存
        self.btn_wash = tk.Button(self.main_frame, text="🔄  开始洗码", font=("Menlo", 12, "bold"), relief="flat", height=2, command=self._wash)
        self.btn_wash.pack(fill="x", padx=P, pady=(0, 10))

        self.save_frame = tk.LabelFrame(self.main_frame, text="  保存设置  ", font=("Menlo", 10, "bold"), padx=14, pady=10)
        self.save_frame.pack(fill="x", padx=P, pady=(0, 10))
        path_row = tk.Frame(self.save_frame); path_row.pack(fill="x", pady=(0, 8))
        self.entry_default_path = tk.Entry(path_row, font=("Menlo", 9), relief="flat", bd=4)
        self.entry_default_path.pack(side="left", fill="x", expand=True, padx=(8, 6))
        self.entry_default_path.insert(0, self.config.get("default_save_path", ""))
        tk.Button(path_row, text="浏览", command=self._browse_default_path).pack(side="left")
        tk.Button(path_row, text="保存设置", command=self._save_default_path_cfg).pack(side="left", padx=4)

        btn_row = tk.Frame(self.save_frame); btn_row.pack(fill="x")
        self.btn_save_to_default = tk.Button(btn_row, text="💾  保存到默认路径", font=("Menlo", 10, "bold"), command=lambda: self._save(True))
        self.btn_save_to_default.pack(side="left", padx=(0, 8))
        self.btn_save_as = tk.Button(btn_row, text="📂  另存为…", font=("Menlo", 10, "bold"), command=lambda: self._save(False))
        self.btn_save_as.pack(side="left")

        self.status_var = tk.StringVar(value="就绪")
        self.status_bar = tk.Label(root, textvariable=self.status_var, font=("Menlo", 9), anchor="w", padx=14, pady=5)
        self.status_bar.pack(fill="x", side="bottom")

    def _build_hash_rows(self, parent):
        widgets = {}
        for algo in ("MD5", "SHA-1", "SHA-256"):
            row = tk.Frame(parent); row.pack(fill="x", pady=2)
            tk.Label(row, text=algo, font=("Menlo", 9, "bold"), width=8, anchor="e").pack(side="left")
            val = tk.Label(row, text="—", font=("Menlo", 9), anchor="w", cursor="hand2")
            val.pack(side="left", padx=(8, 0), fill="x", expand=True)
            val.bind("<Button-1>", lambda e, w=val: self._copy_text(w.cget("text")))
            widgets[algo.lower().replace("-", "")] = val
        return widgets

    def _apply_theme(self):
        T = self.T
        self.root.configure(bg=T["bg"])
        self.header.config(bg=T["surface"]); self.lbl_title.config(bg=T["surface"], fg=T["accent"])
        self.btn_theme.config(bg=T["surface2"], fg=T["text"], text="☀ 浅色" if self.theme_name == "dark" else "🌙 深色")
        self.canvas.config(bg=T["bg"]); self.main_frame.config(bg=T["bg"])
        self.drop_inner.config(bg=T["drop_bg"], highlightbackground=T["border"], highlightthickness=2)
        self.lbl_drop.config(bg=T["drop_bg"], fg=T["text_muted"])
        self.btn_wash.config(bg=T["accent"], fg=T["button_text"])
        for f in (self.info_frame, self.orig_frame, self.new_frame, self.save_frame):
            f.config(bg=T["surface"], fg=T["text_muted"])
            for child in self._all_children(f):
                if isinstance(child, tk.Label): child.config(bg=T["surface"], fg=T["text"])
                if isinstance(child, tk.Frame): child.config(bg=T["surface"])
                if isinstance(child, tk.Button): child.config(bg=T["surface2"], fg=T["text"])
                if isinstance(child, tk.Entry): child.config(bg=T["input_bg"], fg=T["text"], insertbackground=T["text"])
        for d in (self.orig_hashes_widgets, self.new_hashes_widgets):
            for w in d.values(): w.config(bg=T["hash_bg"], fg=T["success"])
        self.btn_save_to_default.config(bg=T["accent2"], fg=T["button_text"])
        self.status_bar.config(bg=T["surface"], fg=T["text_muted"])
        self._refresh_risk_label()

        for lf in (self.info_frame, self.orig_frame, self.new_frame, self.save_frame):
            lf.config(
                highlightthickness=1,
                highlightbackground=T["border"],
                highlightcolor=T["border"],
                bd=0,
                relief="flat"
            )

    def _all_children(self, widget):
        res = []
        for c in widget.winfo_children(): res.append(c); res.extend(self._all_children(c))
        return res

    def _refresh_risk_label(self):
        T = self.T
        if not self.risk_level:
            self.lbl_risk.config(text="—", bg=T["surface"], fg=T["text_muted"])
            return
        
        if self.risk_level == "risky":
            self.lbl_risk.config(text=f"⚠  {self.file_type_desc} — 文本/代码，拒绝洗码", bg=T["error"], fg="#ffffff")
        elif self.risk_level == "warning":
            self.lbl_risk.config(text=f"⚠  {self.file_type_desc} — 修改哈希可能导致部分校验失效", bg=T["warning"], fg="#ffffff")
        elif self.risk_level == "unknown":
            self.lbl_risk.config(text=f"❓  {self.file_type_desc} — 未知类型，谨慎使用", bg=T["warning"], fg="#ffffff")
        else:
            self.lbl_risk.config(text=f"✓  {self.file_type_desc} — 支持安全洗码", bg=T["success"], fg="#ffffff")

    def _wash(self):
        if not self.source_path: return
        
        # 完全遵循浏览器版逻辑
        if self.risk_level == "risky":
            messagebox.showerror("不支持洗码", f"文本/代码文件「{self.file_type_desc}」修改二进制会产生不可逆的损坏。")
            return
        
        if self.risk_level == "warning":
            ok = messagebox.askyesno("风险确认", 
                f"该文件属于「{self.file_type_desc}」。\n\n"
                "洗码方式是在文件末尾追加随机字节。虽然通常不影响使用，但可能导致某些严格的校验（签名、MD5等）报错。\n\n"
                "是否确认继续？")
            if not ok: return
            
        if self.risk_level == "unknown":
            if not messagebox.askyesno("未知类型", "该文件类型不在已知安全列表中，是否继续？"): return

        self._set_status("⏳  正在洗码…", "info")
        threading.Thread(target=self._do_wash, daemon=True).start()

    def _do_wash(self):
        try:
            data = wash_file_data(self.source_path, self.risk_level)
            hashes = hash_bytes(data)
            self.washed_data, self.washed_hashes = data, hashes
            self.root.after(0, self._display_washed_hashes)
        except Exception as e:
            self.root.after(0, lambda: self._set_status(f"❌ 失败: {e}", "error"))

    def _display_washed_hashes(self):
        for k, v in self.washed_hashes.items(): self.new_hashes_widgets[k].config(text=v)
        self._set_status("✅  洗码完成！", "ok")

    def _load_file(self, path):
        if not os.path.isfile(path): return
        self.source_path = path
        self.file_type_desc, self.risk_level = classify_file(path)
        p = Path(path)
        self.val_path.config(text=str(p.parent)); self.val_name.config(text=p.name)
        self.val_size.config(text=self._fmt_size(p.stat().st_size)); self.val_type.config(text=self.file_type_desc)
        for w in self.new_hashes_widgets.values(): w.config(text="—")
        self._refresh_risk_label()
        threading.Thread(target=self._compute_orig_hashes, daemon=True).start()

    def _compute_orig_hashes(self):
        h = compute_hashes(self.source_path)
        self.original_hashes = h
        self.root.after(0, self._display_orig_hashes)

    def _display_orig_hashes(self):
        for k, v in self.original_hashes.items(): self.orig_hashes_widgets[k].config(text=v)
        self._set_status("✅  载入成功", "ok")

    def _save(self, use_default):
        if not self.washed_data: return
        src = Path(self.source_path)
        name = src.stem + "_washed" + src.suffix
        if use_default:
            d = self.entry_default_path.get().strip()
            if not d: messagebox.showwarning("提示", "请先设置默认路径"); return
            out = os.path.join(d, name)
        else:
            out = filedialog.asksaveasfilename(initialfile=name, defaultextension=src.suffix)
        if out:
            with open(out, "wb") as f: f.write(self.washed_data)
            messagebox.showinfo("成功", f"保存至: {out}")

    def _toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.T = THEMES[self.theme_name]
        self.config["theme"] = self.theme_name
        save_config(self.config); self._apply_theme()

    def _pick_file(self):
        p = filedialog.askopenfilename(); self._load_file(p) if p else None
    def _on_drop(self, event):
        p = event.data.strip(); p = p[1:-1] if p.startswith('{') else p
        self._load_file(p)
    def _copy_text(self, text):
        if text != "—": self.root.clipboard_clear(); self.root.clipboard_append(text); self._set_status("📋 已复制", "ok")
    def _set_status(self, msg, level="info"):
        self.status_var.set(msg)
        colors = {"ok": self.T["success"], "error": self.T["error"], "info": self.T["text_muted"]}
        self.status_bar.config(fg=colors.get(level))
    def _fmt_size(self, n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"
    def _browse_default_path(self):
        d = filedialog.askdirectory(); self.entry_default_path.delete(0, tk.END); self.entry_default_path.insert(0, d) if d else None
    def _save_default_path_cfg(self):
        self.config["default_save_path"] = self.entry_default_path.get(); save_config(self.config); self._set_status("✅ 路径配置已保存", "ok")

if __name__ == "__main__":
    FileWasherApp()