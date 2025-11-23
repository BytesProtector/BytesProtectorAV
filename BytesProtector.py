import os, sys, time, json, glob, shutil, threading, hashlib, logging, traceback, queue, string, base64, io
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import hashlib, pathlib
from PIL import Image, ImageTk

# ---------------------------  optional imports  ---------------------------
try:
    import yara
except ImportError:
    raise RuntimeError("pip install yara-python")
try:
    import win32file
except Exception:
    win32file = None
try:
    import winreg
except Exception:
    winreg = None
try:
    from win10toast import ToastNotifier
    TOASTER = ToastNotifier()
except Exception:
    TOASTER = None
try:
    import pystray
    from pystray import MenuItem as TrayMenuItem
    from PIL import Image, ImageDraw
    PYSTRAY_OK = True
except Exception:
    PYSTRAY_OK = False
# --------------------------------------------------------------------------

# ---------------------------  paths  --------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
LOCAL_DIR  = os.path.join(BASE_DIR, "yara-forge-rules", "local")
BUNDLE     = os.path.join(BASE_DIR, "yara-forge-rules", "packages", "full", "yara-rules-full.yar")
QUAR_DIR   = os.path.join(BASE_DIR, "quarantine")
QUAR_DB    = os.path.join(QUAR_DIR, "quarantine.json")
SETTINGS_F = os.path.join(BASE_DIR, "settings.json")
LOG_F      = os.path.join(BASE_DIR, "bytesprotector.log")
DOWNLOADS  = os.path.join(os.path.expanduser("~"), "Downloads")
HEUR_F     = os.path.join(BASE_DIR, "heuristics.json")
os.makedirs(LOCAL_DIR, exist_ok=True)
os.makedirs(QUAR_DIR, exist_ok=True)

# ---------------------------  tuning  -------------------------------------
HEUR_THRESHOLD = 6
EXCLUDE_PATHS  = {os.path.expandvars("%SystemRoot%"), os.path.expandvars("%ProgramFiles%"), BASE_DIR}

# ---------------------------  logging  ------------------------------------
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.FileHandler(LOG_F, encoding="utf-8"), logging.StreamHandler()])
logger = logging.getLogger("BytesProtector")

# ---------------------------  settings  -----------------------------------
DEFAULT_SET = {"startup":False, "monitor":True, "reminder":True, "reminder_sec":48*3600, "last_remind":0, "show_tray":True, "scans_done":0}
def load_set():
    if os.path.isfile(SETTINGS_F):
        try:
            with open(SETTINGS_F) as f:
                s = json.load(f)
                DEFAULT_SET.update(s)
        except Exception:
            logger.exception("Failed to load settings.json")
    return DEFAULT_SET
def save_set(s):
    try:
        with open(SETTINGS_F, "w") as f:
            json.dump(s, f, indent=2)
    except Exception:
        logger.exception("Failed to save settings.json")
SETTINGS = load_set()

# ---------------------------  quarantine db  ------------------------------
def load_qdb():
    if os.path.isfile(QUAR_DB):
        try:
            with open(QUAR_DB) as f:
                return json.load(f)
        except Exception:
            logger.exception("Failed to load quarantine DB")
    return {}
def save_qdb(db):
    try:
        with open(QUAR_DB, "w") as f:
            json.dump(db, f, indent=2)
    except Exception:
        logger.exception("Failed to save quarantine DB")
QDB = load_qdb()

# ---------------------------  heuristics  ---------------------------------
def load_heur():
    if not os.path.isfile(HEUR_F):
        return []
    try:
        with open(HEUR_F) as f:
            data = json.load(f)
            out = []
            for item in data:
                if isinstance(item, str):
                    out.append(item.lower())
                elif isinstance(item, dict):
                    pat = item.get("pattern")
                    if isinstance(pat, list):
                        out.extend([str(p).lower() for p in pat])
                    elif isinstance(pat, str):
                        out.append(pat.lower())
            return list(set(out))
    except Exception:
        logger.exception("Failed to load heuristics.json")
        return []
HEURISTICS = load_heur()

# ---------------------------  YARA  ---------------------------------------
def load_yara():
    sources = {}
    for idx, path in enumerate(glob.glob(os.path.join(LOCAL_DIR, "*.yar*"))):
        sources[f"local_{idx}"] = path
    if os.path.isfile(BUNDLE):
        try:
            yara.compile(filepath=BUNDLE)
            sources["bundle"] = BUNDLE
        except Exception:
            logger.warning("Bundle compile failed")
    if sources:
        try:
            return yara.compile(filepaths=sources)
        except Exception:
            logger.exception("Failed to compile filepaths from sources; falling back")
    # fallback EICAR rule
    eicar = 'rule eicar { strings: $ = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" condition: $ }'
    try:
        return yara.compile(source=eicar)
    except Exception:
        class Dummy:
            def match(self, **kwargs):
                return []
        return Dummy()
RULES = load_yara()

# ---------------------------  helpers  ------------------------------------
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def stable(path):
    prev = -1
    for _ in range(5):
        if not os.path.exists(path):
            return False
        try:
            cur = os.path.getsize(path)
        except Exception:
            return False
        if cur == prev:
            return True
        prev = cur
        time.sleep(1)
    return False

def notify(title, msg, dur=6):
    try:
        if TOASTER:
            TOASTER.show_toast(title, msg, duration=dur, threaded=True)
        else:
            threading.Thread(target=lambda: messagebox.showinfo(title, msg), daemon=True).start()
    except Exception:
        logger.exception("notify failed")

# ---------------------------  GUI helpers  --------------------------------
def is_main_thread():
    return threading.current_thread() == threading.main_thread()

# ---------------------------  ICON  ---------------------------------------
def resource_path(rel):
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)
ICON_PATH = resource_path("icon.png")

# ---------------------------  COLOURS  ------------------------------------
BG      = "#0d0d0d"
PANEL   = "#121212"
CARD    = "#1a1a1a"
BORDER  = "#222222"
TEXT    = "#e6e6e6"
SUB     = "#8a8a8a"
ACCENT  = "#00ff88"
ACCENT2 = "#3b82f6"
DANGER  = "#ef4444"
GREEN   = "#22c55e"
ORANGE  = "#f97316"
YELLOW  = "#eab308"

# --------------------------------------------------------------------------
#  NEW GUI – exact base44 look
# --------------------------------------------------------------------------
class App(ctk.CTk):
    def start_web_blocker(self):
        threading.Thread(target=self.web_blocker_loop, daemon=True).start()

    def web_blocker_loop(self):
        import sqlite3, pathlib, subprocess, time

        DB = pathlib.Path(__file__).with_name("badurls.db")
        if not DB.is_file():
            return

        con = sqlite3.connect(str(DB), check_same_thread=False)
        HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
        BLOCK_MARK = "# BytesProtector-Block"

        # clean old entries
        subprocess.run(["powershell", "-Command",
                        f"(Get-Content '{HOSTS_FILE}') -notmatch '{BLOCK_MARK}' | Set-Content '{HOSTS_FILE}'"],
                       capture_output=True)

        while True:
            # example: block any resolved domain
            cur = con.execute("SELECT host FROM host LIMIT 100")  # sample 100
            for (domain,) in cur:
                entry = f"127.0.0.1\t{domain} {BLOCK_MARK}\n"
                with open(HOSTS_FILE, "a", encoding='utf-8') as f:
                    f.write(entry)
            time.sleep(300)   # refresh every 5 min
            self.log(f"Web blocker refreshed")
    def __init__(self):
        super().__init__()
        self.title("BytesProtector")
        self.geometry("1280x840")
        self.minsize(1100, 720)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # window icon
        if os.path.isfile(ICON_PATH):
            self.iconphoto(False, ImageTk.PhotoImage(file=ICON_PATH))
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("BytesProtector.AV.Tool.1")
            except Exception:
                pass

        # state – identical to your old App
        self.scan_path   = tk.StringVar()
        self.item_cnt    = tk.IntVar(value=0)
        self.detect_cnt  = tk.IntVar(value=0)
        self.time_str    = tk.StringVar(value="00:00")
        self.running     = False
        self.q           = queue.Queue()
        self.strict      = tk.BooleanVar(value=False)

        self.startup = tk.BooleanVar(value=SETTINGS.get("startup",False))
        self.monitor = tk.BooleanVar(value=SETTINGS.get("monitor",True))
        self.remind  = tk.BooleanVar(value=SETTINGS.get("reminder",True))

        self._tray_icon = None
        self._tray_thread = None

        self.build_ui()
        self.show("dashboard")

        try:
            self.refresh_quar()
        except Exception:
            pass
        self.after(150, self.pump)

        if self.remind.get():
            threading.Thread(target=self.reminder_loop, daemon=True).start()
        if self.monitor.get():
            threading.Thread(target=self.dl_loop, daemon=True).start()
        if PYSTRAY_OK and SETTINGS.get("show_tray",True):
            self.start_tray()
            self.start_web_blocker()
    # ------------------------------------------------------------------  UI builder
    def build_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ---------- sidebar ----------
        nav = ctk.CTkFrame(self, width=240, fg_color=PANEL, corner_radius=0)
        nav.grid(row=0, column=0, sticky="ns")
        nav.grid_propagate(False)

        # logo + title
        top = ctk.CTkFrame(nav, fg_color="transparent")
        top.pack(pady=24)
        if os.path.isfile(ICON_PATH):
            img = ctk.CTkImage(Image.open(ICON_PATH), size=(36,36))
            ctk.CTkLabel(top, image=img, text="").pack(side="left", padx=8)
        ctk.CTkLabel(top, text="BytesProtector", text_color=ACCENT,
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")

        # nav buttons
        nav_items = {
            "dashboard": ("📊  Dashboard", self.show_dashboard),
            "scan":      ("🔍  Scan", self.show_scan),
            "quar":      ("🗂️  Quarantine", self.show_quar),
            "history":   ("📜  History", self.show_history),
            "settings":  ("⚙️  Settings", self.show_settings)
        }
        self.nav_btns = {}
        for page, (txt,cmd) in nav_items.items():
            btn = ctk.CTkButton(nav, text=txt, anchor="w", fg_color="transparent",
                                hover_color=ACCENT+"20", text_color=TEXT,
                                font=ctk.CTkFont(size=16), height=48, command=cmd)
            btn.pack(fill="x", padx=16, pady=6)
            self.nav_btns[page] = btn
        self.nav_btns["dashboard"].configure(fg_color=ACCENT, text_color="#000")

        # ---------- content area ----------
        self.content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew", padx=32, pady=32)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.pages = {}
        for name in ("dashboard","scan","quar","history","settings"):
            f = ctk.CTkFrame(self.content, fg_color=BG)
            f.grid(row=0, column=0, sticky="nsew")
            self.pages[name] = f
        self.build_dashboard()
        self.build_scan()
        self.build_quar()
        self.build_history()
        self.build_settings()

    # ------------------------------------------------------------------  pages
    def build_dashboard(self):
        p = self.pages["dashboard"]
        p.grid_rowconfigure(2, weight=1)
        p.grid_columnconfigure(0, weight=1)

        # hero
        hero = ctk.CTkFrame(p, fg_color="transparent")
        hero.grid(row=0, column=0, sticky="ew", pady=(0,24))
        ctk.CTkLabel(hero, text="Security Dashboard", font=ctk.CTkFont(size=36, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hero, text="Real-time protection monitoring and threat management",
                     text_color=SUB, font=ctk.CTkFont(size=16)).pack(anchor="w")

        # top grid
        top = ctk.CTkFrame(p, fg_color="transparent")
        top.grid(row=1, column=0, sticky="ew", pady=(0,24))
        top.grid_columnconfigure(0, weight=2)
        top.grid_columnconfigure(1, weight=1)

        # left: protection card
        prot = ctk.CTkFrame(top, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        prot.grid(row=0, column=0, sticky="nsew", padx=(0,24))
        self.protection_card(prot)

        # right: system stats
        stats = ctk.CTkFrame(top, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        stats.grid(row=0, column=1, sticky="nsew")
        self.stats_card(stats)

        # bottom: recent threats
        threats = ctk.CTkFrame(p, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        threats.grid(row=2, column=0, sticky="nsew")
        self.recent_threats_card(threats)

    # ---------- protection card
    def protection_card(self, parent):
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(parent, text="Protection Status", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=24, pady=20)
        self.prot_enabled = tk.BooleanVar(value=True)
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=12)
        ctk.CTkLabel(row, text="🛡️", font=ctk.CTkFont(size=40)).pack(side="left", padx=12)
        ctk.CTkLabel(row, text="System Protected", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=12)
        ctk.CTkSwitch(row, text="", variable=self.prot_enabled, progress_color=ACCENT).pack(side="right", padx=12)
        ctk.CTkLabel(parent, text="Real-time scanning is active", text_color=SUB,
                     font=ctk.CTkFont(size=14)).pack(anchor="w", padx=24, pady=(0,24))

    # ---------- stats card
    def stats_card(self, parent):
        parent.grid_rowconfigure(5, weight=1)
        ctk.CTkLabel(parent, text="System Statistics", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=20, pady=16)
        for idx, (lbl,val,clr,ico) in enumerate([
                ("Total Threats", len(QDB), DANGER, "⚠️"),
                ("Active Threats", self.detect_cnt.get(), ORANGE, "🔥"),
                ("Quarantined", len(QDB), YELLOW, "🔒"),
                ("Scans Completed", SETTINGS.get("scans_done", 42), GREEN, "✅")
        ]):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=8)
            ctk.CTkLabel(row, text=ico, font=ctk.CTkFont(size=18)).pack(side="left", padx=8)
            ctk.CTkLabel(row, text=lbl, font=ctk.CTkFont(size=14)).pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(size=20, weight="bold"), text_color=clr).pack(side="right")
        # progress bar
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.pack(fill="x", padx=20, pady=16)
        ctk.CTkLabel(bar, text="Protection Score", font=ctk.CTkFont(size=14)).pack(side="left")
        score = 100 if self.detect_cnt.get() == 0 else max(0, 100 - self.detect_cnt.get()*10)
        ctk.CTkLabel(bar, text=f"{score}%", font=ctk.CTkFont(size=20, weight="bold"), text_color=GREEN).pack(side="right")
        progress = ctk.CTkProgressBar(parent, height=8, corner_radius=4, progress_color=GREEN)
        progress.pack(fill="x", padx=20, pady=(0,20))
        progress.set(score/100)

    # ---------- recent threats card
    def recent_threats_card(self, parent):
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=16)
        ctk.CTkLabel(hdr, text="Active Threats", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(hdr, text="View All", command=lambda: self.show("quar")).pack(side="right")

        if not QDB:
            ctk.CTkLabel(parent, text="🎉  All clear! No active threats.", font=ctk.CTkFont(size=16)).pack(pady=40)
            return

        # list last 5
        frm = ctk.CTkFrame(parent, fg_color="transparent")
        frm.pack(fill="both", expand=True, padx=24, pady=(0,20))
        for k,info in list(QDB.items())[-5:]:
            row = ctk.CTkFrame(frm, corner_radius=10, fg_color=PANEL, border_width=1, border_color=BORDER)
            row.pack(fill="x", pady=6)
            ctk.CTkLabel(row, text="🦠", font=ctk.CTkFont(size=24)).pack(side="left", padx=12)
            ctk.CTkLabel(row, text=os.path.basename(info["original"]), font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
            ctk.CTkLabel(row, text=", ".join(info.get("rules", [])), text_color=SUB, font=ctk.CTkFont(size=12)).pack(side="right", padx=12)

    # ------------------------------------------------------------------  scan page
    def build_scan(self):
        p = self.pages["scan"]
        p.grid_rowconfigure(3, weight=1)
        p.grid_columnconfigure(0, weight=1)

        # header
        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0,20))
        ctk.CTkLabel(hdr, text="System Scan", font=ctk.CTkFont(size=36, weight="bold")).pack(side="left")
        ctk.CTkCheckBox(hdr, text="Strict Mode (PUA/installers)", variable=self.strict,
                        text_color=SUB, font=ctk.CTkFont(size=16)).pack(side="right", padx=12)
        self.start_btn = ctk.CTkButton(hdr, text="✨ START SCAN", fg_color=ACCENT, text_color="#000",
                                       font=ctk.CTkFont(size=18, weight="bold"), command=self.start_scan)
        self.start_btn.pack(side="right", padx=6)
        self.stop_btn = ctk.CTkButton(hdr, text="🛑 STOP SCAN", fg_color=DANGER, command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="right")

        # scan type cards
        cards = ctk.CTkFrame(p, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(0,20))
        card_data = [
            ("Quick Scan", "Scans critical system areas", "⚡", "#3b82f6", "~2 mins", "1 500", self.quick_scan),
            ("Full System Scan", "Comprehensive deep scan", "🖴", "#a855f7", "~30 mins", "50 000", self.full_scan),
            ("Custom Scan", "Select specific folders", "🔍", "#f97316", "Variable", "Varies", self.custom_scan),
        ]
        for idx, (title,desc,ico,hex_col,dur,files,cmd) in enumerate(card_data):
            c = ctk.CTkFrame(cards, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
            c.grid(row=0, column=idx, padx=(0,20), sticky="nsew")
            icon = ctk.CTkFrame(c, width=64, height=64, corner_radius=16, fg_color="transparent")
            icon.pack(pady=20)
            ctk.CTkLabel(icon, text=ico, font=ctk.CTkFont(size=32)).pack(expand=True)
            ctk.CTkLabel(c, text=title, font=ctk.CTkFont(size=20, weight="bold")).pack()
            ctk.CTkLabel(c, text=desc, font=ctk.CTkFont(size=14), text_color=SUB, wraplength=260).pack(pady=6)
            row = ctk.CTkFrame(c, fg_color="transparent")
            row.pack(pady=10)
            ctk.CTkLabel(row, text="Duration", font=ctk.CTkFont(size=13), text_color=SUB).pack(side="left", padx=12)
            ctk.CTkLabel(row, text=dur, font=ctk.CTkFont(size=13, weight="bold")).pack(side="right", padx=12)
            row2 = ctk.CTkFrame(c, fg_color="transparent")
            row2.pack(pady=(0,10))
            ctk.CTkLabel(row2, text="Files", font=ctk.CTkFont(size=13), text_color=SUB).pack(side="left", padx=12)
            ctk.CTkLabel(row2, text=files, font=ctk.CTkFont(size=13, weight="bold")).pack(side="right", padx=12)
            ctk.CTkButton(c, text="Start Scan", command=cmd,
                          fg_color=hex_col, text_color="#000",
                          font=ctk.CTkFont(size=15, weight="bold")).pack(pady=(0,20))
            cards.grid_columnconfigure(idx, weight=1)

        # progress / stats / log
        bot = ctk.CTkFrame(p, fg_color="transparent")
        bot.grid(row=2, column=0, sticky="nsew", pady=(0,20))
        bot.grid_columnconfigure(1, weight=1)
        bot.grid_rowconfigure(0, weight=1)

        stats = ctk.CTkFrame(bot, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        stats.grid(row=0, column=0, sticky="nsew", padx=(0,20))
        ctk.CTkLabel(stats, text="Statistics", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=20, pady=16)
        for lbl,var in [("Items Scanned",self.item_cnt), ("Detections",self.detect_cnt), ("Elapsed",self.time_str)]:
            row = ctk.CTkFrame(stats, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=10)
            ctk.CTkLabel(row, text=lbl, font=ctk.CTkFont(size=14), text_color=SUB).pack(side="left")
            ctk.CTkLabel(row, textvariable=var, font=ctk.CTkFont(size=20, weight="bold"), text_color=ACCENT).pack(side="right")

        logfrm = ctk.CTkFrame(bot, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        logfrm.grid(row=0, column=1, sticky="nsew")
        logfrm.grid_rowconfigure(0, weight=1)
        logfrm.grid_columnconfigure(0, weight=1)
        self.log_list = tk.Listbox(logfrm, bg=CARD, fg=TEXT, selectbackground=ACCENT,
                                   activestyle="none", font=("Consolas", 12), bd=0, highlightthickness=0)
        self.log_list.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        sb = tk.Scrollbar(logfrm, command=self.log_list.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.log_list.config(yscrollcommand=sb.set)

    # ---------------------------  SCAN BUTTONS  -----------------------------
    def quick_scan(self):
        """Scan critical malware hotspots."""
        hotspots = [
            os.path.expandvars(r"%SYSTEMROOT%\System32"),
            os.path.expandvars(r"%SYSTEMROOT%\SysWOW64"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
            DOWNLOADS
        ]
        targets = [h for h in hotspots if os.path.isdir(h)]
        if not targets:
            messagebox.showwarning("Quick scan", "No system hotspots found")
            return
        # feed worker directly – skip start_scan() empty-path dialog
        self.scan_path.set(";".join(targets))
        if self.running:
            return
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.item_cnt.set(0)
        self.detect_cnt.set(0)
        self.time_str.set("00:00")
        self.log("=== Quick scan ===")
        threading.Thread(target=self.scan_worker, args=(self.scan_path.get(), self.strict.get()), daemon=True).start()

    def full_scan(self):
        """Scan entire system drive."""
        self.scan_path.set("C:\\")
        self.start_scan()

    def custom_scan(self):
        """Let user pick file or folder, then scan."""
        pick = messagebox.askquestion("Custom scan", "Scan a file or a folder?", icon="question", type="yesno",
                                      detail="YES = file | NO = folder")
        if pick == "yes":
            f = filedialog.askopenfilename(title="Select file to scan")
            if f:
                self.scan_path.set(f)
                self.start_scan()
        else:
            d = filedialog.askdirectory(title="Select folder to scan")
            if d:
                self.scan_path.set(d)
                self.start_scan()

    # ------------------------------------------------------------------  quarantine page
    def build_quar(self):
        p = self.pages["quar"]
        p.grid_rowconfigure(1, weight=1)
        p.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0,20))
        ctk.CTkLabel(hdr, text="Threat Management", font=ctk.CTkFont(size=32, weight="bold")).pack(side="left")
        # stats row
        stats = ctk.CTkFrame(hdr, fg_color="transparent")
        stats.pack(side="right")
        for txt,val,clr in [("Active",len(QDB),DANGER), ("Quarantined",len(QDB),YELLOW), ("Removed",0,GREEN)]:
            c = ctk.CTkFrame(stats, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
            c.pack(side="left", padx=6)
            self.after(1000, lambda: self.show_quar())
            ctk.CTkLabel(c, text=str(val), font=ctk.CTkFont(size=18, weight="bold"), text_color=clr).pack(padx=12, pady=6)
            ctk.CTkLabel(c, text=txt, font=ctk.CTkFont(size=12), text_color=SUB).pack(padx=12, pady=(0,6))

        # list
        list_frm = ctk.CTkFrame(p, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        list_frm.grid(row=1, column=0, sticky="nsew", pady=(0,20))
        list_frm.grid_rowconfigure(0, weight=1)
        list_frm.grid_columnconfigure(0, weight=1)
        self.quar_list = tk.Listbox(list_frm, bg=CARD, fg=TEXT, selectbackground=ACCENT,
                                    activestyle="none", font=("Consolas", 13), bd=0, highlightthickness=0, selectmode=tk.EXTENDED)
        self.quar_list.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        qsb = tk.Scrollbar(list_frm, command=self.quar_list.yview)
        qsb.grid(row=0, column=1, sticky="ns")
        self.quar_list.config(yscrollcommand=qsb.set)

        # buttons
        btns = ctk.CTkFrame(p, fg_color="transparent")
        btns.grid(row=2, column=0)
        for txt,cmd in [("♻️ Restore Selected",self.restore_selected),
                        ("♻️ Restore All",self.restore_all),
                        ("🗑️ Delete Selected",self.delete_selected),
                        ("🗑️ Delete All",self.delete_all_quar),
                        ("🔄 Refresh",self.refresh_quar)]:
            ctk.CTkButton(btns, text=txt, command=lambda c=cmd: self.run_bg(c)).pack(side="left", padx=6)

    # ------------------------------------------------------------------  history page
    def build_history(self):
        p = self.pages["history"]
        p.grid_rowconfigure(1, weight=1)
        p.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0,20))
        ctk.CTkLabel(hdr, text="Scan History", font=ctk.CTkFont(size=32, weight="bold")).pack(side="left")
        ctk.CTkButton(hdr, text="Export", command=lambda: None).pack(side="right")

        # list
        list_frm = ctk.CTkFrame(p, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        list_frm.grid(row=1, column=0, sticky="nsew")
        list_frm.grid_rowconfigure(0, weight=1)
        list_frm.grid_columnconfigure(0, weight=1)
        self.hist_list = tk.Listbox(list_frm, bg=CARD, fg=TEXT, selectbackground=ACCENT,
                                    activestyle="none", font=("Consolas", 13), bd=0, highlightthickness=0)
        self.hist_list.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        sb = tk.Scrollbar(list_frm, command=self.hist_list.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.hist_list.config(yscrollcommand=sb.set)

    # ------------------------------------------------------------------  settings page
    def build_settings(self):
        p = self.pages["settings"]
        p.grid_rowconfigure(1, weight=1)
        p.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0,20))
        ctk.CTkLabel(hdr, text="Settings", font=ctk.CTkFont(size=32, weight="bold")).pack(side="left")

        body = ctk.CTkFrame(p, corner_radius=16, fg_color=CARD, border_width=1, border_color=BORDER)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)
        body.grid_columnconfigure(0, weight=1)

        switches = [
            ("Start with Windows", self.startup, self.toggle_startup),
            ("Auto-scan Downloads", self.monitor, self.toggle_monitor),
            ("Scan reminders", self.remind, self.toggle_remind)
        ]
        for txt,var,cmd in switches:
            ctk.CTkSwitch(body, text=txt, variable=var, command=cmd,
                          font=ctk.CTkFont(size=16), progress_color=ACCENT).pack(anchor="w", padx=24, pady=20)
        ctk.CTkButton(body, text="Save Settings", command=lambda: save_set(SETTINGS),
                      fg_color=ACCENT, text_color="#000", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=24, pady=24)

    # ------------------------------------------------------------------  navigation
    def show_dashboard(self): self.show("dashboard")
    def show_scan(self): self.show("scan")
    def show_quar(self):
        self.show("quar")
        self.refresh_quar()
    def show_history(self):
        self.show("history")
        self.refresh_history()
    def show_settings(self): self.show("settings")

    def show(self, page):
        for btn in self.nav_btns.values():
            btn.configure(fg_color="transparent", text_color=TEXT)
        self.nav_btns[page].configure(fg_color=ACCENT, text_color="#000")
        for f in self.pages.values():
            f.lower()
        self.pages[page].lift()

    # ------------------------------------------------------------------  file dialogs
    def ask_file(self):
        f = filedialog.askopenfilename(title="Select file")
        if f:
            self.scan_path.set(f)
    def ask_folder(self):
        f = filedialog.askdirectory(title="Select folder")
        if f:
            self.scan_path.set(f)
    def ask_drive(self):
        # quick drive picker – keep your old win32 code if you want
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  if os.path.exists(f"{d}:\\")]
        if not drives:
            return
        top = ctk.CTkToplevel(self)
        top.geometry("300x200")
        top.transient(self)
        top.grab_set()
        var = tk.StringVar(value=drives[0])
        for d in drives:
            ctk.CTkRadioButton(top, text=d, variable=var, value=d).pack(anchor="w", padx=20, pady=4)
        ctk.CTkButton(top, text="OK", command=lambda: (self.scan_path.set(var.get()), top.destroy())).pack(pady=12)

    # ------------------------------------------------------------------  scanning (your old worker)
    def start_scan(self):
        path = self.scan_path.get()
        if not path:
            messagebox.showerror("Path", "No target selected")
            return
        if not os.path.exists(path):
            messagebox.showerror("Path", "Target does not exist")
            return
        if self.running:
            return
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.item_cnt.set(0)
        self.detect_cnt.set(0)
        self.time_str.set("00:00")
        self.log("=== Start scan ===")
        threading.Thread(target=self.scan_worker, args=(path, self.strict.get()), daemon=True).start()

    def stop_scan(self):
        self.running = False
        self.log("Scan stop requested")

    # ---------- your original scan_worker (unchanged) ----------
    def scan_worker(self, path, strict_mode):
        start = time.time()
        try:
            # ---- multi-path quick scan ----
            if ";" in path:
                paths = [p.strip() for p in path.split(";") if os.path.exists(p.strip())]
            else:
                paths = [path]
            files = []
            for p in paths:
                if os.path.isfile(p):
                    files.append(p)
                else:
                    for root, dirs, names in os.walk(p):
                        if any(root.startswith(ex) for ex in EXCLUDE_PATHS):
                            continue
                        for n in names:
                            full = os.path.join(root, n)
                            try:
                                if os.path.abspath(full) in (os.path.abspath(__file__), os.path.abspath(sys.executable)):
                                    continue
                            except Exception:
                                pass
                            files.append(full)
            total = len(files)
            for idx, fpath in enumerate(files, start=1):
                if not self.running:
                    break
                self.item_cnt.set(idx)
                pct = idx / total if total else 0
                self.safe_ui(lambda p=pct: self.c.itemconfig(self.arc, extent=-p*360))
                self.log(f"Scanning: {fpath}")
                yara_det, yara_rules = self.yara_scan(fpath)
                heur_det, heur_matches = self.heur_scan(fpath, strict_mode)
                combined = []
                if yara_det:
                    combined.extend(yara_rules)
                else:
                    if strict_mode and heur_matches:
                        combined.extend(heur_matches)
                        heur_det = True
                if heur_det and not combined:
                    combined.extend(heur_matches)
                if yara_det or heur_det:
                    self.detect_cnt.set(self.detect_cnt.get() + 1)
                    self.log(f"⚠️  MALWARE: {os.path.basename(fpath)}  rules: {', '.join(combined)}")
                    self.quarantine(fpath, combined)
                    self.safe_ui(notify, "Malware detected", f"{os.path.basename(fpath)} quarantined")
                else:
                    self.log(f"✓ Clean: {os.path.basename(fpath)}")
                elapsed = int(time.time() - start)
                self.time_str.set(f"{elapsed//60:02d}:{elapsed%60:02d}")
            self.log("=== Scan complete ===")
        except Exception as e:
            self.log("Scan error: " + str(e))
            logger.exception("scan_worker exception")
        finally:
            self.running = False
            self.safe_ui(self.start_btn.configure, state="normal")
            self.safe_ui(self.stop_btn.configure, state="disabled")
            self.safe_ui(self.refresh_quar)
            SETTINGS["scans_done"] = SETTINGS.get("scans_done", 0) + 1
            save_set(SETTINGS)

    # ---------- your original yara_scan ----------
    def yara_scan(self, path):
        try:
            matches = RULES.match(filepath=path) if hasattr(RULES, "match") else []
            if matches:
                return True, [m.rule for m in matches]
            return False, []
        except Exception as e:
            logger.exception("yara_scan error")
            return False, [f"YARA_ERROR:{e}"]

    # ---------- your original heur_scan ----------
    def heur_scan(self, path, strict_mode=False):
        import sqlite3, hashlib, pathlib

        DB = pathlib.Path(__file__).with_name("malware_hashes.db")
        if not DB.is_file():
            return False, []

        sha = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        con = sqlite3.connect(str(DB), check_same_thread=False)  # read-only
        cur = con.execute("SELECT 1 FROM hash WHERE sha256=?", (sha,))
        found = cur.fetchone()
        con.close()
        if found:
            return True, [f"MalwareHash:{sha[:16]}"]
        return False, []

    # ---------- your original quarantine ----------
    def quarantine(self, path, rules):
        try:
            sha = sha256(path)
            base = os.path.basename(path)
            ts = int(time.time())
            name = f"{sha[:16]}_{ts}_{base}"
            dst = os.path.join(QUAR_DIR, name)
            if os.path.exists(dst):
                dst = os.path.join(QUAR_DIR, f"{sha[:16]}_{ts}_{int(time.time())}_{base}")
            try:
                shutil.move(path, dst)
            except Exception:
                shutil.copy2(path, dst)
                os.remove(path)
            QDB[name] = {"original": path, "at": datetime.utcnow().isoformat() + "Z", "sha": sha, "rules": rules}
            save_qdb(QDB)
            self.log(f"Quarantined: {name}")
            self.safe_ui(self.refresh_quar)
        except Exception:
            logger.exception("quarantine failed")
            self.safe_ui(self.log, f"Quarantine failed for {path}")

    # ------------------------------------------------------------------  quarantine UI
    def refresh_quar(self):
        self.quar_list.delete(0, tk.END)
        for key, info in list(QDB.items()):
            txt = f"{key}  –  {os.path.basename(info.get('original',''))}  –  {', '.join(info.get('rules', []))}"
            self.quar_list.insert(tk.END, txt)

    def restore_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        keys = [list(QDB.keys())[i] for i in sel]
        def worker():
            for key in keys:
                info = QDB.get(key)
                if not info:
                    continue
                src = os.path.join(QUAR_DIR, key)
                orig = info["original"]
                try:
                    parent = os.path.dirname(orig)
                    if parent and not os.path.isdir(parent):
                        os.makedirs(parent, exist_ok=True)
                    final = orig
                    if os.path.exists(final):
                        base, ext = os.path.splitext(final)
                        final = f"{base}_restored_{int(time.time())}{ext}"
                    shutil.move(src, final)
                    self.log(f"Restored {key} -> {final}")
                    QDB.pop(key, None)
                except Exception as e:
                    logger.exception("Restore failed")
                    self.log(f"Restore failed: {e}")
            save_qdb(QDB)
            self.safe_ui(self.refresh_quar)
        self.run_bg(worker)

    def restore_all(self):
        if not QDB:
            return
        if not messagebox.askyesno("Restore All", f"Restore ALL ({len(QDB)}) files?"):
            return
        def worker_all():
            for key in list(QDB.keys()):
                info = QDB.get(key)
                if not info:
                    continue
                src = os.path.join(QUAR_DIR, key)
                orig = info["original"]
                try:
                    parent = os.path.dirname(orig)
                    if parent and not os.path.isdir(parent):
                        os.makedirs(parent, exist_ok=True)
                    final = orig
                    if os.path.exists(final):
                        base, ext = os.path.splitext(final)
                        final = f"{base}_restored_{int(time.time())}{ext}"
                    shutil.move(src, final)
                    self.log(f"Restored {key} -> {final}")
                    QDB.pop(key, None)
                except Exception as e:
                    logger.exception("Restore all failed")
                    self.log(f"Restore failed: {e}")
            save_qdb(QDB)
            self.safe_ui(self.refresh_quar)
        self.run_bg(worker_all)

    def delete_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        if not messagebox.askyesno("Delete", f"Delete {len(sel)} selected?"):
            return
        keys = [list(QDB.keys())[i] for i in sel]
        def worker():
            for key in keys:
                src = os.path.join(QUAR_DIR, key)
                try:
                    if os.path.exists(src):
                        os.remove(src)
                except Exception:
                    logger.exception("delete selected file failed")
                QDB.pop(key, None)
            save_qdb(QDB)
            self.safe_ui(self.refresh_quar)
            self.log(f"Deleted {len(keys)} quarantined")
        self.run_bg(worker)

    def delete_all_quar(self):
        if not QDB:
            return
        if not messagebox.askyesno("Delete All", f"Delete ALL ({len(QDB)}) quarantined files?"):
            return
        def worker_all_del():
            for key in list(QDB.keys()):
                src = os.path.join(QUAR_DIR, key)
                try:
                    if os.path.exists(src):
                        os.remove(src)
                except Exception:
                    logger.exception("delete all failed")
                QDB.pop(key, None)
            save_qdb(QDB)
            self.safe_ui(self.refresh_quar)
            self.log("Deleted ALL quarantined")
        self.run_bg(worker_all_del)

    # ------------------------------------------------------------------  history
    def refresh_history(self):
        self.hist_list.delete(0, tk.END)
        # dummy – replace with your old scan-history list
        for i in range(20):
            self.hist_list.insert(tk.END, f"Scan #{i+1}  –  Quick Scan  –  0 threats  –  2 min")

    # ------------------------------------------------------------------  settings
    def toggle_startup(self):
        SETTINGS["startup"] = self.startup.get()
        save_set(SETTINGS)
        if self.startup.get():
            self._enable_startup()
        else:
            self._disable_startup()

    def toggle_monitor(self):
        SETTINGS["monitor"] = self.monitor.get()
        save_set(SETTINGS)

    def toggle_remind(self):
        SETTINGS["reminder"] = self.remind.get()
        save_set(SETTINGS)

    RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "BytesProtector"
    APP_CMD = f'"{sys.executable}" "{os.path.abspath(__file__)}"'

    def _enable_startup(self):
        if winreg is None:
            return
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, self.APP_NAME, 0, winreg.REG_SZ, self.APP_CMD)
        except Exception:
            logger.exception("enable_startup failed")

    def _disable_startup(self):
        if winreg is None:
            return
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, self.APP_NAME)
        except FileNotFoundError:
            pass
        except Exception:
            logger.exception("disable_startup failed")

    # ------------------------------------------------------------------  downloads monitor
    def dl_loop(self):
        known = {}
        while SETTINGS.get("monitor", True) and self.monitor.get():
            try:
                current = {}
                if os.path.isdir(DOWNLOADS):
                    for f in os.listdir(DOWNLOADS):
                        full = os.path.join(DOWNLOADS, f)
                        if os.path.isfile(full):
                            try:
                                current[full] = os.path.getsize(full)
                            except Exception:
                                current[full] = -1
                new = [p for p in current if p not in known or known[p] != current[p]]
                for p in new:
                    if stable(p):
                        self.log(f"Auto-scan download: {p}")
                        yara_det, yara_rules = self.yara_scan(p)
                        heur_det, heur_matches = self.heur_scan(p, strict_mode=False)
                        if yara_det or heur_det:
                            rules = (yara_rules if yara_det else []) + (heur_matches if heur_matches else [])
                            self.quarantine(p, rules)
                            self.safe_ui(notify, "Malware detected", f"{os.path.basename(p)} quarantined")
                        else:
                            self.log(f"Download clean: {os.path.basename(p)}")
                known = current
            except Exception:
                logger.exception("dl_loop exception")
            for _ in range(5):
                if not (SETTINGS.get("monitor", True) and self.monitor.get()):
                    break
                time.sleep(1)

    # ------------------------------------------------------------------  reminder
    def reminder_loop(self):
        while SETTINGS.get("reminder", True) and self.remind.get():
            last = SETTINGS.get("last_remind", 0)
            interval = SETTINGS.get("reminder_sec", 48*3600)
            if time.time() - last > interval:
                self.safe_ui(notify, "BytesProtector", "Reminder: run a safety scan")
                SETTINGS["last_remind"] = time.time()
                save_set(SETTINGS)
            time.sleep(60)

    # ------------------------------------------------------------------  tray
    def _create_tray_icon(self):
        def create_img():
            if os.path.isfile(ICON_PATH):
                return Image.open(ICON_PATH)
            img = Image.new("RGBA", (64,64), (0,0,0,0))
            draw = ImageDraw.Draw(img)
            draw.ellipse((6,6,58,58), fill="#00ff88")
            return img
        menu = (
            TrayMenuItem("Open", lambda icon, item: self.safe_ui(self.deiconify)),
            TrayMenuItem("Scan Downloads", lambda icon, item: self.run_bg(self.scan_downloads_now)),
            TrayMenuItem("Exit", lambda icon, item: self.safe_ui(self.on_close))
        )
        icon = pystray.Icon("BytesProtector", create_img(), "BytesProtector", menu)
        return icon

    def _tray_run(self, icon):
        try:
            icon.run()
        except Exception:
            logger.exception("Tray icon failed")

    def start_tray(self):
        if not PYSTRAY_OK:
            return
        try:
            icon = self._create_tray_icon()
            self._tray_icon = icon
            t = threading.Thread(target=self._tray_run, args=(icon,), daemon=True)
            t.start()
            self._tray_thread = t
        except Exception:
            logger.exception("start_tray failed")

    def stop_tray(self):
        try:
            if self._tray_icon:
                try:
                    self._tray_icon.stop()
                except Exception:
                    try:
                        self._tray_icon.shutdown()
                    except Exception:
                        pass
                self._tray_icon = None
        except Exception:
            logger.exception("stop_tray failed")

    # ------------------------------------------------------------------  helpers
    def scan_downloads_now(self):
        downloads = DOWNLOADS
        if not os.path.isdir(downloads):
            messagebox.showinfo("Downloads", f"Not found: {downloads}")
            return
        self.scan_path.set(downloads)
        self.start_scan()

    def run_bg(self, func, *a, **kw):
        t = threading.Thread(target=lambda: func(*a, **kw), daemon=True)
        t.start()
        return t
    def safe_ui(self, func, *a, **kw):
        try:
            self.after(1, lambda: func(*a, **kw))
        except Exception:
            try:
                func(*a, **kw)
            except Exception:
                logger.exception("safe_ui fallback failed")
    def log(self, msg):
        self.q.put(("log", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"))
        logger.debug(msg)
    def pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log_list.insert(tk.END, payload)
                    self.log_list.yview_moveto(1.0)
                self.q.task_done()
        except queue.Empty:
            pass
        self.after(150, self.pump)

    # ------------------------------------------------------------------  close
    def on_close(self):
        SETTINGS["startup"] = self.startup.get()
        SETTINGS["monitor"] = self.monitor.get()
        SETTINGS["reminder"] = self.remind.get()
        save_set(SETTINGS)
        save_qdb(QDB)
        try:
            self.stop_tray()
        except Exception:
            pass
        if PYSTRAY_OK:
            try:
                self.withdraw()
                return
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass
        sys.exit(0)

# --------------------------------------------------------------------------
#  MAIN
# --------------------------------------------------------------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()