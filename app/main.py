import sys
import os
import json
import string
import ctypes
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget,
    QListWidget, QListWidgetItem,
    QTextEdit, QFrame, QProgressBar,
    QGraphicsDropShadowEffect, QSizePolicy
)
from PySide6.QtCore import (
    Qt, QTimer, QTime, QThread, Signal, QPropertyAnimation,
    QEasingCurve, QRect, QSize
)
from PySide6.QtGui import (
    QIcon, QColor, QPainter, QPen, QBrush,
    QLinearGradient, QRadialGradient, QPainterPath
)

# --------------------------------------------------
# PATHS
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
ICON_DIR  = os.path.join(BASE_DIR, "assets", "icons")
STYLE_DIR = os.path.join(BASE_DIR, "styles")
QSS_PATH  = os.path.join(STYLE_DIR, "dark.qss")
LOG_FILE  = os.path.join(BASE_DIR, "logs", "scan_logs.json")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.usb_predictor import predict_usb_risk

# --------------------------------------------------
# DRIVE DETECTION
# --------------------------------------------------
def get_available_drives():
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
    except Exception:
        drives = ["C:\\", "D:\\", "E:\\"]
    return drives

# --------------------------------------------------
# LOG UTILS
# --------------------------------------------------
def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_log(entry):
    logs = load_logs()
    logs.insert(0, entry)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


# ==================================================
# THREAT PULSE WIDGET  –  animated neon ring
# ==================================================
class ThreatPulse(QWidget):
    COLORS = {
        "idle":      QColor(0x2b, 0x6c, 0xff),
        "scanning":  QColor(0x00, 0xd4, 0xff),
        "SAFE":      QColor(0x3c, 0xcf, 0x91),
        "SOFT_WARN": QColor(0xf1, 0xc4, 0x0f),
        "HARD_WARN": QColor(0xe6, 0x7e, 0x22),
        "CRITICAL":  QColor(0xe7, 0x4c, 0x3c),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(180, 180)
        self._state    = "idle"
        self._angle    = 0
        self._pulse    = 0.0
        self._pulse_dir = 1
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(30)

    def set_state(self, state: str):
        self._state = state

    def _tick(self):
        if self._state == "scanning":
            self._angle = (self._angle + 6) % 360
        self._pulse += 0.04 * self._pulse_dir
        if self._pulse >= 1.0 or self._pulse <= 0.0:
            self._pulse_dir *= -1
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        color = self.COLORS.get(self._state, self.COLORS["idle"])
        cx, cy  = self.width() // 2, self.height() // 2
        max_r   = min(cx, cy) - 4

        # Glow rings
        for i in range(3, 0, -1):
            alpha = int(18 + 14 * self._pulse * (1 - i / 4))
            glow  = QColor(color); glow.setAlpha(alpha)
            r = max_r * (i / 3)
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(int(cx - r), int(cy - r), int(r * 2), int(r * 2))

        # Main ring
        p.setPen(QPen(color, 3)); p.setBrush(Qt.NoBrush)
        p.drawEllipse(cx - max_r, cy - max_r, max_r * 2, max_r * 2)

        # Spinning arc (scanning state)
        if self._state == "scanning":
            arc_pen = QPen(color, 5); arc_pen.setCapStyle(Qt.RoundCap)
            p.setPen(arc_pen)
            p.drawArc(
                cx - max_r + 2, cy - max_r + 2,
                (max_r - 2) * 2, (max_r - 2) * 2,
                int(self._angle * 16), 100 * 16
            )

        # Centre dot
        dot_r = int(6 + 3 * self._pulse)
        p.setPen(Qt.NoPen); p.setBrush(QBrush(color))
        p.drawEllipse(cx - dot_r, cy - dot_r, dot_r * 2, dot_r * 2)
        p.end()


# ==================================================
# SCAN WORKER THREAD  –  THE FIX
# ==================================================
class ScanWorker(QThread):
    """
    Runs predict_usb_risk() on a background thread.
    Emits signals to update the GUI – never blocks Qt event loop.
    """
    log_line = Signal(str)
    finished = Signal(dict)
    error    = Signal(str)

    def __init__(self, drive: str):
        super().__init__()
        self.drive = drive

    def run(self):
        try:
            self.log_line.emit(f"[INIT] Zero Trust engine starting...")
            self.log_line.emit(f"[TARGET] Drive : {self.drive}")
            self.log_line.emit(f"[PHASE 1] Loading ML model...")

            result = predict_usb_risk(self.drive)

            self.log_line.emit(f"[PHASE 2] File system scan complete")
            self.log_line.emit(f"[PHASE 3] Applying rule engine...")

            for r in result["rule_hits"]:
                self.log_line.emit(f"  ⚡  RULE HIT  →  {r['rule']}  (+{r['score']})")

            if not result["rule_hits"]:
                self.log_line.emit("  ✅  No rule violations detected")

            probs = result["ml_probabilities"]
            self.log_line.emit(f"[PHASE 4] ML inference complete")
            self.log_line.emit(
                f"  LOW = {probs['LOW']}%   MEDIUM = {probs['MEDIUM']}%   HIGH = {probs['HIGH']}%"
            )
            self.log_line.emit(f"[PHASE 5] Hybrid scoring → {result['final_score']}")
            self.log_line.emit(f"[DONE]  ─────────────────────────────────────")
            self.finished.emit(result)

        except Exception as exc:
            self.error.emit(str(exc))


# ==================================================
# NEON GLOW LABEL
# ==================================================
class GlowLabel(QLabel):
    def __init__(self, text="", color="#00d4ff", parent=None):
        super().__init__(text, parent)
        self._color = color
        self._apply()

    def _apply(self):
        fx = QGraphicsDropShadowEffect(self)
        fx.setBlurRadius(22)
        fx.setColor(QColor(self._color))
        fx.setOffset(0, 0)
        self.setGraphicsEffect(fx)

    def set_glow_color(self, color: str):
        self._color = color
        self._apply()


# ==================================================
# SIDEBAR
# ==================================================
class Sidebar(QWidget):
    def __init__(self, navigate_cb, scan_drive_cb):
        super().__init__()
        self.setObjectName("Sidebar")
        self.setFixedWidth(295)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 22, 16, 20)
        lay.setSpacing(8)

        # Logo
        logo_row = QHBoxLayout()
        logo_px = QLabel()
        logo_px.setPixmap(QIcon(os.path.join(ICON_DIR, "shield.png")).pixmap(26, 26))
        logo_row.addWidget(logo_px)
        title = GlowLabel("ZERO TRUST", "#00d4ff")
        title.setStyleSheet(
            "font-size:14px;font-weight:900;letter-spacing:4px;color:#00d4ff;"
            "font-family:Consolas;"
        )
        logo_row.addWidget(title)
        logo_row.addStretch()
        lay.addLayout(logo_row)

        def neon_sep():
            s = QFrame(); s.setFixedHeight(1)
            s.setStyleSheet(
                "background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                "stop:0 #0e1117,stop:0.5 #00d4ff,stop:1 #0e1117);"
            )
            return s

        lay.addWidget(neon_sep())
        lay.addSpacing(6)

        def nav_btn(text, icon_file, page):
            b = QPushButton(f"   {text}")
            b.setIcon(QIcon(os.path.join(ICON_DIR, icon_file)))
            b.setIconSize(QSize(18, 18))
            b.setFixedHeight(46)
            b.setObjectName("NavButton")
            b.clicked.connect(lambda: navigate_cb(page))
            return b

        lay.addWidget(nav_btn("Home", "home.png", "home"))
        lay.addWidget(nav_btn("Start Scan", "usb.png", "scan"))
        lay.addWidget(nav_btn("History", "history.png", "history"))

        lay.addSpacing(14)
        drives_lbl = QLabel("▸  AVAILABLE DRIVES")
        drives_lbl.setStyleSheet(
            "font-size:10px;font-weight:bold;letter-spacing:2px;color:#2d3748;font-family:Consolas;"
        )
        lay.addWidget(drives_lbl)
        lay.addSpacing(2)

        for d in get_available_drives():
            btn = QPushButton(f"  💾  {d}")
            btn.setObjectName("DriveTile")
            btn.setFixedHeight(44)
            btn.clicked.connect(lambda _, x=d: scan_drive_cb(x))
            lay.addWidget(btn)

        lay.addStretch()
        lay.addWidget(neon_sep())
        lay.addSpacing(8)

        # Clock
        self.clock = GlowLabel("", "#00d4ff")
        self.clock.setAlignment(Qt.AlignCenter)
        self.clock.setStyleSheet(
            "font-size:21px;font-weight:bold;color:#00d4ff;"
            "letter-spacing:4px;font-family:Consolas;"
        )
        lay.addWidget(self.clock)

        self.threat_counter = QLabel("THREATS BLOCKED : 0")
        self.threat_counter.setAlignment(Qt.AlignCenter)
        self.threat_counter.setStyleSheet("font-size:10px;color:#2d3748;letter-spacing:1px;")
        lay.addWidget(self.threat_counter)

        self._clk_timer = QTimer(self)
        self._clk_timer.timeout.connect(self._update_clock)
        self._clk_timer.start(1000)
        self._update_clock()
        self.refresh_threat_count()

    def _update_clock(self):
        self.clock.setText(QTime.currentTime().toString("HH : mm : ss"))

    def refresh_threat_count(self):
        logs = load_logs()
        n = sum(1 for l in logs if l.get("severity") in ("HARD_WARN", "CRITICAL"))
        self.threat_counter.setText(f"THREATS BLOCKED  :  {n}")


# ==================================================
# HOME PAGE
# ==================================================
class HomePage(QWidget):
    def __init__(self, start_scan):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(18)

        self.pulse = ThreatPulse()
        lay.addWidget(self.pulse, alignment=Qt.AlignCenter)

        title = GlowLabel("ZERO TRUST USB SECURITY", "#00d4ff")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "font-size:24px;font-weight:900;letter-spacing:5px;"
            "color:#00d4ff;font-family:Consolas;"
        )
        lay.addWidget(title)

        sub = GlowLabel("ENGINE STATUS  ·  ARMED & READY", "#3ccf91")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(
            "font-size:12px;letter-spacing:3px;color:#3ccf91;font-family:Consolas;"
        )
        lay.addWidget(sub)

        lay.addSpacing(8)

        # Stats row
        stats = QHBoxLayout(); stats.setSpacing(16)
        def stat_card(label, value_fn):
            card = QFrame(); card.setObjectName("StatCard")
            cl   = QVBoxLayout(card); cl.setContentsMargins(22, 14, 22, 14)
            val  = GlowLabel(value_fn(), "#00d4ff")
            val.setAlignment(Qt.AlignCenter)
            val.setStyleSheet("font-size:26px;font-weight:900;color:#00d4ff;font-family:Consolas;")
            lbl  = QLabel(label)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("font-size:10px;letter-spacing:2px;color:#2d3748;")
            cl.addWidget(val); cl.addWidget(lbl)
            return card

        logs = load_logs()
        stats.addWidget(stat_card("SCANS RUN", lambda: str(len(load_logs()))))
        stats.addWidget(stat_card("THREATS", lambda: str(
            sum(1 for l in load_logs() if l.get("severity") in ("HARD_WARN", "CRITICAL"))
        )))
        stats.addWidget(stat_card("LAST SCAN", lambda: (
            load_logs()[0]["time"].split(" ")[1] if load_logs() else "—"
        )))
        lay.addLayout(stats)
        lay.addSpacing(8)

        btn = QPushButton("⚡   INITIATE SCAN")
        btn.setObjectName("PrimaryButton")
        btn.setFixedWidth(280)
        btn.setFixedHeight(52)
        btn.clicked.connect(start_scan)
        lay.addWidget(btn, alignment=Qt.AlignCenter)

        hint = QLabel("or select a drive from the sidebar")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("font-size:11px;color:#1e293b;")
        lay.addWidget(hint)


# ==================================================
# SCAN PAGE
# ==================================================
class ScanPage(QWidget):
    scan_complete = Signal(dict)

    def __init__(self):
        super().__init__()
        self._worker = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(30, 20, 30, 20)
        lay.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        hdr_lbl = QLabel("▸  SCAN ACTIVITY")
        hdr_lbl.setStyleSheet(
            "font-size:11px;font-weight:bold;letter-spacing:3px;"
            "color:#2d3748;font-family:Consolas;"
        )
        hdr.addWidget(hdr_lbl); hdr.addStretch()
        self.drive_badge = QLabel("")
        self.drive_badge.setObjectName("DriveBadge")
        hdr.addWidget(self.drive_badge)
        lay.addLayout(hdr)

        # Pulse + feed
        center = QHBoxLayout(); center.setSpacing(20)
        self.pulse = ThreatPulse()
        center.addWidget(self.pulse, alignment=Qt.AlignTop)
        self.feed = QTextEdit()
        self.feed.setReadOnly(True)
        self.feed.setObjectName("ScanFeed")
        center.addWidget(self.feed, 1)
        lay.addLayout(center, 1)

        # Indeterminate progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(6)
        self.progress.setVisible(False)
        self.progress.setObjectName("ScanProgress")
        lay.addWidget(self.progress)

        # Result
        self.result_lbl = GlowLabel("", "#3ccf91")
        self.result_lbl.setAlignment(Qt.AlignCenter)
        self.result_lbl.setStyleSheet(
            "font-size:36px;font-weight:900;letter-spacing:6px;font-family:Consolas;"
        )
        lay.addWidget(self.result_lbl)

        self.sub_lbl = QLabel("")
        self.sub_lbl.setAlignment(Qt.AlignCenter)
        self.sub_lbl.setStyleSheet(
            "font-size:12px;color:#4a5568;letter-spacing:2px;font-family:Consolas;"
        )
        lay.addWidget(self.sub_lbl)

    # Public — called from MainWindow
    def run_scan(self, drive: str):
        self.feed.clear()
        self.result_lbl.clear()
        self.sub_lbl.clear()
        self.drive_badge.setText(drive)
        self.pulse.set_state("scanning")
        self.progress.setVisible(True)

        # Kill previous worker if still alive
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait()

        self._worker = ScanWorker(drive)
        self._worker.log_line.connect(self._append_log)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _append_log(self, line: str):
        self.feed.append(line)

    def _on_done(self, result: dict):
        self.progress.setVisible(False)
        sev   = result["severity"]
        cmap  = {"SAFE": "#3ccf91", "SOFT_WARN": "#f1c40f",
                 "HARD_WARN": "#e67e22", "CRITICAL": "#e74c3c"}
        color = cmap.get(sev, "#ffffff")

        self.pulse.set_state(sev)
        self.result_lbl.setText(sev.replace("_", " "))
        self.result_lbl.setStyleSheet(
            f"font-size:36px;font-weight:900;letter-spacing:6px;"
            f"color:{color};font-family:Consolas;"
        )
        self.result_lbl.set_glow_color(color)
        self.sub_lbl.setText(
            f"{result['decision']}  ·  FINAL SCORE  {result['final_score']}"
        )

        save_log({
            "usb":        result["usb_path"],
            "time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decision":   result["decision"],
            "severity":   sev,
            "final_score": result["final_score"],
            "rule_score": result["rule_score"],
            "rule_hits":  result["rule_hits"],
            "ml_probs":   result["ml_probabilities"],
        })
        self.scan_complete.emit(result)

    def _on_error(self, msg: str):
        self.progress.setVisible(False)
        self.pulse.set_state("idle")
        self.feed.append(f"\n[ERROR] {msg}")
        self.result_lbl.setText("ERROR")
        self.result_lbl.setStyleSheet(
            "font-size:30px;font-weight:900;color:#e74c3c;font-family:Consolas;"
        )


# ==================================================
# HISTORY PAGE
# ==================================================
class HistoryPage(QWidget):
    def __init__(self, open_detail):
        super().__init__()
        self.open_detail = open_detail
        lay = QVBoxLayout(self)
        lay.setContentsMargins(30, 20, 30, 20)
        lay.setSpacing(12)

        hdr = QHBoxLayout()
        t   = QLabel("▸  PROTECTION HISTORY")
        t.setStyleSheet("font-size:11px;font-weight:bold;letter-spacing:3px;color:#2d3748;font-family:Consolas;")
        hdr.addWidget(t); hdr.addStretch()
        clr = QPushButton("CLEAR")
        clr.setObjectName("SmallButton")
        clr.setFixedHeight(30)
        clr.clicked.connect(self._clear)
        hdr.addWidget(clr)
        lay.addLayout(hdr)

        self.list = QListWidget()
        self.list.itemClicked.connect(self._open)
        lay.addWidget(self.list)

    def refresh(self):
        self.list.clear()
        icons  = {"SAFE": "✅", "SOFT_WARN": "⚠️", "HARD_WARN": "🔶", "CRITICAL": "🚨"}
        colors = {"SAFE": "#3ccf91", "SOFT_WARN": "#f1c40f",
                  "HARD_WARN": "#e67e22", "CRITICAL": "#e74c3c"}
        for log in load_logs():
            sev   = log.get("severity", "")
            item  = QListWidgetItem(
                f"{icons.get(sev,'❓')}  {log['time']}   |   "
                f"{log['usb']}   |   {sev}   |   Score: {log['final_score']}"
            )
            item.setForeground(QColor(colors.get(sev, "#ffffff")))
            item.setData(Qt.UserRole, log)
            self.list.addItem(item)

    def _open(self, item):
        self.open_detail(item.data(Qt.UserRole))

    def _clear(self):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
        self.refresh()


# ==================================================
# DETAIL PAGE
# ==================================================
class DetailPage(QWidget):
    def __init__(self):
        super().__init__()
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(30, 20, 30, 20)
        self._lay.setSpacing(6)

    def show_log(self, log: dict):
        while self._lay.count():
            w = self._lay.takeAt(0).widget()
            if w: w.deleteLater()

        sev    = log.get("severity", "")
        cmap   = {"SAFE": "#3ccf91", "SOFT_WARN": "#f1c40f",
                  "HARD_WARN": "#e67e22", "CRITICAL": "#e74c3c"}
        color  = cmap.get(sev, "#ffffff")

        hdr = QLabel("▸  SCAN DETAIL")
        hdr.setStyleSheet("font-size:11px;font-weight:bold;letter-spacing:3px;color:#2d3748;font-family:Consolas;")
        self._lay.addWidget(hdr)

        sev_lbl = GlowLabel(sev.replace("_", " "), color)
        sev_lbl.setStyleSheet(
            f"font-size:32px;font-weight:900;letter-spacing:6px;color:{color};font-family:Consolas;"
        )
        self._lay.addWidget(sev_lbl)

        sep = QFrame(); sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{color};")
        self._lay.addWidget(sep)

        for label, val in [
            ("USB PATH",    log.get("usb", "")),
            ("SCAN TIME",   log.get("time", "")),
            ("DECISION",    log.get("decision", "")),
            ("FINAL SCORE", log.get("final_score", "")),
            ("RULE SCORE",  log.get("rule_score", "")),
        ]:
            row = QHBoxLayout()
            l   = QLabel(label)
            l.setStyleSheet("font-size:10px;letter-spacing:2px;color:#2d3748;min-width:150px;font-family:Consolas;")
            v = QLabel(str(val))
            v.setStyleSheet("font-size:13px;color:#e2e8f0;font-family:Consolas;")
            row.addWidget(l); row.addWidget(v); row.addStretch()
            c = QWidget(); c.setLayout(row)
            self._lay.addWidget(c)

        # Rule hits
        self._lay.addSpacing(10)
        self._lay.addWidget(self._section_hdr("RULE ENGINE HITS"))
        for r in log.get("rule_hits", []) or [QLabel("  No rules triggered")]:
            if isinstance(r, dict):
                lbl = QLabel(f"  ⚡  {r['rule']}  (+{r['score']})")
                lbl.setStyleSheet("color:#e67e22;font-family:Consolas;font-size:13px;")
            else:
                lbl = r
            self._lay.addWidget(lbl)

        # ML bars
        self._lay.addSpacing(10)
        self._lay.addWidget(self._section_hdr("ML ENGINE OUTPUT"))
        bcolors = {"LOW": "#3ccf91", "MEDIUM": "#f1c40f", "HIGH": "#e74c3c"}
        for k, v in log.get("ml_probs", {}).items():
            bc  = bcolors.get(k, "#ffffff")
            row = QHBoxLayout()
            kl  = QLabel(k); kl.setFixedWidth(76)
            kl.setStyleSheet(f"color:{bc};font-family:Consolas;font-size:12px;")
            pb = QProgressBar(); pb.setRange(0, 100)
            pb.setValue(int(float(v))); pb.setFixedHeight(10); pb.setTextVisible(False)
            pb.setStyleSheet(
                f"QProgressBar::chunk{{background:{bc};border-radius:5px;}}"
                f"QProgressBar{{background:#1a2332;border-radius:5px;}}"
            )
            vl = QLabel(f"{v}%"); vl.setFixedWidth(52)
            vl.setStyleSheet(f"color:{bc};font-family:Consolas;font-size:12px;")
            row.addWidget(kl); row.addWidget(pb, 1); row.addWidget(vl)
            c = QWidget(); c.setLayout(row)
            self._lay.addWidget(c)

        self._lay.addStretch()

    def _section_hdr(self, text):
        l = QLabel(f"▸  {text}")
        l.setStyleSheet("font-size:10px;font-weight:bold;letter-spacing:2px;color:#2d3748;font-family:Consolas;")
        return l


# ==================================================
# MAIN WINDOW
# ==================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ZERO TRUST USB SECURITY ENGINE")
        self.resize(1280, 760)
        self.setMinimumSize(1000, 600)

        root = QWidget()
        self.setCentralWidget(root)
        main = QHBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        self.sidebar = Sidebar(self.navigate, self.scan_drive)
        main.addWidget(self.sidebar)

        sep = QFrame(); sep.setObjectName("Separator"); sep.setFixedWidth(1)
        main.addWidget(sep)

        self.stack = QStackedWidget()
        main.addWidget(self.stack, 1)

        self.home    = HomePage(self.start_default_scan)
        self.scan    = ScanPage()
        self.history = HistoryPage(self.open_detail)
        self.detail  = DetailPage()

        for w in (self.home, self.scan, self.history, self.detail):
            self.stack.addWidget(w)

        self.scan.scan_complete.connect(lambda _: self.sidebar.refresh_threat_count())
        self.navigate("home")

    def navigate(self, page: str):
        if page == "home":     self.stack.setCurrentWidget(self.home)
        elif page == "scan":   self.stack.setCurrentWidget(self.scan)
        elif page == "history":
            self.history.refresh()
            self.stack.setCurrentWidget(self.history)

    def start_default_scan(self):
        drives = get_available_drives()
        self.scan_drive(drives[0] if drives else "C:\\")

    def scan_drive(self, drive: str):
        self.stack.setCurrentWidget(self.scan)
        self.scan.run_scan(drive)

    def open_detail(self, log: dict):
        self.detail.show_log(log)
        self.stack.setCurrentWidget(self.detail)


# ==================================================
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    if os.path.exists(QSS_PATH):
        with open(QSS_PATH, "r") as f:
            app.setStyleSheet(f.read())

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
