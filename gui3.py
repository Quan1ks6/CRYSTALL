import sys, os, json, glob, math, random, base64, urllib.request, re, time, winreg, subprocess
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from runner import Runner, is_admin, relaunch_as_admin, service_installed, install_service, uninstall_service
    from builder import build_proxy, build_tun, build_tun_via_socks, build_vless_tun_native
    from xray_builder import build_vless_proxy, build_vless_backend
    from hy2_parser import parse_hy2
    from vless_parser import parse_vless
    from pinger import TcpPingThread, UrlPingThread
    import cluster_manager as cm
except ImportError:
    def is_admin(): return False
    def relaunch_as_admin(): return False
    def service_installed(): return False
    def install_service(): return False, 'stub'
    def uninstall_service(): return False, 'stub'
    class Runner:
        def __init__(self): self.proc = None
        def stop(self): self.proc = None
        def start(self, cfg, is_tun, pwd=None, core="singbox"): self.proc = "running"; return True
        def check_alive(self): return True
    def build_proxy(p, s=None): return {}
    def build_tun(p, s=None): return {}
    def build_tun_via_socks(p, port=2081, s=None): return {}
    def build_vless_tun_native(p, s=None): return {}
    def build_vless_proxy(p, s=None): return {}
    def build_vless_backend(p, socks_port=2082): return {}
    def parse_hy2(u): return {"protocol": "hysteria2", "name": "Test", "host": "127.0.0.1", "port": 443}
    def parse_vless(u): return {"protocol": "vless", "name": "Test", "host": "127.0.0.1", "port": 443}
    class TcpPingThread(QThread):
        result = pyqtSignal(bool, float)
        def __init__(self, h, p, t=5.0): super().__init__()
        def run(self): QThread.msleep(300); self.result.emit(True, 55.0)
    class UrlPingThread(QThread):
        result = pyqtSignal(bool, float, int)
        def __init__(self, url="", proxy=None, timeout=10.0): super().__init__()
        def run(self): QThread.msleep(400); self.result.emit(True, 42.0, 204)
    import types
    cm = types.SimpleNamespace(
        CLUSTERS_DIR=os.path.join(os.path.dirname(os.path.abspath(__file__)), "clusters"),
        list_cluster_files=lambda: [],
        load_cluster=lambda p: {},
        save_cluster=lambda p, d: None,
        create_empty_cluster=lambda name, mode="proxy", color=None: "",
        create_subscription_cluster=lambda name, url, profiles, color=None: "",
        delete_cluster=lambda p: None,
        update_cluster_meta=lambda *a, **k: None,
        add_manual_inbound=lambda p, link: {},
        delete_inbound=lambda p, i: None,
        rename_inbound=lambda p, i, n: None,
        refresh_subscription=lambda p, timeout=15.0: 0,
        DEFAULT_PALETTE=["#7c3aed"],
    )

# ── Пути ──────────────────────────────────────────────────────────────────────
_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
        else os.path.dirname(os.path.abspath(__file__))
CLUSTERS_DIR  = os.path.join(_BASE, "clusters")
RULES_FILE    = os.path.join(_BASE, "rules.txt")
PRESETS_FILE  = os.path.join(_BASE, "presets.json") 
LOG_FILE      = os.path.join(_BASE, "logs", "sb.log")
XRAY_LOG_FILE = os.path.join(_BASE, "logs", "xray.log")
SETTINGS_FILE = os.path.join(_BASE, "settings.json")
os.makedirs(CLUSTERS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ── Сохранение/восстановление сессии ─────────────────────────────────────────
SESSION_FILE = os.path.join(_BASE, "session.json")

def save_session(profile: dict, mode: str, cluster_file: str):
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump({"profile": profile, "mode": mode, "cluster_file": cluster_file}, f, indent=2)
    except Exception:
        pass

def load_session() -> dict | None:
    try:
        with open(SESSION_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def clear_session():
    try:
        os.remove(SESSION_FILE)
    except Exception:
        pass

# ── Автостарт Windows (реестр) ────────────────────────────────────────────────
APP_NAME    = "sb-hy2"

def get_autostart() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except OSError:
        return False

def set_autostart(enable: bool):
    try:
        if enable:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                exe_path = os.path.abspath(sys.argv[0])
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        else:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS) as key:
                try: winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError: pass
    except OSError:
        pass


# ── Настройки ─────────────────────────────────────────────────────────────────
def load_settings() -> dict:
    defaults = {
        "autostart": False,
        "silent_start": False,
        "restore_session": True,
        "tun_stack": "system",
        "tun_mtu": 1500,
        "tun_auto_route": True,
        "tun_strict_route": True,
        "sniff": True,
        "route_exclude_auto_gw": True,
        "route_exclude_address": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
        "service_port": 33212,
        "dns_upstream": "1.1.1.1",
        "dns_no_leak":  True,
        "log_to_file":  True,
        "delete_logs_on_exit":  False,
        "use_gen_config":       True,
        "custom_config_path":   "",
        "xray_udp_encoding":    "none",
    }
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            loaded = json.load(f)
        # Мержим: не затираем новые дефолты если ключа нет
        for k, v in defaults.items():
            loaded.setdefault(k, v)
        return loaded
    except Exception:
        return defaults

def save_settings(s: dict):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)

# ── Обновление подписок ───────────────────────────────────────────────────────
class SubUpdateWorker(QThread):
    progress = pyqtSignal(str)   
    finished = pyqtSignal(int, int)  

    def run(self):
        updated = 0; errors = 0
        for f in cm.list_cluster_files():
            try:
                d = cm.load_cluster(f)
                if not d.get("source_url"):
                    continue
                self.progress.emit(d.get("name", f))
                cm.refresh_subscription(f)
                updated += 1
            except Exception as e:
                print(f"Sub update error {f}: {e}"); errors += 1
        self.finished.emit(updated, errors)

# ── Обновление resolved_ip во всех кластерах ─────────────────────────────────
class ResolveWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(int)

    def run(self):
        from hy2_parser import _resolve
        count = 0
        for f in glob.glob(os.path.join(CLUSTERS_DIR, "*.clust")):
            try:
                with open(f, encoding="utf-8") as j: d = json.load(j)
                changed = False
                for p in d.get("profiles", []):
                    host = p.get("host", "")
                    if not host: continue
                    self.progress.emit(host)
                    # Используем vless_parser._resolve для vless (он тот же алгоритм)
                    # hy2_parser._resolve совместим с обоими
                    new_ip = _resolve(host)
                    if new_ip and new_ip != p.get("resolved_ip"):
                        p["resolved_ip"] = new_ip; changed = True; count += 1
                if changed:
                    with open(f, "w", encoding="utf-8") as j:
                        json.dump(d, j, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Resolve error {f}: {e}")
        self.finished.emit(count)

# ── Цвета и стили ─────────────────────────────────────────────────────────────
C_ACCENT = QColor("#7c3aed")
C_ON     = QColor("#10b981")
C_OFF    = QColor("#ef4444")

def btn_style(accent=False, danger=False) -> str:
    if accent:
        return (
            "QPushButton{"
            "background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            "stop:0 #8b5cf6,stop:1 #7c3aed);"
            "color:#fff;border:1px solid #6d28d9;"
            "border-radius:7px;padding:8px 16px;"
            "font-family:monospace;font-weight:bold;font-size:10px;}"
            "QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            "stop:0 #9d70ff,stop:1 #8b5cf6);}"
            "QPushButton:pressed{background:#6d28d9;}"
            "QPushButton:disabled{background:#2d2d4e;color:#555;border-color:#333;}"
        )
    if danger:
        return (
            "QPushButton{"
            "background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            "stop:0 #f87171,stop:1 #ef4444);"
            "color:#fff;border:1px solid #dc2626;"
            "border-radius:7px;padding:8px 16px;"
            "font-family:monospace;font-weight:bold;font-size:10px;}"
            "QPushButton:hover{background:#f87171;}"
            "QPushButton:pressed{background:#dc2626;}"
        )
    return (
        "QPushButton{"
        "background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        "stop:0 #2a2a45,stop:1 #1e1e38);"
        "color:#94a3b8;border:1px solid #334155;"
        "border-radius:7px;padding:8px 16px;"
        "font-family:monospace;font-weight:bold;font-size:10px;}"
        "QPushButton:hover{color:#e2e8f0;border-color:#7c3aed;"
        "background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        "stop:0 #2e2e50,stop:1 #252540);}"
        "QPushButton:pressed{background:#1a1a30;}"
        "QPushButton:disabled{background:#151528;color:#444;border-color:#222;}"
    )

def input_style() -> str:
    return (
        "QLineEdit,QComboBox{"
        "background:#1a1a30;color:#e2e8f0;"
        "border:1px solid #334155;border-radius:6px;"
        "padding:5px 8px;font-family:monospace;font-size:10px;}"
        "QLineEdit:focus,QComboBox:focus{border-color:#7c3aed;}"
        "QComboBox::drop-down{border:none;width:20px;}"
        "QComboBox QAbstractItemView{background:#1a1a30;color:#e2e8f0;"
        "border:1px solid #334155;selection-background-color:#7c3aed;}"
    )

def table_style() -> str:
    return (
        "QTableWidget,QTreeWidget{"
        "background:#0f172a;border:1px solid #2d3748;"
        "border-radius:8px;gridline-color:#1e293b;color:#e2e8f0;}"
        "QTableWidget::item,QTreeWidget::item{padding:3px;}"
        "QTableWidget::item:selected,QTreeWidget::item:selected{background:#7c3aed;}"
        "QHeaderView::section{"
        "background:#1e2a3a;border:none;border-bottom:1px solid #334155;"
        "padding:5px 4px;color:#7c9cbf;font-family:monospace;font-size:9px;"
        "font-weight:bold;}"
        "QHeaderView{background:#1e2a3a;}"
        # Угловая кнопка "выделить всё" (пересечение заголовков) — по умолчанию
        # белый квадрат, который выбивается из тёмной палитры.
        "QTableCornerButton::section{"
        "background:#1e2a3a;border:none;border-bottom:1px solid #334155;}"
        "QScrollBar:vertical{background:#0f172a;width:8px;border-radius:4px;}"
        "QScrollBar::handle:vertical{background:#334155;border-radius:4px;min-height:20px;}"
        "QScrollBar::handle:vertical:hover{background:#7c3aed;}"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0px;}"
    )

def dialog_style() -> str:
    return (
        "QDialog{background:#13131f;color:#e2e8f0;font-family:monospace;border-radius:12px;}"
        "QLabel{color:#94a3b8;font-family:monospace;font-size:10px;}"
    )

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
def strip_ansi(s): return ANSI_RE.sub('', s)

def fmt_bytes(n: int) -> str:
    if n < 1024: return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    if n < 1024**3: return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.2f} GB"

# ── ФОН: ЖИВАЯ СЕТКА ──────────────────────────────────────────────────────────
class BackgroundWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pts = [{"pos": QPointF(random.random()*800, random.random()*900),
                     "v":   QPointF((random.random()-.5)*1.2, (random.random()-.5)*1.2)}
                    for _ in range(55)]
        QTimer(self, timeout=self.update, interval=33).start()

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#1a1a2e"))
        for pt in self.pts:
            pt["pos"] += pt["v"]
            if not (0 < pt["pos"].x() < w): pt["v"].setX(-pt["v"].x())
            if not (0 < pt["pos"].y() < h): pt["v"].setY(-pt["v"].y())
        for i, a in enumerate(self.pts):
            for b in self.pts[i+1:]:
                d = math.hypot(a["pos"].x()-b["pos"].x(), a["pos"].y()-b["pos"].y())
                if d < 120:
                    p.setPen(QPen(QColor(124,58,237,int(130*(1-d/120))), 1))
                    p.drawLine(a["pos"], b["pos"])
        p.setBrush(QColor(124,58,237,180)); p.setPen(Qt.PenStyle.NoPen)
        for pt in self.pts: p.drawEllipse(pt["pos"], 1.5, 1.5)

# ── КНОПКА-ЛЕПЕСТОК ───────────────────────────────────────────────────────────
class CyberBlade(QWidget):
    clicked = pyqtSignal()
    def __init__(self, label, angle, parent=None):
        super().__init__(parent)
        self.label, self.angle, self.hover_progress = label, angle, 0.0
        self.setFixedSize(170, 70)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.anim = QVariantAnimation(self, duration=200, startValue=0.0, endValue=1.0)
        self.anim.valueChanged.connect(lambda v: setattr(self,'hover_progress',v) or self.update())

    def enterEvent(self, _):
        self.anim.setDirection(QAbstractAnimation.Direction.Forward)
        if self.anim.state() != QAbstractAnimation.State.Running: self.anim.start()
    def leaveEvent(self, _):
        self.anim.setDirection(QAbstractAnimation.Direction.Backward)
        if self.anim.state() != QAbstractAnimation.State.Running: self.anim.start()
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton: self.clicked.emit()

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.translate(self.width()/2, self.height()/2)
        p.rotate(self.angle)
        bw = 100 + 28*self.hover_progress
        bh = 12  + 10*self.hover_progress
        off = 12
        path = QPainterPath()
        path.moveTo(-bw/2+off, -bh/2); path.lineTo(bw/2, -bh/2)
        path.lineTo(bw/2-off,   bh/2); path.lineTo(-bw/2, bh/2)
        path.closeSubpath()
        p.setBrush(QColor(0,0,0,int(200+55*self.hover_progress)))
        p.setPen(QPen(QColor(
            int(45+(C_ACCENT.red()-45)*self.hover_progress),
            int(45+(C_ACCENT.green()-45)*self.hover_progress),
            int(68+(C_ACCENT.blue()-68)*self.hover_progress)), 1.5))
        p.drawPath(path)
        if self.hover_progress > 0.05:
            p.setPen(QColor(226,232,240,int(255*self.hover_progress)))
            p.setFont(QFont("monospace", 8, QFont.Weight.Bold))
            p.drawText(QRectF(-bw/2,-bh/2,bw,bh), Qt.AlignmentFlag.AlignCenter, self.label)

# ── ЦЕНТРАЛЬНЫЙ АЛМАЗ ─────────────────────────────────────────────────────────
class DiamondWidget(QWidget):
    clicked = pyqtSignal()
    def __init__(self, parent=None):
        super().__init__(parent); self.state="idle"; self._phase=0.0
        self.setFixedSize(160,210); self.setCursor(Qt.CursorShape.PointingHandCursor)
        QTimer(self, timeout=self._tick, interval=30).start()
    def _tick(self): self._phase+=0.08; self.update()
    def set_state(self, s): self.state=s; self.update()
    def mousePressEvent(self, _): self.clicked.emit()
    def paintEvent(self, _):
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx,cy=80,105; c={"on":C_ON,"off":C_OFF}.get(self.state,C_ACCENT)
        pulse=math.sin(self._phase)*8
        g=QRadialGradient(cx,cy,75+pulse)
        g.setColorAt(0,QColor(c.red(),c.green(),c.blue(),60)); g.setColorAt(1,QColor(0,0,0,0))
        p.setBrush(g); p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(cx-75-pulse,cy-75-pulse,(75+pulse)*2,(75+pulse)*2))
        path=QPainterPath()
        path.moveTo(cx,cy-65); path.lineTo(cx+38,cy)
        path.lineTo(cx,cy+65); path.lineTo(cx-38,cy); path.closeSubpath()
        p.setBrush(c); p.drawPath(path)
        p.setPen(Qt.GlobalColor.white); p.setFont(QFont("monospace",10,QFont.Weight.Bold))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.state.upper())

# ── ИНДИКАТОР-ЛЕПЕСТОК ────────────────────────────────────────────────────────
class PetalIndicator(QWidget):
    """
    Маленький лепесток-индикатор с тремя состояниями:
      'inactive' — тёмный (не активен)
      'active'   — зелёный (работает)
      'error'    — красный (упал / ошибка)

    Кликабелен: по клику эмиттит clicked(label) — MainWindow показывает
    меню 'Kill process / Выйти' (см. _on_indicator_clicked).
    """
    clicked = pyqtSignal(str)

    _COLORS = {
        "inactive": (QColor("#1e293b"), QColor("#334155")),   # fill, border
        "active":   (QColor("#064e3b"), QColor("#10b981")),
        "error":    (QColor("#450a0a"), QColor("#ef4444")),
    }

    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.label  = label
        self._state = "inactive"
        self._phase = random.random() * 6.28   # случайный сдвиг пульса
        self.setFixedSize(80, 36)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._timer = QTimer(self, interval=40, timeout=self._tick)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.label)

    def _tick(self):
        self._phase += 0.10
        self.update()

    def set_state(self, state: str):
        """state: 'inactive' | 'active' | 'error'"""
        if state == self._state:
            return
        self._state = state
        if state in ("active", "error"):
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    @property
    def state(self) -> str:
        return self._state

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        fill_c, border_c = self._COLORS.get(self._state, self._COLORS["inactive"])

        # Пульс для активных состояний
        pulse = 0.0
        if self._state != "inactive":
            pulse = math.sin(self._phase) * 0.18

        # Лепесток — параллелограмм с закруглёнными углами
        off = 6
        path = QPainterPath()
        path.moveTo(off,       2)
        path.lineTo(W - 2,     2)
        path.lineTo(W - 2 - off, H - 2)
        path.lineTo(2,         H - 2)
        path.closeSubpath()

        # Свечение
        if self._state != "inactive":
            alpha = int(40 + 30 * pulse)
            glow_c = QColor(border_c.red(), border_c.green(), border_c.blue(), alpha)
            g = QRadialGradient(W / 2, H / 2, W * 0.7)
            g.setColorAt(0, glow_c)
            g.setColorAt(1, QColor(0, 0, 0, 0))
            p.setBrush(g)
            p.setPen(Qt.PenStyle.NoPen)
            inflate = int(4 + 3 * pulse)
            p.drawEllipse(QRectF(-inflate, -inflate, W + inflate*2, H + inflate*2))

        # Тело
        bc = QColor(border_c.red(), border_c.green(), border_c.blue(),
                    int(200 + 55 * (1 + pulse)))
        p.setBrush(fill_c)
        p.setPen(QPen(bc, 1.2))
        p.drawPath(path)

        # Лейбл
        lbl_c = border_c if self._state != "inactive" else QColor("#475569")
        p.setPen(lbl_c)
        p.setFont(QFont("monospace", 7, QFont.Weight.Bold))
        p.drawText(QRectF(0, 0, W, H - 2), Qt.AlignmentFlag.AlignCenter, self.label)


# ── ТУМБЛЕР PROXY / TUN ───────────────────────────────────────────────────────
class ModeToggle(QWidget):
    toggled = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self._mode="proxy"; self._anim_pos=0.0
        self.setFixedSize(130,28); self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._anim = QVariantAnimation(self, duration=180, startValue=0.0, endValue=1.0)
        self._anim.valueChanged.connect(lambda v: setattr(self,'_anim_pos',v) or self.update())

    @property
    def mode(self): return self._mode

    def set_mode(self, m: str):
        if m == self._mode: return
        self._mode = m
        self._anim.setDirection(QAbstractAnimation.Direction.Forward if m=="tun"
                                else QAbstractAnimation.Direction.Backward)
        if self._anim.state() != QAbstractAnimation.State.Running: self._anim.start()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            new = "tun" if self._mode=="proxy" else "proxy"
            self.set_mode(new); self.toggled.emit(new)

    def paintEvent(self, _):
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W,H=self.width(),self.height()
        p.setBrush(QColor("#0f172a")); p.setPen(QPen(C_ACCENT,1))
        p.drawRoundedRect(0,0,W,H,H//2,H//2)
        pad=3; sw=W//2-pad; sx=pad+self._anim_pos*(W//2-pad)
        g=QLinearGradient(sx,0,sx+sw,0)
        g.setColorAt(0,C_ACCENT.darker(120)); g.setColorAt(1,C_ACCENT)
        p.setBrush(g); p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(sx,pad,sw,H-pad*2),(H-pad*2)//2,(H-pad*2)//2)
        p.setFont(QFont("monospace",8,QFont.Weight.Bold))
        p.setPen(Qt.GlobalColor.white if self._mode=="proxy" else QColor("#64748b"))
        p.drawText(QRectF(0,0,W//2,H), Qt.AlignmentFlag.AlignCenter, "PROXY")
        p.setPen(Qt.GlobalColor.white if self._mode=="tun" else QColor("#64748b"))
        p.drawText(QRectF(W//2,0,W//2,H), Qt.AlignmentFlag.AlignCenter, "TUN")

# ── КНОПКА ШЕСТЕРЁНКИ ─────────────────────────────────────────────────────────
class GearButton(QWidget):
    clicked = pyqtSignal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(32,32); self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hover = False
        self._phase = 0.0
        self._timer = QTimer(self, interval=30, timeout=self._tick)

    def _tick(self):
        self._phase += 0.05; self.update()

    def enterEvent(self, _):
        self._hover = True; self._timer.start(); self.update()
    def leaveEvent(self, _):
        self._hover = False; self._timer.stop(); self.update()
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton: self.clicked.emit()

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = C_ACCENT if self._hover else QColor("#475569")
        p.translate(16, 16)
        if self._hover: p.rotate(math.degrees(self._phase))
        teeth = 8; r_out = 12; r_in = 8; r_hole = 4
        path = QPainterPath()
        for i in range(teeth*2):
            angle = math.pi * i / teeth
            r = r_out if i%2==0 else r_in
            x,y = r*math.cos(angle), r*math.sin(angle)
            if i==0: path.moveTo(x,y)
            else: path.lineTo(x,y)
        path.closeSubpath()
        p.setBrush(c); p.setPen(Qt.PenStyle.NoPen); p.drawPath(path)
        p.setBrush(QColor("#1a1a2e")); p.drawEllipse(QPointF(0,0), r_hole, r_hole)

# ── ДИАЛОГ НАСТРОЕК ───────────────────────────────────────────────────────────
class SettingsDialog(QDialog):
    """
    Настройки с боковой навигацией через QStackedWidget.
    Страницы: APP  |  TUN & NETWORK  |  SERVICE
    Все данные буферизуются в self._s и сохраняются одной кнопкой.
    """
    _COMMON = (
        "QCheckBox{color:#e2e8f0;font-family:monospace;font-size:10px;spacing:8px;}"
        "QCheckBox::indicator{width:15px;height:15px;border-radius:4px;"
        "border:1px solid #334155;background:#1a1a30;}"
        "QCheckBox::indicator:checked{background:#7c3aed;border-color:#7c3aed;}"
        "QGroupBox{color:#7c3aed;font-family:monospace;font-size:10px;font-weight:bold;"
        "border:1px solid #2d3748;border-radius:8px;margin-top:8px;padding-top:8px;}"
        "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;}"
        "QListWidget{background:#1a1a30;color:#e2e8f0;border:1px solid #334155;"
        "border-radius:6px;font-family:monospace;font-size:10px;}"
        "QListWidget::item{padding:3px 6px;}"
        "QListWidget::item:selected{background:#7c3aed;border-radius:3px;}"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SETTINGS")
        self.setFixedSize(460, 500)
        self.setStyleSheet(dialog_style() + self._COMMON)
        self._s = load_settings()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        self._hdr = QLabel("⚙  SETTINGS")
        self._hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hdr.setStyleSheet(
            "background:#0d0d1a;color:#7c3aed;font-family:monospace;font-size:11px;"
            "font-weight:bold;letter-spacing:2px;padding:10px;"
            "border-bottom:1px solid #2d3748;")
        root.addWidget(self._hdr)

        # ── Stack ─────────────────────────────────────────────────────────────
        self._stack = QStackedWidget()
        root.addWidget(self._stack, 1)

        self._stack.addWidget(self._page_main())     # 0 — главное меню
        self._stack.addWidget(self._page_app())      # 1
        self._stack.addWidget(self._page_tun())      # 2
        self._stack.addWidget(self._page_service())  # 3
        self._stack.addWidget(self._page_dns())      # 4
        self._stack.addWidget(self._page_xray())     # 5

        # ── Bottom bar ────────────────────────────────────────────────────────
        bot = QHBoxLayout()
        bot.setContentsMargins(12, 6, 12, 10)
        bot.setSpacing(8)
        self._b_back = QPushButton("← Назад")
        self._b_back.setStyleSheet(btn_style())
        self._b_back.clicked.connect(self._go_main)
        b_cancel = QPushButton("Отмена"); b_cancel.setStyleSheet(btn_style())
        b_save   = QPushButton("💾 Сохранить"); b_save.setStyleSheet(btn_style(accent=True))
        b_cancel.clicked.connect(self.reject)
        b_save.clicked.connect(self._save)
        bot.addWidget(self._b_back)
        bot.addStretch()
        bot.addWidget(b_cancel)
        bot.addWidget(b_save)
        root.addLayout(bot)

        self._go_main()

    # ── Navigation ────────────────────────────────────────────────────────────
    def _go_main(self):
        self._stack.setCurrentIndex(0)
        self._hdr.setText("⚙  SETTINGS")
        self._b_back.setVisible(False)

    def _go(self, idx: int, title: str):
        self._stack.setCurrentIndex(idx)
        self._hdr.setText(f"⚙  {title}")
        self._b_back.setVisible(True)

    @staticmethod
    def _nav_btn(icon: str, label: str, sub: str) -> QPushButton:
        b = QPushButton()
        b.setText(f"  {icon}   {label}")
        b.setToolTip(sub)
        b.setStyleSheet(
            "QPushButton{background:#16162a;color:#e2e8f0;border:1px solid #2d3748;"
            "border-radius:8px;padding:14px 18px;font-family:monospace;font-size:10px;"
            "text-align:left;}"
            "QPushButton:hover{border-color:#7c3aed;color:#c4b5fd;background:#1c1c34;}"
            "QPushButton:pressed{background:#0f0f20;}")
        return b

    # ── PAGE 0: menu ─────────────────────────────────────────────────────────
    def _page_main(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 20, 20, 8); lay.setSpacing(10)
        items = [
            ("🖥", "APP",          "Автостарт, тихий старт, восстановление сессии", 1),
            ("📡", "TUN & NETWORK","Стек, MTU, маршруты, exclude address",           2),
            ("🔌", "SERVICE",       "Windows-сервис для TUN без UAC",                3),
            ("🌐", "DNS & LOGS",    "DNS-сервер, утечки, запись логов в файл",       4),
            ("⚡", "XRAY SETTINGS", "UDP packet encoding и другие Xray-опции",       5),
        ]
        for icon, lbl, sub, page in items:
            b = self._nav_btn(icon, lbl, sub)
            b.clicked.connect(lambda _=False, p=page, l=lbl: self._go(p, l))
            lay.addWidget(b)
        lay.addStretch()
        return w

    # ── PAGE 1: APP ───────────────────────────────────────────────────────────
    def _page_app(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 8); lay.setSpacing(10)

        grp = QGroupBox("ЗАПУСК"); gl = QVBoxLayout(grp); gl.setSpacing(10)
        self.cb_auto    = QCheckBox("Автостарт при загрузке Windows")
        self.cb_silent  = QCheckBox("Тихий старт  (сразу в трей)")
        self.cb_restore = QCheckBox("Восстанавливать последнюю сессию")
        self.cb_auto.setChecked(get_autostart())
        self.cb_silent.setChecked(self._s.get("silent_start", False))
        self.cb_restore.setChecked(self._s.get("restore_session", True))
        for cb in [self.cb_auto, self.cb_silent, self.cb_restore]:
            gl.addWidget(cb)
        lay.addWidget(grp)

        log_grp = QGroupBox("ЛОГИ"); ll = QVBoxLayout(log_grp); ll.setSpacing(8)
        self.cb_log_to_file = QCheckBox("Записывать логи ядра в файл  (logs/sb.log / xray.log)")
        self.cb_log_to_file.setChecked(self._s.get("log_to_file", True))
        ll.addWidget(self.cb_log_to_file)
        self.cb_delete_logs_on_exit = QCheckBox("Очищать логи при выходе из приложения")
        self.cb_delete_logs_on_exit.setChecked(self._s.get("delete_logs_on_exit", False))
        ll.addWidget(self.cb_delete_logs_on_exit)
        lay.addWidget(log_grp)

        gen_grp = QGroupBox("КОНФИГ"); gl2 = QVBoxLayout(gen_grp); gl2.setSpacing(8)
        self.cb_use_gen_config = QCheckBox("Использовать генерируемый конфиг  (по умолчанию)")
        self.cb_use_gen_config.setChecked(self._s.get("use_gen_config", True))
        gl2.addWidget(self.cb_use_gen_config)
        custom_row = QHBoxLayout(); custom_row.setSpacing(6)
        self.le_custom_config = QLineEdit(self._s.get("custom_config_path", ""))
        self.le_custom_config.setPlaceholderText("Путь к своему config.json / config.yaml...")
        self.le_custom_config.setStyleSheet(input_style())
        b_browse = QPushButton("📂"); b_browse.setFixedWidth(30)
        b_browse.setStyleSheet(btn_style())
        b_browse.clicked.connect(self._browse_config)
        custom_row.addWidget(self.le_custom_config); custom_row.addWidget(b_browse)
        gl2.addLayout(custom_row)
        self.cb_use_gen_config.toggled.connect(self.le_custom_config.setDisabled)
        self.le_custom_config.setDisabled(self._s.get("use_gen_config", True))
        lay.addWidget(gen_grp)

        lay.addStretch()
        return w

    # ── PAGE 2: TUN ───────────────────────────────────────────────────────────
    def _page_tun(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 8); lay.setSpacing(10)

        # Core settings
        grp1 = QGroupBox("TUN CORE"); g1 = QVBoxLayout(grp1); g1.setSpacing(8)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Stack:"))
        self.cb_stack = QComboBox(); self.cb_stack.addItems(["system","gvisor","lwip"])
        self.cb_stack.setCurrentText(self._s.get("tun_stack","system"))
        self.cb_stack.setStyleSheet(input_style()); r1.addWidget(self.cb_stack)
        g1.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("MTU:"))
        self.le_mtu = QLineEdit(str(self._s.get("tun_mtu", 1500)))
        self.le_mtu.setStyleSheet(input_style()); r2.addWidget(self.le_mtu)
        g1.addLayout(r2)

        self.cb_auto_route   = QCheckBox("Auto Route")
        self.cb_strict_route = QCheckBox("Strict Route")
        self.cb_sniff        = QCheckBox("Sniff (определение протокола)")
        self.cb_auto_route.setChecked(self._s.get("tun_auto_route", True))
        self.cb_strict_route.setChecked(self._s.get("tun_strict_route", True))
        self.cb_sniff.setChecked(self._s.get("sniff", True))
        for cb in [self.cb_auto_route, self.cb_strict_route, self.cb_sniff]:
            g1.addWidget(cb)
        lay.addWidget(grp1)

        # Route exclude
        grp2 = QGroupBox("ROUTE EXCLUDE ADDRESS"); g2 = QVBoxLayout(grp2); g2.setSpacing(6)
        self.cb_auto_gw = QCheckBox("Автоматически добавлять шлюз (/32) при запуске")
        self.cb_auto_gw.setChecked(self._s.get("route_exclude_auto_gw", True))
        g2.addWidget(self.cb_auto_gw)

        self.excl_list = QListWidget(); self.excl_list.setFixedHeight(68)
        for cidr in self._s.get("route_exclude_address",
                                 ["192.168.0.0/16","10.0.0.0/8","172.16.0.0/12"]):
            self.excl_list.addItem(cidr)
        g2.addWidget(self.excl_list)

        er = QHBoxLayout(); er.setSpacing(5)
        self.le_excl = QLineEdit(); self.le_excl.setPlaceholderText("x.x.x.x/xx")
        self.le_excl.setStyleSheet(input_style()); er.addWidget(self.le_excl, 1)
        for lbl, fn, acc, dng in [("+ADD", self._excl_add, True, False),
                                   ("✕",   self._excl_del, False, True),
                                   ("⚡GW", self._excl_detect_gw, False, False)]:
            b = QPushButton(lbl); b.setFixedWidth(50 if lbl=="+ADD" else 36)
            b.setStyleSheet(btn_style(accent=acc, danger=dng))
            b.clicked.connect(fn); er.addWidget(b)
        g2.addLayout(er)
        lay.addWidget(grp2); lay.addStretch()
        return w

    # ── PAGE 3: SERVICE ───────────────────────────────────────────────────────
    def _page_service(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 8); lay.setSpacing(10)

        grp = QGroupBox("WINDOWS SERVICE  (sb-hy2)"); gl = QVBoxLayout(grp); gl.setSpacing(8)

        port_row = QHBoxLayout(); port_row.setSpacing(6)
        port_row.addWidget(QLabel("HTTP API порт:"))
        self.le_svc_port = QLineEdit(str(self._s.get("service_port", 33212)))
        self.le_svc_port.setStyleSheet(input_style())
        self.le_svc_port.setFixedWidth(80)
        port_row.addWidget(self.le_svc_port)
        port_row.addStretch()
        gl.addLayout(port_row)
        gl.addStretch()

        self.task_status = QLabel("")
        self.task_status.setStyleSheet("font-family:monospace;font-size:9px;")
        self._refresh_task_status()
        gl.addWidget(self.task_status)

        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        self.b_install = QPushButton("⚡ Install Service")
        self.b_delete  = QPushButton("✕ Delete Service")
        self.b_install.setStyleSheet(btn_style(accent=True))
        self.b_delete.setStyleSheet(btn_style(danger=True))
        self.b_install.clicked.connect(self._install_task)
        self.b_delete.clicked.connect(self._delete_task)
        btn_row.addWidget(self.b_install); btn_row.addWidget(self.b_delete)
        gl.addLayout(btn_row)
        lay.addWidget(grp); lay.addStretch()
        return w

    # ── PAGE 4: DNS & LOGS ───────────────────────────────────────────────────
    def _page_dns(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 8); lay.setSpacing(10)

        # DNS
        dns_grp = QGroupBox("DNS"); dl = QVBoxLayout(dns_grp); dl.setSpacing(10)
        row_up = QHBoxLayout(); row_up.setSpacing(6)
        row_up.addWidget(QLabel("Upstream:"))
        self.le_dns_upstream = QLineEdit(self._s.get("dns_upstream", "1.1.1.1"))
        self.le_dns_upstream.setStyleSheet(input_style())
        self.le_dns_upstream.setFixedWidth(130)
        row_up.addWidget(self.le_dns_upstream)
        for label, ip in [("CF", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9"), ("AdGuard", "94.140.14.14")]:
            b = QPushButton(label); b.setFixedHeight(22); b.setFixedWidth(58)
            b.setStyleSheet(btn_style())
            b.clicked.connect(lambda _, v=ip: self.le_dns_upstream.setText(v))
            row_up.addWidget(b)
        row_up.addStretch()
        dl.addLayout(row_up)


        self.cb_no_leak = QCheckBox("Без DNS-утечек  (Fake-IP)  [только TUN]")
        self.cb_no_leak.setChecked(self._s.get("dns_no_leak", True))
        dl.addWidget(self.cb_no_leak)
        lay.addWidget(dns_grp)

        lay.addStretch()
        return w

    # ── PAGE 5: XRAY SETTINGS ────────────────────────────────────────────────
    def _page_xray(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 8); lay.setSpacing(10)

        grp = QGroupBox("VLESS / XRAY"); gl = QVBoxLayout(grp); gl.setSpacing(10)

        enc_row = QHBoxLayout(); enc_row.setSpacing(8)
        enc_row.addWidget(QLabel("UDP Packet Encoding:"))
        self.cb_udp_enc = QComboBox()
        self.cb_udp_enc.addItems(["none", "xudp", "packetaddr"])
        self.cb_udp_enc.setCurrentText(self._s.get("xray_udp_encoding", "none"))
        self.cb_udp_enc.setStyleSheet(input_style())
        enc_row.addWidget(self.cb_udp_enc); enc_row.addStretch()
        gl.addLayout(enc_row)

        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _browse_config(self):
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать конфиг", "",
            "Config files (*.json *.yaml *.yml);;All files (*)")
        if path:
            self.le_custom_config.setText(path)

    # ── Helpers: exclude address ──────────────────────────────────────────────
    def _excl_add(self):
        val = self.le_excl.text().strip()
        if not val: return
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', val):
            QMessageBox.warning(self, "Ошибка", f"Неверный CIDR: {val}"); return
        existing = [self.excl_list.item(i).text() for i in range(self.excl_list.count())]
        if val not in existing: self.excl_list.addItem(val)
        self.le_excl.clear()

    def _excl_del(self):
        for item in self.excl_list.selectedItems():
            self.excl_list.takeItem(self.excl_list.row(item))

    def _excl_detect_gw(self):
        try:
            from builder import get_default_gateway; gw = get_default_gateway()
        except Exception: gw = None
        if not gw:
            QMessageBox.information(self, "Auto GW", "Шлюз не определён."); return
        cidr = f"{gw}/32"
        existing = [self.excl_list.item(i).text() for i in range(self.excl_list.count())]
        if cidr not in existing:
            self.excl_list.addItem(cidr)
            QMessageBox.information(self, "Auto GW", f"Добавлено: {cidr}")
        else:
            QMessageBox.information(self, "Auto GW", f"Уже в списке: {cidr}")

    # ── Helpers: service ─────────────────────────────────────────────────────
    def _refresh_task_status(self):
        if service_installed():
            self.task_status.setText("● Статус: УСТАНОВЛЕН")
            self.task_status.setStyleSheet("color:#10b981;font-family:monospace;font-size:9px;")
        else:
            self.task_status.setText("○ Статус: не установлен")
            self.task_status.setStyleSheet("color:#64748b;font-family:monospace;font-size:9px;")

    def _install_task(self):
        self.b_install.setEnabled(False)
        self.task_status.setText("Устанавливаем... (UAC)")
        self.task_status.setStyleSheet("color:#f59e0b;font-family:monospace;font-size:9px;")
        QApplication.processEvents()
        ok, msg = install_service()
        self._refresh_task_status(); self.b_install.setEnabled(True)
        if ok: QMessageBox.information(self, "Готово", "Сервис установлен!")
        else:  QMessageBox.warning(self, "Ошибка", f"Не удалось:\n{msg}")

    def _delete_task(self):
        self.b_delete.setEnabled(False)
        self.task_status.setText("Удаляем... (UAC)")
        self.task_status.setStyleSheet("color:#f59e0b;font-family:monospace;font-size:9px;")
        QApplication.processEvents()
        ok, msg = uninstall_service()
        self._refresh_task_status(); self.b_delete.setEnabled(True)
        if ok: QMessageBox.information(self, "Готово", "Сервис удалён.")
        else:  QMessageBox.warning(self, "Ошибка", f"Не удалось:\n{msg}")

    # ── Save ──────────────────────────────────────────────────────────────────
    def _save(self):
        set_autostart(self.cb_auto.isChecked())
        self._s["silent_start"]    = self.cb_silent.isChecked()
        self._s["restore_session"] = self.cb_restore.isChecked()

        self._s["tun_stack"]        = self.cb_stack.currentText()
        try:    self._s["tun_mtu"]  = int(self.le_mtu.text())
        except: self._s["tun_mtu"]  = 1500
        self._s["tun_auto_route"]   = self.cb_auto_route.isChecked()
        self._s["tun_strict_route"] = self.cb_strict_route.isChecked()
        self._s["sniff"]            = self.cb_sniff.isChecked()

        self._s["route_exclude_auto_gw"] = self.cb_auto_gw.isChecked()
        self._s["route_exclude_address"] = [
            self.excl_list.item(i).text() for i in range(self.excl_list.count())]

        try:
            port = int(self.le_svc_port.text())
            if not (1024 <= port <= 65535):
                raise ValueError
            self._s["service_port"] = port
        except ValueError:
            QMessageBox.warning(self, "Ошибка",
                "Порт сервиса должен быть числом 1024–65535.")
            return

        upstream = self.le_dns_upstream.text().strip()
        self._s["dns_upstream"] = upstream or "1.1.1.1"
        self._s["dns_no_leak"]  = self.cb_no_leak.isChecked()
        self._s["log_to_file"]  = self.cb_log_to_file.isChecked()
        self._s["delete_logs_on_exit"]   = self.cb_delete_logs_on_exit.isChecked()
        self._s["use_gen_config"]        = self.cb_use_gen_config.isChecked()
        self._s["custom_config_path"]    = self.le_custom_config.text().strip()
        self._s["xray_udp_encoding"]     = self.cb_udp_enc.currentText()

        save_settings(self._s)
        self.accept()

# ── ПРЕСЕТЫ И РЕДАКТОР ПРАВИЛ ────────────────────────────────────────────────
DEFAULT_PRESETS = {
    "🌐 Global — всё через прокси": [
        {"type":"MATCH","value":"","action":"proxy"}
    ],
    "📍 Rule — Россия напрямую": [
        {"type":"DOMAIN-SUFFIX","value":"ru","action":"direct"},
        {"type":"DOMAIN-SUFFIX","value":"рф","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"yandex","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"vk","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"mail.ru","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"sberbank","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"gosuslugi","action":"direct"},
        {"type":"MATCH","value":"","action":"proxy"},
    ],
    "🔒 Privacy — блок трекеров": [
        {"type":"DOMAIN-KEYWORD","value":"analytics","action":"reject"},
        {"type":"DOMAIN-KEYWORD","value":"tracking","action":"reject"},
        {"type":"DOMAIN-KEYWORD","value":"telemetry","action":"reject"},
        {"type":"DOMAIN-SUFFIX","value":"doubleclick.net","action":"reject"},
        {"type":"DOMAIN-SUFFIX","value":"googlesyndication.com","action":"reject"},
        {"type":"DOMAIN-SUFFIX","value":"adnxs.com","action":"reject"},
        {"type":"MATCH","value":"","action":"proxy"},
    ],
    "🎮 Gaming — игровые серверы напрямую": [
        {"type":"DOMAIN-KEYWORD","value":"steam","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"epicgames","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"battlenet","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"riotgames","action":"direct"},
        {"type":"DOMAIN-KEYWORD","value":"faceit","action":"direct"},
        {"type":"MATCH","value":"","action":"proxy"},
    ],
    "📡 Direct — всё напрямую": [
        {"type":"MATCH","value":"","action":"direct"}
    ],
    "🗑 Очистить всё": [],
}

RULE_TYPES   = ["DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","DOTDOMAIN",
                "PROCESS-NAME","PROCESS-PATH","MATCH"]
RULE_ACTIONS = ["proxy","direct","reject"]

def load_presets() -> dict:
    try:
        with open(PRESETS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_PRESETS.copy()

def save_presets(p: dict):
    with open(PRESETS_FILE, "w", encoding="utf-8") as f:
        json.dump(p, f, indent=2, ensure_ascii=False)

class _RuleTable(QTableWidget):
    """
    QTableWidget с перетаскиванием строк мышью.

    Встроенный QAbstractItemView.DragDropMode.InternalMove у QTableWidget
    двигает данные на уровне отдельных ячеек модели, а не строк целиком —
    из-за этого визуально иногда "теряются" QTableWidgetItem на новой
    позиции строки (выглядит как пустая строка, пока не переоткрыть диалог
    и не вызвать полный _refresh()). Поэтому здесь стандартное поведение
    перетаскивания полностью отключено (event.ignore()), а перестановка
    делается вручную через сигнал — на уровне списка self._rules в
    RulesDialog с последующей полной перерисовкой таблицы.
    """
    rowsReordered = pyqtSignal(int, int)   # from_row, to_row

    def dropEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return
        pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        sel = sorted({i.row() for i in self.selectedIndexes()})
        if not sel:
            event.ignore()
            return
        from_row = sel[0]
        target = self.indexAt(pos).row()
        if target == -1:
            target = self.rowCount() - 1
        event.ignore()   # никогда не пускаем Qt в его собственную реализацию move
        if target != from_row:
            self.rowsReordered.emit(from_row, target)


class RulesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("RULES EDITOR"); self.setFixedSize(700,540)
        self.setStyleSheet(dialog_style())
        self._rules = []
        self._presets = load_presets()
        lay = QVBoxLayout(self); lay.setSpacing(8)

        preset_row = QHBoxLayout(); preset_row.setSpacing(6)
        lbl_p = QLabel("Пресет:")
        lbl_p.setStyleSheet("color:#7c3aed;font-family:monospace;font-size:10px;font-weight:bold;")
        preset_row.addWidget(lbl_p)
        
        self.preset_cb = QComboBox()
        self.preset_cb.addItems(list(self._presets.keys()))
        self.preset_cb.setStyleSheet(input_style())
        preset_row.addWidget(self.preset_cb, 1)
        
        b_load = QPushButton("Загрузить"); b_load.setStyleSheet(btn_style())
        b_save_p = QPushButton("💾 Сохранить"); b_save_p.setStyleSheet(btn_style(accent=True))
        b_del_p = QPushButton("🗑"); b_del_p.setStyleSheet(btn_style(danger=True))
        
        b_load.clicked.connect(self._load_preset)
        b_save_p.clicked.connect(self._save_preset)
        b_del_p.clicked.connect(self._delete_preset)
        
        preset_row.addWidget(b_load)
        preset_row.addWidget(b_save_p)
        preset_row.addWidget(b_del_p)
        lay.addLayout(preset_row)

        self.table = _RuleTable(0,3)
        self.table.setHorizontalHeaderLabels(["TYPE","VALUE","ACTION"])
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0,160); self.table.setColumnWidth(2,80)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(table_style())
        # Перетаскивание строк мышью вместо кнопок ▲/▼
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDropIndicatorShown(True)
        self.table.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.table.rowsReordered.connect(self._reorder_rule)
        lay.addWidget(self.table)

        er = QHBoxLayout(); er.setSpacing(6)
        self.e_type   = QComboBox(); self.e_type.addItems(RULE_TYPES)
        self.e_value  = QLineEdit(); self.e_value.setPlaceholderText("value (пусто для MATCH)")
        self.e_action = QComboBox(); self.e_action.addItems(RULE_ACTIONS)
        self.e_type.currentTextChanged.connect(lambda t: self.e_value.setEnabled(t!="MATCH"))
        for w in [self.e_type, self.e_value, self.e_action]: w.setStyleSheet(input_style())
        er.addWidget(self.e_type,2); er.addWidget(self.e_value,3); er.addWidget(self.e_action,1)
        lay.addLayout(er)

        hint_drag = QLabel("↕ Перетаскивай строки мышью, чтобы изменить порядок")
        hint_drag.setStyleSheet("color:#475569;font-family:monospace;font-size:9px;")
        lay.addWidget(hint_drag)

        br = QHBoxLayout(); br.setSpacing(6)
        btns = [("+ ADD",self._add,False),("✕ DEL",self._delete,False),
                ("💾 SAVE & CLOSE",self._save,True)]
        for label,slot,acc in btns:
            b=QPushButton(label); b.clicked.connect(slot)
            b.setStyleSheet(btn_style(accent=acc))
            br.addWidget(b)
        lay.addLayout(br)
        self._load()

    def _update_cb(self, select_name=""):
        self.preset_cb.clear()
        self.preset_cb.addItems(list(self._presets.keys()))
        if select_name: self.preset_cb.setCurrentText(select_name)

    def _load_preset(self):
        name = self.preset_cb.currentText()
        rules = self._presets.get(name, [])
        if self._rules and rules:
            if QMessageBox.question(self, "Пресет",
                f"Заменить текущие правила пресетом '{name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            ) != QMessageBox.StandardButton.Yes:
                return
        self._rules = [dict(r) for r in rules]
        self._refresh()

    def _save_preset(self):
        if not self._rules:
            QMessageBox.warning(self, "Ошибка", "Нельзя сохранить пустой список правил!")
            return
        name, ok = QInputDialog.getText(self, "Сохранить пресет", "Имя пресета:", text=self.preset_cb.currentText())
        if ok and name.strip():
            name = name.strip()
            self._presets[name] = [dict(r) for r in self._rules]
            save_presets(self._presets)
            self._update_cb(name)
            QMessageBox.information(self, "Успех", f"Пресет '{name}' успешно сохранён!")

    def _delete_preset(self):
        name = self.preset_cb.currentText()
        if not name: return
        if QMessageBox.question(self, "Удалить пресет",
            f"Удалить пресет '{name}' навсегда?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            if name in self._presets:
                del self._presets[name]
                save_presets(self._presets)
                self._update_cb()

    def _load(self):
        self._rules.clear()
        if not os.path.exists(RULES_FILE): self._refresh(); return
        with open(RULES_FILE,encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"): continue
                parts=[x.strip() for x in line.split(",")]
                if parts[0].upper()=="MATCH" and len(parts)>=2:
                    self._rules.append({"type":"MATCH","value":"","action":parts[1]})
                elif len(parts)>=3:
                    self._rules.append({"type":parts[0],"value":parts[1],"action":parts[2]})
        self._refresh()

    def _refresh(self):
        self.table.setRowCount(0)
        colors={"proxy":"#1a2535","direct":"#142514","reject":"#251414"}
        for r in self._rules:
            row=self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row,0,QTableWidgetItem(r["type"]))
            self.table.setItem(row,1,QTableWidgetItem(r["value"]))
            self.table.setItem(row,2,QTableWidgetItem(r["action"]))
            c=QColor(colors.get(r["action"],"#1a2535"))
            for col in range(3): self.table.item(row,col).setBackground(c)

    def _sel_rows(self): return sorted({i.row() for i in self.table.selectedItems()})

    def _add(self):
        t=self.e_type.currentText(); v=self.e_value.text().strip() if t!="MATCH" else ""
        a=self.e_action.currentText()
        if t!="MATCH" and not v:
            QMessageBox.warning(self,"Ошибка","Укажи значение"); return
        self._rules.append({"type":t,"value":v,"action":a})
        self.e_value.clear(); self._refresh(); self.table.scrollToBottom()

    def _delete(self):
        for r in sorted(self._sel_rows(),reverse=True): del self._rules[r]
        self._refresh()

    def _reorder_rule(self, from_row: int, to_row: int):
        """
        Перестановка элемента self._rules на новое место + полная
        перерисовка таблицы из данных. Не трогаем QTableWidgetItem-ы
        напрямую — это и есть лекарство от "пустой строки" после drag&drop.
        """
        if not (0 <= from_row < len(self._rules)):
            return
        rule = self._rules.pop(from_row)
        to_row = max(0, min(to_row, len(self._rules)))
        self._rules.insert(to_row, rule)
        self._refresh()
        self.table.selectRow(to_row)

    def _save(self):
        lines=[]
        for r in self._rules:
            lines.append(f"MATCH,{r['action']}" if r["type"]=="MATCH"
                         else f"{r['type']},{r['value']},{r['action']}")
        with open(RULES_FILE,"w",encoding="utf-8") as f: f.write("\n".join(lines)+"\n")
        self.accept()

# ── ПОТОК СБОРА СОЕДИНЕНИЙ ────────────────────────────────────────────────────
class ConnectionsWorker(QThread):
    updated = pyqtSignal(list)
    def __init__(self):
        super().__init__()
        self._running=True; self._history={}; self._proc_cache={}

    def stop(self): self._running=False

    def _proc_name(self, pid):
        if pid in self._proc_cache: return self._proc_cache[pid]
        try:
            name=psutil.Process(pid).name(); self._proc_cache[pid]=name; return name
        except Exception: return f"PID {pid}"

    def run(self):
        while self._running:
            if HAS_PSUTIL:
                try: self._tick()
                except Exception: pass
            QThread.msleep(2000)

    def _tick(self):
        try: conns=psutil.net_connections(kind='all')
        except Exception: return
        for key in self._history:
            if self._history[key]["status"]!="CLOSED":
                self._history[key]["status"]="CLOSED"
        for c in conns:
            if not c.raddr: continue
            pid=c.pid or 0
            laddr=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
            raddr=f"{c.raddr.ip}:{c.raddr.port}"
            key=(pid,laddr,raddr); status=c.status if c.status else c.type.name
            if key not in self._history:
                self._history[key]={
                    "proc":self._proc_name(pid),"pid":pid,"laddr":laddr,"raddr":raddr,
                    "proto":"TCP" if c.type.name=="SOCK_STREAM" else "UDP",
                    "status":status,"sent":"—","recv":"—",
                    "first_seen":time.strftime("%H:%M:%S")}
            else: self._history[key]["status"]=status
        rows=sorted(self._history.values(),
                    key=lambda r:(r["status"]=="CLOSED",r["first_seen"]))
        self.updated.emit(rows)

# ── ДИАЛОГ СОЕДИНЕНИЙ ─────────────────────────────────────────────────────────
class ConnectionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CONNECTIONS"); self.setMinimumSize(860,500)
        self.setStyleSheet(dialog_style())
        lay=QVBoxLayout(self); lay.setSpacing(8)

        tb=QHBoxLayout()
        tb.addWidget(QLabel("Все сетевые соединения системы · обновление каждые 2 сек"))
        tb.addStretch()
        self.filter_edit=QLineEdit(); self.filter_edit.setPlaceholderText("фильтр...")
        self.filter_edit.setFixedWidth(200); self.filter_edit.setStyleSheet(input_style())
        self.filter_edit.textChanged.connect(self._apply_filter)
        tb.addWidget(self.filter_edit)
        b=QPushButton("CLEAR"); b.setStyleSheet(btn_style(danger=True))
        b.clicked.connect(self._clear); tb.addWidget(b)
        lay.addLayout(tb)

        self.lbl_count=QLabel("0 соединений")
        self.lbl_count.setStyleSheet("color:#475569;font-family:monospace;font-size:9px;")
        lay.addWidget(self.lbl_count)

        cols=["PROCESS","PID","PROTO","LOCAL","REMOTE","STATUS","SEEN"]
        self.table=QTableWidget(0,len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4,QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0,140); self.table.setColumnWidth(1,50)
        self.table.setColumnWidth(2,55);  self.table.setColumnWidth(5,90); self.table.setColumnWidth(6,65)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setStyleSheet(table_style())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)
        lay.addWidget(self.table)

        if not HAS_PSUTIL:
            lay.addWidget(QLabel("⚠ psutil не установлен: pip install psutil"))

        self._all_rows=[]
        self._worker=ConnectionsWorker()
        self._worker.updated.connect(self._on_update)
        self._worker.start()

    def _on_update(self, rows):
        self._all_rows=rows
        active=sum(1 for r in rows if r['status']!='CLOSED')
        self.lbl_count.setText(f"{active} активных  /  {len(rows)} всего в истории")
        self._apply_filter()

    def _apply_filter(self):
        flt=self.filter_edit.text().lower()
        rows=[r for r in self._all_rows
              if not flt or flt in r["proc"].lower() or flt in r["raddr"].lower()]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        sc={"ESTABLISHED":"#10b981","LISTEN":"#7c3aed","TIME_WAIT":"#f59e0b","CLOSE_WAIT":"#ef4444"}
        for i,r in enumerate(rows):
            closed=r["status"]=="CLOSED"
            vals=[r["proc"],str(r["pid"]),r["proto"],r["laddr"],r["raddr"],r["status"],r["first_seen"]]
            for col,val in enumerate(vals):
                item=QTableWidgetItem(val)
                if closed:
                    item.setForeground(QBrush(QColor("#2d3748")))
                    item.setBackground(QColor("#0a0a14"))
                elif col==5:
                    item.setForeground(QBrush(QColor(sc.get(r["status"],"#94a3b8"))))
                self.table.setItem(i,col,item)
        self.table.setSortingEnabled(True)

    def _ctx_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item: return
        row = item.row()
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#13131f;color:#e2e8f0;border:1px solid #2d3748;"
            "border-radius:6px;font-family:monospace;font-size:10px;padding:4px;}"
            "QMenu::item{padding:5px 16px;border-radius:3px;}"
            "QMenu::item:selected{background:#7c3aed;}")
        cols = ["PROCESS","PID","PROTO","LOCAL","REMOTE","STATUS","SEEN"]
        for col, name in enumerate(cols):
            val = self.table.item(row, col)
            if val and val.text():
                act = menu.addAction(f"Копировать {name}: {val.text()[:30]}")
                act.setData((row, col))
        if menu.isEmpty(): return
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen:
            row, col = chosen.data()
            text = self.table.item(row, col).text()
            QApplication.clipboard().setText(text)

    def _clear(self):
        if self._worker: self._worker._history.clear()
        self._all_rows=[]; self.table.setRowCount(0)

    def closeEvent(self,_): self._worker.stop()

# ── ПОТОК И ПАНЕЛЬ ЛОГОВ ──────────────────────────────────────────────────────
def _fmt_bytes(b: float) -> str:
    """Умное форматирование: B → KB → MB → GB → TB."""
    for unit in ("B","KB","MB","GB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.2f} TB"


class SpeedGraphWidget(QWidget):
    """
    Мини-граф скорости сети в реальном времени + суммарные счётчики.
    Использует psutil для получения bytes_sent/bytes_recv с интервалом 1 сек.
    Отображает:
      — два кривых линий (▼ download зелёный, ▲ upload синий)
      — текущую скорость и суммарный трафик
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._dl_hist = []   # [bytes/s] последние N точек
        self._ul_hist = []
        self._max_pts = 60   # 60 сек истории
        self._total_dl = 0.0
        self._total_ul = 0.0
        self._last_bytes = None
        self._timer = QTimer(self, interval=1000, timeout=self._sample)

    def start(self):
        try:
            import psutil
            c = psutil.net_io_counters()
            self._last_bytes = (c.bytes_recv, c.bytes_sent)
        except Exception:
            self._last_bytes = None
        self._timer.start()

    def stop_sampling(self):
        self._timer.stop()

    def _sample(self):
        try:
            import psutil
            c = psutil.net_io_counters()
            cur = (c.bytes_recv, c.bytes_sent)
            if self._last_bytes:
                dl = max(0.0, cur[0] - self._last_bytes[0])
                ul = max(0.0, cur[1] - self._last_bytes[1])
                self._dl_hist.append(dl); self._ul_hist.append(ul)
                self._total_dl += dl;     self._total_ul += ul
                if len(self._dl_hist) > self._max_pts:
                    self._dl_hist.pop(0); self._ul_hist.pop(0)
            self._last_bytes = cur
            self.update()
        except Exception:
            pass

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        p.fillRect(0, 0, W, H, QColor("#0a0a14"))

        # Grid lines
        p.setPen(QPen(QColor("#1e293b"), 1))
        for i in range(1, 4):
            y = int(H * i / 4)
            p.drawLine(0, y, W, y)

        def _draw_curve(hist, color):
            if len(hist) < 2: return
            peak = max(max(hist), 1)
            pts = len(hist)
            step = W / max(pts - 1, 1)
            path = QPainterPath()
            x0 = W - (pts - 1) * step
            y0 = H - int(hist[0] / peak * (H - 4)) - 2
            path.moveTo(x0, y0)
            for i, v in enumerate(hist[1:], 1):
                x = x0 + i * step
                y = H - int(v / peak * (H - 4)) - 2
                path.lineTo(x, y)
            p.setPen(QPen(QColor(color), 1.5))
            p.drawPath(path)

        _draw_curve(self._dl_hist, "#10b981")   # зелёный ▼
        _draw_curve(self._ul_hist, "#3b82f6")   # синий   ▲

        # Stats overlay
        dl_spd = self._dl_hist[-1] if self._dl_hist else 0
        ul_spd = self._ul_hist[-1] if self._ul_hist else 0
        p.setPen(QPen(QColor("#10b981")))
        p.setFont(QFont("monospace", 8))
        p.drawText(4, 13, f"▼ {_fmt_bytes(dl_spd)}/s   total {_fmt_bytes(self._total_dl)}")
        p.setPen(QPen(QColor("#3b82f6")))
        p.drawText(4, 27, f"▲ {_fmt_bytes(ul_spd)}/s   total {_fmt_bytes(self._total_ul)}")


class LogTailThread(QThread):
    """
    Следит за ДВУМЯ лог-файлами одновременно (sb.log и xray.log) и
    эмиттит строки с тегом источника — нужно для фильтра XRAY/SING-BOX/CRYSTALL
    в LogPanel. Раньше отслеживался только sb.log, из-за чего в dual-core
    режиме (sing-box TUN + Xray SOCKS5-бэкенд) лог Xray просто не показывался.
    """
    new_lines = pyqtSignal(list)   # список (source:str, line:str)

    def __init__(self):
        super().__init__()
        self._running = True
        self._pos = {LOG_FILE: 0, XRAY_LOG_FILE: 0}

    def reset(self):
        self._pos = {LOG_FILE: 0, XRAY_LOG_FILE: 0}

    def run(self):
        while self._running:
            try:
                batch = []
                for path, source in ((LOG_FILE, "SING-BOX"), (XRAY_LOG_FILE, "XRAY")):
                    if not os.path.exists(path):
                        continue
                    size = os.path.getsize(path)
                    # Файл стал короче (очистили логи) — сбрасываем позицию,
                    # иначе seek() уйдёт за конец и ничего не прочитается.
                    if self._pos[path] > size:
                        self._pos[path] = 0
                    with open(path, encoding="utf-8", errors="replace") as f:
                        f.seek(self._pos[path])
                        lines = f.readlines()
                        self._pos[path] = f.tell()
                    batch.extend((source, l) for l in lines)
                if batch:
                    self.new_lines.emit(batch)
            except Exception:
                pass
            QThread.msleep(400)

    def stop(self):
        self._running = False

class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay=QVBoxLayout(self); lay.setContentsMargins(4,2,4,4); lay.setSpacing(3)

        tb=QHBoxLayout(); tb.setSpacing(6)
        self.tb_layout = tb
        self.lbl=QLabel("LOGS")
        self.lbl.setStyleSheet("color:#7c3aed;font-family:monospace;font-size:9px;font-weight:bold;")
        tb.addWidget(self.lbl)

        # Фильтр по уровню (как и раньше)
        self.level=QComboBox(); self.level.addItems(["ALL","INFO","WARN","ERROR"])
        self.level.setFixedWidth(64)
        self.level.setStyleSheet(input_style())
        self.level.currentTextChanged.connect(self._refilter)
        tb.addWidget(self.level)

        # Фильтр по источнику: XRAY / SING-BOX / CRYSTALL (лог самого приложения)
        self.source=QComboBox(); self.source.addItems(["ALL","SING-BOX","XRAY","CRYSTALL"])
        self.source.setFixedWidth(82)
        self.source.setStyleSheet(input_style())
        self.source.currentTextChanged.connect(self._refilter)
        tb.addWidget(self.source)

        self.b_view_toggle=QPushButton("📊 GRAPHS")
        self.b_view_toggle.setStyleSheet(btn_style() +
            "QPushButton{padding:3px 10px;min-height:26px;}")
        self.b_view_toggle.clicked.connect(self._toggle_view)
        tb.addWidget(self.b_view_toggle)

        self.b_clear=QPushButton("🗑 CLEAR")
        self.b_clear.setStyleSheet(btn_style(danger=True) +
            "QPushButton{padding:3px 10px;min-height:26px;}")
        self.b_clear.clicked.connect(self._clear_logs)
        tb.addWidget(self.b_clear)

        self.b_toggle=QPushButton("▼ HIDE")
        self.b_toggle.setStyleSheet(btn_style() +
            "QPushButton{padding:3px 10px;min-height:26px;}")
        self.b_toggle.clicked.connect(self._toggle)
        tb.addWidget(self.b_toggle)
        lay.addLayout(tb)

        self.text=QTextEdit(); self.text.setReadOnly(True); self.text.setFixedHeight(100)
        self.text.setStyleSheet(
            "QTextEdit{background:rgba(10,10,20,220);color:#475569;"
            "border:1px solid #1e293b;border-radius:8px;"
            "font-family:monospace;font-size:9px;padding:4px;}")
        lay.addWidget(self.text)

        self.graph=SpeedGraphWidget()
        self.graph.setFixedHeight(100)
        self.graph.hide()
        lay.addWidget(self.graph)

        self._all_lines=[]; self._visible=True; self._show_graphs=False
        self._tail=LogTailThread()
        self._tail.new_lines.connect(self._on_lines)
        self._tail.start()

    def append(self, msg):
        """Лог самого приложения (CRYSTALL) — READY (имя инбаунда) и подобное."""
        entry = {"source": "CRYSTALL", "level": "INFO", "text": msg}
        self._all_lines.append(entry)
        if self._visible and self._matches(entry):
            self._put(f"<span style='color:#a78bfa'>[CRYSTALL] › {msg}</span>")

    def _on_lines(self, lines):
        """lines: список (source, raw_line) от LogTailThread."""
        for source, raw in lines:
            raw=strip_ansi(raw).rstrip()
            if not raw: continue
            lvl="ERROR" if "ERROR" in raw or "FATAL" in raw else ("WARN" if "WARN" in raw else "INFO")
            entry = {"source": source, "level": lvl, "text": raw}
            self._all_lines.append(entry)
            if self._visible and self._matches(entry):
                self._put(self._color(entry))

    def _matches(self, entry) -> bool:
        lvl_ok = self.level.currentText() in ("ALL", entry["level"])
        src_ok = self.source.currentText() in ("ALL", entry["source"])
        return lvl_ok and src_ok

    def _color(self, entry):
        lvl_c = {"ERROR":"#ef4444","WARN":"#f59e0b"}.get(entry["level"], "#475569")
        if entry["source"] == "CRYSTALL":
            return f"<span style='color:#a78bfa'>[CRYSTALL] › {entry['text']}</span>"
        tag = f"[{entry['source']}] "
        return f"<span style='color:{lvl_c}'>{tag}{entry['text']}</span>"

    def _put(self, html):
        self.text.append(html)
        self.text.verticalScrollBar().setValue(self.text.verticalScrollBar().maximum())

    def _refilter(self):
        self.text.clear()
        for entry in self._all_lines[-300:]:
            if self._matches(entry):
                self._put(self._color(entry))

    def _clear_logs(self):
        """
        Стирает логи на диске (sb.log, xray.log) и в памяти панели.
        Сбрасывает позицию tail-потока, иначе он попытается прочитать
        с офсета, который теперь за пределами усечённого файла.
        """
        try:
            from runner import clear_logs
            clear_logs()
        except Exception as e:
            print(f"clear_logs failed: {e}")
        self._all_lines.clear()
        self.text.clear()
        self._tail.reset()
        self.append("Логи очищены")

    def _toggle_view(self):
        self._show_graphs = not self._show_graphs
        if self._show_graphs:
            self.b_view_toggle.setText("📝 LOGS")
            self.text.hide()
            self.graph.show()
            self.graph.start()
        else:
            self.b_view_toggle.setText("📊 GRAPHS")
            self.graph.hide()
            self.graph.stop_sampling()
            self.text.show()

    def _toggle(self):
        self._visible=not self._visible
        content_widget = self.graph if self._show_graphs else self.text
        for w in (self.lbl, self.level, self.source, self.b_view_toggle,
                  self.b_clear, content_widget):
            w.setVisible(self._visible)

        if self._visible:
            if self.b_toggle.parent() is not self:
                self.b_toggle.setParent(self)
            if self.tb_layout.indexOf(self.b_toggle) == -1:
                self.tb_layout.addWidget(self.b_toggle)
            self.b_toggle.setText("▼ HIDE")
            self.b_toggle.show()
        else:
            self.tb_layout.removeWidget(self.b_toggle)
            top = self.window()
            self.b_toggle.setParent(top)
            self.b_toggle.setText("▲ SHOW")
            self.b_toggle.adjustSize()
            self.b_toggle.move(top.width()  - self.b_toggle.width()  - 12,
                                top.height() - self.b_toggle.height() - 12)
            self.b_toggle.show()
            self.b_toggle.raise_()

    def reset_tail(self): self._tail.reset()
    def stop(self): self._tail.stop()

# ── ПЛИТКИ: ОБЩИЕ ХЕЛПЕРЫ ─────────────────────────────────────────────────────
def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    hex_color = (hex_color or "#7c3aed").lstrip("#")
    if len(hex_color) != 6:
        hex_color = "7c3aed"
    r = int(hex_color[0:2], 16); g = int(hex_color[2:4], 16); b = int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _tile_btn_style() -> str:
    return (
        "QPushButton{background:transparent;border:none;color:#94a3b8;font-size:11px;}"
        "QPushButton:hover{color:#e2e8f0;}"
        "QPushButton:pressed{color:#7c3aed;}"
    )


class TileButton(QFrame):
    """Базовая 'плитка' — кликабельный QFrame фиксированного размера."""
    clicked = pyqtSignal()

    def __init__(self, w: int = 148, h: int = 104, parent=None):
        super().__init__(parent)
        self.setFixedSize(w, h)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)


class AddTile(TileButton):
    """Плитка '+' — обводка пунктиром, плюс по центру."""
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setStyleSheet(
            "QFrame{background:transparent;border:2px dashed #475569;border-radius:12px;}"
            "QFrame:hover{border-color:#7c3aed;}"
        )
        lay = QVBoxLayout(self)
        plus = QLabel("+")
        plus.setAlignment(Qt.AlignmentFlag.AlignCenter)
        plus.setStyleSheet("color:#475569;font-size:34px;border:none;background:transparent;")
        lay.addWidget(plus)


class ClusterTile(TileButton):
    """Плитка кластера: имя, кол-во инбаундов, ✎ редактировать, 🔄 обновить подписку."""
    editRequested = pyqtSignal()
    refreshRequested = pyqtSignal()

    def __init__(self, data: dict, path: str, parent=None):
        super().__init__(parent=parent)
        self.path = path
        self.data = data
        color = data.get("color") or "#7c3aed"
        bg = _hex_to_rgba(color, 0.14)
        self.setStyleSheet(
            f"QFrame{{background:{bg};border:1.5px solid {color};border-radius:12px;}}"
            f"QFrame:hover{{background:{_hex_to_rgba(color, 0.22)};}}"
        )
        lay = QVBoxLayout(self); lay.setContentsMargins(10, 6, 6, 8); lay.setSpacing(2)

        top = QHBoxLayout(); top.setSpacing(0)
        top.addStretch()
        if data.get("source_url"):
            b_ref = QPushButton("🔄"); b_ref.setFixedSize(22, 22)
            b_ref.setToolTip("Обновить подписку (с обновлением IP)")
            b_ref.setStyleSheet(_tile_btn_style())
            b_ref.clicked.connect(lambda: self.refreshRequested.emit())
            top.addWidget(b_ref)
        b_edit = QPushButton("✎"); b_edit.setFixedSize(22, 22)
        b_edit.setToolTip("Редактировать кластер")
        b_edit.setStyleSheet(_tile_btn_style())
        b_edit.clicked.connect(lambda: self.editRequested.emit())
        top.addWidget(b_edit)
        lay.addLayout(top)

        lay.addStretch()
        title = QLabel(data.get("name", "?"))
        title.setWordWrap(True)
        title.setStyleSheet(
            f"color:{color};font-family:monospace;font-weight:bold;"
            f"font-size:12px;border:none;background:transparent;")
        lay.addWidget(title)

        n = len(data.get("profiles", []))
        meta = f"{n} inbound{'s' if n != 1 else ''}"
        if data.get("source_url"):
            meta += "  ·  SUB"
        sub = QLabel(meta)
        sub.setStyleSheet("color:#94a3b8;font-family:monospace;font-size:8px;border:none;background:transparent;")
        lay.addWidget(sub)


class InboundTile(TileButton):
    """Плитка инбаунда: протокол, имя, host:port, ping, ✎ переименовать, 🗑 удалить."""
    editRequested = pyqtSignal()
    deleteRequested = pyqtSignal()

    def __init__(self, profile: dict, index: int, parent=None):
        super().__init__(parent=parent)
        self.index = index
        self.profile = profile
        is_custom = bool(profile.get("custom"))
        accent = "#10b981" if is_custom else "#7c3aed"
        self.setStyleSheet(
            f"QFrame{{background:#161427;border:1.5px solid {accent};border-radius:12px;}}"
            f"QFrame:hover{{background:#1c1936;}}"
        )
        lay = QVBoxLayout(self); lay.setContentsMargins(10, 6, 6, 8); lay.setSpacing(2)

        top = QHBoxLayout(); top.setSpacing(0)
        proto = profile.get("protocol", "hysteria2")
        badge = QLabel("VLESS" if proto == "vless" else "HY2")
        badge.setStyleSheet(
            f"color:{accent};font-family:monospace;font-size:8px;"
            f"font-weight:bold;border:none;background:transparent;")
        top.addWidget(badge)
        if is_custom:
            cb = QLabel("•custom")
            cb.setStyleSheet("color:#10b981;font-family:monospace;font-size:8px;border:none;background:transparent;")
            top.addWidget(cb)
        top.addStretch()
        b_edit = QPushButton("✎"); b_edit.setFixedSize(20, 20)
        b_edit.setToolTip("Переименовать")
        b_edit.setStyleSheet(_tile_btn_style())
        b_edit.clicked.connect(lambda: self.editRequested.emit())
        b_del = QPushButton("🗑"); b_del.setFixedSize(20, 20)
        b_del.setToolTip("Удалить")
        b_del.setStyleSheet(_tile_btn_style())
        b_del.clicked.connect(lambda: self.deleteRequested.emit())
        top.addWidget(b_edit); top.addWidget(b_del)
        lay.addLayout(top)

        lay.addStretch()
        title = QLabel(profile.get("name", "Node"))
        title.setWordWrap(True)
        title.setStyleSheet(
            "color:#e2e8f0;font-family:monospace;font-weight:bold;"
            "font-size:11px;border:none;background:transparent;")
        lay.addWidget(title)

        sub = QLabel(f"{profile.get('host','')}:{profile.get('port_hopping') or profile.get('port','')}")
        if profile.get("port_hopping"):
            sub.setToolTip("Port Hopping включён")
        sub.setStyleSheet("color:#64748b;font-family:monospace;font-size:8px;border:none;background:transparent;")
        lay.addWidget(sub)

        self.ping_label = QLabel("")
        self.ping_label.setStyleSheet("font-family:monospace;font-size:9px;border:none;background:transparent;")
        lay.addWidget(self.ping_label)

    def set_ping(self, text: str, color: str):
        self.ping_label.setText(text)
        self.ping_label.setStyleSheet(
            f"color:{color};font-family:monospace;font-size:9px;border:none;background:transparent;")


# ── РЕДАКТОР КЛАСТЕРА (имя / цвет / ссылка подписки / удалить) ───────────────
class ClusterEditDialog(QDialog):
    def __init__(self, data: dict, path: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("EDIT CLUSTER"); self.setFixedSize(380, 320)
        self.setStyleSheet(dialog_style())
        self.path = path
        lay = QVBoxLayout(self); lay.setSpacing(8)

        lay.addWidget(QLabel("Имя:"))
        self.le_name = QLineEdit(data.get("name", ""))
        self.le_name.setStyleSheet(input_style())
        lay.addWidget(self.le_name)

        lay.addWidget(QLabel("Цвет:"))
        color_row = QHBoxLayout(); color_row.setSpacing(6)
        self._color = data.get("color") or cm.DEFAULT_PALETTE[0]
        self._swatches = []
        for c in cm.DEFAULT_PALETTE:
            b = QPushButton()
            b.setFixedSize(26, 26)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setProperty("swatch_color", c)
            b.clicked.connect(lambda _checked=False, c=c: self._pick_color(c))
            color_row.addWidget(b)
            self._swatches.append(b)
        color_row.addStretch()
        lay.addLayout(color_row)
        self._refresh_swatches()

        lay.addWidget(QLabel("Ссылка на подписку (пусто = без подписки):"))
        self.le_url = QLineEdit(data.get("source_url", ""))
        self.le_url.setPlaceholderText("https://...")
        self.le_url.setStyleSheet(input_style())
        lay.addWidget(self.le_url)

        lay.addStretch()
        row = QHBoxLayout(); row.setSpacing(6)
        b_del = QPushButton("🗑 Удалить"); b_del.setStyleSheet(btn_style(danger=True))
        b_cancel = QPushButton("Отмена"); b_cancel.setStyleSheet(btn_style())
        b_save = QPushButton("Сохранить"); b_save.setStyleSheet(btn_style(accent=True))
        b_del.clicked.connect(self._delete)
        b_cancel.clicked.connect(self.reject)
        b_save.clicked.connect(self._save)
        row.addWidget(b_del); row.addStretch(); row.addWidget(b_cancel); row.addWidget(b_save)
        lay.addLayout(row)

    def _pick_color(self, c: str):
        self._color = c
        self._refresh_swatches()

    def _refresh_swatches(self):
        for b in self._swatches:
            c = b.property("swatch_color")
            border = "2px solid #a78bfa" if c == self._color else "1px solid #1e293b"
            b.setStyleSheet(f"QPushButton{{background:{c};border-radius:13px;border:{border};}}")

    def _save(self):
        name = self.le_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Ошибка", "Имя не может быть пустым.")
            return
        url = self.le_url.text().strip()
        cm.update_cluster_meta(
            self.path, name=name, color=self._color,
            source_url=url if url else None, clear_source_url=not url)
        self.accept()

    def _delete(self):
        if QMessageBox.question(
                self, "Удалить кластер",
                f"Удалить кластер «{self.le_name.text()}» со всеми инбаундами?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            cm.delete_cluster(self.path)
            self.accept()


# ── ИНБАУНДЫ ВНУТРИ КЛАСТЕРА (плитки) ────────────────────────────────────────
class InboundsGridDialog(QDialog):
    def __init__(self, path: str, data: dict, runner=None, active_mode="proxy", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"INBOUNDS — {data.get('name','?')}"); self.setFixedSize(660, 540)
        self.setStyleSheet(dialog_style())
        self.path = path
        self.selected_data = None
        self._runner = runner; self._active_mode = active_mode
        self.ping_threads = []
        self.tiles = []
        lay = QVBoxLayout(self); lay.setSpacing(8)

        top = QHBoxLayout()
        title = QLabel(f"⬢ {data.get('name','?')}")
        color = data.get("color") or "#7c3aed"
        title.setStyleSheet(f"color:{color};font-family:monospace;font-weight:bold;font-size:13px;")
        top.addWidget(title); top.addStretch()
        self.b_ping = QPushButton("📶 PING ALL"); self.b_ping.setStyleSheet(btn_style())
        self.b_ping.clicked.connect(self._ping_all)
        top.addWidget(self.b_ping)
        b_back = QPushButton("← Назад"); b_back.setStyleSheet(btn_style())
        b_back.clicked.connect(self.reject)
        top.addWidget(b_back)
        lay.addLayout(top)

        self.ping_hint = QLabel("")
        self.ping_hint.setStyleSheet("color:#475569;font-family:monospace;font-size:9px;")
        self._update_ping_hint()
        lay.addWidget(self.ping_hint)

        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True)
        # Явно задаём тёмный фон и самому QScrollArea, и его viewport —
        # "background:transparent" само по себе не гарантирует, что сквозь
        # него не проступит светлый дефолтный фон QWidget без стиля.
        self.scroll.setStyleSheet("QScrollArea{border:none;background:#13131f;}")
        self.scroll.viewport().setStyleSheet("background:#13131f;")
        self.grid_host = QWidget()
        self.grid_host.setStyleSheet("background:#13131f;")
        self.grid = QGridLayout(self.grid_host)
        self.grid.setSpacing(6)
        self.grid.setContentsMargins(2, 2, 2, 2)
        self.grid.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.grid_host)
        lay.addWidget(self.scroll)

        self._refresh()

    def _core_running(self) -> bool:
        return bool(self._runner and self._runner.proc)

    def _update_ping_hint(self):
        if self._core_running():
            m = self._active_mode.upper()
            txt = (f"⚡ URL-пинг через TUN ({m})" if self._active_mode == "tun"
                   else f"⚡ URL-пинг через прокси 127.0.0.1:2080 ({m})")
            self.ping_hint.setText(txt)
        else:
            self.ping_hint.setText("⚡ URL-пинг напрямую (ядро не запущено)")

    def _refresh(self):
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w: w.deleteLater()
        self.tiles = []

        try:
            data = cm.load_cluster(self.path)
        except Exception:
            data = {"profiles": []}

        cols = 3; row = col = 0
        for idx, profile in enumerate(data.get("profiles", [])):
            tile = InboundTile(profile, idx)
            tile.clicked.connect(lambda p=profile: self._select(p))
            tile.editRequested.connect(lambda i=idx, pr=profile: self._rename(i, pr))
            tile.deleteRequested.connect(lambda i=idx, pr=profile: self._delete(i, pr))
            self.grid.addWidget(tile, row, col, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            self.tiles.append(tile)
            col += 1
            if col >= cols: col = 0; row += 1

        add_tile = AddTile()
        add_tile.setToolTip("Добавить инбаунд по ссылке")
        add_tile.clicked.connect(self._add_inbound)
        self.grid.addWidget(add_tile, row, col, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    def _select(self, profile: dict):
        self.selected_data = {"data": profile, "file": self.path}
        self.accept()

    def _rename(self, idx: int, profile: dict):
        new_name, ok = QInputDialog.getText(
            self, "Переименовать инбаунд", "Имя:", text=profile.get("name", ""))
        if ok and new_name.strip():
            cm.rename_inbound(self.path, idx, new_name.strip())
            self._refresh()

    def _delete(self, idx: int, profile: dict):
        if QMessageBox.question(
                self, "Удалить инбаунд", f"Удалить «{profile.get('name','?')}»?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            cm.delete_inbound(self.path, idx)
            self._refresh()

    def _add_inbound(self):
        link, ok = QInputDialog.getText(
            self, "Добавить инбаунд", "Ссылка (hysteria2:// или vless://):")
        if not (ok and link.strip()):
            return
        try:
            cm.add_manual_inbound(self.path, link.strip())
        except Exception as e:
            QMessageBox.critical(self, "Ошибка парсинга", str(e)); return
        self._refresh()

    def _ping_all(self):
        self.ping_threads.clear()
        self._update_ping_hint()
        proxy = None if (self._active_mode == "tun" or not self._core_running()) \
                else "http://127.0.0.1:2080"
        for tile in self.tiles:
            tile.set_ping("⏳", "#94a3b8")
            t = UrlPingThread(proxy=proxy)
            t.result.connect(lambda ok, ms, st, tl=tile: tl.set_ping(*self._fmt_ping(ok, ms, st)))
            self.ping_threads.append(t); t.start()

    @staticmethod
    def _fmt_ping(ok: bool, ms: float, status: int):
        if not ok:
            return "ERR", "#ef4444"
        color = "#10b981" if ms < 200 else ("#f59e0b" if ms < 600 else "#ef4444")
        return f"{ms:.0f}ms", color


# ── МЕНЕДЖЕР КЛАСТЕРОВ (плитки) ───────────────────────────────────────────────
class ProfileDialog(QDialog):
    """
    1 кластер = 1 плитка. Клик по плитке → список инбаундов этого кластера
    (тоже плитками). ✎ на плитке кластера → редактирование (имя/цвет/ссылка/
    удалить). 🔄 (только если есть подписка) → обновить подписку с пересчётом
    IP, не теряя вручную добавленные (custom) инбаунды. Последняя плитка — '+'
    → импорт подписки или пустой кластер.
    """
    def __init__(self, runner=None, active_mode="proxy", parent=None):
        super().__init__(parent)
        self.setWindowTitle("CLUSTERS"); self.setFixedSize(660, 540)
        self.setStyleSheet(dialog_style())
        self.selected_data = None
        self._runner = runner; self._active_mode = active_mode
        lay = QVBoxLayout(self); lay.setSpacing(8)

        hdr = QLabel("Клик по кластеру — список инбаундов. ✎ — редактировать. 🔄 — обновить подписку.")
        hdr.setWordWrap(True)
        hdr.setStyleSheet("color:#64748b;font-family:monospace;font-size:9px;")
        lay.addWidget(hdr)

        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True)
        # Явно задаём тёмный фон и самому QScrollArea, и его viewport —
        # "background:transparent" само по себе не гарантирует, что сквозь
        # него не проступит светлый дефолтный фон QWidget без стиля.
        self.scroll.setStyleSheet("QScrollArea{border:none;background:#13131f;}")
        self.scroll.viewport().setStyleSheet("background:#13131f;")
        self.grid_host = QWidget()
        self.grid_host.setStyleSheet("background:#13131f;")
        self.grid = QGridLayout(self.grid_host)
        self.grid.setSpacing(6)
        self.grid.setContentsMargins(2, 2, 2, 2)
        self.grid.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.grid_host)
        lay.addWidget(self.scroll)

        bottom = QHBoxLayout()
        bottom.addStretch()
        b_close = QPushButton("Закрыть"); b_close.setStyleSheet(btn_style())
        b_close.clicked.connect(self.reject)
        bottom.addWidget(b_close)
        lay.addLayout(bottom)

        self._refresh()

    def _refresh(self):
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w: w.deleteLater()

        cols = 3; row = col = 0
        for path in cm.list_cluster_files():
            try:
                data = cm.load_cluster(path)
            except Exception:
                continue
            tile = ClusterTile(data, path)
            tile.clicked.connect(lambda p=path: self._open_cluster(p))
            tile.editRequested.connect(lambda p=path, d=data: self._edit_cluster(p, d))
            tile.refreshRequested.connect(lambda p=path: self._refresh_subscription(p))
            self.grid.addWidget(tile, row, col, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            col += 1
            if col >= cols: col = 0; row += 1

        add_tile = AddTile()
        add_tile.setToolTip("Импорт подписки или новый пустой кластер")
        add_tile.clicked.connect(self._add_cluster_menu)
        self.grid.addWidget(add_tile, row, col, alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    def _open_cluster(self, path: str):
        try:
            data = cm.load_cluster(path)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e)); return
        d = InboundsGridDialog(path, data, runner=self._runner,
                                active_mode=self._active_mode, parent=self)
        if d.exec() and d.selected_data:
            self.selected_data = d.selected_data
            self.accept()
        else:
            self._refresh()   # переименование/удаление внутри тоже отражаем

    def _edit_cluster(self, path: str, data: dict):
        d = ClusterEditDialog(data, path, parent=self)
        if d.exec():
            self._refresh()

    def _refresh_subscription(self, path: str):
        try:
            n = cm.refresh_subscription(path)
            QMessageBox.information(self, "Подписка обновлена",
                                     f"Получено {n} инбаундов из подписки.\n"
                                     f"Вручную добавленные инбаунды сохранены.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка обновления", str(e))
        self._refresh()

    def _add_cluster_menu(self):
        menu = QMenu(self)
        act_sub = menu.addAction("⬇ Импорт подписки")
        act_empty = menu.addAction("+ Пустой кластер")
        chosen = menu.exec(QCursor.pos())
        if chosen == act_sub:
            self._import_subscription_dialog()
        elif chosen == act_empty:
            self._create_empty_cluster_dialog()

    def _import_subscription_dialog(self):
        url, ok = QInputDialog.getText(self, "Импорт подписки", "URL подписки:")
        if not (ok and url.strip()):
            return
        name, ok2 = QInputDialog.getText(
            self, "Импорт подписки", "Имя кластера:",
            text=f"Sub_{random.randint(100,999)}")
        if not ok2:
            return
        name = name.strip() or f"Sub_{random.randint(100,999)}"
        try:
            cm.import_subscription(url.strip(), name, mode="proxy")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка импорта", str(e)); return
        self._refresh()

    def _create_empty_cluster_dialog(self):
        name, ok = QInputDialog.getText(self, "Новый кластер", "Имя:")
        if not (ok and name.strip()):
            return
        cm.create_empty_cluster(name.strip())
        self._refresh()

# ── ИКОНКА ТРЕЯ ───────────────────────────────────────────────────────────────
def _make_tray_icon(color: QColor) -> QIcon:
    px=QPixmap(32,32); px.fill(Qt.GlobalColor.transparent)
    p=QPainter(px); p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path=QPainterPath()
    path.moveTo(16,2); path.lineTo(30,16); path.lineTo(16,30); path.lineTo(2,16)
    path.closeSubpath()
    p.setBrush(color); p.setPen(Qt.PenStyle.NoPen); p.drawPath(path); p.end()
    return QIcon(px)

# ── ГЛАВНОЕ ОКНО ──────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # ── Очистка ДО создания Runner и любых процессов ────────────────────
        # 1. Логи — стираются на каждом старте приложения (см. кнопка CLEAR
        #    в LogPanel делает то же самое вручную).
        # 2. Зомби sing-box.exe/xray.exe и зависшие TUN-адаптеры от прошлого
        #    аварийного завершения — без этого sing-box иногда падает с
        #    'FATAL cannot create file that already exists'.
        try:
            from runner import clear_logs, cleanup_stale_state
            clear_logs()
            cleanup_stale_state()
        except Exception as e:
            print(f"Startup cleanup failed: {e}")

        self.runner=Runner(); self.active_p=None
        self._active_engine_mode=None   # None | "singbox" | "xray" | "dual"
        self.active_mode="proxy"; self._drag_pos=None
        self._conn_dialog=None; self._ping_thread=None
        self._active_cluster_file=""

        self.setFixedSize(430,720)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        self.bg=BackgroundWidget(self); self.bg.setGeometry(0,0,430,720); self.bg.lower()

        container=QWidget(); self.setCentralWidget(container)
        lay=QVBoxLayout(container); lay.setContentsMargins(10,10,10,10); lay.setSpacing(4)

        top_row=QHBoxLayout()
        self.gear=GearButton(); self.gear.clicked.connect(self._open_settings)
        top_row.addWidget(self.gear)
        top_row.addStretch()

        self.status=QLabel("SYSTEM IDLE")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.setStyleSheet(
            "color:#7c3aed;font-family:monospace;font-size:11px;letter-spacing:2px;")
        top_row.addWidget(self.status)
        top_row.addStretch()
        top_row.addWidget(QWidget()); top_row.itemAt(top_row.count()-1).widget().setFixedSize(32,32)
        lay.addLayout(top_row)

        if not is_admin() and not service_installed():
            w=QLabel("⚠ NOT ADMIN — TUN MODE REQUIRE UAC")
            w.setAlignment(Qt.AlignmentFlag.AlignCenter)
            w.setStyleSheet("color:#f59e0b;font-family:monospace;font-size:9px;")
            lay.addWidget(w)

        tr=QHBoxLayout(); tr.addStretch()
        self.mode_toggle=ModeToggle()
        self.mode_toggle.toggled.connect(self._on_mode_toggled)
        tr.addWidget(self.mode_toggle); tr.addStretch()
        lay.addLayout(tr)

        self.arena=QWidget(); self.arena.setFixedSize(410,380)
        lay.addWidget(self.arena, 0, Qt.AlignmentFlag.AlignCenter)

        self.b_rules=CyberBlade("RULES",    -30, self.arena); self.b_rules.move(0,   42)
        self.b_prof =CyberBlade("CLUSTERS",  30, self.arena); self.b_prof.move(240,  42)
        self.b_conn_p=CyberBlade("CONNECTIONS",30,self.arena);self.b_conn_p.move(0,  272)
        self.b_exit =CyberBlade("EXIT",     -30, self.arena); self.b_exit.move(240, 272)
        self.dia=DiamondWidget(self.arena); self.dia.move(120,82)

        self.b_rules.clicked.connect(self._open_rules)
        self.b_prof.clicked.connect(self._select)
        self.b_conn_p.clicked.connect(self._open_connections)
        self.b_exit.clicked.connect(self._exit_dialog)
        self.dia.clicked.connect(self._toggle)

        self.log_panel=LogPanel()
        lay.addWidget(self.log_panel)

        # ── Индикаторы-лепестки ───────────────────────────────────────────────
        ind_row = QHBoxLayout(); ind_row.setSpacing(10)
        ind_row.addStretch()
        self.ind_core = PetalIndicator("SING-BOX")
        self.ind_xray = PetalIndicator("XRAY")
        self.ind_svc  = PetalIndicator("SERVICE")
        self.ind_core.clicked.connect(self._on_indicator_clicked)
        self.ind_xray.clicked.connect(self._on_indicator_clicked)
        self.ind_svc.clicked.connect(self._on_indicator_clicked)
        ind_row.addWidget(self.ind_core)
        ind_row.addWidget(self.ind_xray)
        ind_row.addWidget(self.ind_svc)
        ind_row.addStretch()
        lay.addLayout(ind_row)

        # Watchdog: каждые 2 сек проверяем реальное состояние процесса
        self._watchdog = QTimer(self, interval=2000, timeout=self._watchdog_tick)
        self._watchdog.start()

        self._tray=QSystemTrayIcon(self)
        self._tray.setIcon(_make_tray_icon(C_ACCENT))
        self._tray.setToolTip("sb-hy2")
        tm=QMenu()
        tm.setStyleSheet(
            "QMenu{background:#13131f;color:#e2e8f0;border:1px solid #2d3748;"
            "border-radius:8px;font-family:monospace;font-size:10px;padding:4px;}"
            "QMenu::item{padding:6px 20px;border-radius:4px;}"
            "QMenu::item:selected{background:#7c3aed;}")
        tm.addAction("Открыть").triggered.connect(self._show_window)
        tm.addAction("Рестарт ядра").triggered.connect(self._restart_core)
        tm.addSeparator()
        tm.addAction("Выйти").triggered.connect(self._quit_app)
        self._tray.setContextMenu(tm)
        self._tray.activated.connect(self._tray_activated)
        self._tray.show()

        s=load_settings()
        if s.get("silent_start"):
            QTimer.singleShot(0, self.hide)

        QTimer.singleShot(500, self._restore_session)

    def _restore_session(self):
        s = load_settings()
        if not s.get("restore_session", True):
            return
        sess = load_session()
        if not sess:
            return
        profile = sess.get("profile")
        mode    = sess.get("mode", "proxy")
        cf      = sess.get("cluster_file", "")
        if not profile or not profile.get("host"):
            return
        self.active_p             = profile
        self.active_mode          = mode
        self._active_cluster_file = cf
        self.mode_toggle.set_mode(mode)
        self.status.setText(f"{profile.get('name','?')} | {mode.upper()}")
        self._log(f"RESTORE: {profile.get('name','?')} [{mode.upper()}]")
        QTimer.singleShot(200, self._toggle)

    def _tray_activated(self, reason):
        if reason==QSystemTrayIcon.ActivationReason.Trigger: self._show_window()

    def _show_window(self):
        self.showNormal(); self.activateWindow(); self.raise_()

    def _quit_app(self):
        s = load_settings()
        if s.get("delete_logs_on_exit", False):
            self.log_panel._clear_logs()
        self.log_panel.stop(); self.runner.stop(); QApplication.quit()

    def _exit_dialog(self):
        dlg=QDialog(self); dlg.setWindowTitle("EXIT"); dlg.setFixedSize(280,140)
        dlg.setStyleSheet(dialog_style())
        lay=QVBoxLayout(dlg); lay.setSpacing(8)
        lay.addWidget(QLabel("Что сделать?"))
        b_hide=QPushButton("Свернуть в трей"); b_hide.setStyleSheet(btn_style())
        b_quit=QPushButton("Выйти полностью"); b_quit.setStyleSheet(btn_style(danger=True))
        b_hide.clicked.connect(lambda:(dlg.accept(),self.hide()))
        b_quit.clicked.connect(lambda:(dlg.accept(),self._quit_app()))
        lay.addWidget(b_hide); lay.addWidget(b_quit)
        dlg.exec()

    def mousePressEvent(self,e):
        if e.button()==Qt.MouseButton.LeftButton: self._drag_pos=e.globalPosition().toPoint()
    def mouseMoveEvent(self,e):
        if self._drag_pos and e.buttons()==Qt.MouseButton.LeftButton:
            self.move(self.pos()+e.globalPosition().toPoint()-self._drag_pos)
            self._drag_pos=e.globalPosition().toPoint()
    def mouseReleaseEvent(self,_): self._drag_pos=None

    def closeEvent(self,e): e.ignore(); self.hide()

    def _on_mode_toggled(self,mode):
        self.active_mode=mode
        if self.active_p: self.status.setText(f"{self.active_p['name']} | {mode.upper()}")
        if self.runner.proc: self._restart_core()

    def _open_settings(self): SettingsDialog(self).exec()
    def _open_rules(self): RulesDialog(self).exec()
    def _open_connections(self):
        if self._conn_dialog is None or not self._conn_dialog.isVisible():
            self._conn_dialog=ConnectionsDialog(self); self._conn_dialog.show()
        else: self._conn_dialog.raise_(); self._conn_dialog.activateWindow()

    def _log(self,m): self.log_panel.append(m)

    def _restart_core(self):
        if self.runner.proc:
            self._log("FORCING CORE RESTART...")
            self.runner.stop()
            # Для TUN-режима нужно больше времени: сервис async + адаптер должен упасть
            delay = 1800 if self.active_mode == "tun" else 600
            QTimer.singleShot(delay, self._toggle)
        else:
            self._log("CORE NOT RUNNING")

    def _on_indicator_clicked(self, label: str):
        """
        Клик по индикатору SING-BOX/XRAY/SERVICE — показывает меню с опциями:
          'Kill process' — жёстко убивает именно этот движок (taskkill),
                           полезно если процесс завис и не реагирует на stop().
          'Выйти'        — полный выход из приложения.
        """
        if label == "SERVICE":
            QMessageBox.information(self, "SERVICE",
                "Управление Windows-сервисом — в Настройках (⚙).")
            return

        engine = "singbox" if label == "SING-BOX" else "xray"

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#13131f;color:#e2e8f0;border:1px solid #2d3748;"
            "border-radius:8px;font-family:monospace;font-size:10px;padding:4px;}"
            "QMenu::item{padding:6px 20px;border-radius:4px;}"
            "QMenu::item:selected{background:#7c3aed;}")
        a_kill = menu.addAction(f"⚠ Kill process ({label})")
        menu.addSeparator()
        a_exit = menu.addAction("Выйти из приложения")

        chosen = menu.exec(QCursor.pos())
        if chosen == a_kill:
            self.runner.force_kill(engine)
            self._log(f"KILLED {label} (вручную, через индикатор)")
            # Состояние сессии могло держаться на этом процессе — сбрасываем
            if (engine == "xray" and self.active_p and
                    self.active_p.get("protocol") == "vless") or \
               (engine == "singbox" and self.active_p and
                    self.active_p.get("protocol") != "vless"):
                self.runner.proc = None
                self.dia.set_state("off")
                self._tray.setIcon(_make_tray_icon(C_ACCENT))
                clear_session()
        elif chosen == a_exit:
            self._quit_app()

    def _safe_background_check(self):
        """
        Вызывается через QTimer.singleShot(3000, ...) сразу после успешного
        runner.start(), чтобы поймать случай, когда API/сервис ответил "ok",
        но реальный процесс движка по факту не поднялся или сразу упал
        (например неверный конфиг). Раньше этот метод вызывался, но не
        существовал — таймер тихо проглатывал AttributeError и проверка
        никогда не выполнялась.

        Просто форсирует немедленный watchdog-тик вместо ожидания до 2 сек
        обычного интервала, обёрнутый в try/except, чтобы единичный сбой
        здесь никогда не уронил приложение.
        """
        try:
            self._watchdog_tick()
        except Exception as e:
            self._log(f"⚠ background check error: {e}")

    def _watchdog_tick(self):
        """
        Watchdog честно отражает состояние КАЖДОГО движка, который реально
        нужен в текущем режиме (self._active_engine_mode):
          "singbox" — только sing-box (hy2 любой, VLESS native-TUN)
          "xray"    — только Xray (VLESS PROXY)
          "dual"    — ОБА движка одновременно (VLESS TUN dual-core):
                      раньше тут принудительно гасился ind_core, теперь
                      оба индикатора показывают РЕАЛЬНОЕ состояние своего
                      процесса независимо друг от друга.
          None      — не подключены, оба индикатора неактивны.
        """
        mode = getattr(self, "_active_engine_mode", None)

        if mode is None:
            self.ind_core.set_state("inactive")
            self.ind_xray.set_state("inactive")
            self._watchdog_service_tick()
            return

        needs_sb = mode in ("singbox", "dual")
        needs_xr = mode in ("xray", "dual")

        sb_alive = self._is_singbox_running() if needs_sb else None
        xr_alive = self._is_xray_running()    if needs_xr else None

        # Индикаторы — независимо друг от друга, только то что реально нужно.
        # ПРИМЕЧАНИЕ: раньше тут также проверялся "рост" лог-файла за
        # последние 4 секунды, но при тике watchdog каждые 2 секунды это
        # условие математически было всегда True — то есть проверка ничего
        # не проверяла и просто маскировала реальное состояние. Плюс на
        # простом PROXY без активного трафика sing-box может не писать в
        # лог вообще, что ложно гасило индикатор в "error". Теперь индикатор
        # отражает только факт того, жив ли процесс — это и надёжнее, и
        # честнее показывает реальное состояние движка.
        if needs_sb:
            self.ind_core.set_state("active" if sb_alive else "error")
        else:
            self.ind_core.set_state("inactive")

        if needs_xr:
            self.ind_xray.set_state("active" if xr_alive else "error")
        else:
            self.ind_xray.set_state("inactive")

        # Главный алмаз (dia) "on" только если ВСЕ нужные для этого режима
        # движки живы — в dual-режиме обрыв любого из двух рвёт туннель целиком.
        overall_alive = (sb_alive if needs_sb else True) and (xr_alive if needs_xr else True)

        if overall_alive and self.dia.state != "on":
            self.dia.set_state("on")
            self._tray.setIcon(_make_tray_icon(C_ON))
        elif not overall_alive and self.dia.state == "on":
            self.dia.set_state("off")
            self._tray.setIcon(_make_tray_icon(C_ACCENT))
            self.runner.proc = None
            crashed = []
            if needs_sb and not sb_alive: crashed.append("SING-BOX")
            if needs_xr and not xr_alive: crashed.append("XRAY")
            self._log(f"CRASHED: {', '.join(crashed)} — проверь логи")
            self._active_engine_mode = None

        self._watchdog_service_tick()

    def _watchdog_service_tick(self):
        """SERVICE индикатор — отдельно, не зависит от режима движков."""
        try:
            from runner import service_installed, service_running
            if not service_installed():
                self.ind_svc.set_state("inactive")
            elif service_running():
                self.ind_svc.set_state("active")
            else:
                self.ind_svc.set_state("error")
        except Exception:
            self.ind_svc.set_state("inactive")

    # ── Вспомогательные методы watchdog ──────────────────────────────────────
    @staticmethod
    def _is_singbox_running() -> bool:
        """True если sing-box.exe есть среди процессов ОС."""
        if HAS_PSUTIL:
            for p in psutil.process_iter(["name"]):
                try:
                    if "sing-box" in p.info["name"].lower():
                        return True
                except Exception:
                    pass
            return False
        # Fallback без psutil — tasklist
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq sing-box.exe", "/NH"],
                text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return "sing-box" in out.lower()
        except Exception:
            return False

    @staticmethod
    def _is_xray_running() -> bool:
        """True если xray.exe есть среди процессов ОС."""
        if HAS_PSUTIL:
            for p in psutil.process_iter(["name"]):
                try:
                    name = p.info["name"].lower()
                    if name in ("xray.exe", "xray"):
                        return True
                except Exception:
                    pass
            return False
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq xray.exe", "/NH"],
                text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return "xray" in out.lower()
        except Exception:
            return False

    def _log_is_growing(self, path: str = None) -> bool:
        """
        True если указанный лог-файл изменился за последние ~4 сек.
        Первый вызов для каждого пути всегда возвращает True (даём ядру
        секунду на раскрутку). path по умолчанию — LOG_FILE (sing-box),
        для проверки Xray передавай XRAY_LOG_FILE.

        Состояние хранится по ключу path в словаре — иначе при одновременной
        проверке двух движков (dual-core режим) они бы затирали общие
        атрибуты self._last_log_mtime/_last_log_check друг у друга.
        """
        if path is None:
            path = LOG_FILE
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return False   # файла нет вовсе

        now = time.monotonic()
        state = getattr(self, "_log_growing_state", None)
        if state is None:
            state = {}
            self._log_growing_state = state

        last_mtime, last_check = state.get(path, (None, 0.0))
        state[path] = (mtime, now)

        if last_mtime is None:
            return True    # первый вызов для этого файла — считаем OK
        # Лог обновлялся менее 4 секунд назад относительно реального времени
        return (now - last_check) < 4.0 or (mtime != last_mtime)

    def _toggle(self):
        if not self.active_p: self._log("ERR: CLUSTER NOT SELECTED"); return
        if self.runner.proc:
            self.runner.stop()
            self.dia.set_state("off")
            self.ind_core.set_state("inactive")
            self.ind_xray.set_state("inactive")
            self._tray.setIcon(_make_tray_icon(C_ACCENT))
            self._log("OFFLINE")
            self._active_engine_mode = None
            clear_session(); return

        # ── Определяем протокол и режим ──────────────────────────────────────
        protocol = self.active_p.get("protocol", "hysteria2")
        is_vless = (protocol == "vless")
        use_tun  = (self.active_mode == "tun")

        if use_tun and not is_admin() and not service_installed():
            reply = QMessageBox.question(
                self, "Требуются права администратора",
                "TUN-режим требует прав администратора.\n\n"
                "Перезапустить с повышенными правами?\n"
                "(Или установи системный сервис в Настройках — тогда UAC не нужен)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                if relaunch_as_admin(): self._quit_app()
                else: QMessageBox.warning(self, "Отказано", "UAC-запрос отклонён.")
            return

        # Полная очистка зомби-процессов и зависших TUN-адаптеров ПЕРЕД
        # каждым стартом — устраняет 'FATAL cannot create file that already
        # exists' и похожие ошибки из-за недочищенного состояния прошлой сессии.
        try:
            from runner import cleanup_stale_state
            cleanup_stale_state()
        except Exception as e:
            self._log(f"⚠ cleanup_stale_state: {e}")

        s_cfg = load_settings()
        self.log_panel.reset_tail()

        # ══════════════════════════════════════════════════════════════════════
        # VLESS + TUN — DUAL CORE ARCHITECTURE (Sing-box TUN -> Xray SOCKS5)
        # Идеальный баланс: process_name работает через Sing-box,
        # а XHTTP-транспорт и Reality тянет Xray на максимальной скорости.
        # ══════════════════════════════════════════════════════════════════════
        if is_vless and use_tun:
            # 1. Генерируем Xray backend (транспорт)
            xray_cfg = build_vless_backend(self.active_p, socks_port=2082)
            with open(os.path.join(_BASE, "temp_xray.json"), "w") as f:
                json.dump(xray_cfg, f, indent=2)

            # 2. Генерируем Sing-box TUN frontend (роутинг по процессам)
            sb_cfg = build_tun_via_socks(self.active_p, socks_port=2082, s=s_cfg)

            # Форсируем оптимизации для локального моста прямо здесь
            sb_cfg["inbounds"][0]["mtu"] = 9000
            sb_cfg["outbounds"][0]["tcp_fast_open"] = True

            with open(os.path.join(_BASE, "temp_sb_tun.json"), "w") as f:
                json.dump(sb_cfg, f, indent=2)

            # 3. Поднимаем сначала Xray (чтобы открыл порт 2082 и ждал трафик)
            xray_ok = self.runner.start_secondary(os.path.join(_BASE, "temp_xray.json"), core="xray")
            if not xray_ok:
                self._log("XRAY BACKEND ERR — не удалось запустить (см. лог XRAY)")
                self.ind_xray.set_state("error")
                self._active_engine_mode = None
                return

            # 4. Поднимаем Sing-box TUN
            ok = self.runner.start(os.path.join(_BASE, "temp_sb_tun.json"),
                                   use_tun=True, core="singbox")
            if ok:
                self._active_engine_mode = "dual"   # ОБА движка должны быть живы
                self.dia.set_state("on")
                self.ind_core.set_state("active")    # Sing-box работает (перехват)
                self.ind_xray.set_state("active")    # Xray работает (VLESS/XHTTP)
                self._tray.setIcon(_make_tray_icon(C_ON))
                self._tray.showMessage("sb-hy2", "Подключено [Dual Core TUN/VLESS]",
                                       QSystemTrayIcon.MessageIcon.Information, 2000)
                self._log("CONNECTED [TUN/VLESS] — Dual Core (Sing-box TUN -> Xray SOCKS)")
                save_session(self.active_p, self.active_mode,
                             getattr(self, '_active_cluster_file', ''))
                if hasattr(self, "_safe_background_check"):
                    QTimer.singleShot(3000, self._safe_background_check)
            else:
                self._log("CORE ERR — не удалось запустить Dual Core VLESS TUN")
                self.dia.set_state("off")
                self.ind_core.set_state("error")
                self.ind_xray.set_state("error")
                self._active_engine_mode = None
                self.runner._stop_secondary()   # глушим Xray, раз sing-box не поднялся
            return

        # ── Обычные режимы (VLESS PROXY / HY2 PROXY / HY2 TUN) ───────────────
        if is_vless:
            cfg        = build_vless_proxy(self.active_p, s_cfg)
            core       = "xray"
            mode_label = "PROXY/XRAY"
            engine_mode = "xray"
        elif use_tun:
            cfg        = build_tun(self.active_p, s_cfg)
            core       = "singbox"
            mode_label = "TUN"
            engine_mode = "singbox"
        else:
            cfg        = build_proxy(self.active_p, s_cfg)
            core       = "singbox"
            mode_label = "PROXY"
            engine_mode = "singbox"

        with open(os.path.join(_BASE, "temp_config.json"), "w") as f:
            json.dump(cfg, f, indent=2)

        try:
            if self.runner.start(os.path.join(_BASE, "temp_config.json"),
                                 use_tun, None, core=core):
                self._active_engine_mode = engine_mode
                self.dia.set_state("on")
                if is_vless:
                    self.ind_xray.set_state("active")
                    self.ind_core.set_state("inactive")
                else:
                    self.ind_core.set_state("active")
                    self.ind_xray.set_state("inactive")
                self._tray.setIcon(_make_tray_icon(C_ON))
                self._tray.showMessage("sb-hy2", f"Подключено [{mode_label}]",
                                       QSystemTrayIcon.MessageIcon.Information, 2000)
                self._log(f"CONNECTED [{mode_label}]")
                save_session(self.active_p, self.active_mode,
                             getattr(self, '_active_cluster_file', ''))
                QTimer.singleShot(3000, self._safe_background_check)
            else:
                self._log(f"CORE ERR — не удалось запустить [{mode_label}]")
                self.dia.set_state("off")
                self.ind_core.set_state("error" if not is_vless else "inactive")
                self.ind_xray.set_state("error" if is_vless else "inactive")
                self._active_engine_mode = None
        except Exception as e:
            self._log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
            self._active_engine_mode = None

    def _select(self):
        d=ProfileDialog(runner=self.runner,active_mode=self.active_mode,parent=self)
        if d.exec():
            self.active_p=d.selected_data["data"]
            self._active_cluster_file=d.selected_data.get("file","")
            self.status.setText(f"{self.active_p['name']} | {self.active_mode.upper()}")
            self._log(f"READY: {self.active_p['name']}")

    def paintEvent(self,_):
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(C_ACCENT,1))
        p.drawRoundedRect(0,0,self.width()-1,self.height()-1,12,12)


if __name__=="__main__":
    app=QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window=MainWindow(); window.show()
    sys.exit(app.exec())