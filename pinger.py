# pinger.py — пинг через HTTP запрос через прокси (как V2rayN/Clash)
import socket
import time
import urllib.request
import urllib.error
import threading
from typing import Optional, Tuple

from PyQt6.QtCore import QThread, pyqtSignal

# URL для пинга — возвращает минимальный ответ, идеально для замера задержки
PING_TARGETS = [
    "http://cp.cloudflare.com/",
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
   # Google, 204 No Content
PING_TIMEOUT = 4.0   # секунд
PING_URL = PING_TARGETS[0]
# Адрес локального прокси sing-box (PROXY-режим)
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 2080


def url_ping_via_proxy(
    url:     str            = PING_URL,
    proxy:   Optional[str]  = None,
    timeout: float          = PING_TIMEOUT,
) -> dict:
    """
    Делает HTTP GET и замеряет RTT.
    proxy=None  → напрямую (ядро выключено, реальная задержка твоей сети)
    proxy=str   → через прокси sing-box (ядро включено, задержка через туннель)

    Возвращает:
        {"ok": bool, "ms": float|None, "status": int|None, "error": str|None}
    """
    t0 = time.perf_counter()
    try:
        if proxy:
            handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener  = urllib.request.build_opener(handler)
        else:
            # Прямое соединение, игнорируем системный прокси
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({})   # пустой — отключает системный прокси
            )
        req = urllib.request.Request(url, headers={"User-Agent": "sb-hy2/ping"})
        with opener.open(req, timeout=timeout) as resp:
            ms     = (time.perf_counter() - t0) * 1000
            status = resp.status
        return {"ok": True, "ms": round(ms, 1), "status": status, "error": None}
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        # 204/301/302/403 — всё равно значит соединение работает
        return {"ok": True, "ms": round(ms, 1), "status": e.code, "error": None}
    except Exception as e:
        return {"ok": False, "ms": None, "status": None, "error": str(e)}


def tcp_ping(host: str, port: int, timeout: float = 5.0) -> dict:
    """
    Прямой TCP пинг до сервера — показывает доступность хоста,
    но НЕ проверяет реальную работу туннеля.
    Используется в менеджере кластеров для быстрой проверки серверов.
    """
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.perf_counter() - t0) * 1000
        return {"ok": True, "ms": round(ms, 1), "error": None}
    except socket.timeout:
        return {"ok": False, "ms": None, "error": "timeout"}
    except OSError as e:
        return {"ok": False, "ms": None, "error": str(e)}


# ── QThread: URL-пинг через прокси (для главного окна) ────────────────────────
class UrlPingThread(QThread):
    """
    Пингует через активный прокси sing-box.
    Используй после успешного запуска sing-box в PROXY-режиме.
    В TUN-режиме прокси не нужен — трафик идёт через tun, просто убери proxy=None.
    """
    result = pyqtSignal(bool, float, int)   # ok, ms, http_status

    def __init__(self,
                 url:      str            = PING_URL,
                 proxy:    Optional[str]  = None,
                 timeout:  float          = PING_TIMEOUT):
        super().__init__()
        self.url     = url
        self.proxy   = proxy
        self.timeout = timeout

    def run(self):
        r = url_ping_via_proxy(self.url, self.proxy, self.timeout)
        ms     = r["ms"]     if r["ms"]     is not None else 0.0
        status = r["status"] if r["status"] is not None else 0
        self.result.emit(r["ok"], ms, status)


# ── QThread: TCP пинг (для менеджера кластеров) ───────────────────────────────
class TcpPingThread(QThread):
    result = pyqtSignal(bool, float)

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        super().__init__()
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def run(self):
        r  = tcp_ping(self.host, self.port, timeout=self.timeout)
        ms = r["ms"] if r["ms"] is not None else 0.0
        self.result.emit(r["ok"], ms)


# ── Вспомогательный класс: URL тест для нескольких сайтов параллельно ─────────
URL_TARGETS = [
    ("Cloudflare", "http://cp.cloudflare.com/"),
    ("Google",     "http://www.gstatic.com/generate_204"),
    ("Яндекс",     "http://yandex.ru/"),
]

class UrlTestThread(QThread):
    """Тестирует несколько URL через прокси параллельно."""
    result = pyqtSignal(bool, float, int)

    def __init__(self, url: str, proxy: Optional[str] = None):
        super().__init__()
        self.url   = url
        self.proxy = proxy

    def run(self):
        r = url_ping_via_proxy(self.url, self.proxy or f"http://{PROXY_HOST}:{PROXY_PORT}")
        ms     = r["ms"]     if r["ms"]     is not None else 0.0
        status = r["status"] if r["status"] is not None else 0
        self.result.emit(r["ok"], ms, status)
