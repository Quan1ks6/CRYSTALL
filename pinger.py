import socket
import time
import urllib.request
import urllib.error
import threading
from typing import Optional, Tuple

from PyQt6.QtCore import QThread, pyqtSignal

PING_TARGETS = [
    "http://cp.cloudflare.com/",
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
PING_TIMEOUT = 4.0
PING_URL = PING_TARGETS[0]
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 2080

def url_ping_via_proxy(
    url:     str            = PING_URL,
    proxy:   Optional[str]  = None,
    timeout: float          = PING_TIMEOUT,
) -> dict:

    t0 = time.perf_counter()
    try:
        if proxy:
            handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener  = urllib.request.build_opener(handler)
        else:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({})
            )
        req = urllib.request.Request(url, headers={"User-Agent": "sb-hy2/ping"})
        with opener.open(req, timeout=timeout) as resp:
            ms     = (time.perf_counter() - t0) * 1000
            status = resp.status
        return {"ok": True, "ms": round(ms, 1), "status": status, "error": None}
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        return {"ok": True, "ms": round(ms, 1), "status": e.code, "error": None}
    except Exception as e:
        return {"ok": False, "ms": None, "status": None, "error": str(e)}

def tcp_ping(host: str, port: int, timeout: float = 5.0) -> dict:

    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.perf_counter() - t0) * 1000
        return {"ok": True, "ms": round(ms, 1), "error": None}
    except socket.timeout:
        return {"ok": False, "ms": None, "error": "timeout"}
    except OSError as e:
        return {"ok": False, "ms": None, "error": str(e)}

class UrlPingThread(QThread):

    result = pyqtSignal(bool, float, int)

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

URL_TARGETS = [
    ("Cloudflare", "http://cp.cloudflare.com/"),
    ("Google",     "http://www.gstatic.com/generate_204"),
    ("Яндекс",     "http://yandex.ru/"),
]

class UrlTestThread(QThread):

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
