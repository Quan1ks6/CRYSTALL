import sys
import os
import json
import logging
import shutil
import subprocess
import threading

from http.server import (
    ThreadingHTTPServer,
    BaseHTTPRequestHandler
)

import win32serviceutil
import win32service
import win32event
import servicemanager
import win32timezone

SVC_NAME = "sb-hy2-svc"

SVC_HOST = "127.0.0.1"

DEFAULT_SVC_PORT = 33212

if getattr(sys, "frozen", False):

    _BASE = os.path.dirname(
        os.path.abspath(sys.executable)
    )

else:

    _BASE = os.path.dirname(
        os.path.abspath(__file__)
    )

os.chdir(_BASE)

def _load_svc_port() -> int:

    try:
        with open(os.path.join(_BASE, "settings.json"), encoding="utf-8") as f:
            return int(json.load(f).get("service_port", DEFAULT_SVC_PORT))
    except Exception:
        return DEFAULT_SVC_PORT

SVC_PORT = _load_svc_port()

LOG_DIR = os.path.join(_BASE, "logs")

os.makedirs(LOG_DIR, exist_ok=True)

SERVICE_LOG = os.path.join(
    LOG_DIR,
    "sb_service.log"
)

CORE_LOG = os.path.join(
    LOG_DIR,
    "sb.log"
)

logging.basicConfig(
    filename=SERVICE_LOG,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def _find_binary(binary_path: str = None):

    if binary_path:
        abs_path = os.path.abspath(binary_path)
        logging.info(f"BINARY OVERRIDE: {abs_path}")
        if os.path.isfile(abs_path):
            return abs_path
        logging.warning(f"BINARY NOT FOUND at override path: {abs_path}")

    return _find_singbox()

def _find_singbox():

    candidates = [

        os.path.join(
            _BASE,
            "sing-box.exe"
        ),

        os.path.join(
            os.path.dirname(sys.executable),
            "sing-box.exe"
        )
    ]

    for c in candidates:

        abs_c = os.path.abspath(c)

        logging.info(
            f"CHECK SINGBOX: {abs_c}"
        )

        if os.path.isfile(abs_c):
            return abs_c

    return (
        shutil.which("sing-box")
        or shutil.which("sing-box.exe")
    )

_state = {

    "proc": None,

    "log_fh": None,

    "lock": threading.RLock()
}

def _start_core(config_path: str, binary_path: str = None) -> dict:

    with _state["lock"]:

        _stop_core_locked()

        exe = _find_binary(binary_path)

        logging.info(
            f"START config={config_path}"
        )

        logging.info(
            f"START exe={exe}"
        )

        logging.info(
            f"cwd={os.getcwd()}"
        )

        if not exe:

            logging.error(
                "sing-box.exe not found"
            )

            return {
                "status": "error",
                "message": "sing-box.exe not found"
            }

        if not os.path.isfile(config_path):

            logging.error(
                f"config not found: {config_path}"
            )

            return {
                "status": "error",
                "message": "config not found"
            }

        try:

            fh = open(
                CORE_LOG,
                "w",
                encoding="utf-8"
            )

            proc = subprocess.Popen(

                [
                    exe,
                    "run",
                    "-c",
                    config_path
                ],

                cwd=_BASE,

                stdout=fh,
                stderr=subprocess.STDOUT,

                creationflags=subprocess.CREATE_NO_WINDOW
            )

            _state["proc"] = proc

            _state["log_fh"] = fh

            logging.info(
                f"CORE STARTED PID={proc.pid}"
            )

            return {
                "status": "ok",
                "pid": proc.pid
            }

        except Exception as e:

            logging.exception(
                "CORE START FAILED"
            )

            return {
                "status": "error",
                "message": str(e)
            }

def _stop_core_locked():

    proc = _state["proc"]

    if proc:

        logging.info(
            "STOP CORE"
        )

        try:

            proc.terminate()

            try:

                proc.wait(timeout=5)

            except subprocess.TimeoutExpired:

                logging.warning(
                    "CORE FORCE KILL"
                )

                proc.kill()

        except Exception:

            logging.exception(
                "CORE STOP FAILED"
            )

            try:
                proc.kill()
            except:
                pass

        _state["proc"] = None

    fh = _state["log_fh"]

    if fh:

        try:
            fh.close()
        except:
            pass

        _state["log_fh"] = None

def _stop_core() -> dict:

    with _state["lock"]:

        _stop_core_locked()

    return {
        "status": "ok"
    }

def _get_status() -> dict:

    with _state["lock"]:

        proc = _state["proc"]

        running = (
            proc is not None
            and proc.poll() is None
        )

        pid = proc.pid if running else None

    return {

        "status": "ok",

        "service": "RUNNING",

        "running": running,

        "pid": pid
    }

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):

        logging.info(fmt % args)

    def _send_json(
        self,
        data: dict,
        code: int = 200
    ):

        body = json.dumps(data).encode("utf-8")

        self.send_response(code)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)

    def _read_json(self) -> dict:

        try:

            length = int(
                self.headers.get(
                    "Content-Length",
                    0
                )
            )

            if length <= 0:
                return {}

            raw = self.rfile.read(length)

            return json.loads(
                raw.decode("utf-8")
            )

        except Exception:

            logging.exception(
                "JSON READ FAILED"
            )

            return {}

    def do_GET(self):

        if self.path == "/status":

            self._send_json(
                _get_status()
            )

            return

        self._send_json(
            {
                "status": "error",
                "message": "not found"
            },
            404
        )

    def do_POST(self):

        if self.path == "/start":

            body = self._read_json()

            cfg = body.get(
                "config_path",
                ""
            )

            if not cfg:

                self._send_json(
                    {
                        "status": "error",
                        "message": "config_path required"
                    },
                    400
                )

                return

            binary_path = body.get("binary_path", None)

            self._send_json(
                _start_core(cfg, binary_path)
            )

            return

        if self.path == "/stop":

            self._send_json(
                _stop_core()
            )

            return

        self._send_json(
            {
                "status": "error",
                "message": "not found"
            },
            404
        )

class SbHy2Service(
    win32serviceutil.ServiceFramework
):

    _svc_name_ = SVC_NAME

    _svc_display_name_ = (
        "sb-hy2 Tunnel Service"
    )

    _svc_description_ = (
        "Runs sing-box as SYSTEM for TUN mode"
    )

    def __init__(self, args):

        super().__init__(args)

        self._stop_event = (
            win32event.CreateEvent(
                None,
                0,
                0,
                None
            )
        )

        self._server = None

    def SvcStop(self):

        logging.info(
            "SERVICE STOP"
        )

        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING
        )

        _stop_core()

        if self._server:

            try:

                self._server.shutdown()

            except Exception:

                logging.exception(
                    "SERVER SHUTDOWN FAILED"
                )

        win32event.SetEvent(
            self._stop_event
        )

    def SvcDoRun(self):

        logging.info(
            "SERVICE STARTED"
        )

        servicemanager.LogMsg(

            servicemanager.EVENTLOG_INFORMATION_TYPE,

            servicemanager.PYS_SERVICE_STARTED,

            (self._svc_name_, '')
        )

        try:

            self._server = (
                ThreadingHTTPServer(
                    (SVC_HOST, SVC_PORT),
                    Handler
                )
            )

            logging.info(
                f"HTTP API STARTED ON "
                f"{SVC_HOST}:{SVC_PORT}  (settings.json service_port={SVC_PORT})"
            )

            threading.Thread(

                target=self._server.serve_forever,

                daemon=True

            ).start()

            win32event.WaitForSingleObject(
                self._stop_event,
                win32event.INFINITE
            )

        except OSError as e:

            logging.error(
                f"BIND FAILED on {SVC_HOST}:{SVC_PORT} — {e}. "
                f"Скорее всего порт занят другим процессом. "
                f"Смени порт в Settings → SERVICE на свободный."
            )

        except Exception:

            logging.exception(
                "SERVICE FAILED"
            )

if __name__ == "__main__":

    if len(sys.argv) == 1:

        servicemanager.Initialize()

        servicemanager.PrepareToHostSingle(
            SbHy2Service
        )

        servicemanager.StartServiceCtrlDispatcher()

    else:

        win32serviceutil.HandleCommandLine(
            SbHy2Service
        )
