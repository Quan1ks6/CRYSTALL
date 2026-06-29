import os
import sys
import json
import signal
import subprocess
import ctypes
import time
import tempfile
import urllib.request
import urllib.error

SERVICE_NAME = "sb-hy2-svc"
DEFAULT_SVC_PORT = 33212

_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
        else os.path.dirname(os.path.abspath(__file__))
_LOG_DIR  = os.path.join(_BASE, "logs")
_LOG_FILE       = os.path.join(_LOG_DIR, "sb.log")
_XRAY_LOG_FILE  = os.path.join(_LOG_DIR, "xray.log")
_SETTINGS_FILE  = os.path.join(_BASE, "settings.json")

def get_service_port() -> int:
    try:
        with open(_SETTINGS_FILE, encoding="utf-8") as f:
            return int(json.load(f).get("service_port", DEFAULT_SVC_PORT))
    except Exception:
        return DEFAULT_SVC_PORT

def _api_base() -> str:
    return f"http://127.0.0.1:{get_service_port()}"

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_as_admin():
    script = os.path.abspath(sys.argv[0])
    args = " ".join(f'"{a}"' for a in sys.argv[1:])

    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{script}" {args}',
        None,
        1
    )

    return ret > 32

def service_installed() -> bool:
    try:
        r = subprocess.run(
            ["sc", "query", SERVICE_NAME],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        return r.returncode == 0

    except Exception:
        return False

def service_running() -> bool:
    try:
        r = subprocess.run(
            ["sc", "query", SERVICE_NAME],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        return "RUNNING" in r.stdout

    except Exception:
        return False

def _api_post(path: str, payload: dict | None = None, timeout: float = 5.0):
    try:
        data = None

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            _api_base() + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }

def _api_get(path: str, timeout: float = 5.0):
    try:
        with urllib.request.urlopen(_api_base() + path, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }

def service_api_alive() -> bool:
    r = _api_get("/status")

    return r.get("service") == "RUNNING"

def install_service() -> tuple[bool, str]:
    _BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
            else os.path.dirname(os.path.abspath(__file__))

    svc_exe = os.path.join(_BASE, "sb_service.exe")

    if not os.path.isfile(svc_exe):
        svc_exe = f'"{sys.executable}" "{os.path.join(_BASE, "sb_service.py")}"'

    if is_admin():
        r = subprocess.run(
            [
                "sc", "create", SERVICE_NAME,
                "binPath=", svc_exe,
                "start=", "auto",
                "DisplayName=", "sb-hy2 Tunnel Service"
            ],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if r.returncode == 0:
            subprocess.run(
                ["sc", "start", SERVICE_NAME],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            return True, "Сервис установлен"

        return False, r.stderr or r.stdout

    bat_path = os.path.join(tempfile.gettempdir(), "sb_hy2_install_svc.bat")

    with open(bat_path, "w", encoding="ansi") as f:
        f.write("@echo off\n")
        f.write(
            f'sc create {SERVICE_NAME} '
            f'binPath= "{svc_exe}" '
            f'start= auto '
            f'DisplayName= "sb-hy2 Tunnel Service" >nul\n'
        )

        f.write(f'sc start {SERVICE_NAME} >nul\n')

    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        bat_path,
        None,
        None,
        0
    )

    if ret <= 32:
        return False, "UAC отклонён"

    for _ in range(15):
        if service_installed():
            return True, "Сервис установлен"

        time.sleep(1.0)

    return False, "Timeout"

def uninstall_service() -> tuple[bool, str]:
    if is_admin():
        subprocess.run(
            ["sc", "stop", SERVICE_NAME],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        subprocess.run(
            ["sc", "delete", SERVICE_NAME],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        ok = not service_installed()

        return ok, "Сервис удалён" if ok else "Ошибка удаления"

    bat_path = os.path.join(tempfile.gettempdir(), "sb_hy2_uninstall_svc.bat")

    with open(bat_path, "w", encoding="ansi") as f:
        f.write("@echo off\n")
        f.write(f'sc stop {SERVICE_NAME} >nul\n')
        f.write(f'sc delete {SERVICE_NAME} >nul\n')

    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        bat_path,
        None,
        None,
        0
    )

    if ret <= 32:
        return False, "UAC отклонён"

    for _ in range(15):
        if not service_installed():
            return True, "Сервис удалён"

        time.sleep(1.0)

    return False, "Timeout"

def clear_logs():
    
    os.makedirs(_LOG_DIR, exist_ok=True)
    for path in (_LOG_FILE, _XRAY_LOG_FILE):
        try:
            open(path, "w", encoding="utf-8").close()
        except Exception as e:
            print(f"clear_logs: не удалось очистить {path}: {e}")

def _adapter_exists(name: str) -> bool:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'(Get-NetAdapter -Name "{name}" -ErrorAction SilentlyContinue) -ne $null'],
            capture_output=True, text=True, timeout=4,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return r.stdout.strip().lower() == "true"
    except Exception:
        return False

def _process_running(image: str) -> bool:
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"IMAGENAME eq {image}", "/NH"],
            text=True, timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return image.lower() in out.lower()
    except Exception:
        return False

def cleanup_stale_state(tun_interface_names: tuple[str, ...] = ("sb-tun", "xray-tun"),
                         max_wait: float = 6.0):
    
    t0 = time.monotonic()

    for image in ("sing-box.exe", "xray.exe"):
        if not _process_running(image):
            continue
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", image],
                capture_output=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass
        while _process_running(image) and (time.monotonic() - t0) < max_wait:
            time.sleep(0.2)

    for name in tun_interface_names:
        if not _adapter_exists(name):
            continue
        try:
            subprocess.run(
                ["netsh", "interface", "set", "interface", name, "admin=disabled"],
                capture_output=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f'Remove-NetAdapter -Name "{name}" -Confirm:$false -ErrorAction SilentlyContinue'],
                capture_output=True, timeout=6,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass

        remaining = max_wait - (time.monotonic() - t0)
        while _adapter_exists(name) and remaining > 0:
            time.sleep(0.3)
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f'Remove-NetAdapter -Name "{name}" -Confirm:$false -ErrorAction SilentlyContinue'],
                    capture_output=True, timeout=4,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception:
                pass
            remaining = max_wait - (time.monotonic() - t0)

class Runner:
    def __init__(self):
        self.proc  = None
        self.proc2 = None
        self._log_fh  = None
        self._log_fh2 = None
        self._via_service = False

    def start(self, config: str, use_tun: bool = False, sudo_password: str = None,
              core: str = "singbox", force_direct: bool = False) -> bool:
        
        if self.proc:
            self.stop()

        if use_tun and not force_direct and service_installed():
            config_path = os.path.abspath(config)

            payload: dict = {"config_path": config_path}
            if core == "xray":
                xray_exe = self._find_xray()
                if xray_exe:
                    payload["binary_path"] = xray_exe

            reply = _api_post("/start", payload)

            if str(reply.get("status", "")).lower() == "ok":
                self._via_service = True
                self.proc = True
                return True

            print(reply)
            return False

        if use_tun and not is_admin():
            return False

        self._via_service = False

        config_path = os.path.abspath(config)

        os.makedirs(_LOG_DIR, exist_ok=True)

        if self._log_fh:
            try:
                self._log_fh.close()
            except:
                pass

        log_path = _XRAY_LOG_FILE if core == "xray" else _LOG_FILE
        self._log_fh = open(
            log_path,
            "w",
            encoding="utf-8"
        )

        if core == "xray":
            exe = self._find_xray()
            if not exe:
                print("xray.exe not found")
                return False
        else:
            exe = self._find_singbox()
            if not exe:
                print("sing-box.exe not found")
                return False

        try:
            self.proc = subprocess.Popen(
                [exe, "run", "-c", config_path],
                stdout=self._log_fh,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                              | subprocess.CREATE_NO_WINDOW
            )

            return True

        except Exception as e:
            print(e)
            return False

    def stop(self):
        if not self.proc:
            return

        if self._via_service:
            _api_post("/stop")
            for _ in range(30):
                time.sleep(0.1)
                st = _api_get("/status")
                if not st.get("running", True):
                    break
            self.proc = None
            self._via_service = False
            self._stop_secondary()
            return

        try:
            self.proc.send_signal(signal.CTRL_BREAK_EVENT)

            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

        except Exception:
            try:
                self.proc.kill()
            except:
                pass

        finally:
            self.proc = None

            if self._log_fh:
                try:
                    self._log_fh.close()
                except:
                    pass

                self._log_fh = None

        self._stop_secondary()

    def _stop_secondary(self):
        
        if not self.proc2:
            return
        try:
            self.proc2.terminate()
            try:
                self.proc2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc2.kill()
        except Exception:
            try:
                self.proc2.kill()
            except:
                pass
        finally:
            self.proc2 = None
            if self._log_fh2:
                try:
                    self._log_fh2.close()
                except:
                    pass
                self._log_fh2 = None

    def start_secondary(self, config: str, core: str = "xray") -> bool:
        
        self._stop_secondary()

        exe = self._find_xray() if core == "xray" else self._find_singbox()
        if not exe:
            print(f"start_secondary: {core} executable not found")
            return False

        config_path = os.path.abspath(config)
        os.makedirs(_LOG_DIR, exist_ok=True)
        log_path = _XRAY_LOG_FILE if core == "xray" else _LOG_FILE

        try:
            self._log_fh2 = open(log_path, "w", encoding="utf-8")
            self.proc2 = subprocess.Popen(
                [exe, "run", "-c", config_path],
                stdout=self._log_fh2,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                              | subprocess.CREATE_NO_WINDOW,
            )
            return True
        except Exception as e:
            print(f"start_secondary error: {e}")
            return False

    @staticmethod
    def force_kill(engine: str):
        
        image = "sing-box.exe" if engine == "singbox" else "xray.exe"
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", image],
                capture_output=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass

    @staticmethod
    def _find_singbox() -> str | None:
        import shutil

        candidates = [
            os.path.join(os.path.dirname(sys.executable), "sing-box.exe"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "sing-box.exe"),
            os.path.join(os.getcwd(), "sing-box.exe")
        ]

        for c in candidates:
            if os.path.isfile(c):
                return c

        return shutil.which("sing-box") or shutil.which("sing-box.exe")

    @staticmethod
    def _find_xray() -> str | None:
        
        import shutil

        candidates = [
            os.path.join(os.path.dirname(sys.executable), "xray.exe"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray.exe"),
            os.path.join(os.getcwd(), "xray.exe"),
        ]

        for c in candidates:
            if os.path.isfile(c):
                return c

        return shutil.which("xray") or shutil.which("xray.exe")
