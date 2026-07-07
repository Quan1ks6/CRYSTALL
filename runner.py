# runner.py — HTTP API Edition
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

# Абсолютный путь к директории приложения — совпадает с _BASE в gui3.py
_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
        else os.path.dirname(os.path.abspath(__file__))
_LOG_DIR  = os.path.join(_BASE, "logs")
_LOG_FILE       = os.path.join(_LOG_DIR, "sb.log")          # sing-box лог
_XRAY_LOG_FILE  = os.path.join(_LOG_DIR, "xray.log")         # xray лог (primary ИЛИ secondary)
_SETTINGS_FILE  = os.path.join(_BASE, "settings.json")


# ── Порт сервиса (настраиваемый, см. SettingsDialog → SERVICE) ────────────────
def get_service_port() -> int:
    """
    Читает порт HTTP API сервиса из settings.json. Если файла/ключа нет —
    дефолт 33212. Это тот же файл, что и GUI использует для своих настроек,
    так что значение, сохранённое в SettingsDialog, подхватывается сразу.
    """
    try:
        with open(_SETTINGS_FILE, encoding="utf-8") as f:
            return int(json.load(f).get("service_port", DEFAULT_SVC_PORT))
    except Exception:
        return DEFAULT_SVC_PORT


def _api_base() -> str:
    return f"http://127.0.0.1:{get_service_port()}"


# ── Проверка прав ──────────────────────────────────────────────────────────────
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


# ── Service status ────────────────────────────────────────────────────────────
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


# ── HTTP API ──────────────────────────────────────────────────────────────────
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


# ── Install / uninstall service ───────────────────────────────────────────────
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


# ── Очистка логов ──────────────────────────────────────────────────────────────
def clear_logs():
    """
    Стирает логи sing-box и Xray (sb.log, xray.log).
    Вызывается при каждом старте приложения и по кнопке 'CLEAR' в LogPanel.
    Не трогает logs/sb_service.log — это персистентный лог самого
    Windows-сервиса, не привязанный к запускам GUI.
    """
    os.makedirs(_LOG_DIR, exist_ok=True)
    for path in (_LOG_FILE, _XRAY_LOG_FILE):
        try:
            open(path, "w", encoding="utf-8").close()
        except Exception as e:
            print(f"clear_logs: не удалось очистить {path}: {e}")


# ── Очистка перед стартом ─────────────────────────────────────────────────────
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
        # Если PowerShell не ответил — считаем, что не уверены, лучше
        # перестраховаться и попробовать удалить ещё раз, чем словить FATAL.
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
    """
    Убирает "хвосты" от прошлого аварийного завершения ДО старта новых
    процессов. Без этого sing-box иногда падает с
    'FATAL cannot create file that already exists' (зависший TUN-адаптер
    с тем же именем) или просто не может забиндить занятый процессом-зомби
    порт.

    В отличие от старой версии (один выстрел и надежда), эта функция
    ЖДЁТ результата:
      1. taskkill зомби-процессов sing-box.exe / xray.exe, затем опрашивает
         tasklist пока процесс реально не исчезнет (Windows не освобождает
         хэндл адаптера мгновенно после kill).
      2. Для каждого TUN-адаптера: сначала disable (драйверы WinTun иногда
         не отпускают адаптер без явного disable), потом Remove-NetAdapter,
         с поллингом Get-NetAdapter до полного исчезновения — вместо того
         чтобы пользователь вручную ждал 15 секунд, мы ждём ровно столько,
         сколько нужно (но не дольше max_wait), и не дольше.
    """
    t0 = time.monotonic()

    # 1. Зомби-процессы — убиваем и ждём фактического завершения
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

    # 2. Зависшие TUN-адаптеры — disable, потом remove, с поллингом
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
        self.proc2 = None        # Вторичный процесс (Xray-бэкенд при VLESS TUN)
        self._log_fh  = None
        self._log_fh2 = None
        self._via_service = False

    def start(self, config: str, use_tun: bool = False, sudo_password: str = None,
              core: str = "singbox", force_direct: bool = False) -> bool:
        """
        core: "singbox" (default) | "xray"
        force_direct: True → никогда не использовать сервис (для dual-process режима).
          В VLESS TUN dual-режиме sing-box стартует напрямую (force_direct=True),
          чтобы сервис не перехватил конфиг и не запустил не тот бинарник.
        """
        if self.proc:
            self.stop()

        if use_tun and not force_direct and service_installed():
            config_path = os.path.abspath(config)

            # Для xray передаём binary_path, чтобы сервис знал что запускать
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

        # Лог идёт в отдельный файл в зависимости от движка — иначе при
        # одновременной работе (dual-core) логи sing-box и Xray перемешиваются
        # в одном файле и фильтр по источнику в GUI становится бессмысленным.
        # Если log_to_file=False — пишем в DEVNULL: файл не создаётся,
        # но GUI всё равно показывает вывод (LogTailThread читает stdout).
        log_to_file = True
        try:
            with open(_SETTINGS_FILE, encoding="utf-8") as _sf:
                log_to_file = json.load(_sf).get("log_to_file", True)
        except Exception:
            pass

        log_path = _XRAY_LOG_FILE if core == "xray" else _LOG_FILE
        if log_to_file:
            self._log_fh = open(log_path, "w", encoding="utf-8")
        else:
            # Не пишем в файл — используем DEVNULL чтобы не накапливать лог
            self._log_fh = open(os.devnull, "w")

        # Выбираем бинарник в зависимости от протокола
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
            # Ждём пока sing-box действительно остановится (сервис async),
            # иначе TUN-адаптер может ещё висеть когда мы стартуем снова.
            for _ in range(30):   # до 3 секунд
                time.sleep(0.1)
                st = _api_get("/status")
                if not st.get("running", True):
                    break
            self.proc = None
            self._via_service = False
            # Останавливаем вторичный процесс (Xray-бэкенд) если был запущен
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

        # Останавливаем Xray-бэкенд если был запущен (VLESS TUN режим)
        self._stop_secondary()

    def _stop_secondary(self):
        """Останавливает вторичный процесс (Xray-бэкенд для VLESS TUN)."""
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
        """
        Запускает вторичный процесс (Xray SOCKS5-бэкенд) для VLESS TUN-режима.
        Вызывается ДО start() с sing-box TUN, чтобы Xray успел поднять SOCKS5.
        Лог пишется в logs/xray_backend.log (отдельно от основного sb.log).
        """
        self._stop_secondary()   # убиваем предыдущий если был

        exe = self._find_xray() if core == "xray" else self._find_singbox()
        if not exe:
            print(f"start_secondary: {core} executable not found")
            return False

        config_path = os.path.abspath(config)
        os.makedirs(_LOG_DIR, exist_ok=True)
        # Тот же файл что и для primary-Xray — источник один и тот же (xray.exe),
        # фильтру в GUI достаточно знать ИМЯ файла, не важно, primary или secondary.
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
        """
        Жёстко убивает процесс движка по имени, независимо от того, кто его
        запустил (GUI напрямую, сервис, или он стал зомби после краша).
        engine: "singbox" | "xray"
        Используется по кнопке 'Kill process' при клике на индикатор.
        """
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
        """Ищет xray.exe рядом с приложением или в PATH."""
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
