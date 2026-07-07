# xray_builder.py — генератор конфигов Xray для VLESS >= 24.x
# Поддерживаемые транспорты: tcp, ws, xhttp, grpc, h2, quic, kcp
# Безопасность: none, tls, reality
# Режимы: PROXY (HTTP 2080 + SOCKS5 2081) и TUN (через wintun.dll)
#
# ПРАВИЛА (rules.txt):
#   Единый формат для обоих ядер — Xray конвертирует sing-box правила
#   на лету. Никаких geoip.dat/geosite.dat не требуется.

import subprocess
import re
from rules import get_route_rules

HTTP_PORT  = 2080
SOCKS_PORT = 2081

# Приватные диапазоны без geoip.dat — используем явные CIDR.
# geoip:private требует geoip.dat рядом с xray.exe, без него Xray
# игнорирует правило и routing ломается целиком.
_PRIVATE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


# ── Default gateway ───────────────────────────────────────────────────────────

def _get_default_gateway() -> str | None:
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


# ── Outbound ──────────────────────────────────────────────────────────────────

def _user(p: dict, s: dict = None) -> dict:
    u = {
        "id":         p["uuid"],
        "encryption": p.get("encryption", "none"),
    }
    if p.get("flow"):
        u["flow"] = p["flow"]
    enc = (s or {}).get("xray_udp_encoding", "none")
    if enc and enc != "none":
        u["packetEncoding"] = enc      # "xudp" | "packetaddr"
    return u


def _stream_settings(p: dict) -> dict:
    transport = p.get("transport", "tcp")
    security  = p.get("security", "none")

    if transport == "splithttp":
        transport = "http"
    if transport == "mkcp":
        transport = "kcp"

    ss: dict = {"network": transport}

    if security == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName":  p.get("sni", p["host"]),
            "fingerprint": p.get("fp", "chrome"),
            "show":        False,
            "publicKey":   p.get("pbk", ""),
            "shortId":     p.get("sid", ""),
            "spiderX":     p.get("spx", "/"),
        }
    elif security == "tls":
        ss["security"] = "tls"
        tls: dict = {
            "serverName":    p.get("sni", p["host"]),
            "allowInsecure": p.get("allow_insecure", False),
            "fingerprint":   p.get("fp", "chrome"),
        }
        if p.get("alpn"):
            tls["alpn"] = p["alpn"]
        ss["tlsSettings"] = tls

    match transport:
        case "tcp":
            ss["tcpSettings"] = {"header": {"type": "none"}}
        case "ws":
            ws: dict = {"path": p.get("path", "/")}
            if p.get("host_header"):
                ws["headers"] = {"Host": p["host_header"]}
            ss["wsSettings"] = ws
        case "xhttp":
            xhttp: dict = {
                "path": p.get("path", "/"),
                "mode": p.get("xhttp_mode", "auto"),
            }
            if p.get("host_header"):
                xhttp["host"] = p["host_header"]
            for k, v in p.get("xhttp_extra", {}).items():
                if k != "mode":
                    xhttp[k] = v
            ss["xhttpSettings"] = xhttp
        case "grpc":
            ss["grpcSettings"] = {
                "serviceName": p.get("service_name", ""),
                "multiMode":   p.get("grpc_multi", False),
            }
        case "h2":
            h2: dict = {"path": p.get("path", "/")}
            if p.get("host_header"):
                h2["host"] = [p["host_header"]]
            ss["httpSettings"] = h2
        case "quic":
            ss["quicSettings"] = {
                "security": p.get("quic_security", "none"),
                "key":      p.get("quic_key", ""),
                "header":   {"type": p.get("quic_header", "none")},
            }
        case "kcp":
            kcp: dict = {"header": {"type": p.get("kcp_header", "none")}}
            if p.get("kcp_seed"):
                kcp["seed"] = p["kcp_seed"]
            ss["kcpSettings"] = kcp

    return ss


def _vless_outbound(p: dict, s: dict = None) -> dict:
    server = p.get("resolved_ip") or p["host"]
    return {
        "tag":      "proxy-out",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server,
                "port":    p["port"],
                "users":   [_user(p, s)],
            }]
        },
        "streamSettings": _stream_settings(p),
        "mux": {"enabled": False, "concurrency": -1},
    }


# ── Rules conversion: sing-box → Xray ────────────────────────────────────────
#
# Маппинг типов доменов:
#   sing-box "domain"        → Xray "full:val"      (точный домен без поддоменов)
#   sing-box "domain_suffix" → Xray "domain:val"    (домен + все поддомены)
#   sing-box "domain_keyword"→ Xray "keyword:val"   (ключевое слово в домене)
#   sing-box "ip_cidr"       → Xray "ip" field      (CIDR-диапазон)
#   sing-box "ip_is_private" → явные приватные CIDR (без geoip.dat!)
#   sing-box "process_name"  → пропускаем           (Xray не поддерживает)
#
# Outbound теги:
#   "proxy-out" → "proxy-out"
#   "direct"    → "direct"
#   reject      → "block"    (blackhole outbound)

def _xray_tag(outbound: str, action: str = "") -> str:
    if action == "reject" or outbound == "reject":
        return "block"
    if outbound == "direct":
        return "direct"
    return "proxy-out"


def _extract_process_rules(sb_rules: list[dict]) -> list[str]:
    """
    Извлекает PROCESS-NAME/PROCESS-PATH правила из rules.txt и возвращает
    список процессов для excludeProcess в TUN inbound.

    В TUN-режиме Xray работает только через excludeProcess (чёрный список):
      PROCESS-NAME,app.exe,direct → app.exe попадает в excludeProcess
                                     (обходит TUN, идёт напрямую)
      PROCESS-NAME,app.exe,proxy  → НЕ нужен excludeProcess
                                     (трафик захватывается TUN по умолчанию)

    Почему НЕ используем includeProcess (белый список):
      includeProcess + strictRoute блокирует svchost.exe (Windows DNS Client),
      из-за чего DNS-резолвинг полностью падает → "сайт не найден".

    Для сценария "только firefox через прокси, остальное напрямую":
      → используй PROXY-режим (HTTP 127.0.0.1:2080), а не TUN.
      → TUN-режим предназначен для "всё через прокси, кроме исключений".
    """
    direct_procs: list[str] = []

    for r in sb_rules:
        if "process_name" not in r and "process_path" not in r:
            continue
        procs = r.get("process_name", []) + r.get("process_path", [])
        tag = _xray_tag(r.get("outbound", "proxy-out"), r.get("action", ""))
        if tag == "direct":
            direct_procs.extend(procs)

    return direct_procs


def _convert_sb_rules(sb_rules: list[dict]) -> list[dict]:
    """
    Конвертирует список правил из sing-box формата в Xray формат.
    Читается из rules.txt через get_route_rules() → уже sing-box dict-ы.
    """
    out = []
    for r in sb_rules:
        # ── process_name / process_path: Xray routing не поддерживает ────────
        if "process_name" in r or "process_path" in r:
            continue

        xr: dict = {"type": "field"}

        # ── Домены ────────────────────────────────────────────────────────────
        domains = []

        # DOMAIN (точный) → full:val
        # В sing-box "domain" = точное совпадение без поддоменов.
        # В Xray plain "example.com" = subdomain-match, нужен prefix "full:"
        for d in r.get("domain", []):
            domains.append(f"full:{d}")

        # DOMAIN-SUFFIX / DOTDOMAIN → domain:val (домен + поддомены)
        # sing-box хранит с ведущей точкой (.example.com) или без.
        # Xray "domain:example.com" матчит example.com и *.example.com.
        for d in r.get("domain_suffix", []):
            domains.append(f"domain:{d.lstrip('.')}")

        # DOMAIN-KEYWORD → keyword:val
        for k in r.get("domain_keyword", []):
            domains.append(f"keyword:{k}")

        if domains:
            xr["domain"] = domains

        # ── IP / CIDR ─────────────────────────────────────────────────────────
        ips = list(r.get("ip_cidr", []))

        # ip_is_private: заменяем geoip:private → явные CIDR (без .dat файлов)
        if r.get("ip_is_private"):
            ips.extend(_PRIVATE_CIDRS)

        if ips:
            xr["ip"] = ips

        # ── Port ──────────────────────────────────────────────────────────────
        if r.get("port"):
            xr["port"] = str(r["port"])

        # Нет ни одного матчера — правило бесполезно, пропускаем
        if not any(k in xr for k in ("domain", "ip", "port")):
            continue

        # ── Outbound ──────────────────────────────────────────────────────────
        xr["outboundTag"] = _xray_tag(
            r.get("outbound", "proxy-out"),
            r.get("action", "")
        )
        out.append(xr)

    return out


# ── Routing ───────────────────────────────────────────────────────────────────

def _build_routing(p: dict, tun_mode: bool = False) -> dict:
    """
    Единая функция routing для PROXY и TUN режимов.

    Порядок правил (важен!):
      1. Системные (сервер, DNS-перехват в TUN, приватные IP)
      2. Пользовательские из rules.txt
      [defaultTag] — всё что не попало

    TUN-режим: defaultTag ВСЕГДА proxy-out, независимо от MATCH в rules.txt.
    Причина: TUN захватывает весь трафик. Если бы default был "direct",
    весь трафик шёл бы в обход туннеля — TUN терял бы смысл.
    Чтобы часть трафика шла напрямую в TUN-режиме — используй
    PROCESS-NAME,app.exe,direct (→ excludeProcess) или IP/domain правила.

    PROXY-режим: уважаем MATCH из rules.txt (может быть direct или proxy-out).
    """
    user_rules, final_tag = get_route_rules()

    system_rules = []

    if tun_mode:
        # DNS через туннель чтобы не было утечек.
        # Порт 53 идёт в proxy-out — там Xray-сервер сделает настоящий резолв.
        system_rules.append(
            {"type": "field", "port": "53", "outboundTag": "proxy-out"}
        )

    # Сервер всегда напрямую — иначе петля
    system_rules.append(
        {"type": "field", "domain": [f"full:{p['host']}"], "outboundTag": "direct"}
    )

    # Приватные сети напрямую (без geoip.dat — явные CIDR)
    system_rules.append(
        {"type": "field", "ip": _PRIVATE_CIDRS, "outboundTag": "direct"}
    )

    # В TUN-режиме fake-ip пул (198.18/15) → через туннель
    if tun_mode:
        system_rules.append(
            {"type": "field", "ip": ["198.18.0.0/15"], "outboundTag": "proxy-out"}
        )

    user_converted = _convert_sb_rules(user_rules)

    if tun_mode:
        # TUN: всегда proxy-out как дефолт (иначе TUN бессмысленен)
        default_tag = "proxy-out"
    else:
        # PROXY: уважаем MATCH из rules.txt
        default_tag = final_tag if final_tag in ("proxy-out", "direct") else "proxy-out"

    return {
        "domainStrategy": "IPIfNonMatch",
        "rules":          system_rules + user_converted,
        "defaultTag":     default_tag,
    }


# ── DNS ───────────────────────────────────────────────────────────────────────

def _build_dns_proxy(p: dict) -> dict:
    """
    DNS для PROXY-режима.
    Хост сервера резолвим через 8.8.8.8 напрямую.
    Остальное тоже через 8.8.8.8 — в PROXY-режиме DNS не утекает,
    т.к. системный DNS не перехвачен.
    """
    return {
        "servers": [
            # Сервер — приоритетно через прямой DNS
            {"address": "8.8.8.8", "domains": [p["host"]], "skipFallback": True},
            "8.8.8.8",
        ],
        "queryStrategy": "UseIPv4",
    }


def _build_dns_tun(p: dict) -> dict:
    """
    DNS для TUN-режима.
    Сервер резолвим через 8.8.8.8 напрямую (до поднятия TUN, resolved_ip
    уже в p["resolved_ip"] из парсера). Остальные запросы — 1.1.1.1,
    они уйдут через port:53 → proxy-out → туннель (anti DNS-leak).
    """
    return {
        "servers": [
            # Хост сервера: прямой DNS, skipFallback чтобы не пошёл через 1.1.1.1
            {"address": "8.8.8.8", "domains": [p["host"]], "skipFallback": True},
            # Всё остальное — через туннель
            "1.1.1.1",
        ],
        "queryStrategy": "UseIPv4",
    }


# ── TUN inbound ───────────────────────────────────────────────────────────────

def _build_tun_exclude_addresses(s: dict) -> list[str]:
    default_excludes = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    excludes = list(s.get("route_exclude_address", default_excludes))
    if s.get("route_exclude_auto_gw", True):
        gw = _get_default_gateway()
        if gw:
            gw_cidr = f"{gw}/32"
            if gw_cidr not in excludes:
                excludes.append(gw_cidr)
    return excludes


def _build_tun_inbound(s: dict, exclude_procs: list[str] = None) -> dict:
    """
    TUN inbound для Xray >= 24.x (wintun.dll).
    Настройки вложены в "settings" (в отличие от sing-box).

    Использует ТОЛЬКО excludeProcess (чёрный список процессов-обходчиков).
    includeProcess намеренно НЕ используется: он блокирует svchost.exe
    (Windows DNS Client) через strictRoute, что убивает DNS-резолвинг.

    Поле "name" (не "interfaceName") — правильное название в Xray 26.x.
    strictRoute=false — безопаснее на Windows, не блокирует служебный трафик.
    """
    # Системные процессы — всегда исключены, иначе Xray зациклится на себе
    _system_exclude = ["xray.exe", "sb_service.exe", "python.exe", "python3.exe"]

    user_exc = list(exclude_procs) if exclude_procs else []
    for p in _system_exclude:
        if p not in user_exc:
            user_exc.append(p)

    return {
        "tag":      "tun-in",
        "protocol": "tun",
        "settings": {
            # "name" — правильное поле в Xray 26.x (interfaceName игнорируется)
            "name":                     "xray-tun",
            "address":                  ["172.19.0.1/30"],
            "mtu":                      int(s.get("tun_mtu", 1500)),
            "autoRoute":                s.get("tun_auto_route", True),
            # strictRoute=false: НЕ блокирует трафик от служебных процессов
            # (svchost.exe DNS Client, lsass.exe и т.д.), которые не в exclude.
            # С strictRoute=true + excludeProcess DNS умирает.
            "strictRoute":              False,
            "stack":                    s.get("tun_stack", "system"),
            "sniff":                    s.get("sniff", True),
            "sniffClampedDestination":  False,
            "sniffOverrideDestination": True,
            "excludeProcess":           user_exc,
            "routeExcludeAddress":      _build_tun_exclude_addresses(s),
        },
    }


# ── Общие части ───────────────────────────────────────────────────────────────

def _common_outbounds(p: dict, s: dict = None) -> list:
    return [
        _vless_outbound(p, s),
        {"tag": "direct", "protocol": "freedom",  "settings": {}},
        {"tag": "block",  "protocol": "blackhole", "settings": {}},
    ]


def _sniff_cfg(s: dict) -> dict:
    return {
        "enabled":      s.get("sniff", True),
        "destOverride": ["http", "tls", "quic"],
        "routeOnly":    False,
    }


def _policy() -> dict:
    return {
        "levels": {
            "0": {
                "handshake":    4,
                "connIdle":     300,
                "uplinkOnly":   1,
                "downlinkOnly": 1,
            }
        },
        "system": {
            "statsInboundUplink":    False,
            "statsInboundDownlink":  False,
            "statsOutboundUplink":   False,
            "statsOutboundDownlink": False,
        },
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_vless_proxy(p: dict, s: dict = None) -> dict:
    """
    PROXY-режим для VLESS через Xray.
      HTTP  → 127.0.0.1:2080  (совместим с pinger.py)
      SOCKS → 127.0.0.1:2081
    Правила из rules.txt применяются автоматически.
    """
    if s is None:
        s = {}

    return {
        "log":      {"loglevel": "info", "access": "", "error": ""},
        "dns":      _build_dns_proxy(p),
        "inbounds": [
            {
                "tag":      "http-in",
                "protocol": "http",
                "listen":   "127.0.0.1",
                "port":     HTTP_PORT,
                "settings": {"allowTransparent": False, "timeout": 0},
                "sniffing": _sniff_cfg(s),
            },
            {
                "tag":      "socks-in",
                "protocol": "socks",
                "listen":   "127.0.0.1",
                "port":     SOCKS_PORT,
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": _sniff_cfg(s),
            },
        ],
        "outbounds": _common_outbounds(p, s),
        "routing":   _build_routing(p, tun_mode=False),
        "policy":    _policy(),
    }


def build_vless_tun(p: dict, s: dict = None) -> dict:
    """
    TUN-режим для VLESS через Xray + wintun.dll.
    Весь системный трафик захватывается, DNS идёт через туннель.
    Требует прав SYSTEM (через сервис) или Администратор.
    Правила из rules.txt применяются автоматически.
    """
    if s is None:
        s = {}

    # Извлекаем PROCESS-NAME,x,direct из rules.txt → excludeProcess в TUN
    # TUN всегда работает в режиме "всё через прокси, кроме исключений".
    # Для "только firefox через прокси" используй PROXY-режим (порт 2080).
    user_rules, _final = get_route_rules()
    exclude_procs = _extract_process_rules(user_rules)

    return {
        "log":       {"loglevel": "info", "access": "", "error": ""},
        "dns":       _build_dns_tun(p),
        "inbounds":  [_build_tun_inbound(s, exclude_procs)],
        "outbounds": _common_outbounds(p, s),
        "routing":   _build_routing(p, tun_mode=True),
        "policy":    _policy(),
    }


# ── Xray как чистый SOCKS5-бэкенд для VLESS TUN режима ───────────────────────
def build_vless_backend(p: dict, socks_port: int = 2082, s: dict = None) -> dict:
    """
    Xray как чистый SOCKS5 backend для sing-box TUN.
    Максимально облегчен: без сниффинга и резолвинга доменов.
    """
    server = p.get("resolved_ip") or p["host"]

    return {
        "log": {
            "loglevel": "warning",
            "access": "",
            "error": ""
        },
        "inbounds": [{
            "tag": "socks-backend",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {
                "auth": "noauth",
                "udp": True,
                "udpOverTcp": False
            },
            "sniffing": {
                "enabled": False  # КРИТИЧЕСКИ ВАЖНО: никакого двойного сниффинга
            },
            "streamSettings": {
                "sockopt": {
                    "tcpFastOpen": True  # КРИТИЧЕСКИ ВАЖНО: ускоряем локальный мост
                }
            }
        }],
        "outbounds": [
            _vless_outbound(p, s),         # основной VLESS
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block",  "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",     # КРИТИЧЕСКИ ВАЖНО: не тратим время на DNS
            "rules": [
                # Сервер всегда напрямую
                {
                    "type": "field",
                    "domain": [f"full:{p['host']}"],
                    "outboundTag": "direct"
                },
                # Если есть resolved_ip
                *([{
                    "type": "field",
                    "ip": [f"{p.get('resolved_ip')}/32"],
                    "outboundTag": "direct"
                }] if p.get("resolved_ip") else []),
                # Loopback — напрямую
                {
                    "type": "field",
                    "ip": ["127.0.0.0/8", "::1/128"],
                    "outboundTag": "direct"
                }
            ],
            "defaultTag": "proxy-out"
        }
    }