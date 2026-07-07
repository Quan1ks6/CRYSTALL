# builder.py — генератор конфигов sing-box >= 1.13
import subprocess
import re
from rules import get_route_rules
import socket

def _is_ip(address: str) -> bool:
    try:
        socket.inet_aton(address)
        return True
    except OSError:
        return False

def get_default_gateway() -> str | None:
    """
    Определяет IP дефолтного шлюза через 'route print 0.0.0.0'.
    Возвращает строку IP или None.
    """
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def _dns_direct_server() -> dict:
    """UDP резолвер для бутстрапа — хардкод 8.8.8.8, не зависит от системы."""
    return {
        "tag":    "dns-direct",
        "type":   "udp",
        "server": "8.8.8.8",
    }


def _dns_blocks(p: dict, s: dict, tun_mode: bool,
                 host_rule: dict | None = None) -> dict:
    """
    Возвращает блок "dns" для sing-box конфига.

    Настраивается через settings (s):
      dns_upstream  — IP/hostname удалённого DNS (по умолч. 1.1.1.1)
      dns_no_leak   — True (по умолч.) / False:
           True  → Fake-IP (без DNS-утечек, трафик через туннель)
           False → Реальный DNS через upstream (утечка возможна, но
                   работают сервисы, завязанные на конкретный IP)

    host_rule — переопределяет правило для хоста сервера, используется
    в build_tun_via_socks где хост уже мог быть раньше разрезолвлен в IP.
    """
    upstream = s.get("dns_upstream", "1.1.1.1").strip() or "1.1.1.1"
    no_leak  = s.get("dns_no_leak", True) if tun_mode else False

    servers = [
        {
            "tag":             "dns-remote",
            "type":            "udp",
            "server":          upstream,
            "domain_resolver": "dns-direct",
        },
        _dns_direct_server(),
    ]

    server_rule = host_rule or {"domain": [p["host"]]}
    rules = [{**server_rule, "server": "dns-direct"}]

    if tun_mode and no_leak:
        servers.append({
            "tag":         "dns-fakeip",
            "type":        "fakeip",
            "inet4_range": "198.18.0.0/15",
        })
        rules.append({"query_type": ["A"],    "server": "dns-fakeip"})
        rules.append({"query_type": ["AAAA"], "action": "reject"})

    return {
        "servers":  servers,
        "rules":    rules,
        "strategy": "ipv4_only",
        "final":    "dns-remote",
    }


def _log_block(s: dict) -> dict:
    """
    Блок "log" для конфига sing-box.
    Если dns_log_to_file=False — выключаем уровень (только stderr/stdout),
    sing-box всё равно пишет в stdout, GUI LogTailThread читает файл —
    поэтому вместо отключения просто меняем уровень на warn чтобы
    не засорять файл INFO-сообщениями когда пользователь отключил логи.
    """
    if s.get("log_to_file", True):
        return {"level": "info"}
    return {"level": "warn", "timestamp": True}


def _outbound(p: dict) -> dict:
    """Hysteria2 outbound. uTLS не используем — несовместимо с QUIC."""
    server_addr = p.get("resolved_ip") or p["host"]

    tls: dict = {
        "enabled":     True,
        "server_name": p["sni"],
        "insecure":    p["insecure"],
    }
    if p.get("alpn"):
        tls["alpn"] = p["alpn"]

    ob = {
        "type":        "hysteria2",
        "tag":         "proxy-out",
        "server":      server_addr,
        "password":    p["password"],
        "domain_resolver": {
            "server":   "dns-direct",
            "strategy": "ipv4_only",
        },
        "tls": tls,
    }

    # Port Hopping — sing-box принимает диапазон портов в server_ports
    # (формат "start:end", через запятую можно несколько) + hop_interval,
    # вместо одиночного server_port. Конвертируем из формата share-ссылки
    # "start-end[,start2-end2]" в формат sing-box "start:end[,start2:end2]".
    hop = p.get("port_hopping")
    ranges = []
    if hop:
        for part in hop.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                if a.isdigit() and b.isdigit():
                    ranges.append(f"{a}:{b}")
            elif part.isdigit():
                ranges.append(part)

    if ranges:
        ob["server_ports"] = ranges
        ob["hop_interval"] = "30s"
    else:
        ob["server_port"] = p["port"]

    if p.get("obfs") == "salamander" and p.get("obfs_password"):
        ob["obfs"] = {
            "type":     "salamander",
            "password": p["obfs_password"],
        }
    return ob


def build_proxy(p: dict, s: dict = None) -> dict:
    """PROXY режим — HTTP/SOCKS5 на 127.0.0.1:2080."""
    if s is None: s = {}
    
    return {
        "log": _log_block(s),
        "dns": _dns_blocks(p, s, tun_mode=False),
        "inbounds": [{
            "type":        "mixed",
            "tag":         "mixed-in",
            "listen":      "127.0.0.1",
            "listen_port": 2080
            # СНИФФИНГА ЗДЕСЬ БОЛЬШЕ НЕТ
        }],
        "outbounds": [
            _outbound(p),
            {"type": "direct", "tag": "direct"},
        ],
        "route": _build_route_proxy(p),
    }

def _build_route_proxy(p: dict) -> dict:
    user_rules, final = get_route_rules()
    system_rules = [
        {"action": "sniff"}, # <--- Сниффинг теперь живет тут
        {"domain": [p["host"]], "outbound": "direct"},
    ]
    return {
        "default_domain_resolver": "dns-direct",
        "rules":                   system_rules + user_rules,
        "auto_detect_interface":   True,
        "final":                   final,
    }


def _build_exclude_address(s: dict) -> list[str]:
    default_excludes = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    user_excludes: list[str] = s.get("route_exclude_address", default_excludes)
    excludes = list(user_excludes)

    if s.get("route_exclude_auto_gw", True):
        gw = get_default_gateway()
        if gw:
            gw_cidr = f"{gw}/32"
            if gw_cidr not in excludes:
                excludes.append(gw_cidr)

    return excludes


def build_tun(p: dict, s: dict = None) -> dict:
    """TUN режим — весь трафик системы через прокси, без DNS-утечек."""
    if s is None: s = {}

    exclude_addr = _build_exclude_address(s)

    return {
        "log": _log_block(s),
        "dns": _dns_blocks(p, s, tun_mode=True),
        "inbounds": [{
            "type":                  "tun", # или "mixed"
            "tag":                   "tun-in",
            "interface_name":        "sb-tun", # Возвращаем старый добрый interface_name!
            "address":               ["172.19.0.1/30"],
            "mtu":                   int(s.get("tun_mtu", 1500)),
            "auto_route":            s.get("tun_auto_route", True),
            "strict_route":          s.get("tun_strict_route", True),
            "stack":                 s.get("tun_stack", "system"),
            "route_exclude_address": exclude_addr,
        }],
        "outbounds": [
            _outbound(p),
            {"type": "direct", "tag": "direct"},
        ],
        "route": _build_route_tun(p),
    }


def _build_route_tun(p: dict) -> dict:
    user_rules, final = get_route_rules()
    system_rules = [
        {"action": "sniff"},
        {"ip_cidr": ["192.168.0.1/32"], "port": 53, "action": "hijack-dns"},
        {"protocol": "dns",              "action": "hijack-dns"},
        {"domain":   [p["host"]],        "outbound": "direct"},
        {"ip_cidr":  ["198.18.0.0/15"],  "outbound": "proxy-out"},
        {"ip_is_private": True,          "outbound": "direct"},
        {"process_name": ["sb-hy2.exe", "sb_service.exe", "python.exe", "python3.exe"],
         "outbound": "direct"},
    ]
    return {
        "default_domain_resolver": "dns-direct",
        "rules":                   system_rules + user_rules,
        "auto_detect_interface":   True,
        "final":                   final,
    }


def _build_route_tun_via_socks(p: dict) -> dict:
    user_rules, final = get_route_rules()
    host_rule = {"ip_cidr": [f"{p['host']}/32"]} if _is_ip(p["host"]) else {"domain": [p["host"]]}
    
    system_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"port": [53], "action": "hijack-dns"},
        {"ip_cidr": ["127.0.0.0/8"], "outbound": "direct"},
        {**host_rule, "outbound": "direct"},
        *([{"ip_cidr": [f"{p['resolved_ip']}/32"], "outbound": "direct"}] if p.get("resolved_ip") else []),
        {"ip_cidr": ["198.18.0.0/15"], "outbound": "proxy-out"},
        {"ip_is_private": True, "outbound": "direct"},
        {"process_name": ["xray.exe", "sing-box.exe", "sb-hy2.exe", "sb_service.exe", "python.exe", "python3.exe"],
         "outbound": "direct"},
    ]
    
    return {
        "default_domain_resolver": "dns-direct",
        "rules": system_rules + user_rules,
        "auto_detect_interface": True,
        "final": final,
    }


def build_tun_via_socks(p: dict, socks_port: int = 2081, s: dict = None) -> dict:
    if s is None: s = {}

    exclude_addr = _build_exclude_address(s)
    if "127.0.0.0/8" not in exclude_addr:
        exclude_addr = list(exclude_addr) + ["127.0.0.0/8"]

    host_rule = {"ip_cidr": [f"{p['host']}/32"]} if _is_ip(p["host"]) else {"domain": [p["host"]]}

    return {
        "log": _log_block(s),
        "dns": _dns_blocks(p, s, tun_mode=True, host_rule=host_rule),
        "inbounds": [{
            "type":                  "tun", # или "mixed"
            "tag":                   "tun-in",
            "interface_name":        "sb-tun", # Возвращаем старый добрый interface_name!
            "address":               ["172.19.0.1/30"],
            "mtu":                   int(s.get("tun_mtu", 1500)),
            "auto_route":            s.get("tun_auto_route", True),
            "strict_route":          s.get("tun_strict_route", True),
            "stack":                 s.get("tun_stack", "system"),
            "route_exclude_address": exclude_addr,
        }],
        "outbounds": [
            {
                "type":        "socks",
                "tag":         "proxy-out",
                "server":      "127.0.0.1",
                "server_port": socks_port,
                "version":     "5",
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": _build_route_tun_via_socks(p),
    }


def _vless_tls(p: dict) -> dict | None:
    security = p.get("security", "none")
    if security not in ("tls", "reality"):
        return None

    tls: dict = {
        "enabled":     True,
        "server_name": p.get("sni", p["host"]),
        "insecure":    p.get("allow_insecure", False),
    }

    if p.get("fp"):
        tls["utls"] = {
            "enabled":     True,
            "fingerprint": p.get("fp", "chrome"),
        }

    if security == "reality":
        tls["reality"] = {
            "enabled":    True,
            "public_key": p.get("pbk", ""),
            "short_id":   p.get("sid", ""),
        }

    if p.get("alpn"):
        tls["alpn"] = p["alpn"]

    return tls


def _vless_transport(p: dict) -> dict | None:
    """Строит блок transport для sing-box VLESS outbound (совместимо с 1.13+)."""
    transport = p.get("transport", "tcp")

    # В sing-box 1.13+ транспорта 'xhttp' нет, вместо него используется 'http'
    if transport in ("splithttp", "xhttp", "h2"):
        transport = "http"
    elif transport == "mkcp":
        transport = "kcp"

    if transport == "tcp":
        return None

    t: dict = {"type": transport}

    match transport:
        case "ws":
            t["path"] = p.get("path", "/")
            if p.get("host_header"):
                t["headers"] = {"Host": p["host_header"]}

        case "http":
            # Универсальный HTTP транспорт в 1.13+ (сюда входят h2, xhttp/splithttp)
            t["path"] = p.get("path", "/")
            
            if p.get("host_header"):
                t["host"] = [p["host_header"]]
                
            # Черный список параметров, которые переварит только Xray
            xray_exclusive = {
                "xPaddingBytes", 
                "scMaxEachPostBytes", 
                "scMaxBufferedPosts", 
                "noSSEHeader", 
                "xmux", 
                "scv"
            }
            
            # Копируем кастомные заголовки, отсекая несовместимый мусор
            for k, v in p.get("xhttp_extra", {}).items():
                if k in xray_exclusive:
                    continue # Игнорируем Xray-параметры, чтобы sing-box не паниковал
                if k not in ("mode", "host") and k not in t:
                    t[k] = v

        case "grpc":
            t["service_name"] = p.get("service_name", "")
            if p.get("grpc_multi"):
                t["idle_timeout"] = "15s"

        case "quic" | "kcp":
            return None

        case _:
            return None

    return t


def _vless_outbound_sb(p: dict) -> dict:
    server = p.get("resolved_ip") or p["host"]

    ob: dict = {
        "type":        "vless",
        "tag":         "proxy-out",
        "server":      server,
        "server_port": p["port"],
        "uuid":        p["uuid"],
        "domain_resolver": {
            "server":   "dns-direct",
            "strategy": "ipv4_only",
        },
    }

    if p.get("flow"):
        ob["flow"] = p["flow"]

    tls = _vless_tls(p)
    if tls:
        ob["tls"] = tls

    transport = _vless_transport(p)
    if transport:
        ob["transport"] = transport

    ob["multiplex"] = {"enabled": False}
    return ob


def _build_route_tun_vless_native(p: dict) -> dict:
    user_rules, final = get_route_rules()
    system_rules = [
        {"action": "sniff"},
        {"ip_cidr": ["192.168.0.1/32"], "port": 53, "action": "hijack-dns"},
        {"protocol": "dns",             "action": "hijack-dns"},
        {"domain":   [p["host"]],       "outbound": "direct"},
        {"ip_cidr":  ["198.18.0.0/15"], "outbound": "proxy-out"},
        {"ip_is_private": True,         "outbound": "direct"},
        {"process_name": ["sb-hy2.exe", "sb_service.exe", "python.exe", "python3.exe", "sing-box.exe"],
         "outbound": "direct"},
    ]
    return {
        "default_domain_resolver": "dns-direct",
        "rules":                   system_rules + user_rules,
        "auto_detect_interface":   True,
        "final":                   final,
    }


def build_vless_tun_native(p: dict, s: dict = None) -> dict:
    """TUN-режим для VLESS через sing-box 1.13+ (нативный)."""
    if s is None: s = {}

    exclude_addr = _build_exclude_address(s)

    return {
        "log": _log_block(s),
        "dns": _dns_blocks(p, s, tun_mode=True),
        "inbounds": [{
            "type":                  "tun", # или "mixed"
            "tag":                   "tun-in",
            "interface_name":        "sb-tun", # Возвращаем старый добрый interface_name!
            "address":               ["172.19.0.1/30"],
            "mtu":                   int(s.get("tun_mtu", 1500)),
            "auto_route":            s.get("tun_auto_route", True),
            "strict_route":          s.get("tun_strict_route", True),
            "stack":                 s.get("tun_stack", "system"),
            "route_exclude_address": exclude_addr,
        }],
        "outbounds": [
            _vless_outbound_sb(p),
            {"type": "direct", "tag": "direct"},
        ],
        "route": _build_route_tun_vless_native(p),
    }