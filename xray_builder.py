import subprocess
import re
from rules import get_route_rules

HTTP_PORT  = 2080
SOCKS_PORT = 2081

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

def _user(p: dict) -> dict:
    u = {
        "id":         p["uuid"],
        "encryption": p.get("encryption", "none"),
    }
    if p.get("flow"):
        u["flow"] = p["flow"]
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

def _vless_outbound(p: dict) -> dict:
    server = p.get("resolved_ip") or p["host"]
    return {
        "tag":      "proxy-out",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server,
                "port":    p["port"],
                "users":   [_user(p)],
            }]
        },
        "streamSettings": _stream_settings(p),
        "mux": {"enabled": False, "concurrency": -1},
    }

def _xray_tag(outbound: str, action: str = "") -> str:
    if action == "reject" or outbound == "reject":
        return "block"
    if outbound == "direct":
        return "direct"
    return "proxy-out"

def _extract_process_rules(sb_rules: list[dict]) -> list[str]:

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

    out = []
    for r in sb_rules:
        if "process_name" in r or "process_path" in r:
            continue

        xr: dict = {"type": "field"}

        domains = []

        for d in r.get("domain", []):
            domains.append(f"full:{d}")

        for d in r.get("domain_suffix", []):
            domains.append(f"domain:{d.lstrip('.')}")

        for k in r.get("domain_keyword", []):
            domains.append(f"keyword:{k}")

        if domains:
            xr["domain"] = domains

        ips = list(r.get("ip_cidr", []))

        if r.get("ip_is_private"):
            ips.extend(_PRIVATE_CIDRS)

        if ips:
            xr["ip"] = ips

        if r.get("port"):
            xr["port"] = str(r["port"])

        if not any(k in xr for k in ("domain", "ip", "port")):
            continue

        xr["outboundTag"] = _xray_tag(
            r.get("outbound", "proxy-out"),
            r.get("action", "")
        )
        out.append(xr)

    return out

def _build_routing(p: dict, tun_mode: bool = False) -> dict:

    user_rules, final_tag = get_route_rules()

    system_rules = []

    if tun_mode:
        system_rules.append(
            {"type": "field", "port": "53", "outboundTag": "proxy-out"}
        )

    system_rules.append(
        {"type": "field", "domain": [f"full:{p['host']}"], "outboundTag": "direct"}
    )

    system_rules.append(
        {"type": "field", "ip": _PRIVATE_CIDRS, "outboundTag": "direct"}
    )

    if tun_mode:
        system_rules.append(
            {"type": "field", "ip": ["198.18.0.0/15"], "outboundTag": "proxy-out"}
        )

    user_converted = _convert_sb_rules(user_rules)

    if tun_mode:
        default_tag = "proxy-out"
    else:
        default_tag = final_tag if final_tag in ("proxy-out", "direct") else "proxy-out"

    return {
        "domainStrategy": "IPIfNonMatch",
        "rules":          system_rules + user_converted,
        "defaultTag":     default_tag,
    }

def _build_dns_proxy(p: dict) -> dict:

    return {
        "servers": [
            {"address": "8.8.8.8", "domains": [p["host"]], "skipFallback": True},
            "8.8.8.8",
        ],
        "queryStrategy": "UseIPv4",
    }

def _build_dns_tun(p: dict) -> dict:

    return {
        "servers": [
            {"address": "8.8.8.8", "domains": [p["host"]], "skipFallback": True},
            "1.1.1.1",
        ],
        "queryStrategy": "UseIPv4",
    }

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

    _system_exclude = ["xray.exe", "sb_service.exe", "python.exe", "python3.exe"]

    user_exc = list(exclude_procs) if exclude_procs else []
    for p in _system_exclude:
        if p not in user_exc:
            user_exc.append(p)

    return {
        "tag":      "tun-in",
        "protocol": "tun",
        "settings": {
            "name":                     "xray-tun",
            "address":                  ["172.19.0.1/30"],
            "mtu":                      int(s.get("tun_mtu", 1500)),
            "autoRoute":                s.get("tun_auto_route", True),
            "strictRoute":              False,
            "stack":                    s.get("tun_stack", "system"),
            "sniff":                    s.get("sniff", True),
            "sniffClampedDestination":  False,
            "sniffOverrideDestination": True,
            "excludeProcess":           user_exc,
            "routeExcludeAddress":      _build_tun_exclude_addresses(s),
        },
    }

def _common_outbounds(p: dict) -> list:
    return [
        _vless_outbound(p),
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

def build_vless_proxy(p: dict, s: dict = None) -> dict:

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
        "outbounds": _common_outbounds(p),
        "routing":   _build_routing(p, tun_mode=False),
        "policy":    _policy(),
    }

def build_vless_tun(p: dict, s: dict = None) -> dict:

    if s is None:
        s = {}

    user_rules, _final = get_route_rules()
    exclude_procs = _extract_process_rules(user_rules)

    return {
        "log":       {"loglevel": "info", "access": "", "error": ""},
        "dns":       _build_dns_tun(p),
        "inbounds":  [_build_tun_inbound(s, exclude_procs)],
        "outbounds": _common_outbounds(p),
        "routing":   _build_routing(p, tun_mode=True),
        "policy":    _policy(),
    }

def build_vless_backend(p: dict, socks_port: int = 2082) -> dict:

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
                "enabled": False
            },
            "streamSettings": {
                "sockopt": {
                    "tcpFastOpen": True
                }
            }
        }],
        "outbounds": [
            _vless_outbound(p),
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block",  "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "domain": [f"full:{p['host']}"],
                    "outboundTag": "direct"
                },
                *([{
                    "type": "field",
                    "ip": [f"{p.get('resolved_ip')}/32"],
                    "outboundTag": "direct"
                }] if p.get("resolved_ip") else []),
                {
                    "type": "field",
                    "ip": ["127.0.0.0/8", "::1/128"],
                    "outboundTag": "direct"
                }
            ],
            "defaultTag": "proxy-out"
        }
    }
