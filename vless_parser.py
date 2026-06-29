import json
import socket
from urllib.parse import urlparse, parse_qs, unquote

def _resolve_direct(host: str, dns_server: str = "8.8.8.8", port: int = 53):

    import struct, random

    def _build_query(name: str):
        tid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        parts = name.rstrip(".").split(".")
        qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
        question = qname + struct.pack(">HH", 1, 1)
        return header + question, tid

    def _parse_ip(data: bytes, tid_expected: int):
        if len(data) < 12: return None
        tid = struct.unpack(">H", data[:2])[0]
        if tid != tid_expected: return None
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0: return None
        i = 12
        while i < len(data) and data[i] != 0:
            if data[i] & 0xC0 == 0xC0: i += 2; break
            i += data[i] + 1
        else:
            i += 1
        i += 4
        for _ in range(ancount):
            if i >= len(data): break
            if data[i] & 0xC0 == 0xC0: i += 2
            else:
                while i < len(data) and data[i] != 0: i += data[i] + 1
                i += 1
            if i + 10 > len(data): break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i+10])
            i += 10
            if rtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[i:i+4])
            i += rdlen
        return None

    try:
        query, tid = _build_query(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(3.0)
            sock.sendto(query, (dns_server, port))
            data, _ = sock.recvfrom(512)
            return _parse_ip(data, tid)
        finally:
            sock.close()
    except Exception:
        return None

def _resolve(host: str) -> str | None:

    try:
        socket.inet_aton(host); return host
    except OSError:
        pass

    ip = _resolve_direct(host, "8.8.8.8")
    if ip:
        print(f"  vless резолв (direct): {host} → {ip}")
        return ip

    try:
        ip = socket.gethostbyname(host)
        parts = ip.split(".")
        if parts[0] == "198" and parts[1] in ("18", "19"):
            print(f"  ⚠ fake-ip {ip} для {host}, игнорируем")
            return None
        print(f"  vless резолв (system): {host} → {ip}")
        return ip
    except Exception:
        pass

    print(f"  ⚠ не удалось зарезолвить {host}")
    return None

def parse_vless(uri: str) -> dict:

    uri = uri.strip()
    if not uri.startswith("vless://"):
        raise ValueError("URI должен начинаться с vless://")

    parsed   = urlparse(uri)
    uuid     = unquote(parsed.username or "")
    host     = parsed.hostname or ""
    port     = parsed.port or 443
    qs       = parse_qs(parsed.query)
    name     = unquote(parsed.fragment) if parsed.fragment else f"{host}:{port}"

    if not uuid: raise ValueError("UUID не найден в URI")
    if not host: raise ValueError("Хост не найден в URI")

    def first(key, default=None):
        return qs[key][0] if key in qs else default

    security  = first("security", "none")
    transport = first("type", "tcp")

    extra_raw = first("extra", "")
    xhttp_extra: dict = {}
    if extra_raw:
        try:
            xhttp_extra = json.loads(unquote(extra_raw))
        except Exception:
            pass

    alpn_raw = first("alpn", "")
    alpn = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else []

    resolved_ip = _resolve(host)

    return {
        "protocol":    "vless",
        "name":        name,

        "host":        host,
        "port":        port,
        "resolved_ip": resolved_ip,

        "uuid":        uuid,
        "encryption":  first("encryption", "none"),
        "flow":        first("flow", ""),

        "security":    security,
        "sni":         first("sni", host),
        "fp":          first("fp", "chrome"),
        "alpn":        alpn,
        "allow_insecure": first("allowInsecure", "0") == "1",

        "pbk":         first("pbk", ""),
        "sid":         first("sid", ""),
        "spx":         first("spx", "/"),

        "transport":   transport,

        "path":        first("path", "/"),
        "host_header": first("host", ""),

        "xhttp_mode":  xhttp_extra.get("mode", first("mode", "auto")),
        "xhttp_extra": xhttp_extra,

        "service_name": first("serviceName", ""),
        "grpc_multi":   first("mode", "gun") == "multi",

        "quic_security": first("quicSecurity", "none"),
        "quic_key":      first("key", ""),
        "quic_header":   first("headerType", "none"),

        "kcp_seed":   first("seed", ""),
        "kcp_header": first("headerType", "none"),
    }
