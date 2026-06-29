import socket
import re
from urllib.parse import urlparse, parse_qs, unquote

def _resolve_direct(host: str, dns_server: str = "8.8.8.8", port: int = 53) -> str | None:
    import struct, random

    def _build_query(name: str) -> bytes:
        tid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        parts = name.rstrip(".").split(".")
        qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
        question = qname + struct.pack(">HH", 1, 1)
        return header + question, tid

    def _parse_ip(data: bytes, tid_expected: int) -> str | None:
        if len(data) < 12:
            return None
        tid = struct.unpack(">H", data[:2])[0]
        if tid != tid_expected:
            return None
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return None
        i = 12
        while i < len(data) and data[i] != 0:
            if data[i] & 0xC0 == 0xC0:
                i += 2; break
            i += data[i] + 1
        else:
            i += 1
        i += 4
        for _ in range(ancount):
            if i >= len(data): break
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += data[i] + 1
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
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    ip = _resolve_direct(host, "8.8.8.8")
    if ip:
        print(f"  резолв (direct): {host} → {ip}")
        return ip

    try:
        ip = socket.gethostbyname(host)
        parts = ip.split(".")
        if parts[0] == "198" and parts[1] in ("18", "19"):
            print(f"  ⚠ системный DNS вернул fake-ip {ip} для {host}, игнорируем")
            return None
        print(f"  резолв (system): {host} → {ip}")
        return ip
    except Exception:
        pass

    print(f"  ⚠ не удалось зарезолвить {host}, используем hostname")
    return None

def parse_hy2(uri: str) -> dict:
    
    uri = uri.strip()
    if not uri.startswith(("hysteria2://", "hy2://")):
        raise ValueError("URI должен начинаться с hysteria2:// или hy2://")

    parsed   = urlparse(uri)
    password = unquote(parsed.username or "")
    host     = parsed.hostname or ""
    qs       = parse_qs(parsed.query)

    authority = parsed.netloc.rpartition("@")[-1]
    port = 443
    port_hopping = None
    if authority.startswith("[") :
        tail = authority.rsplit("]:", 1)
        if len(tail) == 2 and tail[1].isdigit():
            port = int(tail[1])
    elif ":" in authority:
        _, _, port_part = authority.rpartition(":")
        if port_part.isdigit():
            port = int(port_part)
        elif re.match(r'^\d+-\d+(,\d+-\d+)*$', port_part):
            port_hopping = port_part
            port = int(port_part.split(",")[0].split("-")[0])

    if not port_hopping:
        mport = (qs.get("mport") or qs.get("ports") or [None])[0]
        if mport and re.match(r'^\d+-\d+(,\d+-\d+)*$', mport):
            port_hopping = mport

    if not password:
        raise ValueError("Пароль не найден в URI")
    if not host:
        raise ValueError("Хост не найден в URI")

    name = unquote(parsed.fragment) if parsed.fragment else f"{host}:{port}"

    def first(key, default=None):
        return qs[key][0] if key in qs else default

    alpn_raw = first("alpn", "")
    alpn     = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else []

    resolved_ip = _resolve(host)

    return {
        "protocol":      "hysteria2",
        "name":          name,
        "host":          host,
        "port":          port,
        "port_hopping":  port_hopping,
        "password":      password,
        "sni":           first("sni", host),
        "insecure":      first("insecure", "0") == "1",
        "obfs":          first("obfs"),
        "obfs_password": first("obfs-password"),
        "pinned_cert":   first("pinSHA256"),
        "alpn":          alpn,
        "fingerprint":   first("fp", ""),
        "fastopen":      first("fastopen", "0") == "1",
        "resolved_ip":   resolved_ip,
    }
