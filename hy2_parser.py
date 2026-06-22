# hy2_parser.py
import socket
from urllib.parse import urlparse, parse_qs, unquote


def _resolve_direct(host: str, dns_server: str = "8.8.8.8", port: int = 53) -> str | None:
    """
    Резолвит хост напрямую через UDP-запрос к dns_server, минуя системный DNS.
    Это критично когда TUN уже запущен и системный DNS перехвачен fake-ip.
    Возвращает IP-строку или None при ошибке.
    """
    # Минимальный DNS A-запрос вручную (без сторонних библиотек)
    import struct, random

    def _build_query(name: str) -> bytes:
        tid = random.randint(0, 65535)
        # Header: ID, FLAGS(стандартный запрос), QDCOUNT=1, остальное 0
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        # Question: кодируем имя
        parts = name.rstrip(".").split(".")
        qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
        question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
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
        # Пропускаем header (12) + question секцию
        i = 12
        # Пропускаем QNAME
        while i < len(data) and data[i] != 0:
            if data[i] & 0xC0 == 0xC0:  # указатель
                i += 2; break
            i += data[i] + 1
        else:
            i += 1
        i += 4  # QTYPE + QCLASS
        # Читаем первый Answer
        for _ in range(ancount):
            if i >= len(data): break
            # NAME (может быть указатель)
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += data[i] + 1
                i += 1
            if i + 10 > len(data): break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i+10])
            i += 10
            if rtype == 1 and rdlen == 4:  # A-запись
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
    """
    Сначала пробуем прямой DNS (8.8.8.8) — он не зависит от системного.
    Если не получилось — fallback на системный socket.gethostbyname.
    Если хост уже IP — возвращаем как есть.
    """
    # Уже IP?
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    # Прямой DNS через 8.8.8.8
    ip = _resolve_direct(host, "8.8.8.8")
    if ip:
        print(f"  резолв (direct): {host} → {ip}")
        return ip

    # Fallback: системный DNS
    try:
        ip = socket.gethostbyname(host)
        # Проверяем что не получили fake-ip из пула 198.18.0.0/15
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
    """Парсит hysteria2:// URI в словарь параметров."""
    uri = uri.strip()
    if not uri.startswith(("hysteria2://", "hy2://")):
        raise ValueError("URI должен начинаться с hysteria2:// или hy2://")

    parsed   = urlparse(uri)
    password = unquote(parsed.username or "")
    host     = parsed.hostname or ""
    port     = parsed.port or 443
    qs       = parse_qs(parsed.query)
    name     = unquote(parsed.fragment) if parsed.fragment else f"{host}:{port}"

    if not password:
        raise ValueError("Пароль не найден в URI")
    if not host:
        raise ValueError("Хост не найден в URI")

    def first(key, default=None):
        return qs[key][0] if key in qs else default

    alpn_raw = first("alpn", "")
    alpn     = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else []

    resolved_ip = _resolve(host)

    return {
        "protocol":      "hysteria2",   # для детекции в GUI (hy2 vs vless)
        "name":          name,
        "host":          host,
        "port":          port,
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
