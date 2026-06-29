import os
import json
import base64
import sys
import glob
import urllib.request
from hy2_parser import parse_hy2
from vless_parser import parse_vless

_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
CLUSTERS_DIR = os.path.join(_BASE, "clusters")
os.makedirs(CLUSTERS_DIR, exist_ok=True)

DEFAULT_PALETTE = [
    "#7c3aed", "#10b981", "#f59e0b", "#ef4444",
    "#3b82f6", "#ec4899", "#14b8a6", "#a3e635",
]

def _next_color() -> str:
    n = len(glob.glob(os.path.join(CLUSTERS_DIR, "*.clust")))
    return DEFAULT_PALETTE[n % len(DEFAULT_PALETTE)]

def list_cluster_files() -> list[str]:
    return sorted(glob.glob(os.path.join(CLUSTERS_DIR, "*.clust")))

def load_cluster(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def save_cluster(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _safe_filename(name: str) -> str:
    keep = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip()
    return keep or "cluster"

def create_empty_cluster(name: str, mode: str = "proxy", color: str | None = None) -> str:
    
    fname = _safe_filename(name)
    path = os.path.join(CLUSTERS_DIR, f"{fname}.clust")
    n = 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(CLUSTERS_DIR, f"{fname}_{n}.clust")
    save_cluster(path, {
        "name": name,
        "mode": mode,
        "color": color or _next_color(),
        "profiles": [],
    })
    return path

def create_subscription_cluster(name: str, url: str, profiles: list[dict],
                                 color: str | None = None) -> str:
    fname = _safe_filename(name)
    path = os.path.join(CLUSTERS_DIR, f"{fname}.clust")
    n = 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(CLUSTERS_DIR, f"{fname}_{n}.clust")
    save_cluster(path, {
        "name": name,
        "mode": "proxy",
        "color": color or _next_color(),
        "source_url": url,
        "profiles": profiles,
    })
    return path

def delete_cluster(path: str):
    if os.path.exists(path):
        os.remove(path)

def update_cluster_meta(path: str, name: str | None = None,
                         color: str | None = None, source_url: str | None = None,
                         clear_source_url: bool = False):
    d = load_cluster(path)
    if name is not None:
        d["name"] = name
    if color is not None:
        d["color"] = color
    if clear_source_url:
        d.pop("source_url", None)
    elif source_url is not None:
        d["source_url"] = source_url
    save_cluster(path, d)

def add_manual_inbound(path: str, link: str) -> dict:
    
    link = link.strip()
    if link.startswith(("hysteria2://", "hy2://")):
        profile = parse_hy2(link)
    elif link.startswith("vless://"):
        profile = parse_vless(link)
    else:
        raise ValueError("Ссылка должна начинаться с hysteria2:// или vless://")
    profile["custom"] = True

    d = load_cluster(path)
    d.setdefault("profiles", []).append(profile)
    save_cluster(path, d)
    return profile

def delete_inbound(path: str, index: int):
    d = load_cluster(path)
    profiles = d.get("profiles", [])
    if 0 <= index < len(profiles):
        profiles.pop(index)
        save_cluster(path, d)

def rename_inbound(path: str, index: int, new_name: str):
    d = load_cluster(path)
    profiles = d.get("profiles", [])
    if 0 <= index < len(profiles):
        profiles[index]["name"] = new_name
        save_cluster(path, d)

def refresh_subscription(path: str, timeout: float = 15.0) -> int:
    
    d = load_cluster(path)
    url = d.get("source_url")
    if not url:
        raise ValueError("У этого кластера нет ссылки на подписку")

    req = urllib.request.Request(url, headers={"User-Agent": "sb-hy2-client"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8").strip()
    raw += "=" * ((4 - len(raw) % 4) % 4)
    decoded = base64.b64decode(raw).decode("utf-8")

    new_profiles = []
    for line in decoded.splitlines():
        line = line.strip()
        try:
            if line.startswith(("hysteria2://", "hy2://")):
                new_profiles.append(parse_hy2(line))
            elif line.startswith("vless://"):
                new_profiles.append(parse_vless(line))
        except Exception:
            continue
    if not new_profiles:
        raise ValueError("Подписка не содержит валидных hysteria2:// / vless:// ссылок")

    custom_kept = [p for p in d.get("profiles", []) if p.get("custom")]
    d["profiles"] = new_profiles + custom_kept
    save_cluster(path, d)
    return len(new_profiles)

def import_subscription(url: str, cluster_name: str, mode: str = "proxy"):
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'sb-hy2-client'})
        with urllib.request.urlopen(req) as response:
            b64_data = response.read().decode('utf-8').strip()

        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        decoded_text = base64.b64decode(b64_data).decode('utf-8')

        profiles = []
        for line in decoded_text.splitlines():
            line = line.strip()
            if line.startswith("hysteria2://"):
                try:
                    parsed_data = parse_hy2(line)
                    profiles.append(parsed_data)
                except Exception as e:
                    print(f"Ошибка парсинга hy2 {line[:30]}... : {e}")
            elif line.startswith("vless://"):
                try:
                    parsed_data = parse_vless(line)
                    profiles.append(parsed_data)
                except Exception as e:
                    print(f"Ошибка парсинга vless {line[:30]}... : {e}")

        if not profiles:
            raise ValueError("Не найдено ни одной валидной hysteria2:// или vless:// ссылки!")

        cluster_data = {
            "name": cluster_name,
            "mode": mode,
            "color": _next_color(),
            "source_url": url,
            "profiles": profiles
        }

        filepath = os.path.join(CLUSTERS_DIR, f"{cluster_name}.clust")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cluster_data, f, indent=2, ensure_ascii=False)

        return len(profiles)

    except Exception as e:
        raise RuntimeError(f"Ошибка импорта: {e}")
