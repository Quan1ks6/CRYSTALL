import os
import json
import base64
import sys
import urllib.request
from hy2_parser import parse_hy2
from vless_parser import parse_vless


_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
CLUSTERS_DIR = os.path.join(_BASE, "clusters")
os.makedirs(CLUSTERS_DIR, exist_ok=True)

def import_subscription(url: str, cluster_name: str, mode: str = "proxy"):
    """Скачивает подписку, парсит только hy2 и сохраняет в .clust файл"""
    try:
        # Скачиваем данные
        req = urllib.request.Request(url, headers={'User-Agent': 'sb-hy2-client'})
        with urllib.request.urlopen(req) as response:
            b64_data = response.read().decode('utf-8').strip()
            
        # У ссылок-подписок часто бывают невалидные символы для b64, фиксим паддинг
        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        decoded_text = base64.b64decode(b64_data).decode('utf-8')
        
        # Фильтруем и парсим
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

        # Сохраняем кластер в файл
        cluster_data = {
            "name": cluster_name,
            "mode": mode,
            "profiles": profiles
        }
        
        filepath = os.path.join(CLUSTERS_DIR, f"{cluster_name}.clust")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cluster_data, f, indent=2, ensure_ascii=False)
            
        return len(profiles)
        
    except Exception as e:
        raise RuntimeError(f"Ошибка импорта: {e}")
