# rules.py — парсер правил маршрутизации → sing-box route rules

import sys, os

_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(_BASE, "rules.txt")

# Маппинг действий из нашего формата → теги sing-box
_ACTION_MAP = {
    "proxy":  "proxy-out",
    "direct": "direct",
    "reject": "reject",   # это rule action, не outbound
}

# ── Парсер ────────────────────────────────────────────────────────────────────

def load_rules(path: str = RULES_FILE) -> list[dict]:
    """
    Читает rules.txt и возвращает список sing-box route rules.
    Комментарии (#) и пустые строки игнорируются.
    Match всегда последний — становится route.final.
    """
    if not os.path.exists(path):
        return []

    sb_rules = []
    final    = "proxy-out"   # дефолт если Match не указан

    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                print(f"  ⚠ rules.txt:{lineno}: некорректная строка: {raw.rstrip()!r}")
                continue

            rule_type = parts[0].upper()
            # Match — особый случай: одно поле + действие
            if rule_type == "MATCH":
                action = parts[1].lower()
                final  = _resolve_action(action)
                continue

            if len(parts) < 3:
                print(f"  ⚠ rules.txt:{lineno}: нужно 3 поля: {raw.rstrip()!r}")
                continue

            value  = parts[1]
            action = parts[2].lower()
            rule   = _build_rule(rule_type, value, action, lineno)
            if rule:
                sb_rules.append(rule)

    return sb_rules, final


def _resolve_action(action: str) -> str:
    """Возвращает outbound tag или action string."""
    return _ACTION_MAP.get(action, "proxy-out")


def _build_rule(rule_type: str, value: str, action: str, lineno: int) -> dict | None:
    """Преобразует одно правило в sing-box dict."""
    target = _resolve_action(action)
    is_reject = (action == "reject")

    def make(key, val):
        if is_reject:
            return {key: [val], "action": "reject"}
        return {key: [val], "outbound": target}

    match rule_type:
        case "DOMAIN":
            return make("domain", value)

        case "DOMAIN-KEYWORD":
            return make("domain_keyword", value)

        case "DOMAIN-SUFFIX":
            # sing-box: domain_suffix матчит домен и все поддомены
            return make("domain_suffix", value)

        case "DOTDOMAIN":
            # Наш кастомный тип: матчит домены с таким TLD/суффиксом
            # Убираем ведущую точку если есть
            suffix = value.lstrip(".")
            return make("domain_suffix", f".{suffix}")

        case "PROCESS-NAME":
            return make("process_name", value)

        case "PROCESS-PATH":
            return make("process_path", value)

        case _:
            print(f"  ⚠ rules.txt:{lineno}: неизвестный тип правила: {rule_type!r}")
            return None


# ── Публичный интерфейс для builder.py ───────────────────────────────────────

def get_route_rules(rules_file: str = RULES_FILE) -> tuple[list[dict], str]:
    """
    Возвращает (user_rules, final_outbound) для вставки в route.
    Если файла нет — возвращает пустой список и "proxy-out".
    """
    if not os.path.exists(rules_file):
        return [], "proxy-out"
    result = load_rules(rules_file)
    if isinstance(result, tuple):
        return result
    return result, "proxy-out"


# ── CLI для быстрой проверки ──────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    rules, final = get_route_rules()
    print(f"Final outbound: {final}")
    print(f"Rules ({len(rules)}):")
    print(json.dumps(rules, indent=2, ensure_ascii=False))
