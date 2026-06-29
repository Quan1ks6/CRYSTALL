import sys, os

_BASE = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(_BASE, "rules.txt")

_ACTION_MAP = {
    "proxy":  "proxy-out",
    "direct": "direct",
    "reject": "reject",
}

def load_rules(path: str = RULES_FILE) -> list[dict]:

    if not os.path.exists(path):
        return []

    sb_rules = []
    final    = "proxy-out"

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

    return _ACTION_MAP.get(action, "proxy-out")

def _build_rule(rule_type: str, value: str, action: str, lineno: int) -> dict | None:

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
            return make("domain_suffix", value)

        case "DOTDOMAIN":
            suffix = value.lstrip(".")
            return make("domain_suffix", f".{suffix}")

        case "PROCESS-NAME":
            return make("process_name", value)

        case "PROCESS-PATH":
            return make("process_path", value)

        case _:
            print(f"  ⚠ rules.txt:{lineno}: неизвестный тип правила: {rule_type!r}")
            return None

def get_route_rules(rules_file: str = RULES_FILE) -> tuple[list[dict], str]:

    if not os.path.exists(rules_file):
        return [], "proxy-out"
    result = load_rules(rules_file)
    if isinstance(result, tuple):
        return result
    return result, "proxy-out"

if __name__ == "__main__":
    import json
    rules, final = get_route_rules()
    print(f"Final outbound: {final}")
    print(f"Rules ({len(rules)}):")
    print(json.dumps(rules, indent=2, ensure_ascii=False))
