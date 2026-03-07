from pathlib import Path
from tqdm import tqdm
from parsuricata import parse_rules
from parse.parsuricata_adapter import rule_to_suricata_rule
import re

ACTIONS = ("alert ", "drop ", "reject ", "pass ", "log ")

# ✅ 新增：把规则变成单行（去掉 "\" 续行 + 压缩空白）
_CONT_RE = re.compile(r"\\\r?\n\s*")  # "\" + 换行 + 下一行缩进
_WS_RE   = re.compile(r"\s+")         # 任意空白（含换行/tab/多空格）

def normalize_rule_one_line(s: str) -> str:
    s = _CONT_RE.sub(" ", s)   # 处理行续接 \
    s = _WS_RE.sub(" ", s)     # 压成单空格
    return s.strip()


def preprocess_rules_text(text: str, keep_disabled: bool = False) -> str:
    out_lines = []
    for line in text.splitlines():
        s = line.lstrip()

        if not s:
            out_lines.append(line)
            continue

        if s.startswith("#"):
            s2 = s[1:].lstrip()
            is_disabled_rule = s2.startswith(ACTIONS)
            if is_disabled_rule:
                if keep_disabled:
                    out_lines.append(s2)   # 直接用去掉#后的内容
                else:
                    continue
            else:
                continue
        else:
            out_lines.append(line)

    return "\n".join(out_lines) + "\n"


def export_http_to_server_rules_simple(
    in_rules_path: str,
    out_rules_path: str,
    keep_disabled: bool = True,
    require_established: bool = False,
) -> int:
    raw = Path(in_rules_path).read_text(encoding="utf-8", errors="ignore")
    cleaned = preprocess_rules_text(raw, keep_disabled=keep_disabled)

    parsed_rules = parse_rules(cleaned)

    out_path = Path(out_rules_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with out_path.open("w", encoding="utf-8") as f_out:
        for r0 in tqdm(parsed_rules, desc="Filtering rules"):
            try:
                r = rule_to_suricata_rule(r0)

                flow = r.body.flow
                if not flow or not flow.to_server:
                    continue
                if require_established and not flow.established:
                    continue

                if r.header.protocol.lower() != "http":
                    continue

                raw_rule_text = getattr(r0, "raw", None) or getattr(r0, "text", None) or str(r0)

                # ✅ 关键：写出前压成单行
                f_out.write(normalize_rule_one_line(raw_rule_text) + "\n")
                count += 1

            except Exception:
                continue

    return count


if __name__ == "__main__":
    n = export_http_to_server_rules_simple(
        in_rules_path=r"E:\Develop\devpy\experiment\resources\dataset\emerging-all.rules",
        out_rules_path=r"E:\Develop\devpy\experiment\resources\dataset\converted_emerging-all_http.rules",
        keep_disabled=True,
        require_established=False,
    )
    print("exported:", n)