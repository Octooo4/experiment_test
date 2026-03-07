from pathlib import Path
from tqdm import tqdm
from parsuricata import parse_rules
import re

ACTIONS = ("alert ", "drop ", "reject ", "pass ", "log ")
END_RE = re.compile(r";\s*\)\s*$")   # ✅ 正确的规则结束： ;  + 可选空白 + ) + 行尾

def iter_rule_texts(file_path: str):
    """
    逐条产出规则文本：
    - 纯注释行跳过
    - '# alert ...' 这种禁用规则：去掉 '#'
    - 以行尾匹配 ';\s*)' 作为规则结束标记（最简单且靠谱）
    """
    buf = []
    in_rule = False

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.lstrip()
            if not s:
                if in_rule:
                    buf.append(line)
                continue

            # 注释/禁用处理：禁用规则去掉 '#'
            if s.startswith("#"):
                s2 = s[1:].lstrip()
                if s2.startswith(ACTIONS):
                    line = s2
                    s = line.lstrip()
                else:
                    continue

            s3 = s.lstrip("\ufeff")  # 处理 BOM（保险）

            if not in_rule:
                if s3.startswith(ACTIONS):
                    in_rule = True
                    buf = [line]
                    # 单行规则就结束
                    if END_RE.search(line):
                        yield "".join(buf).strip()
                        buf = []
                        in_rule = False
                else:
                    continue
            else:
                buf.append(line)
                if END_RE.search(line):
                    yield "".join(buf).strip()
                    buf = []
                    in_rule = False


def count_unparsable_rules(in_rules_path: str, bad_output_path: str | None = None, max_bad_dump: int = 200):
    total = 0
    ok = 0
    bad = 0
    dumped = 0

    bad_out = open(bad_output_path, "w", encoding="utf-8") if bad_output_path else None
    try:
        for rule_text in tqdm(iter_rule_texts(in_rules_path), desc="Parsing rules"):
            total += 1
            try:
                parsed = parse_rules(rule_text)
                if parsed:
                    ok += 1
                else:
                    bad += 1
                    if bad_out and dumped < max_bad_dump:
                        bad_out.write(f"--- BAD RULE #{total} (empty parse) ---\n{rule_text}\n\n")
                        dumped += 1
            except Exception as e:
                bad += 1
                if bad_out and dumped < max_bad_dump:
                    bad_out.write(f"--- BAD RULE #{total} ---\n{repr(e)}\n{rule_text}\n\n")
                    dumped += 1

        return {"total_rules": total, "ok_rules": ok, "bad_rules": bad, "bad_dumped": dumped}
    finally:
        if bad_out:
            bad_out.close()


if __name__ == "__main__":
    in_path = r"E:\Develop\devpy\experiment\resources\dataset\emerging-all.rules"
    bad_path = r"E:\Develop\devpy\experiment\resources\dataset\bad_rules.txt"

    stats = count_unparsable_rules(in_path, bad_output_path=bad_path, max_bad_dump=300)
    print(stats)