from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.models import (
    BSizeMatch,
    BufferSwitch,
    ContentMatch,
    DSizeMatch,
    FlowTerm,
    IsDataAtMatch,
    PcreMatch,
    RuleBody,
    RuleHeader,
    SuricataRule,
)
from parsuricata import parse_rules as _parse_raw_rules

CONTINUE_ON_ERROR: bool = False

_PC_RE = re.compile(r'^\s*"?\s*/(?P<body>(?:\\/|[^/])*)/(?P<flags>[A-Za-z]*)\s*"?\s*$')
_DSIZE_RE = re.compile(r"^\s*(?P<op>>=|<=|<>|>|<|=)?\s*(?P<a>\d+)\s*(?:<>\s*(?P<b>\d+)\s*)?$")

# 与 adapter 保持一致
STICKY_BUFFER_KEYWORDS = {
    "http.method": "http.method",
    "http.uri": "http.uri",
    "http.uri.raw": "http.uri.raw",
    "http.request_line": "http.request_line",
    "http.start": "http.start",
    "http.protocol": "http.protocol",
    "http.header": "http.header",
    "http.header.raw": "http.header.raw",
    "http.header_names": "http.header_names",
    "http.host": "http.host",
    "http.host.raw": "http.host.raw",
    "http.user_agent": "http.user_agent",
    "http.referer": "http.referer",
    "http.referer.raw": "http.referer.raw",
    "http.accept": "http.accept",
    "http.accept_lang": "http.accept_lang",
    "http.accept_enc": "http.accept_enc",
    "http.connection": "http.connection",
    "http.content_type": "http.content_type",
    "http.content_len": "http.content_len",
    "http.cookie": "http.cookie",
    "http.cookie.raw": "http.cookie.raw",
    "http.request_body": "http.request_body",
    "http.response_body": "http.response_body",
    "http.stat_code": "http.stat_code",
    "http.stat_msg": "http.stat_msg",
    "http.response_line": "http.response_line",
    "file.data": "file.data",
    "pkt_data": "pkt_data",
    "http_method": "http.method",
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_request_line": "http.request_line",
    "http_start": "http.start",
    "http_protocol": "http.protocol",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent",
    "http_referer": "http.referer",
    "http_raw_referer": "http.referer.raw",
    "http_accept": "http.accept",
    "http_accept_lang": "http.accept_lang",
    "http_accept_enc": "http.accept_enc",
    "http_connection": "http.connection",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_cookie": "http.cookie",
    "http_raw_cookie": "http.cookie.raw",
    "http_client_body": "http.request_body",
    "http_request_body": "http.request_body",
    "http_response_body": "http.response_body",
}

LEGACY_BUFFER_MODIFIERS = {
    "http_method": "http.method",
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_request_line": "http.request_line",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent",
    "http_referer": "http.referer",
    "http_raw_referer": "http.referer.raw",
    "http_accept": "http.accept",
    "http_accept_lang": "http.accept_lang",
    "http_accept_enc": "http.accept_enc",
    "http_connection": "http.connection",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_cookie": "http.cookie",
    "http_raw_cookie": "http.cookie.raw",
    "http_client_body": "http.request_body",
    "http_request_body": "http.request_body",
    "http_response_body": "http.response_body",
    "file_data": "file.data",
}

SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev", "flow", "content", "pcre", "isdataat", "dsize", "bsize",
    "nocase", "fast_pattern", "startswith", "endswith", "offset", "depth", "distance", "within",
    "header_lowercase", "to_lowercase",
    *STICKY_BUFFER_KEYWORDS.keys(),
    *LEGACY_BUFFER_MODIFIERS.keys(),
}

# 这些关键字通常只承载分类/注释/告警展示信息，不改变内容匹配语义。
# 在 to_server 请求生成阶段将其视为“已知但忽略”，避免误报 UNSUPPORTED_KEYWORD。
NON_BLOCKING_METADATA_KEYWORDS = {
    "reference",
    "metadata",
    "classtype",
    "priority",
    "target",
    "tag",
    "threshold",
}

SUPPORTED_KEYWORDS = SUPPORTED_KEYWORDS | NON_BLOCKING_METADATA_KEYWORDS


@dataclass
class RawOption:
    keyword: str
    value: Optional[str]
    negated: bool


@dataclass
class Rule:
    header: RuleHeader
    raw_text: str = ""
    sid: str = ""
    msg: str = ""
    flow: Optional[FlowTerm] = None
    raw_options: List[RawOption] = field(default_factory=list)
    content: List[ContentMatch] = field(default_factory=list)
    pcre: List[PcreMatch] = field(default_factory=list)
    sticky_buffers: List[str] = field(default_factory=list)
    legacy_modifiers: List[str] = field(default_factory=list)
    unsupported_keywords: List[str] = field(default_factory=list)


def _settings_text(obj: object) -> str:
    return "" if obj is None else str(obj)


def _is_negated_setting(obj: object) -> bool:
    return bool(getattr(obj, "is_negated", False))


def decode_hex_blocks(s: str) -> str:
    def repl(m: re.Match) -> str:
        b = bytes(int(x, 16) for x in m.group(1).split())
        return b.decode("latin-1", errors="replace")

    return re.sub(r"\|([0-9A-Fa-f ]+)\|", repl, s)


def parse_flow(setting_obj: object) -> FlowTerm:
    text = _settings_text(setting_obj)
    parts = [p.strip().lower() for p in text.split(",") if p.strip()]
    return FlowTerm(to_server=("to_server" in parts), to_client=("to_client" in parts), established=("established" in parts))


def parse_dsize(text: str) -> DSizeMatch:
    m = _DSIZE_RE.match(text.strip())
    if not m:
        raise ValueError(f"invalid dsize: {text!r}")
    op = m.group("op") or "="
    a = int(m.group("a"))
    b = m.group("b")
    return DSizeMatch(op=op, a=a, b=(int(b) if b is not None else None))


def parse_bsize(text: str) -> BSizeMatch:
    m = _DSIZE_RE.match(text.strip())
    if not m:
        raise ValueError(f"invalid bsize: {text!r}")
    op = m.group("op") or "="
    a = int(m.group("a"))
    b = m.group("b")
    return BSizeMatch(op=op, a=a, b=(int(b) if b is not None else None))


def parse_isdataat(setting_obj: object) -> IsDataAtMatch:
    neg = _is_negated_setting(setting_obj)
    text = _settings_text(setting_obj).strip()
    if text.startswith("!"):
        neg = True
        text = text[1:].strip()
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        raise ValueError(f"invalid isdataat: {text!r}")
    offset = int(parts[0])
    return IsDataAtMatch(
        offset=offset,
        relative=any(p.lower() == "relative" for p in parts[1:]),
        rawbytes=any(p.lower() == "rawbytes" for p in parts[1:]),
        negated=neg,
    )


def _split_rule_candidates(text: str) -> List[str]:
    chunks: List[str] = []
    current: List[str] = []
    in_quote = False
    esc = False
    depth = 0

    for ch in text:
        current.append(ch)
        if in_quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            continue
        if ch == '(':
            depth += 1
        elif ch == ')' and depth > 0:
            depth -= 1
            if depth == 0:
                candidate = "".join(current).strip()
                if candidate:
                    chunks.append(candidate)
                current = []
    trailing = "".join(current).strip()
    if trailing and trailing.lower().startswith(("alert ", "drop ", "reject ", "pass ", "log ")):
        chunks.append(trailing)
    return chunks


def _build_rule_ast(raw_rule: object, raw_text: str) -> Rule:
    header = RuleHeader(
        action=str(getattr(raw_rule, "action", "") or ""),
        protocol=str(getattr(raw_rule, "protocol", "") or ""),
        src=str(getattr(raw_rule, "src", "") or ""),
        src_port=str(getattr(raw_rule, "src_port", "") or ""),
        direction=str(getattr(raw_rule, "direction", "->") or "->"),
        dst=str(getattr(raw_rule, "dst", "") or ""),
        dst_port=str(getattr(raw_rule, "dst_port", "") or ""),
    )
    ast = Rule(header=header, raw_text=raw_text)

    for opt in (getattr(raw_rule, "options", []) or []):
        keyword = str(getattr(opt, "keyword", "") or "")
        settings = getattr(opt, "settings", None)
        negated = _is_negated_setting(settings)
        value = _settings_text(settings) if settings is not None else None

        ast.raw_options.append(RawOption(keyword=keyword, value=value, negated=negated))

        if keyword not in SUPPORTED_KEYWORDS and keyword not in ast.unsupported_keywords:
            ast.unsupported_keywords.append(keyword)

        if keyword == "msg" and value is not None:
            ast.msg = value
        elif keyword == "sid" and value is not None:
            ast.sid = value
        elif keyword == "flow" and settings is not None:
            ast.flow = parse_flow(settings)
        elif keyword == "content" and settings is not None:
            raw_text = value.strip()
            c_neg = negated
            if raw_text.startswith("!"):
                c_neg = True
                raw_text = raw_text[1:].lstrip()
            if len(raw_text) >= 2 and raw_text[0] == '"' and raw_text[-1] == '"':
                raw_text = raw_text[1:-1]
            ast.content.append(ContentMatch(raw=raw_text, decoded=decode_hex_blocks(raw_text), negated=c_neg))
        elif keyword == "pcre" and settings is not None:
            ast.pcre.append(PcreMatch(raw=value, negated=negated, buffer=None))
        elif keyword in STICKY_BUFFER_KEYWORDS and settings is None:
            ast.sticky_buffers.append(STICKY_BUFFER_KEYWORDS[keyword])
        elif keyword in LEGACY_BUFFER_MODIFIERS:
            ast.legacy_modifiers.append(LEGACY_BUFFER_MODIFIERS[keyword])

    return ast


def parse_rules(path: str | Path) -> List[Rule]:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    rules: List[Rule] = []
    for candidate in _split_rule_candidates(text):
        try:
            parsed = _parse_raw_rules(candidate)
        except Exception:
            continue
        if not parsed:
            continue
        rules.append(_build_rule_ast(parsed[0], candidate))
    return rules


def ast_to_suricata_rule(ast: Rule) -> SuricataRule:
    body = RuleBody(msg=ast.msg, sid=ast.sid, flow=ast.flow)
    last_content: Optional[ContentMatch] = None
    last_pcre: Optional[PcreMatch] = None
    last_mod_target: Optional[str] = None
    last_buffer_switch: Optional[BufferSwitch] = None

    content_idx = 0
    pcre_idx = 0

    for opt in ast.raw_options:
        k, v = opt.keyword, opt.value

        if k in {"msg", "sid", "flow", "rev"}:
            if k == "rev" and v is not None:
                body.rev = v
            continue
        if k in STICKY_BUFFER_KEYWORDS and v is None:
            bs = BufferSwitch(buffer=STICKY_BUFFER_KEYWORDS[k])
            body.clauses.append(bs)
            last_buffer_switch = bs
            continue
        if k == "header_lowercase":
            if last_buffer_switch is not None and "header_lowercase" not in last_buffer_switch.transforms:
                last_buffer_switch.transforms.append("header_lowercase")
            continue
        if k == "to_lowercase":
            if last_buffer_switch is not None and "to_lowercase" not in last_buffer_switch.transforms:
                last_buffer_switch.transforms.append("to_lowercase")
            continue
        if k == "content" and v is not None:
            cm = ast.content[content_idx] if content_idx < len(ast.content) else ContentMatch(raw=v, decoded=decode_hex_blocks(v), negated=opt.negated)
            content_idx += 1
            body.clauses.append(cm)
            last_content = cm
            last_mod_target = "content"
            continue
        if k == "pcre" and v is not None:
            pm = ast.pcre[pcre_idx] if pcre_idx < len(ast.pcre) else PcreMatch(raw=v, negated=opt.negated)
            pcre_idx += 1
            body.clauses.append(pm)
            last_pcre = pm
            last_mod_target = "pcre"
            continue
        if k == "isdataat" and v is not None:
            body.clauses.append(parse_isdataat(v))
            continue
        if k == "dsize" and v is not None:
            body.clauses.append(parse_dsize(v))
            continue
        if k == "bsize" and v is not None:
            body.clauses.append(parse_bsize(v))
            continue
        if k == "nocase":
            if last_mod_target == "content" and last_content is not None:
                last_content.nocase = True
            elif last_mod_target == "pcre" and last_pcre is not None:
                last_pcre.nocase = True
            continue
        if k == "fast_pattern" and last_content is not None:
            last_content.fast_pattern = True
            continue
        if k == "startswith" and last_content is not None:
            last_content.startswith = True
            continue
        if k == "endswith" and last_content is not None:
            last_content.endswith = True
            continue
        if k in LEGACY_BUFFER_MODIFIERS:
            mapped = LEGACY_BUFFER_MODIFIERS[k]
            bs = BufferSwitch(buffer=mapped)
            body.clauses.append(bs)
            last_buffer_switch = bs
            continue
        if k in {"offset", "depth", "distance", "within"} and v is not None and last_content is not None:
            try:
                iv = int(v)
            except Exception:
                continue
            setattr(last_content, k, iv)

    return SuricataRule(header=ast.header, body=body)


# --- existing helpers below ---

def sanitize_pcre(pcre: str, sid: str) -> str:
    s = pcre
    while "\\s" in s:
        s = s.replace("\\s", " ")
    while "+?" in s:
        s = s.replace("+?", "+")
    while "*?" in s:
        s = s.replace("*?", "*")
    for needle in (".+", ".*", ".?"):
        while needle in s:
            s = s.replace(needle, "[a-z]")
    for needle, repl in [
        ("[^&]", "[a-z]"),
        ("[^\\\\]", "[a-z]"),
        ("[^\\\\n]", "[a-z]"),
        ("[^\\\\r\\\\n]", "[a-z]"),
        ("[^\\\\x2f]", "[a-z]"),
    ]:
        while needle in s:
            s = s.replace(needle, repl)
    return s


def fallback_string_from_regex(pat: str, max_len: int = 512) -> str:
    pat = pat.strip().lstrip("^").rstrip("$")

    def _unescape(s: str) -> str:
        def repl_hex(m: re.Match) -> str:
            try:
                ch = bytes([int(m.group(1), 16)]).decode("latin-1")
                return ch if ch.isprintable() else "A"
            except Exception:
                return "A"

        s = re.sub(r"\\x([0-9A-Fa-f]{2})", repl_hex, s)
        s = s.replace(r"\r", "\r").replace(r"\n", "\n").replace(r"\t", "\t")
        s = s.replace(r"\0", "\0")
        s = s.replace(r"\/", "/")
        s = s.replace(r"\.", ".").replace(r"\-", "-").replace(r"\_", "_")
        s = re.sub(r"\\([\\\[\]{}()*+?.^$|])", r"\1", s)
        return s

    literal_chunks = re.findall(r"(?:\\.|[^\\\[\]{}()*+?.^$|])+", pat)
    longest_literal = _unescape(max(literal_chunks, key=len)) if literal_chunks else ""
    out: List[str] = []
    i = 0

    def _emit(ch: str, n: int = 1) -> None:
        if n > 0:
            out.append(ch * min(n, 16))

    while i < len(pat) and sum(len(x) for x in out) < max_len:
        c = pat[i]
        if c == "\\" and i + 1 < len(pat):
            nxt = pat[i + 1]
            if nxt == "x" and i + 3 < len(pat):
                hx = pat[i + 2 : i + 4]
                try:
                    ch = bytes([int(hx, 16)]).decode("latin-1")
                    _emit(ch if ch.isprintable() else "A")
                except Exception:
                    _emit("A")
                i += 4
                continue
            if nxt in ("d", "D"):
                _emit("0")
                i += 2
                continue
            if nxt in ("w", "W"):
                _emit("A")
                i += 2
                continue
            if nxt in ("s", "S"):
                _emit(" ")
                i += 2
                continue
            _emit(nxt)
            i += 2
            continue
        if c == "[":
            end = pat.find("]", i + 1)
            if end == -1:
                i += 1
                continue
            cls = pat[i + 1 : end]
            ch = "A"
            if "0-9" in cls or r"\d" in cls:
                ch = "0"
            elif "a-z" in cls:
                ch = "a"
            elif "A-Z" in cls:
                ch = "A"
            elif cls:
                ch = cls[0]
            _emit(ch)
            i = end + 1
            continue
        if c in ("(", ")", "|"):
            i += 1
            continue
        if c == ".":
            _emit("A")
            i += 1
            continue
        if c in ("*", "+", "?") or c == "{":
            if not out:
                i += 1
                continue
            last = out.pop()
            base = last[-1] if last else "A"
            if c in ("*", "+", "?"):
                _emit(base, 1)
                i += 1
                continue
            m = re.match(r"\{(\d+)(?:,(\d+))?\}", pat[i:])
            if m:
                _emit(base, int(m.group(1)))
                i += len(m.group(0))
                continue
            i += 1
            continue
        _emit(c)
        i += 1

    candidate = _unescape("".join(out))
    if len(candidate) < 3 and longest_literal:
        return longest_literal[:max_len]
    return candidate[:max_len] if candidate else (longest_literal[:max_len] if longest_literal else "A")


def _pcre_semantic_sample(pcre_string: str) -> Optional[str]:
    s = pcre_string or ""
    common = [
        (r"UNION\s\+SELECT|UNION\s\*SELECT|UNION\s\+SELECT|UNION\s+SELECT", "UNION SELECT"),
        (r"SELECT\.\+FROM|SELECT.+FROM", "SELECT a FROM"),
        (r"DELETE\.\+FROM|DELETE.+FROM", "DELETE a FROM"),
        (r"INSERT\.\+INTO|INSERT.+INTO", "INSERT a INTO"),
        (r"UPDATE\.\+SET|UPDATE.+SET", "UPDATE a SET"),
        (r"OR\s\+1=1|OR\s+1=1", "OR 1=1"),
        (r"AND\s\+1=1|AND\s+1=1", "AND 1=1"),
        (r"xp_cmdshell", "xp_cmdshell"),
        (r"cmd\.exe", "cmd.exe"),
        (r"\d\{1, ?5\}", "12345"),
        (r"\d\{1, ?3\}", "123"),
        (r"\d\+", "12345"),
        (r"\w\+", "abc"),
        (r"\w\{1, ?8\}", "abcd"),
        (r"\s\+", " "),
    ]
    for pat, repl in common:
        if re.search(pat, s, flags=re.IGNORECASE):
            return repl
    return None


def generate_string_from_pcre(pcre_string: str) -> str:
    semantic = _pcre_semantic_sample(pcre_string)
    if semantic:
        return semantic

    try:
        import exrex  # type: ignore

        return exrex.getone(pcre_string) or ""
    except Exception:
        pass
    try:
        proc = subprocess.run(["exrex", "-r", pcre_string], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and (proc.stdout or "").splitlines():
            return proc.stdout.splitlines()[0]
    except FileNotFoundError:
        pass
    return fallback_string_from_regex(pcre_string)


def parse_pcre_raw(pcre_raw: str) -> Tuple[str, str]:
    s = (pcre_raw or "").strip()
    m = _PC_RE.match(s)
    if m:
        return m.group("body"), (m.group("flags") or "")
    s2 = s.strip('"').strip()
    if s2.startswith("/") and s2.count("/") >= 2:
        last = s2.rfind("/")
        return s2[1:last], s2[last + 1 :]
    return s2, ""


def pcre_flags_to_bucket(flags: str) -> str:
    f = set(flags or "")
    if "M" in f:
        return "method"
    if "U" in f or "I" in f:
        return "uri"
    if "H" in f or "D" in f:
        return "header"
    if "P" in f:
        return "body"
    if "C" in f or "K" in f:
        return "cookie"
    return "other"


def remove_crlf_escapes(s: str, sid: str) -> str:
    if not s:
        if not CONTINUE_ON_ERROR:
            raise SystemExit(1)
        return s
    while len(s) >= 2 and s[-2] == "\\" and s[-1] in ("r", "n"):
        s = s[:-2]
    while len(s) >= 2 and s[0] == "\\" and s[1] in ("r", "n"):
        s = s[2:]
    return s


def sanitize_header(header: str, sid: str) -> str:
    if not header:
        if not CONTINUE_ON_ERROR:
            raise SystemExit(1)
        return header
    header = remove_crlf_escapes(header, sid)
    if header.endswith(":"):
        header += " DummyValue"
    elif header.endswith(" :") or (len(header) >= 2 and header[-2] == ":" and header[-1] == " "):
        header += "DummyValue"
    elif ":" not in header:
        header = "DummyHeader: " + header
    return header


def sanitize_header_value(value: str) -> str:
    return (value or "").replace("\r", "").replace("\n", "").strip()


def normalize_header_name(name: str) -> str:
    return (name or "").strip()


def header_lines_to_dict(lines: List[str], sid: str, lowercase_names: bool = False) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for line in lines:
        line = sanitize_header(line, sid)
        if ":" in line:
            k, v = line.split(":", 1)
            k = normalize_header_name(k)
            if lowercase_names:
                k = k.lower()
            d[k] = sanitize_header_value(v.lstrip())
        else:
            k = normalize_header_name(line)
            if lowercase_names:
                k = k.lower()
            d[k] = ""
    return d



def has_header(headers: Dict[str, str], name: str) -> bool:
    target = name.lower()
    return any(k.lower() == target for k in headers.keys())


def set_header_case_insensitive(headers: Dict[str, str], name: str, value: str) -> None:
    value = sanitize_header_value(value)
    target = name.lower()
    for k in list(headers.keys()):
        if k.lower() == target:
            headers[k] = value
            return
    headers[name] = value

def match_size_constraint(n: int, op: str, a: int, b: Optional[int] = None) -> bool:
    if op == "=":
        return n == a
    if op == ">":
        return n > a
    if op == ">=":
        return n >= a
    if op == "<":
        return n < a
    if op == "<=":
        return n <= a
    if op == "<>":
        if b is None:
            return False
        return a < n < b
    return False


def apply_bsize_constraints(s: str, bsize_terms: List[object], fill: str = "A") -> str:
    terms = [t for t in bsize_terms if isinstance(t, BSizeMatch)]
    if not terms:
        return s

    equals = [t for t in terms if t.op == "="]
    if equals:
        target = equals[-1].a
        if len(s) > target:
            raise ValueError(f"generated content length {len(s)} exceeds bsize target {target}: {s!r}")
        if len(s) < target:
            s = s + (fill * (target - len(s)))
        return s

    min_len = len(s)
    for t in terms:
        if t.op == ">=":
            min_len = max(min_len, t.a)
        elif t.op == ">":
            min_len = max(min_len, t.a + 1)

    max_len = None
    for t in terms:
        if t.op == "<=":
            max_len = t.a if max_len is None else min(max_len, t.a)
        elif t.op == "<":
            bound = t.a - 1
            max_len = bound if max_len is None else min(max_len, bound)

    excluded_ranges = []
    for t in terms:
        if t.op == "<>" and t.b is not None:
            excluded_ranges.append((t.a, t.b))

    if len(s) < min_len:
        s = s + (fill * (min_len - len(s)))

    if max_len is not None and len(s) > max_len:
        raise ValueError(f"generated content length {len(s)} exceeds max allowed by bsize ({max_len})")

    changed = True
    while changed:
        changed = False
        for a, b in excluded_ranges:
            if a < len(s) < b:
                target = b
                if max_len is not None and target > max_len:
                    raise ValueError(f"cannot satisfy bsize <> {a},{b} together with upper bound")
                s = s + (fill * (target - len(s)))
                changed = True

    return s
