from __future__ import annotations

import re
import subprocess
from typing import Dict, List, Optional, Tuple

from core.models import BSizeMatch

CONTINUE_ON_ERROR: bool = False

_PC_RE = re.compile(r'^\s*"?\s*/(?P<body>(?:\\/|[^/])*)/(?P<flags>[A-Za-z]*)\s*"?\s*$')


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
