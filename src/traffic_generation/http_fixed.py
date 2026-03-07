from __future__ import annotations

from parse.buckets_sorting import split_clauses_for_http_generation
from parse.parsuricata_adapter import rule_to_suricata_rule
from parsuricata import parse_rules
from urllib.parse import urlparse
import http.client
import sys
import urllib.parse
import socket
from typing import Dict, Tuple, List, Any, Optional, Literal
import re
import subprocess
from pydantic import BaseModel, Field
from core.models import ContentMatch, IsDataAtMatch, BSizeMatch, BufferSwitch
from core.models import PcreMatch  # type: ignore

PRINT_RESPONSE: bool = False
CONTINUE_ON_ERROR: bool = False
VERBOSE: bool = False

HEADER_BUCKET_TO_NAME = {
    "host": "Host",
    "user_agent": "User-Agent",
    "referer": "Referer",
    "accept": "Accept",
    "accept_language": "Accept-Language",
    "accept_encoding": "Accept-Encoding",
    "connection": "Connection",
    "content_type": "Content-Type",
    "content_length": "Content-Length",
}

BUFFER_TO_HEADER_KEYWORD = {
    "host": "http.host",
    "user_agent": "http.user_agent",
    "referer": "http.referer",
    "accept": "http.accept",
    "accept_language": "http.accept_lang",
    "accept_encoding": "http.accept_enc",
    "connection": "http.connection",
    "content_type": "http.content_type",
    "content_length": "http.content_len",
}


class HttpRequestSpec(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""


def _pad_to(s: str, n: int, fill: str = "A") -> str:
    if len(s) >= n:
        return s
    return s + (fill * (n - len(s)))


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
    """
    Best-effort adjust string length to satisfy bsize constraints.
    """
    terms = [t for t in bsize_terms if isinstance(t, BSizeMatch)]
    if not terms:
        return s

    equals = [t for t in terms if t.op == "="]
    if equals:
        target = equals[-1].a
        if len(s) > target:
            raise ValueError(
                f"generated content length {len(s)} exceeds bsize target {target}: {s!r}"
            )
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
        raise ValueError(
            f"generated content length {len(s)} exceeds max allowed by bsize ({max_len})"
        )

    changed = True
    while changed:
        changed = False
        for a, b in excluded_ranges:
            if a < len(s) < b:
                target = b
                if max_len is not None and target > max_len:
                    raise ValueError(
                        f"cannot satisfy bsize <> {a},{b} together with upper bound"
                    )
                s = s + (fill * (target - len(s)))
                changed = True

    return s


def build_stream_from_contents(contents: List[ContentMatch], fill: str = "A") -> tuple[str, int]:
    s = ""
    prev_end = 0
    for c in contents:
        if getattr(c, "negated", False):
            continue
        token = getattr(c, "decoded", "") or getattr(c, "raw", "")
        if token == "":
            continue

        if getattr(c, "startswith", False) and len(s) == 0:
            s = token
            prev_end = len(token)
            continue

        cursor = prev_end
        off = getattr(c, "offset", None)
        if off is not None:
            cursor = max(0, int(off))

        dist = getattr(c, "distance", None)
        if dist is not None:
            cursor = prev_end + int(dist)

        within = getattr(c, "within", None)
        if within is not None:
            latest_start = max(0, prev_end + int(within) - len(token))
            if cursor > latest_start:
                cursor = latest_start

        depth = getattr(c, "depth", None)
        if depth is not None:
            base = int(off) if off is not None else cursor
            latest_start = max(0, base + int(depth) - len(token))
            if cursor > latest_start:
                cursor = latest_start

        s = _pad_to(s, cursor, fill)
        s = s[:cursor] + token + s[cursor + len(token):]
        prev_end = cursor + len(token)

    ends = [c for c in contents if getattr(c, "endswith", False) and not getattr(c, "negated", False)]
    if ends:
        tail = getattr(ends[-1], "decoded", "") or getattr(ends[-1], "raw", "")
        if tail and not s.endswith(tail):
            s += tail
            prev_end = len(s)

    return s, prev_end


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
                hx = pat[i + 2:i + 4]
                try:
                    ch = bytes([int(hx, 16)]).decode("latin-1")
                    _emit(ch if ch.isprintable() else "A")
                except Exception:
                    _emit("A")
                i += 4
                continue
            if nxt in ("d", "D"):
                _emit("0"); i += 2; continue
            if nxt in ("w", "W"):
                _emit("A"); i += 2; continue
            if nxt in ("s", "S"):
                _emit(" "); i += 2; continue
            _emit(nxt)
            i += 2
            continue
        if c == "[":
            end = pat.find("]", i + 1)
            if end == -1:
                i += 1
                continue
            cls = pat[i + 1:end]
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


_PC_RE = re.compile(r'^\s*"?\s*/(?P<body>(?:\\/|[^/])*)/(?P<flags>[A-Za-z]*)\s*"?\s*$')


def parse_pcre_raw(pcre_raw: str) -> Tuple[str, str]:
    s = (pcre_raw or "").strip()
    m = _PC_RE.match(s)
    if m:
        return m.group("body"), (m.group("flags") or "")
    s2 = s.strip('"').strip()
    if s2.startswith("/") and s2.count("/") >= 2:
        last = s2.rfind("/")
        return s2[1:last], s2[last + 1:]
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


def has_explicit_buffer_switch(clauses: List[object]) -> bool:
    return any(isinstance(c, BufferSwitch) for c in clauses)


def _looks_like_host_fragment(tok: str) -> bool:
    t = (tok or "").strip()
    if not t:
        return False
    low = t.lower()
    if low.startswith("host:"):
        return True
    if t.startswith(".") and "." in t:
        return True
    if "." in t and "/" not in t and " " not in t and not t.startswith("/"):
        return True
    return False


def _split_domain_and_path(tok: str) -> tuple[Optional[str], Optional[str]]:
    t = (tok or "").strip()
    m = re.match(r"^([A-Za-z0-9._-]+\.[A-Za-z]{2,})(/.*)$", t)
    if m:
        return m.group(1), m.group(2)
    return None, None


def validate_http_request(req: HttpRequestSpec) -> None:
    valid_methods = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}

    if req.method.upper() not in valid_methods:
        raise ValueError(f"invalid HTTP method: {req.method!r}")

    if not req.path:
        raise ValueError("empty path")

    if " " in req.path or "\r" in req.path or "\n" in req.path:
        raise ValueError(f"invalid path contains control/space: {req.path!r}")

    if not req.path.startswith("/"):
        raise ValueError(f"path must start with '/': {req.path!r}")


def render_http_request(req: HttpRequestSpec) -> str:
    lines = [f"{req.method} {req.path} HTTP/1.1"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.body:
        lines.append(req.body)
    return "\r\n".join(lines)


def classify_http_rule_strategy(clauses: List[object]) -> Literal["sticky", "recoverable_raw", "raw_text"]:
    """
    sticky: 显式 sticky buffer
    recoverable_raw: 无 sticky，但有明显 method / Host / header 线索
    raw_text: 无 sticky，且更像原始 HTTP 文本片段匹配
    """
    if has_explicit_buffer_switch(clauses):
        return "sticky"

    contents = [c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)]
    pcres = [c for c in clauses if PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False)]

    decoded_tokens = [(getattr(c, "decoded", "") or getattr(c, "raw", "")).strip() for c in contents]
    decoded_tokens = [t for t in decoded_tokens if t]

    for t in decoded_tokens:
        low = t.lower()
        if low.startswith("host:") or low.startswith("user-agent:") or low.startswith("referer:") \
           or low.startswith("cookie:") or low.startswith("accept:") or low.startswith("connection:"):
            return "recoverable_raw"
        if t.upper() in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}:
            return "recoverable_raw"

    if any(t.lower() in {"host:", "user-agent:", "referer:", "cookie:"} for t in decoded_tokens):
        return "recoverable_raw"

    for c in contents:
        if getattr(c, "distance", None) is not None or getattr(c, "within", None) is not None \
           or getattr(c, "offset", None) is not None or getattr(c, "depth", None) is not None:
            return "raw_text"

    if pcres:
        return "raw_text"

    return "raw_text"


def extract_header_candidates_from_raw_clauses(
    clauses: List[object],
    sid: str
) -> Tuple[Dict[str, str], Optional[str], Optional[str]]:
    """
    对“无 sticky buffer 但可恢复结构”的规则做保守恢复。
    """
    headers: Dict[str, str] = {}
    inferred_method: Optional[str] = None
    inferred_path: Optional[str] = None

    contents: List[ContentMatch] = [
        c for c in clauses
        if isinstance(c, ContentMatch) and not getattr(c, "negated", False)
    ]

    raw_fragments: List[str] = []
    for c in contents:
        token = (getattr(c, "decoded", "") or getattr(c, "raw", ""))
        if token:
            raw_fragments.append(token)

    merged = "".join(raw_fragments)

    HEADER_NAME_WHITELIST = {
        "host",
        "user-agent",
        "referer",
        "cookie",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "content-type",
        "content-length",
        "x-raw",
    }

    for token in raw_fragments:
        t = token.strip()
        if not t:
            continue

        m = re.match(r'^\s*(?:\r\n)?([A-Za-z0-9\-]+)\s*:\s*([^\r\n]+)(?:\r\n)?\s*$', t, flags=re.IGNORECASE)
        if not m:
            continue

        name = m.group(1).strip()
        value = sanitize_header_value(m.group(2))
        if not name or not value:
            continue

        if name.lower() not in HEADER_NAME_WHITELIST:
            continue

        set_header_case_insensitive(headers, name, value)

    HTTP_METHODS = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}
    for c in contents:
        token = ((getattr(c, "decoded", "") or getattr(c, "raw", "")).strip()).upper()
        if token in HTTP_METHODS:
            inferred_method = token
            break

    saw_host_marker = False
    host_value_candidate: Optional[str] = None

    for c in contents:
        token = (getattr(c, "decoded", "") or getattr(c, "raw", ""))
        low = token.lower().strip()

        if low == "host:" or low == "host: " or low.startswith("host:"):
            saw_host_marker = True
            parts = token.split(":", 1)
            if len(parts) == 2:
                rest = sanitize_header_value(parts[1])
                if rest:
                    host_value_candidate = rest
                    break
            continue

        if saw_host_marker:
            if "." in token and "\r" not in token and "\n" not in token:
                host_value_candidate = sanitize_header_value(token)
                break

    if host_value_candidate is None:
        m = re.search(r"Host:\s*([^\r\n]+)", merged, flags=re.IGNORECASE)
        if m:
            host_value_candidate = sanitize_header_value(m.group(1))

    if host_value_candidate:
        if host_value_candidate.startswith("."):
            host_value_candidate = "www" + host_value_candidate
        set_header_case_insensitive(headers, "Host", host_value_candidate)

    for c in clauses:
        if not (PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False)):
            continue

        body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))

        m = re.search(
            r'User-Agent\\:\s*0\\:0\\:\[\^\\x0a\|\\x0d\]\{(\d+)\}',
            body_rx,
            flags=re.IGNORECASE,
        )
        if m:
            n = int(m.group(1))
            set_header_case_insensitive(headers, "User-Agent", "0:0:" + ("A" * n))
            continue

        m = re.search(
            r'User-Agent\\:\s*([^\\]+?)\{(\d+)\}',
            body_rx,
            flags=re.IGNORECASE,
        )
        if m and not has_header(headers, "User-Agent"):
            prefix = m.group(1)
            n = int(m.group(2))
            prefix = prefix.replace(r'\:', ':').replace(r'\ ', ' ')
            prefix = prefix.replace("User-Agent:", "").strip()
            set_header_case_insensitive(headers, "User-Agent", prefix + ("A" * n))
            continue

        if re.search(r'User-Agent\\:\s*0\\:0\\:', body_rx, flags=re.IGNORECASE):
            if not has_header(headers, "User-Agent"):
                set_header_case_insensitive(headers, "User-Agent", "0:0:" + ("A" * 128))
            continue

    return headers, inferred_method, inferred_path

def _normalize_uri_fragment(s: str) -> str:
    if not s:
        return ""

    s = s.strip().strip('\"').strip("'")
    s = s.replace("\r", "").replace("\n", "")
    s = re.sub(r"\s+", "+", s)
    return s


def _merge_uri_parts(parts: list[str]) -> str:
    if not parts:
        return "/"

    norm = [_normalize_uri_fragment(p) for p in parts if p and _normalize_uri_fragment(p)]

    path = ""
    query_parts: list[str] = []

    i = 0
    while i < len(norm):
        p = norm[i]

        if not path and p.startswith("/"):
            if "?" in p:
                left, right = p.split("?", 1)
                path = left if left else "/"
                if right:
                    query_parts.append(right)
            else:
                path = p
            i += 1
            continue

        if p.endswith("="):
            key = p[:-1]
            if i + 1 < len(norm):
                val = norm[i + 1]
                if val.endswith("="):
                    query_parts.append(f"{key}=1")
                    i += 1
                else:
                    query_parts.append(f"{key}={val}")
                    i += 2
                continue
            else:
                query_parts.append(f"{key}=1")
                i += 1
                continue

        if "=" in p and not p.startswith("/"):
            query_parts.append(p)
            i += 1
            continue

        if path and not p.startswith("/"):
            query_parts.append(p)
            i += 1
            continue

        if not path:
            path = "/" + p.lstrip("/")
        else:
            query_parts.append(p)
        i += 1

    if not path:
        path = "/"

    if query_parts:
        query = "&".join(q.strip("&?") for q in query_parts if q.strip("&?"))
        return f"{path}?{query}" if query else path

    return path


def _choose_body_content_type(body: str) -> Optional[str]:
    if not body:
        return None

    low = body.lower()

    if "content-disposition:" in low or "filename=" in low or "multipart/form-data" in low:
        return "multipart/form-data; boundary=----ChatGPTBoundary"

    if "=" in body and "&" in body:
        return "application/x-www-form-urlencoded"

    if "=" in body and "\n" not in body and "\r" not in body:
        return "application/x-www-form-urlencoded"

    return "text/plain"


def _wrap_multipart_if_needed(body: str) -> str:
    if not body:
        return body

    low = body.lower()
    if "content-disposition:" not in low and "filename=" not in low and "pk" not in low:
        return body

    boundary = "----ChatGPTBoundary"

    if body.startswith(f"--{boundary}"):
        return body

    filename = "sample.zip" if "pk" in low else "sample.bin"

    wrapped = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"{body}\r\n"
        f"--{boundary}--\r\n"
    )
    return wrapped


def build_http_request_from_raw_clauses(
    clauses: List[object],
    sid: str = "",
    default_method: str = "GET",
) -> HttpRequestSpec:
    """
    无 sticky buffer，但仍尝试恢复结构化 HTTP。
    只做保守恢复，不再过度把 token 塞进 URI / User-Agent。
    """
    headers: Dict[str, str] = {}
    method = default_method
    path = "/"
    body = ""

    recovered, inferred_method, inferred_path = extract_header_candidates_from_raw_clauses(clauses, sid)
    headers.update(recovered)

    if inferred_method:
        method = inferred_method
    if inferred_path:
        path = inferred_path

    contents = [c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)]
    residual_tokens: List[str] = []
    for c in contents:
        token = (getattr(c, "decoded", "") or getattr(c, "raw", "")).strip()
        if not token:
            continue
        low = token.lower()

        if low.startswith("host:") or low.startswith("user-agent:") or low.startswith("cookie:") \
           or low.startswith("referer:") or low.startswith("accept:") or low.startswith("connection:") \
           or low.startswith("x-raw:"):
            continue

        if token.upper() in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}:
            continue

        residual_tokens.append(token)

    host_candidate: Optional[str] = None
    path_candidate: Optional[str] = None
    raw_header_fragments: List[str] = []
    other_fragments: List[str] = []

    for tok in residual_tokens:
        h, p = _split_domain_and_path(tok)
        if h and not has_header(headers, "Host") and not host_candidate:
            host_candidate = h
            if p and path == "/" and not path_candidate:
                path_candidate = p
            continue

        if _looks_like_host_fragment(tok):
            t = tok
            if t.lower().startswith("host:"):
                t = t.split(":", 1)[1].strip()
            if t.startswith("."):
                t = "www" + t
            if not has_header(headers, "Host") and not host_candidate:
                host_candidate = t
            else:
                raw_header_fragments.append(tok)
            continue

        if tok.startswith("/") or "?" in tok or "=" in tok or tok.endswith(".php") or tok.endswith(".asp") \
           or tok.endswith(".cgi") or "/" in tok:
            if path == "/" and not path_candidate:
                path_candidate = tok if tok.startswith("/") else "/" + tok
            else:
                other_fragments.append(tok)
            continue

        other_fragments.append(tok)

    if host_candidate and not has_header(headers, "Host"):
        set_header_case_insensitive(headers, "Host", host_candidate)

    if path == "/" and path_candidate:
        path = path_candidate if path_candidate.startswith("/") else "/" + path_candidate

    if raw_header_fragments:
        joined = "".join(raw_header_fragments)
        if not has_header(headers, "X-Raw"):
            set_header_case_insensitive(headers, "X-Raw", joined)
        else:
            other_fragments.append(joined)

    if other_fragments:
        joined = "".join(other_fragments)
        if not has_header(headers, "X-Raw"):
            set_header_case_insensitive(headers, "X-Raw", joined)
        else:
            body = joined

    if not headers and method == default_method and path == "/" and not body:
        fallback = synthesize_bucket_text(clauses, sid, fill="A", strip_crlf=True)
        if fallback:
            if method.upper() == "GET":
                path = "/" + fallback.lstrip("/")
            else:
                body = fallback

    valid_methods = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}
    if method.upper() not in valid_methods:
        method = default_method

    path = (path or "/").replace("\r", "").replace("\n", "")
    path = re.sub(r"\s+", "", path)
    if not path.startswith("/"):
        path = "/" + path
    if not path:
        path = "/"

    if sid:
        headers["Rulesid"] = str(sid).strip()

    return HttpRequestSpec(method=method, path=path, headers=headers, body=body)


def synthesize_bucket_text(
    clauses: List[object],
    sid: str,
    *,
    fill: str = "A",
    strip_crlf: bool = False
) -> str:
    contents = [c for c in clauses if isinstance(c, ContentMatch)]
    s, prev_end = build_stream_from_contents(contents, fill=fill) if contents else ("", 0)

    for c in clauses:
        if PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False):
            body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
            sample = generate_string_from_pcre(sanitize_pcre(body_rx, sid))
            s += sample or ""
            prev_end = len(s)

    for c in clauses:
        if isinstance(c, IsDataAtMatch):
            need = int(c.offset)

            if c.relative:
                remain = len(s) - prev_end
                if c.negated:
                    if remain >= need:
                        s = s[:prev_end + max(0, need - 1)]
                else:
                    if remain < need:
                        s = _pad_to(s, prev_end + need, fill)
            else:
                total = len(s)
                if c.negated:
                    if total >= need:
                        s = s[:max(0, need - 1)]
                else:
                    if total < need:
                        s = _pad_to(s, need, fill)

    s = apply_bsize_constraints(s, clauses, fill=fill)

    if strip_crlf:
        s = s.replace("\r", "").replace("\n", "")
    return s


def apply_named_header_buckets(headers: Dict[str, str], buckets: Dict[str, Any], sid: str) -> None:
    transforms_by_buf: Dict[str, List[str]] = buckets.get("_buffer_transforms", {})

    for bucket_name, header_name in HEADER_BUCKET_TO_NAME.items():
        clauses = buckets.get(bucket_name, [])
        if not clauses:
            continue
        value = synthesize_bucket_text(clauses, sid, fill="A", strip_crlf=True)
        if not value:
            continue

        transforms = transforms_by_buf.get(BUFFER_TO_HEADER_KEYWORD[bucket_name], [])
        final_name = header_name.lower() if "header_lowercase" in transforms else header_name
        set_header_case_insensitive(headers, final_name, value)

    header_names_text = synthesize_bucket_text(
        buckets.get("header_names", []), sid, fill="A", strip_crlf=False
    )
    for raw_line in re.split(r"\\r\\n|\r\n|\\n|\n", header_names_text):
        name = raw_line.strip(" :\t")
        if name:
            headers.setdefault(name, "DummyValue")


def rebucket_pcre_by_flags(buckets: Dict[str, Any]) -> Dict[str, Any]:
    moved: Dict[str, Any] = {}
    for k, v in buckets.items():
        if isinstance(v, list):
            moved[k] = list(v)
        else:
            moved[k] = v

    for src in ("other", "file"):
        lst = moved.get(src, [])
        if not isinstance(lst, list):
            continue

        keep: List[object] = []
        for clause in lst:
            if PcreMatch is not None and isinstance(clause, PcreMatch) and not getattr(clause, "negated", False):
                _, flags = parse_pcre_raw(getattr(clause, "raw", ""))
                dst = pcre_flags_to_bucket(flags)
                if dst in moved and isinstance(moved[dst], list):
                    moved[dst].append(clause)
                else:
                    keep.append(clause)
            else:
                keep.append(clause)
        moved[src] = keep
    return moved


def build_http_request_from_buckets(
    buckets: Dict[str, Any],
    sid: str = "",
    default_method: str = "GET"
) -> HttpRequestSpec:
    transforms_by_buf: Dict[str, List[str]] = buckets.get("_buffer_transforms", {})

    method = default_method
    request_line_text = synthesize_bucket_text(
        buckets.get("request_line", []), sid, fill="A", strip_crlf=True
    )
    path = ""
    if request_line_text:
        m = re.match(r"^([A-Z]+)\s+(\S+)", request_line_text)
        if m:
            method = m.group(1)
            path = m.group(2)

    valid_methods = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}
    for c in buckets.get("method", []):
        if isinstance(c, ContentMatch) and not getattr(c, "negated", False):
            candidate = (getattr(c, "decoded", "") or getattr(c, "raw", "")).strip().upper()
            if candidate in valid_methods:
                method = candidate
                break
        if PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False):
            body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
            candidate = generate_string_from_pcre(sanitize_pcre(body_rx, sid)).strip().upper()
            if candidate in valid_methods:
                method = candidate
                break

    if not path:
        uri_parts: List[str] = []
        for c in buckets.get("uri", []):
            if isinstance(c, ContentMatch) and not getattr(c, "negated", False):
                tok = getattr(c, "decoded", "") or getattr(c, "raw", "")
                if tok:
                    uri_parts.append(tok)
            elif PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False):
                body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
                sample = generate_string_from_pcre(sanitize_pcre(body_rx, sid))
                if sample:
                    uri_parts.append(sample)
        if uri_parts:
            path = _merge_uri_parts(uri_parts)
        else:
            uri_text = synthesize_bucket_text(buckets.get("uri", []), sid, fill="a", strip_crlf=True)
            path = _normalize_uri_fragment(uri_text or "/")

    if not path.startswith("/"):
        path = "/" + path

    header_lines: List[str] = []
    for c in buckets.get("header", []):
        if isinstance(c, ContentMatch) and not getattr(c, "negated", False):
            header_lines.append(getattr(c, "decoded", "") or getattr(c, "raw", ""))
        elif PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False):
            body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
            header_lines.append(generate_string_from_pcre(sanitize_pcre(body_rx, sid)))

    header_transforms = transforms_by_buf.get("http.header", []) + transforms_by_buf.get("http.header.raw", [])
    lowercase_names = "header_lowercase" in header_transforms
    headers = header_lines_to_dict(header_lines, sid=sid, lowercase_names=lowercase_names)

    apply_named_header_buckets(headers, buckets, sid)

    cookie_blob = synthesize_bucket_text(buckets.get("cookie", []), sid, fill="A", strip_crlf=True)
    if cookie_blob:
        set_header_case_insensitive(headers, "Cookie", cookie_blob)

    body_str = synthesize_bucket_text(buckets.get("body", []), sid, fill="A", strip_crlf=True)

    if method.upper() == "GET":
        body_str = ""
        for hk in list(headers.keys()):
            if hk.lower() == "content-length":
                headers.pop(hk, None)
    else:
        body_str = _wrap_multipart_if_needed(body_str)
        content_type = _choose_body_content_type(body_str)
        if body_str and content_type and not has_header(headers, "Content-Type"):
            set_header_case_insensitive(headers, "Content-Type", content_type)
        if body_str and not has_header(headers, "Content-Length"):
            set_header_case_insensitive(headers, "Content-Length", str(len(body_str.encode("utf-8", errors="replace"))))

    if method.upper() not in valid_methods:
        method = default_method

    path = (path or "/").replace("\r", "").replace("\n", "")
    path = re.sub(r"\s+", "", path)
    if not path.startswith("/"):
        path = "/" + path
    if not path:
        path = "/"

    if sid:
        headers["Rulesid"] = str(sid)

    return HttpRequestSpec(method=method, path=path, headers=headers, body=body_str)

def build_raw_http_text_request_from_clauses(
    clauses: List[object],
    sid: str = "",
    server: str = "http://127.0.0.1:80",
) -> bytes:
    """
    针对老式“无 sticky buffer、只有 content/modifier”的规则，
    直接构造原始 HTTP 文本，尽量保持 token 在 header 区域连续出现。
    """
    host = urlparse(server).hostname if "://" in server else server.split(":", 1)[0]
    if not host:
        host = "127.0.0.1"

    contents = [c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)]

    tokens: List[str] = []
    for c in contents:
        tok = (getattr(c, "decoded", "") or getattr(c, "raw", ""))
        if tok:
            tokens.append(tok)

    method = "GET"
    for t in tokens:
        u = t.strip().upper()
        if u in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}:
            method = u
            break

    host_value = host
    saw_host = False
    for t in tokens:
        low = t.lower().strip()
        if low.startswith("host:"):
            saw_host = True
            rest = t.split(":", 1)[1].strip()
            if rest:
                host_value = rest
                break
            continue
        if saw_host and "." in t and "\r" not in t and "\n" not in t:
            host_value = t.strip()
            if host_value.startswith("."):
                host_value = "www" + host_value
            break

    path = "/"
    for t in tokens:
        s = t.strip()
        if s.startswith("/"):
            path = s
            break
        m = re.match(r"^([A-Za-z0-9._-]+\.[A-Za-z]{2,})(/.*)$", s)
        if m:
            host_value = m.group(1)
            path = m.group(2)
            break

    path = path.replace("\r", "").replace("\n", "")
    path = re.sub(r"\s+", "", path)
    if not path.startswith("/"):
        path = "/" + path
    if not path:
        path = "/"

    extra_parts: List[str] = []
    for t in tokens:
        s = t.strip()
        if s.upper() == method:
            continue
        if s.lower().startswith("host:"):
            continue
        if s == host_value:
            continue
        if s.startswith(path) or s == path:
            continue
        if s == ("." + host_value.lstrip("www")):
            continue
        extra_parts.append(s)

    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_value}",
    ]

    if extra_parts:
        lines.append(f"X-Raw: {''.join(extra_parts)}")

    if sid:
        lines.append(f"Rulesid: {sid}")

    lines.append("Connection: close")
    lines.append("")
    lines.append("")

    raw = "\r\n".join(lines)
    return raw.encode("latin-1", errors="replace")


def ensure_common_headers(
    server: str,
    req: HttpRequestSpec,
    *,
    add_user_agent: bool = True,
    add_accept: bool = True,
    add_connection: bool = True,
    add_accept_language: bool = False
) -> None:
    host = urlparse(server).hostname if "://" in server else server.split(":", 1)[0]
    if host and not has_header(req.headers, "Host"):
        req.headers["Host"] = host
    if add_user_agent and not has_header(req.headers, "User-Agent"):
        req.headers["User-Agent"] = "Mozilla/5.0 (compatible; ids-rule-generator/1.0)"
    if add_accept and not has_header(req.headers, "Accept"):
        req.headers["Accept"] = "*/*"
    if add_accept_language and not has_header(req.headers, "Accept-Language"):
        req.headers["Accept-Language"] = "en-US,en;q=0.9"
    if add_connection and not has_header(req.headers, "Connection"):
        req.headers["Connection"] = "close"


def _parse_server(server: str) -> Tuple[str, int, bool]:
    if "://" in server:
        u = urllib.parse.urlparse(server)
        if not u.hostname:
            raise ValueError("Invalid server URL")
        use_tls = (u.scheme.lower() == "https")
        port = u.port or (443 if use_tls else 80)
        return u.hostname, port, use_tls
    if ":" in server and server.count(":") == 1:
        h, p = server.split(":", 1)
        return h, int(p), False
    return server, 80, False


def send_http_request(server: str, req: HttpRequestSpec, timeout: int = 3) -> Tuple[int, bytes]:
    validate_http_request(req)

    host, port, use_tls = _parse_server(server)
    path = req.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    conn: http.client.HTTPConnection
    conn = (
        http.client.HTTPSConnection(host, port, timeout=timeout)
        if use_tls else
        http.client.HTTPConnection(host, port, timeout=timeout)
    )

    safe_headers = {k: sanitize_header_value(v) for k, v in req.headers.items()}
    body_bytes = req.body.encode("utf-8", errors="replace") if req.body else None
    conn.request(method=req.method, url=path, body=body_bytes, headers=safe_headers)
    resp = conn.getresponse()
    data = resp.read()
    status = int(resp.status)
    conn.close()

    if PRINT_RESPONSE:
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace") + "\n")
        except Exception:
            pass
    return status, data


def send_raw_http_bytes(server: str, raw_bytes: bytes, timeout: int = 3) -> Tuple[int, bytes]:
    host, port, use_tls = _parse_server(server)
    if use_tls:
        raise ValueError("send_raw_http_bytes currently supports only plain HTTP")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(raw_bytes)
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    data = b"".join(chunks)
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", data)
    status = int(m.group(1)) if m else 0

    if PRINT_RESPONSE:
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace") + "\n")
        except Exception:
            pass

    return status, data


def build_request_for_rule(
    rule,
    server: str,
) -> Tuple[str, Optional[HttpRequestSpec], Optional[bytes]]:
    """
    返回:
      strategy, structured_req, raw_bytes
    其中 structured_req/raw_bytes 二选一非空
    """
    strategy = classify_http_rule_strategy(rule.body.clauses)

    if strategy == "sticky":
        buckets = split_clauses_for_http_generation(rule.body.clauses)
        buckets = rebucket_pcre_by_flags(buckets)
        req = build_http_request_from_buckets(buckets, sid=rule.body.sid)
        ensure_common_headers(server, req)
        return strategy, req, None

    if strategy == "recoverable_raw":
        req = build_http_request_from_raw_clauses(rule.body.clauses, sid=rule.body.sid)
        ensure_common_headers(server, req)
        return strategy, req, None

    raw_bytes = build_raw_http_text_request_from_clauses(
        rule.body.clauses,
        sid=rule.body.sid,
        server=server,
    )
    return strategy, None, raw_bytes


if __name__ == '__main__':
    TARGET_SERVER = "http://192.168.1.199:80"

    RULE_2013005 = r'''
alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg: "ET DELETED Spyware 2020"; flow: to_server, established; content: "|48 6F 73 74 3A 20 77 77 77 2E 32 30 32 30 73 65 61 72 63 68 2E 63 6F 6D|"; content: "|49 70 41 64 64 72|"; reference: url, securityresponse.symantec.com/avcenter/venc/data/spyware.2020search.html; classtype: trojan-activity; sid: 2000327; rev: 10; metadata: created_at 2010_07_30, signature_severity Unknown, updated_at 2019_07_26; )
'''
    rules = parse_rules(RULE_2013005)
    rule_original = rules[0]
    rule = rule_to_suricata_rule(rule_original)

    strategy, req, raw_bytes = build_request_for_rule(rule, TARGET_SERVER)
    print("strategy =", strategy)

    if req is not None:
        print(req)
        print(render_http_request(req))
        status, data = send_http_request(TARGET_SERVER, req)
        print(status)
    else:
        print(raw_bytes.decode("latin-1", errors="replace"))
        status, data = send_raw_http_bytes(TARGET_SERVER, raw_bytes)
        print(status)