import sys

from pydantic import BaseModel, Field
from typing import Dict, Tuple
from core.models import ContentMatch
import subprocess
import re

# configuration
PRINT_RESPONSE = False
CONTINUE_ON_ERROR = False
VERBOSE = False
PACKET_COUNTER = 1

# data model
class HttpRequestSpec(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""

class Constraint(BaseModel):
    kind: str  # "content" | "pcre" | "isdataat" | "dsize"
    decoded: str | None = None
    raw: str | None = None
    negated: bool = False
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None
    startswith: bool = False
    endswith: bool = False


# content 序列拼接
def _pad_to(s: str, n: int, fill: str = "A") -> str:
    if len(s) >= n:
        return s
    return s + (fill * (n - len(s)))

def build_stream_from_contents(contents: list[ContentMatch], fill: str = "A") -> str:
    s = ""
    cursor = 0
    prev_end = 0

    for i, c in enumerate(contents):
        if c.negated:
            # 生成器无法保证“全局不包含”，通常做法是跳过或记录为“无法保证”
            continue

        token = c.decoded if not c.nocase else c.decoded.lower()

        # startswith
        if c.startswith:
            # 强制放开头
            if i != 0 and s:
                # 简化：若不是第一个，降级为普通拼接
                pass
            else:
                s = token + s[len(token):]
                cursor = len(token)
                prev_end = cursor
                continue

        # absolute offset
        if c.offset is not None:
            cursor = c.offset

        # relative distance
        if c.distance is not None:
            cursor = prev_end + c.distance

        # depth constraint: token must fit into [cursor, cursor+depth)
        if c.depth is not None:
            latest_start = cursor + max(0, c.depth - len(token))
            # 我们选择最早位置 cursor；若放不下就降级到 latest_start 或直接报错
            if cursor > latest_start:
                cursor = latest_start

        # ensure string length
        s = _pad_to(s, cursor, fill)

        # place token at cursor (overwrite)
        s = s[:cursor] + token + s[cursor + len(token):]
        prev_end = cursor + len(token)
        cursor = prev_end

    # endswith: 简化做法：如果某个 content 标记 endswith，放最后
    # 更严谨：应该把 endswith 的项从序列抽出单独处理
    ends = [c for c in contents if c.endswith and (not c.negated)]
    if ends:
        tail = ends[-1].decoded
        # 强制尾部
        if not s.endswith(tail):
            s += tail

    return s

# pcre 生成
def sanitize_pcre(pcre: str, sid: str) -> str:
    """
    Replaces unsupported classes/constructs for exrex and reduces "wild" patterns.
    """
    s = pcre

    # Replace \s with a single space
    while "\\s" in s:
        s = s.replace("\\s", " ")
        if VERBOSE:
            print(f"INFO: replaced \\s with single whitespace before generation. sid:{sid}")

    # Lazy quantifiers
    while "+?" in s:
        s = s.replace("+?", "+")
        if VERBOSE:
            print(f"INFO: replaced +? with + in pcre before generation. sid:{sid}")
    while "*?" in s:
        s = s.replace("*?", "*")
        if VERBOSE:
            print(f"INFO: replaced *? with * in pcre before generation. sid:{sid}")

    # The original C++ had a likely typo: ".+" -> "[a-z]}" (note the brace).
    # We'll use "[a-z]" as intended.
    while ".+" in s:
        s = s.replace(".+", "[a-z]")
        if VERBOSE:
            print(f"INFO: replaced .+ with [a-z] in pcre before generation. sid:{sid}")
    while ".*" in s:
        s = s.replace(".*", "[a-z]")
        if VERBOSE:
            print(f"INFO: replaced .* with [a-z] in pcre before generation. sid:{sid}")
    while ".?" in s:
        s = s.replace(".?", "[a-z]")
        if VERBOSE:
            print(f"INFO: replaced .? with [a-z] in pcre before generation. sid:{sid}")

    # Negative character classes that exrex struggles with
    for needle, repl in [
        ("[^&]", "[a-z]"),
        ("[^\\\\]", "[a-z]"),
        ("[^\\\\n]", "[a-z]"),
        ("[^\\\\r\\\\n]", "[a-z]"),
        ("[^\\\\x2f]", "[a-z]"),
    ]:
        while needle in s:
            s = s.replace(needle, repl)
            if VERBOSE:
                print(f"INFO: replaced {needle} with {repl} in pcre before generation. sid:{sid}")

    return s

def fallback_string_from_regex(pat: str, max_len: int = 512) -> str:
    """
    Best-effort fallback when exrex isn't available (Python 3.12 environments often
    lack a compatible exrex build).

    This does NOT fully expand PCRE. It tries to produce a short candidate string
    that satisfies common IDS regexes (anchors, literals, simple classes, simple
    quantifiers). If it can't, it falls back to the longest literal substring.
    """
    # Strip common anchors
    pat = pat.strip()
    pat = pat.lstrip("^")
    pat = pat.rstrip("$")

    # Quick path: if regex is just literals/escapes, unescape them.
    def _unescape(s: str) -> str:
        # Replace hex escapes like \x41
        def repl_hex(m: re.Match[str]) -> str:
            try:
                ch = bytes([int(m.group(1), 16)]).decode("latin-1")
                return ch if ch.isprintable() else "A"
            except Exception:
                return "A"
        s = re.sub(r"\\x([0-9A-Fa-f]{2})", repl_hex, s)
        s = s.replace(r"\r", "\r").replace(r"\n", "\n").replace(r"\t", "\t")
        s = s.replace(r"\0", "\0")
        s = s.replace(r"\/", "/")
        s = s.replace(r"\.", ".")
        s = s.replace(r"\-", "-")
        s = s.replace(r"\_", "_")
        # Common escapes that mean "literal X"
        s = re.sub(r"\\([\\\[\]{}()*+?.^$|])", r"\1", s)
        return s

    # Extract a long literal substring as a safety net
    # (drop obvious metacharacters)
    literal_chunks = re.findall(r"(?:\\.|[^\\\[\]{}()*+?.^$|])+",
                                pat)
    longest_literal = _unescape(max(literal_chunks, key=len)) if literal_chunks else ""

    out: list[str] = []
    i = 0

    def _emit(ch: str, n: int = 1) -> None:
        if n <= 0:
            return
        out.append(ch * min(n, 16))  # cap repeats

    while i < len(pat) and sum(len(x) for x in out) < max_len:
        c = pat[i]

        # Escaped char
        if c == "\\" and i + 1 < len(pat):
            nxt = pat[i + 1]
            # \xHH
            if nxt == "x" and i + 3 < len(pat):
                hx = pat[i + 2:i + 4]
                try:
                    ch = bytes([int(hx, 16)]).decode("latin-1")
                    _emit(ch if ch.isprintable() else "A")
                except Exception:
                    _emit("A")
                i += 4
                continue
            # Common classes
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
            # Literal escape
            _emit(nxt)
            i += 2
            continue

        # Character class [...]
        if c == "[":
            end = pat.find("]", i + 1)
            if end == -1:
                i += 1
                continue
            cls = pat[i + 1:end]
            # choose a representative
            ch = "A"
            if "0-9" in cls or "\d" in cls:
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

        # Grouping / alternation: pick first branch very crudely
        if c in ("(", ")", "|"):
            i += 1
            continue

        # Dot: any char
        if c == ".":
            _emit("A")
            i += 1
            continue

        # Quantifiers apply to previous emitted char; we handle {m,n} and +/?/*
        if c in ("*", "+", "?") or c == "{":
            # apply to last emitted token if possible
            if not out:
                i += 1
                continue
            last = out.pop()
            base = last[-1] if last else "A"

            if c == "*":
                # 0 or more: choose 1 to be safe
                _emit(base, 1)
                i += 1
                continue
            if c == "+":
                _emit(base, 1)
                i += 1
                continue
            if c == "?":
                _emit(base, 1)
                i += 1
                continue
            # {m,n}
            m = re.match(r"\{(\d+)(?:,(\d+))?\}", pat[i:])
            if m:
                mn = int(m.group(1))
                _emit(base, mn)
                i += len(m.group(0))
                continue
            i += 1
            continue

        # Regular literal
        _emit(c)
        i += 1

    candidate = "".join(out)
    candidate = _unescape(candidate)

    # If candidate is too empty or still looks non-literal, prefer the longest literal
    if len(candidate) < 3 and longest_literal:
        return longest_literal[:max_len]
    return candidate[:max_len] if candidate else (longest_literal[:max_len] if longest_literal else "A")

_PC_RE = re.compile(
    r'^\s*"?\s*/(?P<body>(?:\\/|[^/])*)/(?P<flags>[A-Za-z]*)\s*"?\s*$'
)

def parse_pcre_raw(pcre_raw: str) -> Tuple[str, str]:
    """
    returns (body, flags)
    e.g. ' "/php\\?r=\\d+&p=/U"' -> ('php\\?r=\\d+&p=', 'U')
    """
    s = (pcre_raw or "").strip()
    m = _PC_RE.match(s)
    if not m:
        return s.strip('"').strip(), ""
    return m.group("body"), (m.group("flags") or "")

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

def generate_string_from_pcre(pcre_string: str) -> str:
    """
    Generate a concrete string from a regex.
    C++ used: `exrex -r "<regex>"` via popen().

    In the Python we try:
    1) import exrex and use exrex.getone()
    2) call `exrex -r "<regex>"` if CLI exists

    The input should be the raw regex (NOT wrapped in /.../ and not quoted).
    """
    # Try python module first
    try:
        import exrex  # type: ignore
        return exrex.getone(pcre_string) or ""
    except Exception:
        pass

    # Try CLI
    cmd = ["exrex", "-r", pcre_string]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return fallback_string_from_regex(pcre_string)
        # exrex prints one sample per line; take first line
        out = (proc.stdout or "").splitlines()
        return out[0] if out else ""
    except FileNotFoundError:
        # No exrex available: fallback heuristic.
        return fallback_string_from_regex(pcre_string)

def remove_crlf_escapes(s: str, sid: str) -> str:
    """
    Remove leading and trailing escaped CR/LF sequences (\\r, \\n) like C++ removeCRLF().
    """
    if not s:
        sys.stderr.write(
            f"Error, can not sanitize empty Header for rulesid:{sid}. "
            "Likely, this rule produced an empty pcre string, check pcre.\n"
        )
        if not CONTINUE_ON_ERROR:
            raise SystemExit(1)
        return s

    # Remove trailing escaped newlines: ...\\r or ...\\n at end
    while len(s) >= 2 and s[-2] == "\\" and s[-1] in ("r", "n"):
        s = s[:-2]

    # Remove leading escaped CR/LF sequences
    while len(s) >= 2 and s[0] == "\\" and s[1] in ("r", "n"):
        s = s[2:]

    if s == "":
        sys.stderr.write(f"WARNING: Empty String after removing initial and trailing newlines. sid: {sid}\n")
    return s


def sanitize_header(header: str, sid: str) -> str:
    """
    Mirrors C++ sanitizeHeader():
    - remove excess escaped CR/LF
    - ensure it looks like Name: Value
    """
    if not header:
        sys.stderr.write(
            f"Error, can not sanitize empty Header for rulesid:{sid}. "
            "Likely, this rule produced an empty pcre string, check pcre.\n"
        )
        if not CONTINUE_ON_ERROR:
            raise SystemExit(1)
        return header

    header = remove_crlf_escapes(header, sid)

    if header.endswith(":"):
        header += " DummyValue"
        if VERBOSE:
            print(f"INFO: added dummy value to incomplete name:value header. sid:{sid}")
    elif header.endswith(" :") or (len(header) >= 2 and header[-2] == ":" and header[-1] == " "):
        header += "DummyValue"
        if VERBOSE:
            print(f"INFO: added dummy value to incomplete name:value header. sid:{sid}")
    elif ":" not in header:
        header = "DummyHeader: " + header
        if VERBOSE:
            print(f"INFO: added dummy header name. sid:{sid}")

    if header == "":
        sys.stderr.write(f"WARNING: Empty header after sanitization. sid: {sid}\n")
    return header


