from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Literal, Optional

from core.models import ContentMatch, IsDataAtMatch
from core.models import PcreMatch  # type: ignore

from traffic_generation.rule_parse import (
    apply_bsize_constraints,
    generate_string_from_pcre,
    parse_pcre_raw,
    sanitize_pcre,
)


@dataclass
class ConcreteMatch:
    kind: Literal["content", "pcre"]
    pattern: str
    value: bytes = b""
    generator: Optional[Callable[[], bytes]] = None
    negated: bool = False
    nocase: bool = False
    startswith: bool = False
    endswith: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None


def parse_content_string(s: str) -> bytes:
    """Parse Suricata content string to bytes.

    Supports mixed ASCII and |hh hh| hex blocks plus a minimal escape set.
    """
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "|":
            end = s.find("|", i + 1)
            if end == -1:
                raise ValueError(f"unterminated hex block in content: {s!r}")
            block = s[i + 1 : end].strip()
            if block:
                for tok in block.split():
                    if len(tok) != 2 or any(c not in "0123456789abcdefABCDEF" for c in tok):
                        raise ValueError(f"invalid hex byte {tok!r} in content: {s!r}")
                    out.append(int(tok, 16))
            i = end + 1
            continue

        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            esc = {
                "r": b"\r",
                "n": b"\n",
                "t": b"\t",
                "0": b"\x00",
                "\\": b"\\",
                '"': b'"',
                ":": b":",
                ";": b";",
            }
            if nxt in esc:
                out.extend(esc[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < len(s):
                hx = s[i + 2 : i + 4]
                if all(c in "0123456789abcdefABCDEF" for c in hx):
                    out.append(int(hx, 16))
                    i += 4
                    continue
            out.append(ord(nxt) & 0xFF)
            i += 2
            continue

        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


def _pad_to(s: bytearray, n: int, fill: bytes = b"A") -> None:
    if len(s) < n:
        s.extend(fill * (n - len(s)))


def _concrete_from_clause(c: object, sid: str) -> Optional[ConcreteMatch]:
    if isinstance(c, ContentMatch):
        raw = getattr(c, "raw", "") or getattr(c, "decoded", "")
        try:
            val = parse_content_string(raw)
        except Exception:
            val = (getattr(c, "decoded", "") or raw).encode("latin-1", errors="replace")
        return ConcreteMatch(
            kind="content",
            pattern=raw,
            value=val,
            negated=bool(getattr(c, "negated", False)),
            nocase=bool(getattr(c, "nocase", False)),
            startswith=bool(getattr(c, "startswith", False)),
            endswith=bool(getattr(c, "endswith", False)),
            offset=getattr(c, "offset", None),
            depth=getattr(c, "depth", None),
            distance=getattr(c, "distance", None),
            within=getattr(c, "within", None),
        )
    if PcreMatch is not None and isinstance(c, PcreMatch):
        body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
        sanitized = sanitize_pcre(body_rx, sid)

        def _gen() -> bytes:
            return generate_string_from_pcre(sanitized).encode("latin-1", errors="replace")

        return ConcreteMatch(
            kind="pcre",
            pattern=getattr(c, "raw", ""),
            generator=_gen,
            negated=bool(getattr(c, "negated", False)),
            nocase=bool(getattr(c, "nocase", False)),
        )
    return None


def build_stream_from_contents(contents: List[ConcreteMatch], fill: bytes = b"A") -> tuple[bytes, int]:
    s = bytearray()
    prev_end = 0
    for c in contents:
        if c.negated or c.kind != "content":
            continue
        token = c.value
        if token == b"":
            continue

        if c.startswith and len(s) == 0:
            s = bytearray(token)
            prev_end = len(token)
            continue

        cursor = prev_end
        off = c.offset
        if off is not None:
            cursor = max(0, int(off))

        dist = c.distance
        if dist is not None:
            cursor = prev_end + int(dist)

        within = c.within
        if within is not None:
            latest_start = max(0, prev_end + int(within) - len(token))
            if cursor > latest_start:
                cursor = latest_start

        depth = c.depth
        if depth is not None:
            base = int(off) if off is not None else cursor
            latest_start = max(0, base + int(depth) - len(token))
            if cursor > latest_start:
                cursor = latest_start

        _pad_to(s, cursor, fill)
        _pad_to(s, cursor + len(token), fill)
        s[cursor : cursor + len(token)] = token
        prev_end = cursor + len(token)

    ends = [c for c in contents if c.kind == "content" and c.endswith and not c.negated]
    if ends:
        tail = ends[-1].value
        if tail and not bytes(s).endswith(tail):
            s.extend(tail)
            prev_end = len(s)

    return bytes(s), prev_end


def _strip_negated_contents(text: bytes, clauses: List[ConcreteMatch]) -> bytes:
    out = text
    for c in clauses:
        if c.kind == "content" and c.negated:
            token = c.value
            if token:
                out = out.replace(token, b"")
    return out


def synthesize_bucket_bytes(
    clauses: List[object], sid: str, *, fill: bytes = b"A", strip_crlf: bool = False
) -> bytes:
    concrete = [_concrete_from_clause(c, sid) for c in clauses]
    terms = [c for c in concrete if c is not None]

    s, prev_end = build_stream_from_contents(terms, fill=fill) if terms else (b"", 0)

    for c in terms:
        if c.kind == "pcre" and not c.negated and c.generator is not None:
            sample = c.generator()
            s += sample or b""
            prev_end = len(s)

    for c in clauses:
        if isinstance(c, IsDataAtMatch):
            need = int(c.offset)

            if c.relative:
                remain = len(s) - prev_end
                if c.negated:
                    if remain >= need:
                        s = s[: prev_end + max(0, need - 1)]
                else:
                    if remain < need:
                        tmp = bytearray(s)
                        _pad_to(tmp, prev_end + need, fill)
                        s = bytes(tmp)
            else:
                total = len(s)
                if c.negated:
                    if total >= need:
                        s = s[: max(0, need - 1)]
                else:
                    if total < need:
                        tmp = bytearray(s)
                        _pad_to(tmp, need, fill)
                        s = bytes(tmp)

    s = apply_bsize_constraints(s.decode("latin-1", errors="replace"), clauses, fill=fill.decode("latin-1", errors="replace")).encode("latin-1", errors="replace")
    s = _strip_negated_contents(s, terms)

    if strip_crlf:
        s = s.replace(b"\r", b"").replace(b"\n", b"")
    return s


def synthesize_bucket_text(
    clauses: List[object], sid: str, *, fill: str = "A", strip_crlf: bool = False
) -> str:
    raw = synthesize_bucket_bytes(
        clauses,
        sid,
        fill=fill.encode("latin-1", errors="replace") or b"A",
        strip_crlf=strip_crlf,
    )
    return raw.decode("latin-1", errors="replace")
