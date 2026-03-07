from __future__ import annotations

from typing import List

from core.models import ContentMatch, IsDataAtMatch
from core.models import PcreMatch  # type: ignore

from traffic_generation.rule_parse import (
    apply_bsize_constraints,
    generate_string_from_pcre,
    parse_pcre_raw,
    sanitize_pcre,
)


def _pad_to(s: str, n: int, fill: str = "A") -> str:
    if len(s) >= n:
        return s
    return s + (fill * (n - len(s)))


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
        s = s[:cursor] + token + s[cursor + len(token) :]
        prev_end = cursor + len(token)

    ends = [c for c in contents if getattr(c, "endswith", False) and not getattr(c, "negated", False)]
    if ends:
        tail = getattr(ends[-1], "decoded", "") or getattr(ends[-1], "raw", "")
        if tail and not s.endswith(tail):
            s += tail
            prev_end = len(s)

    return s, prev_end


def _strip_negated_contents(text: str, clauses: List[object]) -> str:
    out = text
    for c in clauses:
        if isinstance(c, ContentMatch) and getattr(c, "negated", False):
            token = getattr(c, "decoded", "") or getattr(c, "raw", "")
            if token:
                out = out.replace(token, "")
    return out


def synthesize_bucket_text(
    clauses: List[object], sid: str, *, fill: str = "A", strip_crlf: bool = False
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
                        s = s[: prev_end + max(0, need - 1)]
                else:
                    if remain < need:
                        s = _pad_to(s, prev_end + need, fill)
            else:
                total = len(s)
                if c.negated:
                    if total >= need:
                        s = s[: max(0, need - 1)]
                else:
                    if total < need:
                        s = _pad_to(s, need, fill)

    s = apply_bsize_constraints(s, clauses, fill=fill)
    s = _strip_negated_contents(s, clauses)

    if strip_crlf:
        s = s.replace("\r", "").replace("\n", "")
    return s
