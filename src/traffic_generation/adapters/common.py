from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional


AdapterKind = Literal["http", "tcp_raw", "udp_raw"]

HTTP_STICKY_PREFIX = "http."

TCP_RULE_KEYWORDS = {
    "flags",
    "seq",
    "ack",
    "window",
    "flow",
    "flowbits",
    "flowint",
    "stream_size",
}

UDP_RULE_KEYWORDS = {
    "dsize",
    "bsize",
    "isdataat",
}


@dataclass
class SynthesisSegment:
    segment_name: str
    segment_bytes: bytes
    solver_backend: str
    unsat_reason: Optional[str] = None


@dataclass
class AdapterBuildResult:
    adapter: AdapterKind
    payload: bytes
    segments: list[SynthesisSegment] = field(default_factory=list)
    transport_warnings: list[str] = field(default_factory=list)


def has_http_sticky_buffers(rule: object) -> bool:
    clauses = getattr(getattr(rule, "body", None), "clauses", []) or []
    for c in clauses:
        buf = getattr(c, "buffer", None)
        if isinstance(buf, str) and buf.startswith(HTTP_STICKY_PREFIX):
            return True
    return False


def extract_transport_keyword_warnings(rule: object, *, protocol: str) -> list[str]:
    raw_options = getattr(rule, "raw_options", []) or []
    seen = set()
    warnings: list[str] = []
    keyword_set = TCP_RULE_KEYWORDS if protocol == "tcp" else UDP_RULE_KEYWORDS
    for opt in raw_options:
        kw = str(getattr(opt, "keyword", "") or "").strip().lower()
        if kw in keyword_set and kw not in seen:
            warnings.append(f"contains transport keyword: {kw}")
            seen.add(kw)
    return warnings
