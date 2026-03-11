from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional


AdapterKind = Literal["http", "tcp_raw", "udp_raw"]

HTTP_STICKY_PREFIX = "http."

# NOTE: This set marks features the current raw TCP/UDP generator cannot satisfy.
# It is intentionally conservative and is not full Suricata semantic coverage.
UNSUPPORTED_TRANSPORT_KEYWORDS = {
    "flowbits",
    "flowint",
    "flags",
    "fragbits",
    "fragoffset",
    "seq",
    "ack",
    "window",
    "ttl",
    "tos",
    "id",
    "sameip",
    "stream_size",
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
    unsupported_transport_features: list[str] = field(default_factory=list)


def has_http_sticky_buffers(rule: object) -> bool:
    clauses = getattr(getattr(rule, "body", None), "clauses", []) or []
    for c in clauses:
        buf = getattr(c, "buffer", None)
        if isinstance(buf, str) and buf.startswith(HTTP_STICKY_PREFIX):
            return True
        sticky = getattr(c, "buffer", None)
        if isinstance(sticky, str) and sticky.startswith(HTTP_STICKY_PREFIX):
            return True
    return False


def _normalize_keyword(raw: object) -> str:
    return str(raw or "").strip().lower()


def collect_unsupported_transport_features(rule: object) -> list[str]:
    raw_options = getattr(rule, "raw_options", []) or []
    seen: set[str] = set()
    features: list[str] = []

    for opt in raw_options:
        kw = _normalize_keyword(getattr(opt, "keyword", ""))
        if kw in UNSUPPORTED_TRANSPORT_KEYWORDS and kw not in seen:
            features.append(kw)
            seen.add(kw)

    flow = getattr(getattr(rule, "body", None), "flow", None)
    if flow is not None:
        if bool(getattr(flow, "to_client", False)) and "flow.to_client" not in seen:
            features.append("flow.to_client")
            seen.add("flow.to_client")

    return features


def extract_transport_keyword_warnings(rule: object, *, protocol: str) -> tuple[list[str], list[str]]:
    _ = protocol
    unsupported = collect_unsupported_transport_features(rule)
    warnings = [f"unsupported transport feature: {kw}" for kw in unsupported]
    return warnings, unsupported
