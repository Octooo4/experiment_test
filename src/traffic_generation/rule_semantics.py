from __future__ import annotations

import re
from typing import Dict, List, Literal, Optional, Tuple

from core.models import BufferSwitch, ContentMatch
from core.models import PcreMatch  # type: ignore

from traffic_generation.rule_parse import (
    has_header,
    parse_pcre_raw,
    sanitize_header_value,
    set_header_case_insensitive,
)


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


def classify_http_rule_strategy(clauses: List[object]) -> Literal["sticky", "recoverable_raw", "raw_text"]:
    if has_explicit_buffer_switch(clauses):
        return "sticky"

    contents = [c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)]
    pcres = [
        c
        for c in clauses
        if PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False)
    ]

    decoded_tokens = [(getattr(c, "decoded", "") or getattr(c, "raw", "")).strip() for c in contents]
    decoded_tokens = [t for t in decoded_tokens if t]

    for t in decoded_tokens:
        low = t.lower()
        if (
            low.startswith("host:")
            or low.startswith("user-agent:")
            or low.startswith("referer:")
            or low.startswith("cookie:")
            or low.startswith("accept:")
            or low.startswith("connection:")
        ):
            return "recoverable_raw"
        if t.upper() in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}:
            return "recoverable_raw"

    if any(t.lower() in {"host:", "user-agent:", "referer:", "cookie:"} for t in decoded_tokens):
        return "recoverable_raw"

    for c in contents:
        if (
            getattr(c, "distance", None) is not None
            or getattr(c, "within", None) is not None
            or getattr(c, "offset", None) is not None
            or getattr(c, "depth", None) is not None
        ):
            return "raw_text"

    if pcres:
        return "raw_text"

    return "raw_text"


def extract_header_candidates_from_raw_clauses(
    clauses: List[object], sid: str
) -> Tuple[Dict[str, str], Optional[str], Optional[str]]:
    headers: Dict[str, str] = {}
    inferred_method: Optional[str] = None
    inferred_path: Optional[str] = None

    contents: List[ContentMatch] = [
        c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)
    ]

    raw_fragments: List[str] = []
    for c in contents:
        token = getattr(c, "decoded", "") or getattr(c, "raw", "")
        if token:
            raw_fragments.append(token)

    merged = "".join(raw_fragments)

    header_name_whitelist = {
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

        m = re.match(r"^\s*(?:\r\n)?([A-Za-z0-9\-]+)\s*:\s*([^\r\n]+)(?:\r\n)?\s*$", t, flags=re.IGNORECASE)
        if not m:
            continue

        name = m.group(1).strip()
        value = sanitize_header_value(m.group(2))
        if not name or not value:
            continue

        if name.lower() not in header_name_whitelist:
            continue

        set_header_case_insensitive(headers, name, value)

    http_methods = {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}
    for c in contents:
        token = ((getattr(c, "decoded", "") or getattr(c, "raw", "")).strip()).upper()
        if token in http_methods:
            inferred_method = token
            break

    saw_host_marker = False
    host_value_candidate: Optional[str] = None

    for c in contents:
        token = getattr(c, "decoded", "") or getattr(c, "raw", "")
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

        m = re.search(r"User-Agent\\:\s*0\\:0\\:\[\^\\x0a\|\\x0d\]\{(\d+)\}", body_rx, flags=re.IGNORECASE)
        if m:
            n = int(m.group(1))
            set_header_case_insensitive(headers, "User-Agent", "0:0:" + ("A" * n))
            continue

        m = re.search(r"User-Agent\\:\s*([^\\]+?)\{(\d+)\}", body_rx, flags=re.IGNORECASE)
        if m and not has_header(headers, "User-Agent"):
            prefix = m.group(1)
            n = int(m.group(2))
            prefix = prefix.replace(r"\:", ":").replace(r"\ ", " ")
            prefix = prefix.replace("User-Agent:", "").strip()
            set_header_case_insensitive(headers, "User-Agent", prefix + ("A" * n))
            continue

        if re.search(r"User-Agent\\:\s*0\\:0\\:", body_rx, flags=re.IGNORECASE):
            if not has_header(headers, "User-Agent"):
                set_header_case_insensitive(headers, "User-Agent", "0:0:" + ("A" * 128))
            continue

    return headers, inferred_method, inferred_path
