from collections import defaultdict
from typing import DefaultDict, List, Dict, Any

from core.models import Clause, BufferSwitch, ContentMatch, PcreMatch, IsDataAtMatch, DSizeMatch, BSizeMatch

# 请求生成阶段允许的 buffer 映射（固定白名单）
TARGET_BUCKET_BY_BUFFER = {
    "http.method": "method",
    "http.uri": "uri",
    "http.uri.raw": "uri",
    "http.request_line": "request_line",
    "http.header": "header",
    "http.header_names": "header_names",
    "http.cookie": "cookie",
    "http.user_agent": "user_agent",
    "http.host": "host",
    "http.request_body": "body",
}


def _looks_like_header_clause(clause: Clause) -> bool:
    token = ""
    if isinstance(clause, ContentMatch):
        token = (getattr(clause, "decoded", "") or getattr(clause, "raw", "") or "").strip()
    elif isinstance(clause, PcreMatch):
        token = getattr(clause, "raw", "") or ""

    if not token:
        return False

    low = token.lower()
    return (
        ":" in token
        or "host" in low
        or "user-agent" in low
        or "cookie" in low
        or "header" in low
    )


def _looks_like_body_clause(clause: Clause) -> bool:
    token = ""
    if isinstance(clause, ContentMatch):
        token = (getattr(clause, "decoded", "") or getattr(clause, "raw", "") or "").strip()
    elif isinstance(clause, PcreMatch):
        token = getattr(clause, "raw", "") or ""

    if not token:
        return False

    low = token.lower()
    return (
        "=" in token
        or "&" in token
        or "request_body" in low
        or "content-disposition" in low
        or "multipart" in low
    )


def split_clauses_for_http_generation(clauses: List[Clause]) -> Dict[str, Any]:
    per_buf: DefaultDict[str, List[Clause]] = defaultdict(list)
    transforms_by_buf: Dict[str, List[str]] = {}
    cur_buf: str = "pkt"

    for c in clauses:
        if isinstance(c, BufferSwitch):
            cur_buf = c.buffer
            transforms_by_buf[cur_buf] = list(getattr(c, "transforms", []) or [])
            continue
        per_buf[cur_buf].append(c)

    buckets: Dict[str, Any] = {
        "method": [],
        "uri": [],
        "request_line": [],
        "protocol": [],
        "header": [],
        "header_names": [],
        "host": [],
        "user_agent": [],
        "referer": [],
        "accept": [],
        "accept_language": [],
        "accept_encoding": [],
        "connection": [],
        "content_type": [],
        "content_length": [],
        "cookie": [],
        "body": [],
        "response_body": [],
        "status_code": [],
        "status_msg": [],
        "response_line": [],
        "file": [],
        "other": [],
        "_mapping_suspect": False,
        "_buffer_transforms": transforms_by_buf,
    }

    for buf, lst in per_buf.items():
        for clause in lst:
            clause_buf = getattr(clause, "buffer", None) if isinstance(clause, (ContentMatch, PcreMatch)) else None
            effective_buf = clause_buf or buf
            target = TARGET_BUCKET_BY_BUFFER.get(effective_buf)
            if target is not None:
                buckets[target].append(clause)
                continue

            if effective_buf == "pkt_data":
                if _looks_like_header_clause(clause):
                    buckets["header"].append(clause)
                elif _looks_like_body_clause(clause):
                    buckets["body"].append(clause)
                else:
                    buckets["_mapping_suspect"] = True
                continue

            buckets["other"].append(clause)

    return buckets


def clauses_to_terms(clauses: List[Clause]) -> List[dict]:
    out: List[dict] = []
    for c in clauses:
        if isinstance(c, ContentMatch):
            out.append({
                "type": "content",
                "decoded": c.decoded,
                "raw": c.raw,
                "negated": c.negated,
                "nocase": c.nocase,
                "fast_pattern": c.fast_pattern,
                "startswith": c.startswith,
                "endswith": c.endswith,
                "offset": c.offset,
                "depth": c.depth,
                "distance": c.distance,
                "within": c.within,
            })
        elif isinstance(c, PcreMatch):
            out.append({
                "type": "pcre",
                "raw": c.raw,
                "negated": c.negated,
                "nocase": c.nocase,
            })
        elif isinstance(c, IsDataAtMatch):
            out.append({"type": "isdataat", **c.model_dump()})
        elif isinstance(c, DSizeMatch):
            out.append({"type": "dsize", **c.model_dump()})
        elif isinstance(c, BSizeMatch):
            out.append({"type": "bsize", **c.model_dump()})
        else:
            out.append({"type": "unknown", "raw": str(c)})
    return out
