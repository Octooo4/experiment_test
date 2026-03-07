from collections import defaultdict
from typing import DefaultDict, List, Dict, Any

from core.models import Clause, BufferSwitch, ContentMatch, PcreMatch, IsDataAtMatch, DSizeMatch, BSizeMatch

# 请求侧常见 HTTP sticky buffers
TARGET_BUCKET_BY_BUFFER = {
    # request line / method / uri
    "http.method": "method",
    "http.uri": "uri",
    "http.uri.raw": "uri",
    "http.request_line": "request_line",
    "http.start": "request_line",
    "http.protocol": "protocol",

    # generic headers
    "http.header": "header",
    "http.header.raw": "header",
    "http.header_names": "header_names",

    # named headers
    "http.host": "host",
    "http.host.raw": "host",
    "http.user_agent": "user_agent",
    "http.referer": "referer",
    "http.referer.raw": "referer",
    "http.accept": "accept",
    "http.accept_lang": "accept_language",
    "http.accept_enc": "accept_encoding",
    "http.connection": "connection",
    "http.content_type": "content_type",
    "http.content_len": "content_length",

    # cookie / body
    "http.cookie": "cookie",
    "http.cookie.raw": "cookie",
    "http.request_body": "body",

    # response/file side，当前请求生成阶段只能尽量归类
    "http.response_body": "body",
    "file.data": "file",
}


def split_clauses_for_http_generation(clauses: List[Clause]) -> Dict[str, Any]:
    """
    按 sticky buffer 对 HTTP 请求生成进行分桶。
    关键点：
    1. 保留每个 buffer 内部原始顺序。
    2. 对具名请求头单独分桶，避免 http.user_agent 被错误落到 body。
    3. 未显式指定 buffer 的 pkt 仍保守放 body。
    4. 记录每个 buffer 上的 transforms，供 http_fixed.py 使用。
    """
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
        "file": [],
        "other": [],
        "_buffer_transforms": transforms_by_buf,
    }

    for buf, lst in per_buf.items():
        target = TARGET_BUCKET_BY_BUFFER.get(buf)
        if target is not None:
            buckets[target].extend(lst)
        elif buf == "pkt":
            buckets["other"].extend(lst)
        else:
            buckets["other"].extend(lst)

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