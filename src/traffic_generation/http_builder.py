from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from core.models import ContentMatch
from core.models import PcreMatch  # type: ignore
from traffic_generation.buffer_solver import synthesize_bucket_bytes, synthesize_bucket_text
from traffic_generation.rule_parse import (
    generate_string_from_pcre,
    has_header,
    header_lines_to_dict,
    parse_pcre_raw,
    sanitize_header_value,
    sanitize_pcre,
    set_header_case_insensitive,
)
from traffic_generation.rule_semantics import (
    _looks_like_host_fragment,
    _split_domain_and_path,
    classify_http_rule_strategy,
    extract_header_candidates_from_raw_clauses,
)

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




def _has_nonprintable_bytes(data: bytes) -> bool:
    return any((b < 0x20 or b > 0x7E) for b in data)


def _is_http_binary_unsafe(buckets: Dict[str, Any], sid: str) -> bool:
    check_fields = (
        ("http.uri", "uri"),
        ("http.header", "header"),
        ("http.request_line", "request_line"),
    )
    for _field, bucket in check_fields:
        payload = synthesize_bucket_bytes(buckets.get(bucket, []), sid, fill=b"A", strip_crlf=False)
        if payload and _has_nonprintable_bytes(payload):
            return True
    return False
class HttpRequestSpec(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""


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





def _drop_dedicated_headers_from_lines(header_lines: List[str]) -> List[str]:
    dedicated = {"host", "user-agent", "cookie"}
    out: List[str] = []
    for line in header_lines:
        name, _, _ = line.partition(":")
        if name.strip().lower() in dedicated:
            continue
        out.append(line)
    return out

def _normalize_uri_fragment(s: str) -> str:
    if not s:
        return ""

    s = s.strip().strip('"').strip("'")
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

    header_names_text = synthesize_bucket_text(buckets.get("header_names", []), sid, fill="A", strip_crlf=False)
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

    from traffic_generation.rule_parse import pcre_flags_to_bucket

    for src in ("other", "file"):
        lst = moved.get(src, [])
        if not isinstance(lst, list):
            continue

        keep: List[object] = []
        for clause in lst:
            if PcreMatch is not None and isinstance(clause, PcreMatch) and not getattr(clause, "negated", False):
                _, flags = parse_pcre_raw(getattr(clause, "raw", ""))
                dst = pcre_flags_to_bucket(flags)
                if dst == src:
                    # 防止向正在遍历的同一列表回写，导致列表膨胀和近似死循环。
                    keep.append(clause)
                elif dst in moved and isinstance(moved[dst], list):
                    moved[dst].append(clause)
                else:
                    keep.append(clause)
            else:
                keep.append(clause)
        moved[src] = keep
    return moved


def build_http_request_from_raw_clauses(
    clauses: List[object], sid: str = "", default_method: str = "GET"
) -> HttpRequestSpec:
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

        if (
            low.startswith("host:")
            or low.startswith("user-agent:")
            or low.startswith("cookie:")
            or low.startswith("referer:")
            or low.startswith("accept:")
            or low.startswith("connection:")
            or low.startswith("x-raw:")
        ):
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

            # 形如 ".info" 的后缀优先并到已有 Host，适配 host 前缀+后缀拆分规则
            if t.startswith("."):
                current_host = host_candidate
                if current_host is None:
                    for k, v in headers.items():
                        if k.lower() == "host":
                            current_host = (v or "").strip()
                            break
                if current_host:
                    merged_host = current_host.rstrip(".") + t
                    if host_candidate is not None:
                        host_candidate = merged_host
                    else:
                        set_header_case_insensitive(headers, "Host", merged_host)
                    continue
                t = "www" + t

            if not has_header(headers, "Host") and not host_candidate:
                host_candidate = t
            else:
                raw_header_fragments.append(tok)
            continue

        if (
            tok.startswith("/")
            or "?" in tok
            or "=" in tok
            or tok.endswith(".php")
            or tok.endswith(".asp")
            or tok.endswith(".cgi")
            or "/" in tok
        ):
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


def build_http_request_from_buckets(buckets: Dict[str, Any], sid: str = "", default_method: str = "GET") -> HttpRequestSpec:
    transforms_by_buf: Dict[str, List[str]] = buckets.get("_buffer_transforms", {})

    method = default_method
    request_line_text = synthesize_bucket_text(buckets.get("request_line", []), sid, fill="A", strip_crlf=True)
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
    header_lines = _drop_dedicated_headers_from_lines(header_lines)
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
        headers["Rulesid"] = str(sid).strip()

    return HttpRequestSpec(method=method, path=path, headers=headers, body=body_str)


def build_http_response_from_buckets(buckets: Dict[str, Any], sid: str = "") -> bytes:
    status_code = 200
    status_msg = "OK"

    status_code_text = synthesize_bucket_text(buckets.get("status_code", []), sid, fill="2", strip_crlf=True)
    m = re.search(r"\d{3}", status_code_text or "")
    if m:
        status_code = int(m.group(0))

    status_msg_text = synthesize_bucket_text(buckets.get("status_msg", []), sid, fill="A", strip_crlf=True)
    if status_msg_text:
        status_msg = status_msg_text

    header_lines: List[str] = []
    for c in buckets.get("header", []):
        if isinstance(c, ContentMatch) and not getattr(c, "negated", False):
            header_lines.append(getattr(c, "decoded", "") or getattr(c, "raw", ""))
        elif PcreMatch is not None and isinstance(c, PcreMatch) and not getattr(c, "negated", False):
            body_rx, _ = parse_pcre_raw(getattr(c, "raw", ""))
            header_lines.append(generate_string_from_pcre(sanitize_pcre(body_rx, sid)))
    headers = header_lines_to_dict(header_lines, sid=sid, lowercase_names=False)

    body_text = synthesize_bucket_text(buckets.get("response_body", []), sid, fill="d", strip_crlf=False)
    body_bytes = body_text.encode("latin-1", errors="replace")

    if body_bytes and not has_header(headers, "Content-Length"):
        set_header_case_insensitive(headers, "Content-Length", str(len(body_bytes)))
    if not has_header(headers, "Content-Type"):
        set_header_case_insensitive(headers, "Content-Type", "text/plain")

    lines = [f"HTTP/1.1 {status_code} {status_msg}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    head = "\r\n".join(lines).encode("latin-1", errors="replace") + b"\r\n"
    return head + body_bytes


def build_raw_http_text_request_from_clauses(
    clauses: List[object], sid: str = "", server: str = "http://127.0.0.1:80"
) -> bytes:
    host = urlparse(server).hostname if "://" in server else server.split(":", 1)[0]
    if not host:
        host = "127.0.0.1"

    contents = [c for c in clauses if isinstance(c, ContentMatch) and not getattr(c, "negated", False)]

    tokens: List[str] = []
    for c in contents:
        tok = getattr(c, "decoded", "") or getattr(c, "raw", "")
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

    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_value}"]

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
    add_accept_language: bool = False,
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


def build_request_for_rule(rule, server: str) -> Tuple[str, Optional[HttpRequestSpec], Optional[bytes]]:
    from parse.buckets_sorting import split_clauses_for_http_generation

    strategy = classify_http_rule_strategy(rule.body.clauses)

    if strategy == "recoverable_raw":
        req = build_http_request_from_raw_clauses(rule.body.clauses, sid=rule.body.sid)
        ensure_common_headers(server, req)
        return strategy, req, None

    if strategy == "raw_text":
        raw_bytes = build_raw_http_text_request_from_clauses(
            rule.body.clauses,
            sid=rule.body.sid,
            server=server,
        )
        return strategy, None, raw_bytes

    buckets = split_clauses_for_http_generation(rule.body.clauses)
    if buckets.get("_mapping_suspect"):
        return "BUFFER_MAPPING_SUSPECT", None, None

    buckets = rebucket_pcre_by_flags(buckets)
    if _is_http_binary_unsafe(buckets, rule.body.sid):
        return "SKIP_HTTP_BINARY_UNSAFE", None, None

    req = build_http_request_from_buckets(buckets, sid=rule.body.sid)
    ensure_common_headers(server, req)
    return strategy, req, None


def build_transaction_artifacts_for_rule(
    rule, server: str
) -> Tuple[str, Optional[HttpRequestSpec], Optional[bytes]]:
    strategy, req, raw_bytes = build_request_for_rule(rule, server)
    return strategy, req, raw_bytes
