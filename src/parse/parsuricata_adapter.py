from __future__ import annotations
import re
from typing import Any, Optional
from core.models import (
    DSizeMatch,
    IsDataAtMatch,
    SuricataRule,
    RuleHeader,
    RuleBody,
    ContentMatch,
    PcreMatch,
    BufferSwitch,
    FlowTerm, BSizeMatch,
)

HEX_RE = re.compile(r"\|([0-9A-Fa-f ]+)\|")

def decode_hex_blocks(s: str) -> str:
    def repl(m: re.Match) -> str:
        b = bytes(int(x, 16) for x in m.group(1).split())
        return b.decode("latin-1", errors="replace")
    return HEX_RE.sub(repl, s)

def _is_negated_setting(obj: Any) -> bool:
    try:
        return bool(getattr(obj, "is_negated", False))
    except Exception:
        return False

def _settings_text(obj: Any) -> str:
    return "" if obj is None else str(obj)

_DSIZE_RE = re.compile(r"^\s*(?P<op>>=|<=|<>|>|<|=)?\s*(?P<a>\d+)\s*(?:<>\s*(?P<b>\d+)\s*)?$")

def parse_flow(setting_obj: Any) -> FlowTerm:
    text = _settings_text(setting_obj)
    parts = [p.strip().lower() for p in text.split(",") if p.strip()]
    return FlowTerm(
        to_server=("to_server" in parts),
        to_client=("to_client" in parts),
        established=("established" in parts),
    )

def parse_dsize(text: str) -> DSizeMatch:
    t = text.strip()
    m = _DSIZE_RE.match(t)
    if not m:
        raise ValueError(f"invalid dsize: {text!r}")
    op = m.group("op") or "="
    a = int(m.group("a"))
    b = m.group("b")
    if op == "<>":
        return DSizeMatch(op="<>", a=a, b=int(b) if b is not None else None)
    return DSizeMatch(op=op, a=a)

def parse_isdataat(setting_obj: Any) -> IsDataAtMatch:
    neg = _is_negated_setting(setting_obj)
    text = _settings_text(setting_obj).strip()
    if text.startswith("!"):
        neg = True
        text = text[1:].strip()
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        raise ValueError(f"invalid isdataat: {text!r}")
    offset = int(parts[0])
    relative = any(p.lower() == "relative" for p in parts[1:])
    rawbytes = any(p.lower() == "rawbytes" for p in parts[1:])
    return IsDataAtMatch(offset=offset, relative=relative, rawbytes=rawbytes, negated=neg)

def parse_bsize(text: str) -> BSizeMatch:
    t = text.strip()
    m = _DSIZE_RE.match(t)
    if not m:
        raise ValueError(f"invalid bsize: {text!r}")
    op = m.group("op") or "="
    a = int(m.group("a"))
    b = m.group("b")
    if op == "<>":
        return BSizeMatch(op="<>", a=a, b=int(b) if b is not None else None)
    return BSizeMatch(op=op, a=a)

# 请求侧常见 HTTP sticky buffers / aliases
STICKY_BUFFER_KEYWORDS = {
    # 常规写法
    "http.method": "http.method",
    "http.uri": "http.uri",
    "http.uri.raw": "http.uri.raw",
    "http.request_line": "http.request_line",
    "http.start": "http.start",
    "http.protocol": "http.protocol",

    "http.header": "http.header",
    "http.header.raw": "http.header.raw",
    "http.header_names": "http.header_names",
    "http.host": "http.host",
    "http.host.raw": "http.host.raw",
    "http.user_agent": "http.user_agent",
    "http.referer": "http.referer",
    "http.referer.raw": "http.referer.raw",
    "http.accept": "http.accept",
    "http.accept_lang": "http.accept_lang",
    "http.accept_enc": "http.accept_enc",
    "http.connection": "http.connection",
    "http.content_type": "http.content_type",
    "http.content_len": "http.content_len",
    "http.cookie": "http.cookie",
    "http.cookie.raw": "http.cookie.raw",
    "http.request_body": "http.request_body",
    "http.response_body": "http.response_body",
    "http.stat_code": "http.stat_code",
    "http.stat_msg": "http.stat_msg",
    "http.response_line": "http.response_line",
    "file.data": "file.data",

    # 常见别名 / 下划线风格
    "http_method": "http.method",
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_request_line": "http.request_line",
    "http_start": "http.start",
    "http_protocol": "http.protocol",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent",
    "http_referer": "http.referer",
    "http_raw_referer": "http.referer.raw",
    "http_accept": "http.accept",
    "http_accept_lang": "http.accept_lang",
    "http_accept_enc": "http.accept_enc",
    "http_connection": "http.connection",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_cookie": "http.cookie",
    "http_raw_cookie": "http.cookie.raw",
    "http_client_body": "http.request_body",
    "http_request_body": "http.request_body",
    "http_response_body": "http.response_body",
}

_INT_KEYS = {"offset", "depth", "distance", "within"}
_LEGACY_BUFFER_MODIFIERS = {
    "http_method": "http.method",
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_request_line": "http.request_line",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent",
    "http_referer": "http.referer",
    "http_raw_referer": "http.referer.raw",
    "http_accept": "http.accept",
    "http_accept_lang": "http.accept_lang",
    "http_accept_enc": "http.accept_enc",
    "http_connection": "http.connection",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_cookie": "http.cookie",
    "http_raw_cookie": "http.cookie.raw",
    "http_client_body": "http.request_body",
    "http_request_body": "http.request_body",
    "http_response_body": "http.response_body",
    "file_data": "file.data",
}

def rule_to_suricata_rule(r: Any) -> SuricataRule:
    header = RuleHeader(
        action=str(getattr(r, "action", "") or ""),
        protocol=str(getattr(r, "protocol", "") or ""),
        src=str(getattr(r, "src", "") or ""),
        src_port=str(getattr(r, "src_port", "") or ""),
        direction=str(getattr(r, "direction", "") or "->"),
        dst=str(getattr(r, "dst", "") or ""),
        dst_port=str(getattr(r, "dst_port", "") or ""),
    )
    body = RuleBody()

    last_content: Optional[ContentMatch] = None
    last_pcre: Optional[PcreMatch] = None
    last_mod_target: Optional[str] = None
    last_buffer_switch: Optional[BufferSwitch] = None

    for opt in (getattr(r, "options", []) or []):
        k = str(getattr(opt, "keyword", "") or "")
        s_obj = getattr(opt, "settings", None)

        if k == "msg" and s_obj is not None:
            body.msg = _settings_text(s_obj)
            continue
        if k == "sid" and s_obj is not None:
            body.sid = _settings_text(s_obj)
            continue
        if k == "rev" and s_obj is not None:
            body.rev = _settings_text(s_obj)
            continue

        if k in STICKY_BUFFER_KEYWORDS and s_obj is None:
            bs = BufferSwitch(buffer=STICKY_BUFFER_KEYWORDS[k])
            body.clauses.append(bs)
            last_buffer_switch = bs
            continue

        # transform 绑定到最近的 buffer switch
        if k == "header_lowercase":
            if last_buffer_switch is not None and "header_lowercase" not in last_buffer_switch.transforms:
                last_buffer_switch.transforms.append("header_lowercase")
            continue

        if k == "to_lowercase":
            if last_buffer_switch is not None and "to_lowercase" not in last_buffer_switch.transforms:
                last_buffer_switch.transforms.append("to_lowercase")
            continue

        if k == "content" and s_obj is not None:
            raw_text = _settings_text(s_obj).strip()
            neg = _is_negated_setting(s_obj)
            if raw_text.startswith("!"):
                neg = True
                raw_text = raw_text[1:].lstrip()
            if len(raw_text) >= 2 and raw_text[0] == '"' and raw_text[-1] == '"':
                raw_text = raw_text[1:-1]

            cm = ContentMatch(raw=raw_text, decoded=decode_hex_blocks(raw_text), negated=neg)
            body.clauses.append(cm)
            last_content = cm
            last_mod_target = "content"
            continue

        if k == "pcre" and s_obj is not None:
            pm = PcreMatch(raw=_settings_text(s_obj), negated=_is_negated_setting(s_obj), buffer=None)
            body.clauses.append(pm)
            last_pcre = pm
            last_mod_target = "pcre"
            continue

        if k == "isdataat" and s_obj is not None:
            body.clauses.append(parse_isdataat(s_obj))
            continue
        if k == "dsize" and s_obj is not None:
            body.clauses.append(parse_dsize(_settings_text(s_obj)))
            continue
        if k == "bsize" and s_obj is not None:
            body.clauses.append(parse_bsize(_settings_text(s_obj)))
            continue
        if k == "flow" and s_obj is not None:
            body.flow = parse_flow(s_obj)
            continue

        if k == "nocase":
            if last_mod_target == "content" and last_content is not None:
                last_content.nocase = True
            elif last_mod_target == "pcre" and last_pcre is not None:
                last_pcre.nocase = True
            continue
        if k == "fast_pattern":
            if last_content is not None:
                last_content.fast_pattern = True
            continue
        if k == "startswith":
            if last_content is not None:
                last_content.startswith = True
            continue
        if k == "endswith":
            if last_content is not None:
                last_content.endswith = True
            continue

        if k in _LEGACY_BUFFER_MODIFIERS:
            mapped = _LEGACY_BUFFER_MODIFIERS[k]
            if last_mod_target == "content" and last_content is not None:
                last_content.buffer = mapped
            elif last_mod_target == "pcre" and last_pcre is not None:
                last_pcre.buffer = mapped
            continue

        if k in _INT_KEYS and s_obj is not None and last_content is not None:
            try:
                v = int(_settings_text(s_obj))
            except Exception:
                continue
            if k == "offset":
                last_content.offset = v
            elif k == "depth":
                last_content.depth = v
            elif k == "distance":
                last_content.distance = v
            elif k == "within":
                last_content.within = v
            continue

    return SuricataRule(header=header, body=body)