from __future__ import annotations

from urllib.parse import urlparse

from traffic_generation.adapters.common import AdapterKind, has_dns_sticky_buffers, has_http_sticky_buffers
from traffic_generation.adapters.dns_adapter import build_dns_for_rule
from traffic_generation.adapters.http_adapter import build_http_for_rule
from traffic_generation.adapters.tcp_raw_adapter import build_payload_for_rule as build_tcp_payload_for_rule
from traffic_generation.adapters.udp_raw_adapter import build_payload_for_rule as build_udp_payload_for_rule
from traffic_generation.traffic_emit import send_raw_http_bytes, send_raw_tcp_bytes, send_raw_udp_bytes

_PORT_VAR_MAP = {
    "$HTTP_PORTS": 80,
    "$HTTPS_PORTS": 443,
    "$DNS_PORTS": 53,
    "$SMTP_PORTS": 25,
    "$SSH_PORTS": 22,
}


def choose_rule_adapter(rule: object) -> AdapterKind:
    protocol = str(getattr(getattr(rule, "header", None), "protocol", "") or "").lower()
    if protocol == "http" or has_http_sticky_buffers(rule):
        return "http"
    if protocol == "dns" or has_dns_sticky_buffers(rule):
        return "dns"
    if protocol == "udp":
        return "udp_raw"
    if protocol == "tcp":
        return "tcp_raw"
    return "unsupported"


def _selected_protocol(rule: object) -> str:
    return str(getattr(getattr(rule, "header", None), "protocol", "") or "").lower()


def _target_host_port(target_server: str, fallback_port: int) -> tuple[str, int]:
    if "://" in target_server:
        u = urlparse(target_server)
        host = u.hostname or "127.0.0.1"
        port = u.port or fallback_port
        return host, int(port)
    if ":" in target_server and target_server.count(":") == 1:
        h, p = target_server.split(":", 1)
        return h, int(p)
    return target_server, fallback_port


def _parse_port_token(token: str) -> int | None:
    t = (token or "").strip()
    if not t:
        return None
    if t.isdigit():
        p = int(t)
        return p if 0 < p <= 65535 else None
    up = t.upper()
    if up in _PORT_VAR_MAP:
        return _PORT_VAR_MAP[up]
    if ":" in t and t.count(":") == 1:
        left, right = [x.strip() for x in t.split(":", 1)]
        if left:
            return _parse_port_token(left)
        if right:
            return _parse_port_token(right)
    return None


def _rule_dst_port(rule: object) -> int | None:
    dst_port = str(getattr(getattr(rule, "header", None), "dst_port", "") or "").strip()
    if not dst_port or dst_port.lower() == "any":
        return None
    cleaned = dst_port.strip("[]")
    for token in cleaned.split(","):
        parsed = _parse_port_token(token)
        if parsed is not None:
            return parsed
    return None


def _resolve_rule_port(rule: object, fallback_port: int) -> dict[str, object]:
    raw = str(getattr(getattr(rule, "header", None), "dst_port", "") or "").strip()
    parsed = _rule_dst_port(rule)
    if parsed is not None:
        return {"rule_dst_port_raw": raw, "rule_dst_port": parsed, "used_fallback": False, "port_resolution_note": None}
    return {
        "rule_dst_port_raw": raw,
        "rule_dst_port": fallback_port,
        "used_fallback": True,
        "port_resolution_note": f"dst_port parse failed or non-concrete ({raw or 'empty'}), using fallback {fallback_port}",
    }


def build_rule_payload(rule: object, target_server: str) -> dict[str, object]:
    selected_protocol = _selected_protocol(rule)
    adapter = choose_rule_adapter(rule)

    if adapter == "unsupported":
        return {
            "adapter": "unsupported",
            "selected_protocol": selected_protocol,
            "payload": b"",
            "status": "SKIPPED",
            "skip_reason": "SKIP_UNSUPPORTED_APPLICATION_PROTOCOL",
            "warnings": [f"protocol {selected_protocol} unsupported"],
        }

    if adapter == "http":
        out = build_http_for_rule(rule, target_server)
        payload = out.raw_bytes or b""
        return {"adapter": adapter, "selected_protocol": selected_protocol, "payload": payload, "strategy": out.strategy}

    if adapter == "dns":
        out = build_dns_for_rule(rule)
        out["selected_protocol"] = selected_protocol
        return out

    if adapter == "udp_raw":
        out = build_udp_payload_for_rule(rule)
        return {
            "adapter": adapter,
            "selected_protocol": selected_protocol,
            "payload": out.payload,
            "segments": out.segments,
            "warnings": out.transport_warnings,
            "unsupported_transport_features": out.unsupported_transport_features,
        }

    out = build_tcp_payload_for_rule(rule)
    return {
        "adapter": adapter,
        "selected_protocol": selected_protocol,
        "payload": out.payload,
        "segments": out.segments,
        "warnings": out.transport_warnings,
        "unsupported_transport_features": out.unsupported_transport_features,
    }


def _emit_tcp_with_retry(host: str, preferred_port: int | None, fallback_port: int, payload: bytes, timeout: int, *, segment_payloads: list[bytes] | None = None) -> dict[str, object]:
    tried_ports: list[int] = []
    if preferred_port:
        tried_ports.append(int(preferred_port))
    if fallback_port not in tried_ports:
        tried_ports.append(int(fallback_port))

    last_error: Exception | None = None
    for port in tried_ports:
        try:
            sent = send_raw_tcp_bytes(host, port, payload, timeout=timeout, segments=segment_payloads)
            return {"bytes_sent": sent, "target_port": port, "emit_error": None, "tried_ports": tried_ports}
        except OSError as exc:
            last_error = exc

    return {
        "bytes_sent": 0,
        "target_port": tried_ports[0] if tried_ports else fallback_port,
        "emit_error": str(last_error) if last_error is not None else "tcp emit failed",
        "tried_ports": tried_ports,
    }


def emit_rule_payload(rule: object, target_server: str, timeout: int = 3, *, dns_target_host: str | None = None, dns_target_port_udp: int = 53, dns_target_port_tcp: int = 53) -> dict[str, object]:
    built = build_rule_payload(rule, target_server)
    adapter = built["adapter"]
    payload = built.get("payload", b"") or b""

    if built.get("status") == "SKIPPED":
        return {**built, "bytes_sent": 0, "target_port": None, "emit_error": None, "generation_success": False}

    if adapter == "http":
        status, _ = send_raw_http_bytes(target_server, payload, timeout=timeout)
        return {**built, "status": status, "generation_success": bool(payload)}

    unsupported = list(built.get("unsupported_transport_features") or [])
    if unsupported:
        return {
            **built,
            "status": "SKIPPED",
            "skip_reason": "SKIP_UNSUPPORTED_TRANSPORT",
            "bytes_sent": 0,
            "target_port": None,
            "emit_error": None,
            "unsupported_transport_features": unsupported,
            "generation_success": False,
        }

    if not payload:
        return {
            **built,
            "status": "SKIPPED",
            "skip_reason": "SKIP_EMPTY_PAYLOAD",
            "bytes_sent": 0,
            "target_port": None,
            "emit_error": None,
            "generation_success": False,
        }

    if adapter == "dns":
        transport = str(built.get("transport") or "udp").lower()
        host = dns_target_host or _target_host_port(target_server, fallback_port=53)[0]
        fallback = dns_target_port_udp if transport == "udp" else dns_target_port_tcp
        port_info = _resolve_rule_port(rule, fallback)
        dst_port = int(port_info["rule_dst_port"])
        try:
            sent = send_raw_udp_bytes(host, dst_port, payload, timeout=timeout) if transport == "udp" else send_raw_tcp_bytes(host, dst_port, payload, timeout=timeout)
            return {
                **built,
                "transport": transport,
                "bytes_sent": sent,
                "target_host": host,
                "target_port": dst_port,
                "emit_error": None,
                "emit_info": {**port_info, "transport": transport},
                "generation_success": bool(payload) and sent > 0,
            }
        except OSError as exc:
            return {
                **built,
                "transport": transport,
                "bytes_sent": 0,
                "target_host": host,
                "target_port": dst_port,
                "emit_error": str(exc),
                "emit_info": {**port_info, "transport": transport},
                "generation_success": False,
            }

    if adapter == "udp_raw":
        host, fallback_port = _target_host_port(target_server, fallback_port=53)
        port_info = _resolve_rule_port(rule, fallback_port)
        dst_port = int(port_info["rule_dst_port"])
        try:
            sent = send_raw_udp_bytes(host, dst_port, payload, timeout=timeout)
            return {**built, "bytes_sent": sent, "target_port": dst_port, "emit_error": None, "emit_info": port_info, "generation_success": sent > 0}
        except OSError as exc:
            return {**built, "bytes_sent": 0, "target_port": dst_port, "emit_error": str(exc), "emit_info": port_info, "generation_success": False}

    host, fallback_port = _target_host_port(target_server, fallback_port=80)
    port_info = _resolve_rule_port(rule, fallback_port)
    preferred_port = None if bool(port_info["used_fallback"]) else int(port_info["rule_dst_port"])
    segment_payloads = [seg.segment_bytes for seg in built.get("segments", []) if getattr(seg, "segment_bytes", b"")]
    emitted = _emit_tcp_with_retry(host, preferred_port, fallback_port, payload, timeout, segment_payloads=segment_payloads or None)
    generation_success = bool(payload) and int(emitted.get("bytes_sent") or 0) > 0 and not emitted.get("emit_error")
    return {**built, **emitted, "emit_info": port_info, "generation_success": generation_success}
