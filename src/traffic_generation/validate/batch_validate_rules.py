from __future__ import annotations

from urllib.parse import urlparse

from traffic_generation.adapters.common import AdapterKind, has_http_sticky_buffers
from traffic_generation.adapters.http_adapter import build_http_for_rule
from traffic_generation.adapters.tcp_raw_adapter import build_payload_for_rule as build_tcp_payload_for_rule
from traffic_generation.adapters.udp_raw_adapter import build_payload_for_rule as build_udp_payload_for_rule
from traffic_generation.traffic_emit import send_raw_http_bytes, send_raw_tcp_bytes, send_raw_udp_bytes


def choose_rule_adapter(rule: object) -> AdapterKind:
    protocol = str(getattr(getattr(rule, "header", None), "protocol", "") or "").lower()
    if protocol == "http" or has_http_sticky_buffers(rule):
        return "http"
    if protocol == "udp":
        return "udp_raw"
    return "tcp_raw"


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


def _rule_dst_port(rule: object) -> int | None:
    dst_port = str(getattr(getattr(rule, "header", None), "dst_port", "") or "").strip()
    if dst_port.isdigit():
        p = int(dst_port)
        if 0 < p <= 65535:
            return p
    return None


def build_rule_payload(rule: object, target_server: str) -> dict[str, object]:
    adapter = choose_rule_adapter(rule)
    if adapter == "http":
        out = build_http_for_rule(rule, target_server)
        payload = out.raw_bytes or b""
        return {"adapter": adapter, "payload": payload, "strategy": out.strategy}
    if adapter == "udp_raw":
        out = build_udp_payload_for_rule(rule)
        return {"adapter": adapter, "payload": out.payload, "segments": out.segments, "warnings": out.transport_warnings}

    out = build_tcp_payload_for_rule(rule)
    return {"adapter": adapter, "payload": out.payload, "segments": out.segments, "warnings": out.transport_warnings}


def emit_rule_payload(rule: object, target_server: str, timeout: int = 3) -> dict[str, object]:
    built = build_rule_payload(rule, target_server)
    adapter = built["adapter"]
    payload = built.get("payload", b"") or b""

    if adapter == "http":
        status, _ = send_raw_http_bytes(target_server, payload, timeout=timeout)
        return {**built, "status": status}

    if adapter == "udp_raw":
        host, port = _target_host_port(target_server, fallback_port=53)
        port = _rule_dst_port(rule) or port
        sent = send_raw_udp_bytes(host, port, payload, timeout=timeout)
        return {**built, "bytes_sent": sent}

    host, port = _target_host_port(target_server, fallback_port=80)
    port = _rule_dst_port(rule) or port
    sent = send_raw_tcp_bytes(host, port, payload, timeout=timeout)
    return {**built, "bytes_sent": sent}
