from __future__ import annotations

from dataclasses import asdict

from traffic_generation.dns_builder import build_dns_query_from_plan
from traffic_generation.dns_semantics import extract_dns_plan


def build_dns_for_rule(rule: object) -> dict[str, object]:
    plan = extract_dns_plan(rule)

    if plan.direction == "response":
        return {
            "adapter": "dns",
            "payload": b"",
            "transport": plan.transport or "udp",
            "plan": asdict(plan),
            "warnings": list(plan.warnings),
            "unsupported_dns_features": list(plan.unsupported_dns_features),
            "status": "SKIPPED",
            "skip_reason": "SKIP_DNS_RESPONSE_NOT_SUPPORTED",
        }

    if plan.unsupported_dns_features:
        return {
            "adapter": "dns",
            "payload": b"",
            "transport": plan.transport or "udp",
            "plan": asdict(plan),
            "warnings": list(plan.warnings),
            "unsupported_dns_features": list(plan.unsupported_dns_features),
            "status": "SKIPPED",
            "skip_reason": "SKIP_UNSUPPORTED_DNS_FEATURES",
        }

    built = build_dns_query_from_plan(plan)
    if not built.payload:
        return {
            "adapter": "dns",
            "payload": b"",
            "transport": built.transport,
            "plan": asdict(plan),
            "warnings": built.warnings,
            "unsupported_dns_features": built.unsupported_dns_features,
            "status": "SKIPPED",
            "skip_reason": "SKIP_DNS_EMPTY_PAYLOAD",
        }

    return {
        "adapter": "dns",
        "payload": built.payload,
        "transport": built.transport,
        "plan": asdict(plan),
        "qname": built.qname,
        "qtype": built.qtype,
        "opcode": built.opcode,
        "warnings": built.warnings,
        "unsupported_dns_features": built.unsupported_dns_features,
    }
