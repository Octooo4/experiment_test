from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.models import BufferSwitch, ContentMatch, DnsOpcodeMatch, DnsRrtypeMatch, PcreMatch

QUERY_BUFFERS = {"dns.query", "dns.queries.rrname"}
RESPONSE_ONLY_BUFFERS = {
    "dns.answers.rrname",
    "dns.response.rrname",
    "dns.authorities.rrname",
    "dns.additionals.rrname",
}


@dataclass
class DnsQuestionConstraint:
    match_type: str
    value: str
    nocase: bool = False
    source_buffer: str = "dns.query"


@dataclass
class DnsTransactionPlan:
    transport: Optional[str] = None
    direction: str = "query"
    opcode: Optional[int] = None
    rrtype: Optional[str] = None
    qname_constraints: list[DnsQuestionConstraint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unsupported_dns_features: list[str] = field(default_factory=list)
    selected_buffer: Optional[str] = None


def _rrtype_from_value(v: str) -> str:
    text = (v or "").strip().upper()
    mapping = {"1": "A", "28": "AAAA", "15": "MX", "16": "TXT", "2": "NS", "5": "CNAME"}
    return mapping.get(text, text or "A")


def extract_dns_plan(rule: object) -> DnsTransactionPlan:
    protocol = str(getattr(getattr(rule, "header", None), "protocol", "") or "").strip().lower()
    transport = "tcp" if protocol == "tcp" else "udp"
    plan = DnsTransactionPlan(transport=transport)
    clauses = getattr(getattr(rule, "body", None), "clauses", []) or []
    flow = getattr(getattr(rule, "body", None), "flow", None)
    if flow is not None and bool(getattr(flow, "to_client", False)):
        plan.direction = "response"
        plan.unsupported_dns_features.append("flow.to_client")

    active_buffer: Optional[str] = None
    for clause in clauses:
        if isinstance(clause, BufferSwitch):
            active_buffer = str(clause.buffer)
            if active_buffer in QUERY_BUFFERS:
                plan.selected_buffer = active_buffer
            if active_buffer in RESPONSE_ONLY_BUFFERS:
                plan.unsupported_dns_features.append(active_buffer)
            continue

        if isinstance(clause, DnsOpcodeMatch):
            plan.opcode = int(clause.opcode)
            continue
        if isinstance(clause, DnsRrtypeMatch):
            plan.rrtype = _rrtype_from_value(str(clause.rrtype))
            continue

        clause_buffer = str(getattr(clause, "buffer", "") or "")
        effective_buffer = active_buffer
        if clause_buffer in QUERY_BUFFERS | RESPONSE_ONLY_BUFFERS:
            effective_buffer = clause_buffer

        if isinstance(clause, ContentMatch) and effective_buffer in QUERY_BUFFERS:
            if clause.negated:
                plan.warnings.append("negated dns qname content not supported in V1")
                continue
            if clause.startswith:
                m = "prefix"
            elif clause.endswith:
                m = "suffix"
            else:
                m = "contains"
            plan.qname_constraints.append(
                DnsQuestionConstraint(match_type=m, value=clause.decoded, nocase=bool(clause.nocase), source_buffer=effective_buffer)
            )
            continue

        if isinstance(clause, PcreMatch) and effective_buffer in QUERY_BUFFERS:
            if clause.negated:
                plan.warnings.append("negated dns qname pcre not supported in V1")
                continue
            plan.qname_constraints.append(
                DnsQuestionConstraint(match_type="pcre", value=clause.raw, nocase=bool(clause.nocase), source_buffer=effective_buffer)
            )

        if isinstance(clause, (ContentMatch, PcreMatch)) and effective_buffer in RESPONSE_ONLY_BUFFERS:
            plan.unsupported_dns_features.append(effective_buffer)

    if len([c for c in plan.qname_constraints if c.match_type != "pcre"]) > 1:
        plan.warnings.append("multiple qname constraints detected; builder uses first feasible one")

    if any(f in plan.unsupported_dns_features for f in RESPONSE_ONLY_BUFFERS):
        plan.direction = "response"

    # de-duplicate while preserving order for diagnostics
    plan.unsupported_dns_features = list(dict.fromkeys(plan.unsupported_dns_features))

    return plan
