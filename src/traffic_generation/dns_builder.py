from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from traffic_generation.dns_semantics import DnsTransactionPlan

_RRTYPE_TO_CODE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


@dataclass
class DnsQuestionSpec:
    qname: str
    qtype: int = 1
    qclass: int = 1


@dataclass
class DnsMessageSpec:
    tid: int
    opcode: int = 0
    rd: int = 1
    question: DnsQuestionSpec = field(default_factory=lambda: DnsQuestionSpec(qname="example.com"))


@dataclass
class DnsBuildResult:
    payload: bytes
    transport: str
    qname: str
    qtype: int
    opcode: int
    warnings: list[str] = field(default_factory=list)
    unsupported_dns_features: list[str] = field(default_factory=list)


def encode_dns_name(name: str) -> bytes:
    normalized = (name or "").strip().strip(".")
    if not normalized:
        raise ValueError("empty dns name")
    labels = normalized.split(".")
    out = bytearray()
    for label in labels:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,63}", label):
            raise ValueError(f"invalid dns label: {label}")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def _to_qtype(rrtype: str | None) -> int:
    if not rrtype:
        return 1
    up = str(rrtype).strip().upper()
    if up.isdigit():
        v = int(up)
        return v if 1 <= v <= 65535 else 1
    return _RRTYPE_TO_CODE.get(up, 1)


def _name_from_constraints(plan: DnsTransactionPlan) -> tuple[str, list[str]]:
    warnings: list[str] = []
    if not plan.qname_constraints:
        warnings.append("dns qname defaulted to example.com")
        return "example.com", warnings

    for c in plan.qname_constraints:
        if c.match_type in {"contains", "prefix", "suffix"}:
            raw = c.value.strip().strip('"')
            if "." in raw:
                return raw.lower(), warnings
            return f"{raw.lower()}.example.com", warnings
    warnings.append("dns qname constraint not directly buildable; fallback to example.com")
    return "example.com", warnings


def build_dns_query_from_plan(plan: DnsTransactionPlan) -> DnsBuildResult:
    warnings = list(plan.warnings)
    qname, extra = _name_from_constraints(plan)
    warnings.extend(extra)

    opcode = int(plan.opcode or 0)
    qtype = _to_qtype(plan.rrtype)
    msg = DnsMessageSpec(tid=random.randint(0, 65535), opcode=opcode, question=DnsQuestionSpec(qname=qname, qtype=qtype))

    flags = ((msg.opcode & 0xF) << 11) | ((msg.rd & 0x1) << 8)
    header = msg.tid.to_bytes(2, "big") + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + (0).to_bytes(2, "big") * 3
    question = encode_dns_name(msg.question.qname) + msg.question.qtype.to_bytes(2, "big") + msg.question.qclass.to_bytes(2, "big")
    dns_payload = header + question

    transport = (plan.transport or "udp").lower()
    if transport == "tcp":
        payload = len(dns_payload).to_bytes(2, "big") + dns_payload
    else:
        payload = dns_payload
        transport = "udp"

    return DnsBuildResult(
        payload=payload,
        transport=transport,
        qname=qname,
        qtype=qtype,
        opcode=opcode,
        warnings=warnings,
        unsupported_dns_features=list(plan.unsupported_dns_features),
    )
