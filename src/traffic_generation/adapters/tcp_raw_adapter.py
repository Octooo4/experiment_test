from __future__ import annotations

from core.models import BSizeMatch, BufferSwitch, ContentMatch, DSizeMatch, IsDataAtMatch, PcreMatch
from traffic_generation.adapters.common import AdapterBuildResult, SynthesisSegment, extract_transport_keyword_warnings
from traffic_generation.buffer_solver import synthesize_bucket

_SUPPORTED_RAW_TYPES = (ContentMatch, PcreMatch, IsDataAtMatch, DSizeMatch, BSizeMatch)


def _is_http_specific_clause(clause: object) -> bool:
    if isinstance(clause, BufferSwitch):
        buf = getattr(clause, "buffer", None)
        return isinstance(buf, str) and buf.startswith("http.")
    buf = getattr(clause, "buffer", None)
    return isinstance(buf, str) and buf.startswith("http.")


def build_payload_for_rule(rule: object) -> AdapterBuildResult:
    clauses = getattr(getattr(rule, "body", None), "clauses", []) or []
    sid = str(getattr(getattr(rule, "body", None), "sid", "") or "")

    segments: list[SynthesisSegment] = []
    chunks: list[bytes] = []
    warnings: list[str] = []

    for idx, clause in enumerate(clauses):
        if _is_http_specific_clause(clause):
            warnings.append(f"http-only clause ignored at index={idx}: {type(clause).__name__}")
            continue
        if not isinstance(clause, _SUPPORTED_RAW_TYPES):
            warnings.append(f"unsupported raw clause ignored at index={idx}: {type(clause).__name__}")
            continue

        synth = synthesize_bucket([clause], sid=sid, fill=b"A", strip_crlf=False)
        if synth.bytes:
            chunks.append(synth.bytes)
        segments.append(
            SynthesisSegment(
                segment_name=f"raw_clause_{idx}_{type(clause).__name__}",
                segment_bytes=synth.bytes,
                solver_backend=synth.solved_by,
                unsat_reason=synth.unsat_reason,
            )
        )

    payload = b"".join(chunks)
    if not payload:
        payload = b"A"
        warnings.append("payload fallback byte used: no positive raw content synthesized")

    transport_warnings, unsupported = extract_transport_keyword_warnings(rule, protocol="tcp")
    warnings.extend(transport_warnings)
    return AdapterBuildResult(
        adapter="tcp_raw",
        payload=payload,
        segments=segments,
        transport_warnings=warnings,
        unsupported_transport_features=unsupported,
    )
