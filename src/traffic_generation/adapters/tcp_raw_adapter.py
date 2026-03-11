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

    warnings: list[str] = []
    supported_clauses: list[object] = []
    supported_indexes: list[int] = []

    for idx, clause in enumerate(clauses):
        if _is_http_specific_clause(clause):
            warnings.append(f"http-only clause ignored at index={idx}: {type(clause).__name__}")
            continue
        if not isinstance(clause, _SUPPORTED_RAW_TYPES):
            warnings.append(f"unsupported raw clause ignored at index={idx}: {type(clause).__name__}")
            continue
        supported_clauses.append(clause)
        supported_indexes.append(idx)

    segments: list[SynthesisSegment] = []
    payload = b""
    if supported_clauses:
        synth = synthesize_bucket(supported_clauses, sid=sid, fill=b"A", strip_crlf=False)
        payload = synth.bytes or b""
        segments.append(
            SynthesisSegment(
                segment_name=(
                    f"raw_rule_joint_solve_{supported_indexes[0]}_{supported_indexes[-1]}"
                    if supported_indexes
                    else "raw_rule_joint_solve"
                ),
                segment_bytes=payload,
                solver_backend=synth.solved_by,
                unsat_reason=synth.unsat_reason,
            )
        )
    else:
        warnings.append("no supported tcp_raw clause remained after filtering")

    transport_warnings, unsupported = extract_transport_keyword_warnings(rule, protocol="tcp")
    warnings.extend(transport_warnings)
    return AdapterBuildResult(
        adapter="tcp_raw",
        payload=payload,
        segments=segments,
        transport_warnings=warnings,
        unsupported_transport_features=unsupported,
    )
