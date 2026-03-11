from __future__ import annotations

from parse.buckets_sorting import split_clauses_for_http_generation
from traffic_generation.buffer_solver import synthesize_bucket
from traffic_generation.adapters.common import AdapterBuildResult, SynthesisSegment, extract_transport_keyword_warnings

_BUCKET_ORDER = ["pkt_data", "other", "uri", "header", "body", "protocol"]


def build_payload_for_rule(rule: object) -> AdapterBuildResult:
    clauses = getattr(getattr(rule, "body", None), "clauses", []) or []
    sid = str(getattr(getattr(rule, "body", None), "sid", "") or "")
    buckets = split_clauses_for_http_generation(clauses)

    segments: list[SynthesisSegment] = []
    chunks: list[bytes] = []

    for bucket in _BUCKET_ORDER:
        bucket_clauses = buckets.get(bucket)
        if not isinstance(bucket_clauses, list) or not bucket_clauses:
            continue
        synth = synthesize_bucket(bucket_clauses, sid=sid, fill=b"A", strip_crlf=False)
        if synth.bytes:
            chunks.append(synth.bytes)
        segments.append(
            SynthesisSegment(
                segment_name=bucket,
                segment_bytes=synth.bytes,
                solver_backend=synth.solved_by,
                unsat_reason=synth.unsat_reason,
            )
        )

    payload = b"".join(chunks)
    if not payload:
        payload = b"A"

    warnings = extract_transport_keyword_warnings(rule, protocol="udp")
    return AdapterBuildResult(adapter="udp_raw", payload=payload, segments=segments, transport_warnings=warnings)
