from __future__ import annotations

"""Backward-compatible entrypoints for HTTP traffic generation.

This module is intentionally thin and delegates implementation to focused modules:
- rule_parse
- rule_semantics
- buffer_solver
- http_builder
- traffic_emit
"""

from traffic_generation.buffer_solver import build_stream_from_contents, synthesize_bucket_text
from traffic_generation.http_builder import (
    HttpRequestSpec,
    apply_named_header_buckets,
    build_http_request_from_buckets,
    build_http_request_from_raw_clauses,
    build_http_response_from_buckets,
    build_raw_http_text_request_from_clauses,
    build_request_for_rule,
    build_transaction_artifacts_for_rule,
    ensure_common_headers,
    rebucket_pcre_by_flags,
    render_http_request,
    validate_http_request,
)
from traffic_generation.rule_parse import (
    apply_bsize_constraints,
    fallback_string_from_regex,
    generate_string_from_pcre,
    has_header,
    header_lines_to_dict,
    match_size_constraint,
    normalize_header_name,
    parse_pcre_raw,
    pcre_flags_to_bucket,
    remove_crlf_escapes,
    sanitize_header,
    sanitize_header_value,
    sanitize_pcre,
    set_header_case_insensitive,
)
from traffic_generation.rule_semantics import (
    classify_http_rule_strategy,
    extract_header_candidates_from_raw_clauses,
    has_explicit_buffer_switch,
)
from traffic_generation.traffic_emit import send_http_request, send_raw_http_bytes

__all__ = [
    "HttpRequestSpec",
    "match_size_constraint",
    "apply_bsize_constraints",
    "build_stream_from_contents",
    "sanitize_pcre",
    "fallback_string_from_regex",
    "generate_string_from_pcre",
    "parse_pcre_raw",
    "pcre_flags_to_bucket",
    "remove_crlf_escapes",
    "sanitize_header",
    "sanitize_header_value",
    "normalize_header_name",
    "header_lines_to_dict",
    "has_header",
    "set_header_case_insensitive",
    "has_explicit_buffer_switch",
    "validate_http_request",
    "render_http_request",
    "classify_http_rule_strategy",
    "extract_header_candidates_from_raw_clauses",
    "build_http_request_from_raw_clauses",
    "synthesize_bucket_text",
    "apply_named_header_buckets",
    "rebucket_pcre_by_flags",
    "build_http_request_from_buckets",
    "build_http_response_from_buckets",
    "build_raw_http_text_request_from_clauses",
    "ensure_common_headers",
    "send_http_request",
    "send_raw_http_bytes",
    "build_request_for_rule",
    "build_transaction_artifacts_for_rule",
]
