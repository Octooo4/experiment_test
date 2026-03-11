from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from traffic_generation.http_builder import build_request_for_rule


@dataclass
class HttpAdapterResult:
    strategy: str
    request_obj: Optional[object]
    raw_bytes: Optional[bytes]


def build_http_for_rule(rule: object, server: str) -> HttpAdapterResult:
    strategy, request_obj, raw_bytes = build_request_for_rule(rule, server)
    return HttpAdapterResult(strategy=strategy, request_obj=request_obj, raw_bytes=raw_bytes)
