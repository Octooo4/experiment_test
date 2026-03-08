from traffic_generation.http_builder import build_request
from traffic_generation.rule_semantics import BufferSegment, ContentMatchPlan, MatchModifiers, TransactionPlan


def test_host_suffix_prefixed_for_valid_http_host_header():
    plan = TransactionPlan(
        request_segments=[
            BufferSegment(
                buffer="http.host",
                matches=[ContentMatchPlan(kind="content", raw=".familiawhite.com.ar", modifiers=MatchModifiers())],
            )
        ]
    )
    req = build_request(plan, default_host="example.com").decode("latin-1", errors="replace")
    assert "Host: www.familiawhite.com.ar" in req
