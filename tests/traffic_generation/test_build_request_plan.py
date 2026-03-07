from traffic_generation.http_builder import build_request
from traffic_generation.rule_semantics import BufferSegment, ContentMatchPlan, FlowConstraint, MatchModifiers, TransactionPlan


def test_uri_dual_track_prefers_raw_for_request_line():
    plan = TransactionPlan(
        flow=FlowConstraint(to_server=True),
        request_segments=[
            BufferSegment(buffer="http.method", matches=[ContentMatchPlan(kind="content", raw="GET", modifiers=MatchModifiers())]),
            BufferSegment(buffer="http.uri.raw", matches=[ContentMatchPlan(kind="content", raw="/raw%2fpath", modifiers=MatchModifiers())]),
            BufferSegment(buffer="http.uri", matches=[ContentMatchPlan(kind="content", raw="/norm/path", modifiers=MatchModifiers())]),
        ],
    )

    req_bytes = build_request(plan, default_host="example.com")
    text = req_bytes.decode("latin-1", errors="replace")
    assert text.startswith("GET /raw%2fpath HTTP/1.1")


def test_build_request_from_plan_adds_host_and_connection_defaults():
    plan = TransactionPlan(
        flow=FlowConstraint(to_server=True),
        request_segments=[
            BufferSegment(buffer="http.request_body", matches=[ContentMatchPlan(kind="content", raw="a=1", modifiers=MatchModifiers())]),
        ],
    )
    req = build_request(plan, default_host="host.local").decode("latin-1", errors="replace")
    assert "Host: host.local" in req
    assert "Connection: close" in req
