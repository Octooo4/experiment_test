from core.models import BufferSwitch, ContentMatch
from parse.buckets_sorting import split_clauses_for_http_generation


def test_split_clauses_respects_sticky_buffers():
    clauses = [
        BufferSwitch(buffer="http.method"),
        ContentMatch(raw="GET", decoded="GET"),
        BufferSwitch(buffer="http.uri"),
        ContentMatch(raw="/x", decoded="/x"),
    ]

    buckets = split_clauses_for_http_generation(clauses)

    assert [c.decoded for c in buckets["method"]] == ["GET"]
    assert [c.decoded for c in buckets["uri"]] == ["/x"]
