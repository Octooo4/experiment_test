from core.models import ContentMatch
from traffic_generation.http_builder import build_http_request_from_buckets


def test_cookie_bucket_overrides_cookie_from_generic_header_lines():
    buckets = {
        "header": [
            ContentMatch(raw="Cookie: a=1", decoded="Cookie: a=1"),
            ContentMatch(raw="Host: ignored.example", decoded="Host: ignored.example"),
            ContentMatch(raw="X-Test: ok", decoded="X-Test: ok"),
        ],
        "cookie": [ContentMatch(raw="b=2", decoded="b=2")],
    }

    req = build_http_request_from_buckets(buckets)

    assert req.headers["Cookie"] == "b=2"
    assert "Host" not in req.headers
    assert req.headers["X-Test"] == "ok"
