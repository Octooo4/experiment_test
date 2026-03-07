from core.models import ContentMatch
from traffic_generation.http_builder import build_http_request_from_buckets


def test_post_request_body_sets_content_type_and_length():
    buckets = {
        "method": [ContentMatch(raw="POST", decoded="POST")],
        "body": [ContentMatch(raw="a=1&b=2", decoded="a=1&b=2")],
    }

    req = build_http_request_from_buckets(buckets)

    assert req.method == "POST"
    assert req.body == "a=1&b=2"
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert req.headers["Content-Length"] == str(len("a=1&b=2".encode("utf-8")))
