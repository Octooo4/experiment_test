from core.models import ContentMatch
from traffic_generation.http_builder import build_http_request_from_buckets


def test_uri_raw_percent_encoding_is_preserved():
    buckets = {
        "uri": [ContentMatch(raw="/a%2fb?q=%2F", decoded="/a%2fb?q=%2F")],
    }

    req = build_http_request_from_buckets(buckets, sid="", default_method="GET")

    assert req.path == "/a%2fb?q=%2F"
