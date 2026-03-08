from core.models import BufferSwitch, ContentMatch, RuleBody, RuleHeader, SuricataRule
from traffic_generation.http_builder import build_request_for_rule
from traffic_generation.rule_semantics import classify_http_rule_strategy


def _mk_rule(clauses, sid="1"):
    return SuricataRule(
        header=RuleHeader(action="alert", protocol="http", src="any", src_port="any", direction="->", dst="any", dst_port="80"),
        body=RuleBody(sid=sid, msg="m", clauses=clauses),
    )


def test_classify_no_sticky_header_fragments_as_recoverable_raw():
    clauses = [
        ContentMatch(raw="GET ", decoded="GET "),
        ContentMatch(raw="|0d 0a|Host|3a| example.com|0d 0a|", decoded="\r\nHost: example.com\r\n"),
    ]
    assert classify_http_rule_strategy(clauses) == "recoverable_raw"



def test_build_request_for_rule_uses_recoverable_raw_path():
    rule = _mk_rule(
        [
            ContentMatch(raw="GET ", decoded="GET "),
            ContentMatch(raw="Host: example.com", decoded="Host: example.com"),
        ],
        sid="2000",
    )

    strategy, req, raw = build_request_for_rule(rule, "http://127.0.0.1:80")

    assert strategy == "recoverable_raw"
    assert req is not None
    assert raw is None
    assert req.headers.get("Host") == "example.com"



def test_classify_with_buffer_switch_is_sticky():
    clauses = [BufferSwitch(buffer="http.header"), ContentMatch(raw="Host: x", decoded="Host: x")]
    assert classify_http_rule_strategy(clauses) == "sticky"
