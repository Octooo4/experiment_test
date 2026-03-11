from types import SimpleNamespace

from core.models import ContentMatch, RuleBody, RuleHeader, SuricataRule
from traffic_generation.adapters.tcp_raw_adapter import build_payload_for_rule as build_tcp_payload_for_rule
from traffic_generation.adapters.udp_raw_adapter import build_payload_for_rule as build_udp_payload_for_rule
from traffic_generation.validate.batch_validate_rules import choose_rule_adapter


def _rule(protocol: str, clauses: list[object]) -> SuricataRule:
    return SuricataRule(
        header=RuleHeader(action="alert", protocol=protocol, src="any", src_port="any", direction="->", dst="any", dst_port="any"),
        body=RuleBody(sid="1", clauses=clauses),
    )


def test_choose_http_adapter_for_http_sticky_even_on_tcp_header():
    r = _rule("tcp", [ContentMatch(raw="/admin", decoded="/admin", buffer="http.uri")])
    assert choose_rule_adapter(r) == "http"


def test_choose_tcp_raw_adapter_for_plain_tcp_rule():
    r = _rule("tcp", [ContentMatch(raw="abc", decoded="abc")])
    assert choose_rule_adapter(r) == "tcp_raw"


def test_choose_udp_raw_adapter_for_udp_rule():
    r = _rule("udp", [ContentMatch(raw="xyz", decoded="xyz")])
    assert choose_rule_adapter(r) == "udp_raw"


def test_tcp_raw_adapter_builds_payload_and_transport_warnings():
    r = SimpleNamespace(
        header=RuleHeader(action="alert", protocol="tcp", src="any", src_port="any", direction="->", dst="any", dst_port="any"),
        body=RuleBody(sid="2", clauses=[ContentMatch(raw="abc", decoded="abc")]),
        raw_options=[SimpleNamespace(keyword="flags")],
    )
    out = build_tcp_payload_for_rule(r)
    assert out.payload
    assert out.adapter == "tcp_raw"
    assert any("flags" in w for w in out.transport_warnings)


def test_udp_raw_adapter_builds_payload_and_transport_warnings():
    r = SimpleNamespace(
        header=RuleHeader(action="alert", protocol="udp", src="any", src_port="any", direction="->", dst="any", dst_port="any"),
        body=RuleBody(sid="3", clauses=[ContentMatch(raw="abc", decoded="abc")]),
        raw_options=[SimpleNamespace(keyword="dsize")],
    )
    out = build_udp_payload_for_rule(r)
    assert out.payload
    assert out.adapter == "udp_raw"
    assert any("dsize" in w for w in out.transport_warnings)
