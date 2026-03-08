from core.models import BufferSwitch, ContentMatch, FlowTerm, RuleBody, RuleHeader, SuricataRule
from core.models import PcreMatch
from traffic_generation.rule_semantics import extract_http_plan


def test_extract_http_plan_segments_follow_sticky_and_legacy_bound_buffers():
    clauses = [
        ContentMatch(raw="GET", decoded="GET", buffer="http.method"),
        BufferSwitch(buffer="http.header"),
        ContentMatch(raw="Host: a", decoded="Host: a"),
        PcreMatch(raw='"/User-Agent\\: test/"', buffer="http.user_agent"),
    ]
    rule = SuricataRule(
        header=RuleHeader(action="alert", protocol="http", src="any", src_port="any", direction="->", dst="any", dst_port="80"),
        body=RuleBody(sid="1", msg="x", clauses=clauses, flow=FlowTerm(to_server=True, established=True)),
    )

    plan = extract_http_plan(rule)

    assert plan.flow.to_server is True
    assert plan.flow.established is True
    # pkt_data default + method + header + user_agent
    buffers = [seg.buffer for seg in plan.request_segments if seg.matches]
    assert buffers == ["http.method", "http.header", "http.user_agent"]


def test_extract_http_plan_keeps_match_modifiers():
    clauses = [
        ContentMatch(raw="abc", decoded="abc", nocase=True, offset=1, depth=5, distance=0, within=4),
    ]
    rule = SuricataRule(
        header=RuleHeader(action="alert", protocol="http", src="any", src_port="any", direction="->", dst="any", dst_port="80"),
        body=RuleBody(sid="2", msg="y", clauses=clauses),
    )

    plan = extract_http_plan(rule)
    m = plan.request_segments[0].matches[0]
    assert m.modifiers.nocase is True
    assert m.modifiers.offset == 1
    assert m.modifiers.depth == 5
    assert m.modifiers.distance == 0
    assert m.modifiers.within == 4


def test_extract_http_plan_prefers_decoded_content():
    from traffic_generation.rule_parse import parse_rules, ast_to_suricata_rule

    text = 'alert http any any -> any any (msg:"t"; flow:to_server,established; content:"|2f|abc"; http_uri; sid:2; rev:1;)\n'
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "r.rules"
        f.write_text(text, encoding="utf-8")
        ast = parse_rules(f)[0]
    rule = ast_to_suricata_rule(ast)
    plan = extract_http_plan(rule)
    assert plan.request_segments
    uri_matches = [m for seg in plan.request_segments if seg.buffer == "http.uri" for m in seg.matches]
    assert uri_matches and uri_matches[0].raw.startswith("/abc")
