from core.models import ContentMatch, FlowTerm, RuleBody, RuleHeader, SuricataRule
from traffic_generation.http_builder import build_request
from traffic_generation.rule_semantics import extract_http_plan


def test_startswith_endswith_preserved_from_plan_to_request():
    rule = SuricataRule(
        header=RuleHeader(action="alert", protocol="http", src="any", src_port="any", direction="->", dst="any", dst_port="any"),
        body=RuleBody(
            flow=FlowTerm(to_server=True, established=True),
            sid="1",
            clauses=[ContentMatch(raw=".example.com", decoded=".example.com", endswith=True, buffer="http.host")],
        ),
    )

    plan = extract_http_plan(rule)
    host_match = [m for s in plan.request_segments if s.buffer == "http.host" for m in s.matches][0]
    assert host_match.modifiers.endswith is True

    req = build_request(plan, default_host="fallback.local").decode("latin-1", errors="replace")
    assert "Host: www.example.com" in req
