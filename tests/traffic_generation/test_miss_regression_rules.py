from core.models import ContentMatch
from traffic_generation.http_builder import build_http_request_from_raw_clauses
from traffic_generation.rule_parse import RuleHeader, Rule, RawOption, ast_to_suricata_rule
from traffic_generation.rule_semantics import extract_header_candidates_from_raw_clauses
from core.models import PcreMatch


def test_legacy_http_uri_modifier_binds_previous_content():
    ast = Rule(
        header=RuleHeader(action="alert", protocol="http", src="any", src_port="any", direction="->", dst="any", dst_port="80"),
        sid="2011353",
        msg="x",
        raw_options=[
            RawOption(keyword="content", value="\"/jquery.jxx?v=\"", negated=False),
            RawOption(keyword="http_uri", value=None, negated=False),
        ],
        content=[ContentMatch(raw="/jquery.jxx?v=", decoded="/jquery.jxx?v=")],
    )

    rule = ast_to_suricata_rule(ast)
    content = [c for c in rule.body.clauses if isinstance(c, ContentMatch)][0]
    assert content.buffer == "http.uri"


def test_recoverable_raw_host_suffix_merges_into_host_header():
    clauses = [
        ContentMatch(raw="GET ", decoded="GET "),
        ContentMatch(raw="|0d 0a|Host|3a| google.analytics.com.|", decoded="\r\nHost: google.analytics.com."),
        ContentMatch(raw=".info|0d 0a|", decoded=".info\r\n"),
    ]
    req = build_http_request_from_raw_clauses(clauses, sid="2010866")
    assert req.headers.get("Host") == "google.analytics.com.info"


def test_recoverable_raw_pcre_user_agent_0_0_len_pattern():
    clauses = [
        ContentMatch(raw="|0d 0a|User-Agent|3a| 0|3a|0|3a|", decoded="\r\nUser-Agent: 0:0:"),
        PcreMatch(raw='"/\\x0d\\x0aUser-Agent\\: 0\\:0\\:[^\\n]{120}/"', negated=False),
    ]
    headers, _, _ = extract_header_candidates_from_raw_clauses(clauses, sid="2007647")
    assert "User-Agent" in headers
    assert headers["User-Agent"] == "0:0:" + ("A" * 120)
