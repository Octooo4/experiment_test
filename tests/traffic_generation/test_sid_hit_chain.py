from pathlib import Path

from traffic_generation.http_builder import build_transaction_artifacts_for_rule
from traffic_generation.rule_parse import ast_to_suricata_rule, parse_rules
from traffic_generation.rule_semantics import get_rule_admission_skip_reason


def test_to_server_established_rule_keeps_sid_through_build_chain(tmp_path: Path):
    rule_text = (
        'alert http any any -> any any '
        '(msg:"sid chain"; flow:to_server,established; '
        'http.method; content:"GET"; http.uri; content:"/login"; sid:2001;)'
    )
    rule_file = tmp_path / "rule.rules"
    rule_file.write_text(rule_text, encoding="utf-8")

    ast = parse_rules(rule_file)[0]
    rule = ast_to_suricata_rule(ast)

    assert get_rule_admission_skip_reason(rule) is None

    strategy, req, raw = build_transaction_artifacts_for_rule(rule, "http://127.0.0.1:8080")

    assert strategy == "sticky"
    assert raw is None
    assert req is not None
    assert req.headers["Rulesid"] == "2001"
