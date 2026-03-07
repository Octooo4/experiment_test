from pathlib import Path

from traffic_generation.rule_parse import ast_to_suricata_rule, parse_rules


def test_legacy_http_uri_modifier_maps_to_buffer_switch(tmp_path: Path):
    rule_text = (
        'alert http any any -> any any '
        '(content:"abc"; http_uri; content:"/admin"; sid:1001;)'
    )
    rule_file = tmp_path / "rule.rules"
    rule_file.write_text(rule_text, encoding="utf-8")

    ast = parse_rules(rule_file)[0]
    parsed = ast_to_suricata_rule(ast)

    assert parsed.body.clauses[1].buffer == "http.uri"
