from pathlib import Path

from traffic_generation.batch_validate_http_rules import NO_ALERT_FOR_SID, SKIP_UNSUPPORTED_KEYWORD
from traffic_generation.rule_parse import parse_rules


def test_no_alert_reason_constant_name():
    assert NO_ALERT_FOR_SID == "NO_ALERT_FOR_SID"


def test_urilen_and_url_decode_not_marked_unsupported(tmp_path: Path):
    rule_text = (
        'alert http any any -> any any (msg:"t"; flow:to_server,established; '
        'content:"/a.php"; http.uri; urilen:>5; url_decode; sid:1; rev:1;)\n'
    )
    f = tmp_path / "r.rules"
    f.write_text(rule_text, encoding="utf-8")

    rules = parse_rules(f)
    assert len(rules) == 1
    assert "urilen" not in rules[0].unsupported_keywords
    assert "url_decode" not in rules[0].unsupported_keywords


def test_skip_unsupported_keyword_constant_name():
    assert SKIP_UNSUPPORTED_KEYWORD == "SKIP_UNSUPPORTED_KEYWORD"
