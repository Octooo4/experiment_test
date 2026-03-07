from traffic_generation.batch_validate_http_rules import normalize_rule_for_suricata_eval


def test_normalize_rule_header_replaces_vars_with_any():
    raw = (
        'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
        '( msg:"x"; sid:1; rev:1; )'
    )
    out = normalize_rule_for_suricata_eval(raw)
    assert out.startswith('alert http any any -> any any (')
    assert 'msg:"x"; sid:1; rev:1;' in out


def test_normalize_rule_header_keeps_nonmatching_text():
    raw = 'not a valid rule line'
    assert normalize_rule_for_suricata_eval(raw) == raw
