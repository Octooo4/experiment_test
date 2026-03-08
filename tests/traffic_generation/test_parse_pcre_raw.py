from traffic_generation.rule_parse import parse_pcre_raw


def test_parse_pcre_raw_quoted_literal():
    body, flags = parse_pcre_raw('"/abc\\/def/i"')
    assert body == r"abc\/def"
    assert flags == "i"


def test_parse_pcre_raw_handles_unterminated_fast():
    raw = '"/' + ('\\/' * 10000)
    body, flags = parse_pcre_raw(raw)
    assert isinstance(body, str)
    assert isinstance(flags, str)
    assert flags == ""
