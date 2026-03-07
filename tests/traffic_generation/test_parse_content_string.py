from traffic_generation.buffer_solver import parse_content_string


def test_parse_content_string_mixed_ascii_hex_and_escape():
    raw = "ABC|20 2f|\\x41\\n"
    assert parse_content_string(raw) == b"ABC /A\n"
