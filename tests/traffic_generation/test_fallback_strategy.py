from traffic_generation.batch_validate_http_rules import should_try_legacy_fallback
from types import SimpleNamespace

from traffic_generation.batch_validate_http_rules import build_fallback_attempts


def test_fallback_strategy_allows_known_builders():
    assert should_try_legacy_fallback("sticky") is True
    assert should_try_legacy_fallback("recoverable_raw") is True
    assert should_try_legacy_fallback("raw_text") is True


def test_fallback_strategy_rejects_unknown_builder():
    assert should_try_legacy_fallback("plan_only_custom") is False


def test_build_fallback_attempts_expands_for_sticky(monkeypatch):
    rule = SimpleNamespace(body=SimpleNamespace(clauses=[], sid="1"))

    monkeypatch.setattr(
        "traffic_generation.batch_validate_http_rules.build_request_for_rule",
        lambda _rule, _server: ("sticky", None, b"A"),
    )
    monkeypatch.setattr(
        "traffic_generation.batch_validate_http_rules.build_http_request_from_raw_clauses",
        lambda _clauses, sid="": SimpleNamespace(),
    )
    monkeypatch.setattr(
        "traffic_generation.batch_validate_http_rules.render_http_request",
        lambda _req: "B",
    )
    monkeypatch.setattr(
        "traffic_generation.batch_validate_http_rules.build_raw_http_text_request_from_clauses",
        lambda _clauses, sid="": b"C",
    )

    attempts = build_fallback_attempts(rule, "http://x")
    assert attempts == [("sticky", b"A"), ("recoverable_raw", b"B"), ("raw_text", b"C")]
