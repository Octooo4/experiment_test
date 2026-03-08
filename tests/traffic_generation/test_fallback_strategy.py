from traffic_generation.batch_validate_http_rules import should_try_legacy_fallback


def test_fallback_strategy_allows_known_builders():
    assert should_try_legacy_fallback("sticky") is True
    assert should_try_legacy_fallback("recoverable_raw") is True
    assert should_try_legacy_fallback("raw_text") is True


def test_fallback_strategy_rejects_unknown_builder():
    assert should_try_legacy_fallback("plan_only_custom") is False
