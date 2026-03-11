from core.models import RuleBody, RuleHeader, SuricataRule
from traffic_generation.validate.batch_validate_rules import emit_rule_payload


def _tcp_rule(dst_port: str = "8888") -> SuricataRule:
    return SuricataRule(
        header=RuleHeader(action="alert", protocol="tcp", src="$HOME_NET", src_port="any", direction="->", dst="$EXTERNAL_NET", dst_port=dst_port),
        body=RuleBody(msg="x", sid="1", rev="1", clauses=[]),
    )


def _udp_rule(dst_port: str = "53") -> SuricataRule:
    return SuricataRule(
        header=RuleHeader(action="alert", protocol="udp", src="$HOME_NET", src_port="any", direction="->", dst="$EXTERNAL_NET", dst_port=dst_port),
        body=RuleBody(msg="x", sid="2", rev="1", clauses=[]),
    )


def test_emit_rule_payload_tcp_retries_target_server_port(monkeypatch):
    called = []

    def _fake_send(host, port, payload, timeout=3):
        called.append(port)
        if port == 8888:
            raise OSError("connection refused")
        return len(payload)

    monkeypatch.setattr("traffic_generation.validate.batch_validate_rules.send_raw_tcp_bytes", _fake_send)
    out = emit_rule_payload(_tcp_rule("8888"), "http://127.0.0.1:80", timeout=1)

    assert out["adapter"] == "tcp_raw"
    assert out["bytes_sent"] == 1
    assert out["target_port"] == 80
    assert out["emit_error"] is None
    assert called == [8888, 80]


def test_emit_rule_payload_udp_returns_emit_error_instead_of_raising(monkeypatch):
    def _fake_send(_host, _port, _payload, timeout=3):
        raise OSError("network unreachable")

    monkeypatch.setattr("traffic_generation.validate.batch_validate_rules.send_raw_udp_bytes", _fake_send)
    out = emit_rule_payload(_udp_rule("4444"), "http://127.0.0.1:80", timeout=1)

    assert out["adapter"] == "udp_raw"
    assert out["bytes_sent"] == 0
    assert out["target_port"] == 4444
    assert "network unreachable" in (out["emit_error"] or "")
