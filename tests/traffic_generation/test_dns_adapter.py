from core.models import BufferSwitch, ContentMatch, DnsOpcodeMatch, DnsRrtypeMatch, FlowTerm, RuleBody, RuleHeader, SuricataRule
from traffic_generation.adapters.dns_adapter import build_dns_for_rule
from traffic_generation.validate.batch_validate_rules import choose_rule_adapter


def _rule(*, protocol: str = "dns", clauses: list[object], to_client: bool = False) -> SuricataRule:
    return SuricataRule(
        header=RuleHeader(action="alert", protocol=protocol, src="any", src_port="any", direction="->", dst="any", dst_port="any"),
        body=RuleBody(sid="100", flow=FlowTerm(to_server=not to_client, to_client=to_client), clauses=clauses),
    )


def test_choose_dns_adapter_by_protocol():
    r = _rule(clauses=[ContentMatch(raw="x", decoded="x")])
    assert choose_rule_adapter(r) == "dns"


def test_choose_dns_adapter_by_sticky_buffer_without_dns_protocol():
    r = _rule(protocol="udp", clauses=[BufferSwitch(buffer="dns.query"), ContentMatch(raw="google.com", decoded="google.com")])
    assert choose_rule_adapter(r) == "dns"


def test_dns_build_udp_query():
    r = _rule(clauses=[BufferSwitch(buffer="dns.query"), ContentMatch(raw="google.com", decoded="google.com"), DnsRrtypeMatch(rrtype="A"), DnsOpcodeMatch(opcode=0)])
    out = build_dns_for_rule(r)
    assert out["adapter"] == "dns"
    assert out["transport"] == "udp"
    assert out["payload"]
    assert out["qtype"] == 1


def test_dns_response_rule_skips():
    r = _rule(to_client=True, clauses=[BufferSwitch(buffer="dns.answers.rrname"), ContentMatch(raw="example.com", decoded="example.com")])
    out = build_dns_for_rule(r)
    assert out["status"] == "SKIPPED"
    assert out["skip_reason"] == "SKIP_DNS_RESPONSE_NOT_SUPPORTED"
