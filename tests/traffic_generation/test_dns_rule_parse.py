from pathlib import Path

from core.models import BufferSwitch, DnsOpcodeMatch, DnsRrtypeMatch
from traffic_generation.rule_parse import ast_to_suricata_rule, parse_rules


def test_parse_dns_keywords_to_clause_models(tmp_path: Path):
    txt = 'alert dns any any -> any any (msg:"dns"; flow:to_server; dns.query; content:"example.com"; dns.rrtype:A; dns.opcode:0; sid:1; rev:1;)\n'
    p = tmp_path / 'dns.rules'
    p.write_text(txt, encoding='utf-8')
    ast = parse_rules(p)[0]
    rule = ast_to_suricata_rule(ast)
    assert any(isinstance(c, BufferSwitch) and c.buffer == 'dns.query' for c in rule.body.clauses)
    assert any(isinstance(c, DnsRrtypeMatch) and c.rrtype == 'A' for c in rule.body.clauses)
    assert any(isinstance(c, DnsOpcodeMatch) and c.opcode == 0 for c in rule.body.clauses)
