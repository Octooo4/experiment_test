from __future__ import annotations
from typing import List, Optional, Union, Literal, Dict
from pydantic import BaseModel, Field, model_validator

Transform = Literal[
    "to_lowercase",
    "header_lowercase",
]

class BufferSwitch(BaseModel):
    """sticky buffer：切换后续匹配作用域"""
    buffer: str
    transforms: List[Transform] = Field(default_factory=list)

class FlowTerm(BaseModel):
    to_server: bool = False
    to_client: bool = False
    established: bool = False

class ContentMatch(BaseModel):
    raw: str
    decoded: str
    negated: bool = False
    # legacy modifier may bind buffer to this specific content
    buffer: Optional[str] = None

    nocase: bool = False
    fast_pattern: bool = False

    offset: Optional[int] = None
    depth: Optional[int] = None
    startswith: bool = False
    endswith: bool = False

    distance: Optional[int] = None
    within: Optional[int] = None

    @model_validator(mode="after")
    def _validate(self):
        if self.within == 0:
            raise ValueError("within cannot be 0")
        if self.startswith and any(v is not None for v in (self.offset, self.depth, self.distance, self.within)):
            raise ValueError("startswith cannot co-exist with offset/depth/distance/within")
        return self

class PcreMatch(BaseModel):
    raw: str
    negated: bool = False
    nocase: bool = False
    buffer: Optional[str] = None

class IsDataAtMatch(BaseModel):
    offset: int
    relative: bool = False
    rawbytes: bool = False
    negated: bool = False

class DSizeMatch(BaseModel):
    op: Literal["=", ">", ">=", "<", "<=", "<>"] = "="
    a: int = 0
    b: Optional[int] = None

class BSizeMatch(BaseModel):
    op: Literal["=", ">", ">=", "<", "<=", "<>"] = "="
    a: int = 0
    b: Optional[int] = None

class DnsOpcodeMatch(BaseModel):
    opcode: int

class DnsRrtypeMatch(BaseModel):
    rrtype: str

class ReferenceItem(BaseModel):
    kind: str
    value: str

Clause = Union[
    BufferSwitch,
    ContentMatch,
    PcreMatch,
    IsDataAtMatch,
    DSizeMatch,
    BSizeMatch,
    DnsOpcodeMatch,
    DnsRrtypeMatch,
]

class RuleHeader(BaseModel):
    action: str = ""
    protocol: str = ""
    src: str = ""
    src_port: str = ""
    direction: Literal["->", "<>"] = "->"
    dst: str = ""
    dst_port: str = ""

class RuleBody(BaseModel):
    msg: str = ""
    sid: str = ""
    rev: str = ""
    clauses: List[Clause] = Field(default_factory=list)
    flow: Optional[FlowTerm] = None
    references: List[ReferenceItem] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)

class SuricataRule(BaseModel):
    header: RuleHeader
    body: RuleBody
