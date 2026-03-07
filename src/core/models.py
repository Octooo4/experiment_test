from __future__ import annotations
from typing import List, Optional, Union, Literal, Dict
from pydantic import BaseModel, Field, model_validator

# —— 你只做 HTTP 请求时，先覆盖这些 buffer 就够用
HttpBufferLiteral = Literal[
    # fallback
    "pkt",

    # request line / uri
    "http.method",
    "http.uri",
    "http.uri.raw",
    "http.request_line",
    "http.protocol",
    "http.start",

    # generic headers
    "http.header",
    "http.header.raw",
    "http.header_names",

    # named headers
    "http.host",
    "http.host.raw",
    "http.user_agent",
    "http.referer",
    "http.referer.raw",
    "http.accept",
    "http.accept_lang",
    "http.accept_enc",
    "http.connection",
    "http.content_type",
    "http.content_len",
    "http.cookie",
    "http.cookie.raw",

    # bodies
    "http.request_body",
    "http.response_body",

    # response line / status
    "http.stat_code",
    "http.stat_msg",
    "http.response_line",

    # file/body-like
    "file.data",
]

Transform = Literal[
    "to_lowercase",
    "header_lowercase",
]

class BufferSwitch(BaseModel):
    """sticky buffer：切换后续匹配作用域"""
    buffer: HttpBufferLiteral
    transforms: List[Transform] = Field(default_factory=list)

class FlowTerm(BaseModel):
    to_server: bool = False
    to_client: bool = False
    established: bool = False

class ContentMatch(BaseModel):
    raw: str
    decoded: str
    negated: bool = False

    nocase: bool = False
    fast_pattern: bool = False

    # absolute modifiers
    offset: Optional[int] = None
    depth: Optional[int] = None
    startswith: bool = False
    endswith: bool = False

    # relative modifiers (relative to previous content match)
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
    # legacy content modifier 也可能只修饰前一个 pcre
    buffer: Optional[HttpBufferLiteral] = None

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

class ReferenceItem(BaseModel):
    kind: str   # url/cve/...
    value: str

Clause = Union[
    BufferSwitch,
    ContentMatch,
    PcreMatch,
    IsDataAtMatch,
    DSizeMatch,
    BSizeMatch,
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

    # 关键：顺序语句流
    clauses: List[Clause] = Field(default_factory=list)

    flow: Optional[FlowTerm] = None

    # 可选保留（不影响匹配语义，但用于标注/回显）
    references: List[ReferenceItem] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)

class SuricataRule(BaseModel):
    header: RuleHeader
    body: RuleBody