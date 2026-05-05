"""
脆弱性データスキーマ定義
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import uuid
import json


class Language(str, Enum):
    PYTHON     = "python"
    C          = "c"
    CPP        = "cpp"
    JAVA       = "java"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PHP        = "php"
    GO         = "go"
    RUST       = "rust"
    RUBY       = "ruby"


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Exploitability(str, Enum):
    THEORETICAL = "theoretical"
    PRACTICAL   = "practical"
    CONFIRMED   = "confirmed"


class AttackType(str, Enum):
    INJECTION       = "injection"
    OVERFLOW        = "overflow"
    AUTH_BYPASS     = "auth_bypass"
    LOGIC_BUG       = "logic_bug"
    DESERIALIZATION = "deserialization"
    RCE             = "rce"
    XSS             = "xss"
    PATH_TRAVERSAL  = "path_traversal"
    SSRF            = "ssrf"
    XXE             = "xxe"
    IDOR            = "idor"
    COMPOUND        = "compound"
    SECOND_ORDER    = "second_order"


class PatchType(str, Enum):
    INPUT_VALIDATION = "input_validation"
    SANITIZATION     = "sanitization"
    REWRITE          = "rewrite"
    DISABLE_FUNCTION = "disable_function"
    ACCESS_CONTROL   = "access_control"


@dataclass
class Label:
    is_vulnerable: bool
    severity: Optional[Severity] = None
    cwe: Optional[str] = None


@dataclass
class Analysis:
    input: str
    sink: str
    flow: List[str] = field(default_factory=list)


@dataclass
class AttackModel:
    type: AttackType
    exploitability: Exploitability
    assumption: str


@dataclass
class Reasoning:
    why_vulnerable: str
    why_exploitable: str
    false_positive_risk: str


@dataclass
class AttackScenario:
    steps: List[str]
    result: str
    poc_script: Optional[str] = None  # pwntools/curlスクリプト


@dataclass
class Fix:
    patch_type: PatchType
    patched_code: str
    explanation: str


@dataclass
class Context:
    file: str
    function: str
    cross_file_refs: List[str] = field(default_factory=list)
    entry_point: Optional[str] = None
    # CodeQL結果
    codeql_confirmed: bool = False
    codeql_flow: List[str] = field(default_factory=list)
    # 複合脆弱性
    is_compound: bool = False
    compound_functions: List[str] = field(default_factory=list)


@dataclass
class VulnSample:
    code: str
    language: Language
    label: Label
    analysis: Analysis
    attack_model: AttackModel
    reasoning: Reasoning
    attack_scenario: AttackScenario
    fix: Fix
    context: Optional[Context] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "language": self.language.value,
            "code": self.code,
            "label": {
                "is_vulnerable": self.label.is_vulnerable,
                "severity": self.label.severity.value if self.label.severity else None,
                "cwe": self.label.cwe,
            },
            "analysis": {
                "input": self.analysis.input,
                "sink": self.analysis.sink,
                "flow": self.analysis.flow,
            },
            "attack_model": {
                "type": self.attack_model.type.value,
                "exploitability": self.attack_model.exploitability.value,
                "assumption": self.attack_model.assumption,
            },
            "reasoning": {
                "why_vulnerable": self.reasoning.why_vulnerable,
                "why_exploitable": self.reasoning.why_exploitable,
                "false_positive_risk": self.reasoning.false_positive_risk,
            },
            "attack_scenario": {
                "steps": self.attack_scenario.steps,
                "result": self.attack_scenario.result,
                "poc_script": self.attack_scenario.poc_script,
            },
            "fix": {
                "patch_type": self.fix.patch_type.value,
                "patched_code": self.fix.patched_code,
                "explanation": self.fix.explanation,
            },
            "context": {
                "file": self.context.file,
                "function": self.context.function,
                "cross_file_refs": self.context.cross_file_refs,
                "entry_point": self.context.entry_point,
                "codeql_confirmed": self.context.codeql_confirmed,
                "codeql_flow": self.context.codeql_flow,
                "is_compound": self.context.is_compound,
                "compound_functions": self.context.compound_functions,
            } if self.context else None,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
