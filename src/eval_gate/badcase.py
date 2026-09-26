# coding: utf-8
"""badcase 候选 — L1↔agent_evolving 数据契约（"评测产数据、优化吃数据、门禁管准入"）.

规格来源（PROP-0001 v1.6 §6 数据循环、§4.9 #8；文档全文见
docs/data-contract-agent-evolving.md）:

数据流（**单向，准入归 eval-gate**）::

    eval-gate(L1/L2/L3) ──BadCaseCandidate──▶ eval-assets(CNB 私有仓, 落库)
        ▲                                          │
        │                                          ▼
        └──── 产出物回 eval-gate 过门禁 ◀── gpumachine(agent_evolving 消费优化)

- ``labels`` 是 **归因标签树路径**（如 ``"security/secret-leak"``），是 PROP-0011
  扫描规则库的生长接口：同标签 badcase 累计 → 生成 semgrep 规则草案 → 新规则本身
  过 eval-gate 自身 L1 准入（见 packs/README.md）；
- ``to_json_schema()`` 生成 JSON Schema（draft 2020-12），是跨仓/跨机的落库契约；
  本模块自带一份不依赖第三方库的最小校验器（jsonschema 包不是依赖）；
- 候选只进 eval-assets（私有仓），**永远不直接进 main**——进 main 的必须是
  优化产出物过完 L1/L3 之后的版本。
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping

from .gate import VERDICTS

SCHEMA_VERSION = "1.0"

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_LABEL_PATTERN = r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$"
_SOURCES = ("l1_funnel", "l2_oracle", "l3_gate", "human", "external")


class BadCaseValidationError(ValueError):
    """候选未过最小校验（附全部错误，不是首错即停）。"""

    def __init__(self, errors: List[str]) -> None:
        self.errors = list(errors)
        super().__init__("badcase validation failed: " + "; ".join(self.errors))


@dataclass
class BadCaseCandidate:
    """badcase 候选（评测侧产出的失败样本，供优化消费的原子单位）。"""

    candidate_id: str
    created_at: str                      # ISO 8601 UTC，如 2026-09-26T08:00:00+00:00
    source: str                          # l1_funnel / l2_oracle / l3_gate / human / external
    domain: str                          # "code" / "video" / "ops" / ...（小写短横线词）
    verdict: str                         # 产生该候选时的门禁判定（三态）
    labels: List[str] = field(default_factory=list)   # 归因标签树路径（可多条）
    input: Dict[str, Any] = field(default_factory=dict)   # 触发失败的输入/上下文
    expected: Any = None                 # oracle 基线期望（无则 None）
    actual: Any = None                   # 被测实际产出（无则 None）
    evidence: Dict[str, Any] = field(default_factory=dict)
    # evidence 建议键：trace_ref（Langfuse trace id 只作引用）、guardrail_run_id、
    # oracle_run_id、diff_paths、tool、rule_id——引用不复制状态（v1.6 4.9 #10 同构）
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    # ── 校验（最小契约，不依赖 jsonschema 包） ────────────────────────────

    def validate(self) -> None:
        errors: List[str] = []
        if self.schema_version != SCHEMA_VERSION:
            errors.append(f"schema_version must be {SCHEMA_VERSION!r}, got {self.schema_version!r}")
        if not re.match(_ID_PATTERN, self.candidate_id or ""):
            errors.append(f"candidate_id {self.candidate_id!r} does not match {_ID_PATTERN}")
        try:
            datetime.fromisoformat((self.created_at or "").replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"created_at {self.created_at!r} is not ISO 8601 datetime")
        if self.source not in _SOURCES:
            errors.append(f"source {self.source!r} not in {_SOURCES}")
        if not re.match(r"^[a-z0-9][a-z0-9-]*$", self.domain or ""):
            errors.append(f"domain {self.domain!r} must be a lowercase/dash token")
        if self.verdict not in VERDICTS:
            errors.append(f"verdict {self.verdict!r} not in {sorted(VERDICTS)}")
        if not isinstance(self.labels, list):
            errors.append("labels must be a list")
        else:
            for lb in self.labels:
                if not re.match(_LABEL_PATTERN, lb or ""):
                    errors.append(f"label {lb!r} does not match tag-tree path {_LABEL_PATTERN}")
        if not isinstance(self.input, dict):
            errors.append("input must be an object")
        if not isinstance(self.evidence, dict):
            errors.append("evidence must be an object")
        if errors:
            raise BadCaseValidationError(errors)

    # ── 序列化 ────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BadCaseCandidate":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    # ── 与漏斗的衔接 ──────────────────────────────────────────────────────

    def to_funnel_candidate(self):
        """转成 L1 级联漏斗的 :class:`eval_gate.funnel.Candidate`（延迟导入防环）。"""
        from .funnel import Candidate
        return Candidate(candidate_id=self.candidate_id, kind="badcase",
                         payload=self.to_dict(), metadata={"source": self.source,
                                                           "domain": self.domain})

    # ── JSON Schema（落库契约的权威表达） ─────────────────────────────────

    @staticmethod
    def to_json_schema() -> Dict[str, Any]:
        """生成 JSON Schema draft 2020-12（全文导出见 docs/data-contract-agent-evolving.md）。"""
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://raw.githubusercontent.com/CloudCrane-Software/eval-gate/main/docs/schemas/badcase-candidate-1.0.json",
            "title": "BadCaseCandidate",
            "description": "eval-gate ↔ agent_evolving 的 badcase 候选契约 v1.0"
                           "（评测产数据、优化吃数据、门禁管准入；PROP-0001 v1.6 §6）",
            "type": "object",
            "additionalProperties": False,
            "required": ["schema_version", "candidate_id", "created_at", "source",
                         "domain", "verdict", "labels", "input"],
            "properties": {
                "schema_version": {"const": SCHEMA_VERSION},
                "candidate_id": {"type": "string", "pattern": _ID_PATTERN},
                "created_at": {"type": "string", "format": "date-time"},
                "source": {"enum": list(_SOURCES)},
                "domain": {"type": "string",
                           "pattern": "^[a-z0-9][a-z0-9-]*$",
                           "examples": ["code", "video", "ops"]},
                "verdict": {"enum": sorted(VERDICTS)},
                "labels": {
                    "type": "array",
                    "items": {"type": "string", "pattern": _LABEL_PATTERN},
                    "description": "归因标签树路径（PROP-0011 生长接口），如 security/secret-leak",
                },
                "input": {"type": "object",
                          "description": "触发失败的输入/上下文（脱敏后）"},
                "expected": {},
                "actual": {},
                "evidence": {
                    "type": "object",
                    "description": "引用而非复制：trace_ref/guardrail_run_id/oracle_run_id/diff_paths",
                },
                "notes": {"type": "string"},
            },
        }

    @staticmethod
    def to_json_schema_text(*, indent: int = 2) -> str:
        return json.dumps(BadCaseCandidate.to_json_schema(), ensure_ascii=False, indent=indent)
