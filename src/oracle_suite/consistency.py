# coding: utf-8
"""语义一致性测试骨架 — 交互记录不变式检查，违规产出 badcase 候选（PROP-0006）.

规格来源（PROP-0001 v1.7 §14 PROP-0006"语义一致性测试"；v1.6 §6 数据循环——
badcase 候选契约对齐 ``eval_gate.badcase.BadCaseCandidate``，落 eval-assets 私有仓）:

- :class:`Invariant`：一条不变式 = 稳定名 + 检查函数（``record dict -> Optional[str]``，
  ``None``=通过，非空 str=违规描述）；
- 内置不变式工厂：:func:`schema_is_v1` / :func:`has_model_field` /
  :func:`latency_under` / :func:`no_redact_residue` / :func:`response_nonempty`；
- :func:`check`：对单条交互记录逐条跑不变式 → :class:`ConsistencyReport`
  （三态聚合语义同 L3：一票否决 BLOCKED；不变式抛异常 = 证据缺失 UNKNOWN，
  不静默放行）；
- :func:`to_badcase_candidates`：把报告中的违规转成 :class:`BadCaseCandidate`
  （``source="l2_oracle"``，labels 挂 ``oracle-suite/consistency/<不变式>``，
  evidence 只存引用——record_id + 不变式 + 描述，不复制记录正文）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from eval_gate.badcase import BadCaseCandidate
from eval_gate.gate import BLOCKED, PASS, UNKNOWN

from .recorder import INTERACTION_SCHEMA, InteractionRecord, scan_for_secrets

ConsistencyCheck = Callable[[Mapping[str, Any]], Optional[str]]


@dataclass(frozen=True)
class Invariant:
    """一条不变式：``name`` 稳定（进 labels/candidate_id），``check`` 返回 None=通过。"""

    name: str
    check: ConsistencyCheck
    description: str = ""


# ── 内置不变式工厂 ───────────────────────────────────────────────────────────


def schema_is_v1() -> Invariant:
    """记录必须声明 ``interaction_schema=v1``。"""
    def _check(rec: Mapping[str, Any]) -> Optional[str]:
        got = rec.get("interaction_schema")
        if got != INTERACTION_SCHEMA:
            return f"interaction_schema must be {INTERACTION_SCHEMA!r}, got {got!r}"
        return None
    return Invariant(name="record.schema_is_v1", check=_check,
                     description="记录必须声明 interaction_schema=v1")


def has_model_field() -> Invariant:
    """metadata.model 必须存在且非空（响应含 model 字段的可追溯版本）。"""
    def _check(rec: Mapping[str, Any]) -> Optional[str]:
        metadata = rec.get("metadata")
        model = metadata.get("model") if isinstance(metadata, Mapping) else None
        if not isinstance(model, str) or not model:
            return "metadata.model is missing or empty"
        return None
    return Invariant(name="metadata.has_model", check=_check,
                     description="metadata.model 必须存在且非空")


def latency_under(max_ms: float) -> Invariant:
    """metadata.latency_ms 必须存在且 < max_ms（缺失视为违规：证据不全不放行）。"""
    def _check(rec: Mapping[str, Any]) -> Optional[str]:
        metadata = rec.get("metadata")
        latency = metadata.get("latency_ms") if isinstance(metadata, Mapping) else None
        if latency is None:
            return "metadata.latency_ms is missing"
        try:
            value = float(latency)
        except (TypeError, ValueError):
            return f"metadata.latency_ms {latency!r} is not a number"
        if value >= max_ms:
            return f"metadata.latency_ms {value} >= threshold {max_ms}"
        return None
    return Invariant(name=f"metadata.latency_under_{int(max_ms)}ms", check=_check,
                     description=f"latency_ms 必须存在且 < {max_ms}ms")


def no_redact_residue() -> Invariant:
    """无 REDACT 泄漏残留：序列化后的记录不得再含 key/token/手机号形态.

    与 ``oracle_suite.recorder.scan_for_secrets`` 共用同一套模式（单一真源）；
    违规描述只含类别与次数，**不含命中值本身**。
    """
    def _check(rec: Mapping[str, Any]) -> Optional[str]:
        text = json.dumps(rec, ensure_ascii=False, default=str)
        hits = scan_for_secrets(text)
        if hits:
            by_category: Dict[str, int] = {}
            for category, _value in hits:
                by_category[category] = by_category.get(category, 0) + 1
            summary = ", ".join(f"{k}x{v}" for k, v in sorted(by_category.items()))
            return f"sensitive-pattern residue found ({summary})"
        return None
    return Invariant(name="security.no_redact_residue", check=_check,
                     description="记录序列化后不得残留 key/token/手机号形态")


def response_nonempty() -> Invariant:
    """response 必须是非空对象（空响应 = 证据缺失）。"""
    def _check(rec: Mapping[str, Any]) -> Optional[str]:
        response = rec.get("response")
        if not isinstance(response, Mapping) or not response:
            return "response is missing or empty"
        return None
    return Invariant(name="response.nonempty", check=_check,
                     description="response 必须是非空对象")


# ── 检查与报告 ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Violation:
    """一次不变式违规（或证据缺失）。"""

    invariant: str
    detail: str
    verdict: str          # BLOCKED（违规） / UNKNOWN（检查器异常=证据缺失）


@dataclass
class ConsistencyReport:
    """单条记录的语义一致性报告（三态聚合，fail-closed）。"""

    record_id: str
    total: int
    passed: int
    violations: Tuple[Violation, ...] = ()
    created_at: Optional[str] = field(default=None)

    @property
    def failed(self) -> int:
        return sum(1 for v in self.violations if v.verdict == BLOCKED)

    @property
    def errored(self) -> int:
        return sum(1 for v in self.violations if v.verdict == UNKNOWN)

    @property
    def verdict(self) -> str:
        verdicts = [v.verdict for v in self.violations]
        if BLOCKED in verdicts:
            return BLOCKED
        if UNKNOWN in verdicts or self.total == 0:
            return UNKNOWN
        return PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id, "total": self.total, "passed": self.passed,
            "failed": self.failed, "errored": self.errored, "verdict": self.verdict,
            "violations": [{"invariant": v.invariant, "detail": v.detail,
                            "verdict": v.verdict} for v in self.violations],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# 语义一致性报告（record `{self.record_id}`）",
            "",
            f"- 不变式 {self.total} 条：通过 {self.passed}，"
            f"违规 {self.failed}，异常 {self.errored} → **verdict={self.verdict}**",
            "",
        ]
        if self.violations:
            lines += ["| invariant | verdict | detail |", "| --- | --- | --- |"]
            for v in self.violations:
                detail = v.detail.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {v.invariant} | {v.verdict} | {detail} |")
        return "\n".join(lines) + "\n"


def check(record: Any, invariants: Sequence[Invariant]) -> ConsistencyReport:
    """对单条交互记录逐条跑不变式（记录可为 InteractionRecord 或 dict）.

    三态：不变式返回违规描述 → BLOCKED；不变式抛异常 → UNKNOWN（证据缺失，
    不静默放行）；否则 PASS。空不变式集 = 无证据 = UNKNOWN。
    """
    if isinstance(record, InteractionRecord):
        rec = record.to_dict()
        record_id = record.record_id
    elif isinstance(record, Mapping):
        rec = dict(record)
        record_id = str(rec.get("record_id") or "<unknown>")
    else:
        raise TypeError(f"cannot check {type(record).__name__} as an interaction record")

    violations: List[Violation] = []
    passed = 0
    for invariant in invariants:
        try:
            detail = invariant.check(rec)
        except Exception as exc:  # noqa: BLE001 — 检查器崩溃 = 证据缺失，fail-closed
            violations.append(Violation(invariant=invariant.name, verdict=UNKNOWN,
                                        detail=f"{type(exc).__name__}: {exc}"))
            continue
        if detail:
            violations.append(Violation(invariant=invariant.name, verdict=BLOCKED,
                                        detail=detail))
        else:
            passed += 1
    return ConsistencyReport(record_id=record_id, total=len(invariants),
                             passed=passed, violations=tuple(violations),
                             created_at=datetime.now(timezone.utc)
                             .isoformat(timespec="seconds"))


# ── badcase 衔接（契约对齐 eval_gate.badcase，落 eval-assets 私有仓） ────────


def _slug(name: str) -> str:
    out = []
    for ch in name.lower():
        if ch.isalnum() or ch in "_-":
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-") or "invariant"


def to_badcase_candidates(report: ConsistencyReport, *, record: Any = None,
                          domain: str = "ops",
                          source: str = "l2_oracle") -> List[BadCaseCandidate]:
    """把报告中的违规转成 BadCaseCandidate（每条违规一个候选）.

    - ``source`` 默认 ``l2_oracle``（oracle-suite 属 L2 侧产物）；
    - labels 挂归因标签树路径 ``oracle-suite/consistency/<不变式 slug>``；
    - evidence **引用不复制**：record_id + 不变式 + 违规描述，不复制记录正文；
    - candidate_id = ``bc-<yyyymmdd>-<hash8(record_id:invariant)>``，确定性可重放。
    """
    from .recorder import _hash8  # 延迟导入，内部工具复用

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    day = now[:10].replace("-", "")
    candidates: List[BadCaseCandidate] = []
    for violation in report.violations:
        digest = _hash8(f"{report.record_id}:{violation.invariant}")
        labels = [f"oracle-suite/consistency/{_slug(violation.invariant)}"]
        candidate = BadCaseCandidate(
            candidate_id=f"bc-{day}-{digest}",
            created_at=now,
            source=source,
            domain=domain,
            verdict=violation.verdict,          # BLOCKED / UNKNOWN 都在契约枚举内
            labels=labels,
            input={
                "record_id": report.record_id,
                "invariant": violation.invariant,
            },
            evidence={
                "record_ref": report.record_id,   # 引用不复制：记录本体在 eval-assets
                "invariant": violation.invariant,
                "detail": violation.detail,
                "suite": "oracle-suite/consistency",
            },
            notes=f"语义一致性不变式 {violation.invariant} 未过（{violation.verdict}）",
        )
        candidate.validate()  # 产出即校验：不合契约的候选不出本模块
        candidates.append(candidate)
    return candidates
