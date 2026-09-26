# coding: utf-8
"""L1 级联漏斗 — 规则（便宜）→ 决策层 Score 灰区（中等）→ 大模型深分析（贵）.

规格来源（PROP-0001 v1.6 §6 / v1.7 §6、§12.9；决策层 Score 归 jiuwen-glue 侧
WO-0010，本仓只定义注入点与灰区阈值）:

级联顺序与短路语义（**写死**，见 tests/test_funnel.py）:

1. **规则层**：按声明顺序逐条求值（便宜，声明式规则表 match → verdict），
   **第一条命中的规则给出最终判定并短路**——不再求值其余规则、不进 Score/深分析；
2. **Score 层**：无规则命中时求 ``score_fn(candidate)``（决策层注入，本仓不实现）；
   ``score >= block_above`` → ``BLOCKED``；``score <= pass_below`` → ``PASS``；
   落在灰区 → 升级第 3 层；
3. **深分析层**：``deep_analyzer(candidate)``（大模型接口注入，本仓不内置调用——
   决策点唯一：模型推理在这里被调用，但"允不允许"仍由三态聚合决定）；
   未注入深分析器 → ``UNKNOWN``（fail-closed）。

fail-closed 汇总：无规则命中且未注入 score_fn → ``UNKNOWN``；score 非数值/NaN →
``UNKNOWN``；深分析返回非法判定值 → ``UNKNOWN``。任何一层都不得静默放行。
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .gate import BLOCKED, PASS, UNKNOWN, VERDICTS, coerce_verdict

ScoreFn = Callable[["Candidate"], float]
DeepAnalyzer = Callable[["Candidate"], str]


@dataclass(frozen=True)
class Candidate:
    """变更 / badcase 候选：被检对象的最小抽象。

    ``payload`` 是被检内容（如代码 diff、skill 包描述、优化产物摘要）；
    ``metadata`` 是旁证（来源工单、trace 引用等），规则可读但不作为 match 主对象。
    """

    candidate_id: str
    kind: str                                    # "code_change" / "badcase" / "skill" / ...
    payload: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    """声明式规则表的一行：match → verdict（命中即短路）。"""

    rule_id: str
    match: Callable[[Candidate], bool]
    verdict: str                                 # 三态之一；UNKNOWN 规则 = "此类我看不了"（fail-closed）
    description: str = ""
    severity: str = "medium"

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id must be non-empty")
        if self.verdict not in VERDICTS:
            raise ValueError(f"rule {self.rule_id!r}: verdict must be one of "
                             f"{sorted(VERDICTS)}, got {self.verdict!r}")


# ── 灰区阈值 ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GrayZoneConfig:
    """Score 灰区阈值：``score <= pass_below`` 放行；``score >= block_above`` 否决；
    两者之间 = 灰区，升级深分析。``pass_below`` 不得大于 ``block_above``。"""

    pass_below: float = 0.3
    block_above: float = 0.7

    def __post_init__(self) -> None:
        for name, v in (("pass_below", self.pass_below), ("block_above", self.block_above)):
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v):
                raise ValueError(f"gray zone {name} must be a finite number, got {v!r}")
        if self.pass_below > self.block_above:
            raise ValueError("gray zone misconfigured: pass_below > block_above "
                             f"({self.pass_below} > {self.block_above})")


@dataclass(frozen=True)
class FunnelTraceStep:
    layer: str          # "rule" / "score" / "deep" / "fail_closed"
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FunnelResult:
    candidate_id: str
    verdict: str
    decided_by: str                       # "rule:<id>" / "score" / "deep" / "fail_closed"
    score: Optional[float] = None
    matched_rule: Optional[str] = None
    trace: Tuple[FunnelTraceStep, ...] = ()


# ── 漏斗本体 ─────────────────────────────────────────────────────────────────


class CascadeFunnel:
    """级联漏斗：规则表 + 可选 Score 注入 + 可选深分析注入。

    短路语义在 :meth:`evaluate` 内实现且有测试锁定，调用方不可绕过。
    """

    def __init__(self,
                 rules: Sequence[Rule] = (),
                 *,
                 score_fn: Optional[ScoreFn] = None,
                 gray_zone: Optional[GrayZoneConfig] = None,
                 deep_analyzer: Optional[DeepAnalyzer] = None) -> None:
        ids = [r.rule_id for r in rules]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate rule_id in rule table: {dupes}")
        self._rules: Tuple[Rule, ...] = tuple(rules)
        self._score_fn = score_fn
        self._gray = gray_zone or GrayZoneConfig()
        self._deep = deep_analyzer

    @property
    def rules(self) -> Tuple[Rule, ...]:
        return self._rules

    def evaluate(self, candidate: Candidate) -> FunnelResult:
        trace: List[FunnelTraceStep] = []
        # ── 第 1 层：规则（命中即短路） ──
        for rule in self._rules:
            hit = bool(rule.match(candidate))
            trace.append(FunnelTraceStep("rule", {"rule_id": rule.rule_id, "matched": hit}))
            if hit:
                verdict = coerce_verdict(rule.verdict)
                return FunnelResult(
                    candidate_id=candidate.candidate_id, verdict=verdict,
                    decided_by=f"rule:{rule.rule_id}", matched_rule=rule.rule_id,
                    trace=tuple(trace))
        # ── 第 2 层：决策层 Score（注入点） ──
        if self._score_fn is None:
            trace.append(FunnelTraceStep("fail_closed", {
                "reason": "no rule matched and no score_fn configured"}))
            return FunnelResult(candidate_id=candidate.candidate_id, verdict=UNKNOWN,
                                decided_by="fail_closed", trace=tuple(trace))
        raw_score = self._score_fn(candidate)
        trace.append(FunnelTraceStep("score", {"score": repr(raw_score)}))
        if not isinstance(raw_score, (int, float)) or isinstance(raw_score, bool) \
                or not math.isfinite(float(raw_score)):
            trace.append(FunnelTraceStep("fail_closed", {
                "reason": f"score_fn returned non-finite/non-numeric score: {raw_score!r}"}))
            return FunnelResult(candidate_id=candidate.candidate_id, verdict=UNKNOWN,
                                decided_by="fail_closed", trace=tuple(trace))
        score = float(raw_score)
        if score >= self._gray.block_above:
            return FunnelResult(candidate_id=candidate.candidate_id, verdict=BLOCKED,
                                decided_by="score", score=score, trace=tuple(trace))
        if score <= self._gray.pass_below:
            return FunnelResult(candidate_id=candidate.candidate_id, verdict=PASS,
                                decided_by="score", score=score, trace=tuple(trace))
        # ── 灰区 → 第 3 层：深分析（注入点，本仓不内置大模型调用） ──
        trace.append(FunnelTraceStep("deep", {"entered": True, "configured": self._deep is not None}))
        if self._deep is None:
            trace.append(FunnelTraceStep("fail_closed", {
                "reason": "gray zone but no deep_analyzer configured"}))
            return FunnelResult(candidate_id=candidate.candidate_id, verdict=UNKNOWN,
                                decided_by="fail_closed", score=score, trace=tuple(trace))
        raw = self._deep(candidate)
        verdict = coerce_verdict(raw)
        if verdict == UNKNOWN:
            trace.append(FunnelTraceStep("fail_closed", {
                "reason": f"deep analyzer returned non-canonical verdict: {raw!r}"}))
        return FunnelResult(candidate_id=candidate.candidate_id, verdict=verdict,
                            decided_by="deep", score=score, trace=tuple(trace))


# ── 声明式规则表加载（配置驱动，match 不需要写 Python 回调） ────────────────────


def _payload_get(payload: Mapping[str, Any], dotted: str) -> Tuple[bool, Any]:
    """按 a.b.c 取 payload 字段；返回 (found, value)。"""
    cur: Any = payload
    for part in dotted.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


_OPS = ("equals", "contains", "regex", "exists", "in")


def _make_matcher(spec: Mapping[str, Any]) -> Callable[[Candidate], bool]:
    if "field" not in spec or "op" not in spec:
        raise ValueError(f"declarative match needs 'field' and 'op', got {dict(spec)!r}")
    dotted, op = str(spec["field"]), str(spec["op"])
    if op not in _OPS:
        raise ValueError(f"unknown match op {op!r} (supported: {_OPS})")
    value = spec.get("value")

    def match(candidate: Candidate) -> bool:
        found, actual = _payload_get(candidate.payload, dotted)
        if op == "exists":
            return found == bool(value) if isinstance(value, bool) else found
        if not found:
            return False
        try:
            if op == "equals":
                return actual == value
            if op == "contains":
                return isinstance(actual, (str, list, tuple)) and value in actual
            if op == "in":
                return actual in value  # type: ignore[operator]
            if op == "regex":
                return isinstance(actual, str) and re.search(str(value), actual) is not None
        except TypeError:
            return False
        return False

    return match


def load_rule_table(specs: Sequence[Mapping[str, Any]]) -> List[Rule]:
    """从声明式 spec 列表构建规则表（顺序即级联优先级，前者更便宜/更优先）.

    每条 spec: ``{rule_id, verdict, match: {field, op, value?}, description?, severity?}``；
    match 也允许直接给 ``callable``（代码规则），两种形态可混排。
    """
    rules: List[Rule] = []
    for i, spec in enumerate(specs):
        if "rule_id" not in spec or "verdict" not in spec:
            raise ValueError(f"rule table spec #{i} needs rule_id and verdict")
        m = spec.get("match")
        if isinstance(m, Mapping):
            matcher = _make_matcher(m)
        elif callable(m):
            matcher = m
        else:
            raise ValueError(f"rule {spec['rule_id']!r}: match must be a mapping or callable")
        rules.append(Rule(rule_id=str(spec["rule_id"]), match=matcher,
                          verdict=str(spec["verdict"]),
                          description=str(spec.get("description", "")),
                          severity=str(spec.get("severity", "medium"))))
    return rules
