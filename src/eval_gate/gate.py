# coding: utf-8
"""L3 GuardrailRun 门禁 — 公司级三态聚合（协议聚合薄层，不做检查器本体）.

规格来源（PROP-0001 v1.6 §4.1 / §4.9 #2、v1.7 §6；Handbook §3.3.2 Guardrail 语义；
数据形状与 jiuwen-glue 的 GuardrailRun 协议字段对齐）:

- 原生 core.security.guardrail 管"检查执行"（检查器本体），TeamPermissionRail 管工具级
  授权三态；**本模块只做协议聚合**：动作上下文 → 检查结果与 Evidence 验收 → 固化 →
  执行前门控查询。不新增第二个决策点。
- 聚合语义三态：``PASS`` / ``BLOCKED`` / ``UNKNOWN``，**fail-closed**：
  1. 空检查集 = 无证据 = ``UNKNOWN``（不静默放行）；
  2. 任一 ``BLOCKED`` → 整体 ``BLOCKED``（一票否决）；
  3. 否则存在 ``UNKNOWN``（工具不可用/执行失败/非法判定值）→ 整体 ``UNKNOWN``；
  4. 全部 ``PASS`` 才 ``PASS``。
- 门控消费方（CI/发布系统）在执行动作前查询本结果：只有 ``PASS`` 可继续；
  ``BLOCKED``/``UNKNOWN`` 都不得放行。
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

# ── 三态判定常量：全仓唯一真源（funnel/oracle/scan/badcase 一律从这里引用） ──
PASS = "PASS"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"
VERDICTS = frozenset({PASS, BLOCKED, UNKNOWN})


def coerce_verdict(value: Any) -> str:
    """把任意判定值收敛到三态：非法值一律 ``UNKNOWN``（fail-closed）。

    深分析/LLM/外部工具返回的奇怪字符串（None / "ok" / "blocked " 带空格等）
    不得被解释为放行——只认精确的三个大写常量。
    """
    if isinstance(value, str) and value in VERDICTS:
        return value
    return UNKNOWN


# ── Spec / Result 数据形状（字段名与 glue GuardrailRun 协议兼容） ─────────────


@dataclass(frozen=True)
class CheckSpec:
    """一条 Check 的声明（固化进 Spec，供执行方按 tool/params 分发）。"""

    check_id: str
    tier: str                 # "static" / "light" / "deep" / 自定义
    tool: str                 # "ruff" / "gitleaks" / "semgrep" / "llm_review" / "oracle" ...
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckResult:
    """一条 Check 的执行结果 + Evidence（快照式，固化后不可变）。"""

    check_id: str
    verdict: str              # 三态（非法值经 coerce_verdict 收敛为 UNKNOWN）
    tool: str = ""
    reason: Optional[str] = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", coerce_verdict(self.verdict))


@dataclass(frozen=True)
class GateSpec:
    """GuardrailRun **Spec**：动作上下文 + 固化规则（本仓内即检查清单）。

    字段名与 glue GuardrailRun 协议一致：action / resource / agent_identity_ref /
    env_ref / tenant_id / checks。身份三件（agent_identity_ref/env_ref/tenant_id）
    承接 v1.7 §12.5 三层复合身份的引用（本仓只存引用，不解析身份）。
    """

    action: str
    resource: str
    agent_identity_ref: str
    env_ref: str
    tenant_id: str
    checks: Tuple[CheckSpec, ...] = ()
    gate_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "created_at": self.created_at,
            "action": self.action,
            "resource": self.resource,
            "agent_identity_ref": self.agent_identity_ref,
            "env_ref": self.env_ref,
            "tenant_id": self.tenant_id,
            "checks": [dict(c.__dict__) for c in self.checks],
        }


@dataclass(frozen=True)
class GateResult:
    """GuardrailRun **Result**：与 Spec 同键，外加 checks 结果与整体 verdict。"""

    action: str
    resource: str
    agent_identity_ref: str
    env_ref: str
    tenant_id: str
    checks: Tuple[CheckResult, ...] = ()
    verdict: str = UNKNOWN
    reason: Optional[str] = None
    gate_id: str = ""
    decided_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "action": self.action,
            "resource": self.resource,
            "agent_identity_ref": self.agent_identity_ref,
            "env_ref": self.env_ref,
            "tenant_id": self.tenant_id,
            "checks": [dict(c.__dict__) for c in self.checks],
            "verdict": self.verdict,
            "reason": self.reason,
            "decided_at": self.decided_at,
        }


def to_protocol_dict(result: GateResult) -> Dict[str, Any]:
    """导出 glue GuardrailRun 协议形状（聚合语义一致：PASS/BLOCKED/UNKNOWN）。

    恰好暴露协议键：action / resource / agent_identity_ref / env_ref / tenant_id /
    checks / verdict（另附 reason 供审计，glue 侧可忽略）。
    """
    return {
        "action": result.action,
        "resource": result.resource,
        "agent_identity_ref": result.agent_identity_ref,
        "env_ref": result.env_ref,
        "tenant_id": result.tenant_id,
        "checks": [
            {
                "check_id": c.check_id,
                "tool": c.tool,
                "verdict": c.verdict,
                "reason": c.reason,
                "evidence": dict(c.evidence),
            }
            for c in result.checks
        ],
        "verdict": result.verdict,
        "reason": result.reason,
    }


# ── 聚合（唯一门控决策点） ────────────────────────────────────────────────────


def aggregate(checks: Iterable[CheckResult]) -> str:
    """三态聚合（与 glue 语义一致，fail-closed）.

    - 空集 / 任一 UNKNOWN / 任一非法判定值 → ``UNKNOWN``；
    - 任一 ``BLOCKED`` → ``BLOCKED``；
    - 全部 ``PASS`` → ``PASS``。
    """
    items = list(checks)
    if not items:
        return UNKNOWN                      # 无证据不放行
    verdicts = [coerce_verdict(c.verdict) for c in items]
    if BLOCKED in verdicts:
        return BLOCKED                      # 一票否决
    if UNKNOWN in verdicts:
        return UNKNOWN                      # 证据不全不放行
    return PASS


def aggregate_reason(checks: Iterable[CheckResult]) -> Optional[str]:
    """给 aggregate 的结论配一句可审计的原因（只在非 PASS 时有内容）。"""
    items = list(checks)
    if not items:
        return "no checks produced evidence (fail-closed)"
    blocked = [c.check_id for c in items if coerce_verdict(c.verdict) == BLOCKED]
    if blocked:
        return "blocked by: " + ", ".join(blocked)
    unknown = [c.check_id for c in items if coerce_verdict(c.verdict) == UNKNOWN]
    if unknown:
        return "insufficient evidence from: " + ", ".join(unknown)
    return None


def run_gate(spec: GateSpec,
             executor: Callable[[CheckSpec], CheckResult]) -> GateResult:
    """按 Spec 执行全部 Check 并聚合。**执行器崩溃不外抛**——该 Check 记
    UNKNOWN + 原因（fail-closed：门禁自身的故障不能变成放行理由）。"""
    results: List[CheckResult] = []
    for check in spec.checks:
        started = time.time()
        try:
            res = executor(check)
            if not isinstance(res, CheckResult):
                res = CheckResult(check_id=check.check_id, verdict=UNKNOWN,
                                  tool=check.tool,
                                  reason=f"executor returned non-CheckResult: {type(res).__name__}")
        except Exception as exc:  # noqa: BLE001 — 门禁不因执行器故障而放行
            res = CheckResult(check_id=check.check_id, verdict=UNKNOWN,
                              tool=check.tool,
                              reason=f"executor crashed: {type(exc).__name__}: {exc}")
        if res.duration_ms is None:
            res = CheckResult(**{**res.__dict__,
                                 "duration_ms": (time.time() - started) * 1000.0})
        results.append(res)
    verdict = aggregate(results)
    reason = aggregate_reason(results) if verdict != PASS else None
    return GateResult(
        action=spec.action, resource=spec.resource,
        agent_identity_ref=spec.agent_identity_ref, env_ref=spec.env_ref,
        tenant_id=spec.tenant_id, checks=tuple(results), verdict=verdict,
        reason=reason, gate_id=spec.gate_id)
