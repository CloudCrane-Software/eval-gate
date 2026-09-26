# coding: utf-8
"""eval-gate — 公司级评测门禁（WO-0004：M2 前置）.

定位（PROP-0001 v1.7 §6 / §12.9 / §4.9 #8）：**一切 Agent Release 产出物过
eval-gate 才能进 main**。三层：

- **L1 级联漏斗**   → :mod:`eval_gate.funnel`（规则 → 决策层 Score 灰区 → 大模型深分析）
- **L2 oracle 差分** → :mod:`eval_gate.oracle`（oracle 基线 vs 被测产出差分）
- **L3 门禁聚合**   → :mod:`eval_gate.gate`（GuardrailRun 协议形状，三态 fail-closed）

扫描三档（§12.9）→ :mod:`eval_gate.scan`：static / light / deep，映射为 L3 Spec 的三档 Check。
数据契约（L1↔agent_evolving）→ :mod:`eval_gate.badcase`。

三态语义（与 jiuwen-glue GuardrailRun 协议对齐，决策点唯一）：
``PASS`` / ``BLOCKED`` / ``UNKNOWN``；**任何"证据缺失/工具不可用/执行失败"一律
UNKNOWN（fail-closed，不静默放行）**。
"""
from __future__ import annotations

from .badcase import SCHEMA_VERSION, BadCaseCandidate, BadCaseValidationError
from .funnel import (
    Candidate,
    CascadeFunnel,
    DeepAnalyzer,
    FunnelResult,
    FunnelTraceStep,
    GrayZoneConfig,
    Rule,
    ScoreFn,
    load_rule_table,
)
from .gate import (
    BLOCKED,
    PASS,
    UNKNOWN,
    VERDICTS,
    CheckResult,
    CheckSpec,
    GateResult,
    GateSpec,
    aggregate,
    run_gate,
    to_protocol_dict,
)
from .oracle import DiffResult, OracleCase, OracleReport, OracleRunner, diff
from .scan import TIERS, run_tier

__version__ = "0.2.0"

__all__ = [
    # verdict 三态（唯一定义处，其余模块一律从这里引用）
    "PASS", "BLOCKED", "UNKNOWN", "VERDICTS",
    # L3
    "CheckSpec", "CheckResult", "GateSpec", "GateResult",
    "aggregate", "run_gate", "to_protocol_dict",
    # L1
    "Candidate", "Rule", "GrayZoneConfig", "CascadeFunnel", "FunnelResult",
    "FunnelTraceStep", "ScoreFn", "DeepAnalyzer", "load_rule_table",
    # L2
    "OracleCase", "DiffResult", "OracleReport", "OracleRunner", "diff",
    # 扫描三档
    "TIERS", "run_tier",
    # 数据契约
    "BadCaseCandidate", "BadCaseValidationError", "SCHEMA_VERSION",
]
