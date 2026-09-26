# coding: utf-8
"""L2 oracle 差分测试 — oracle 基线 vs 被测产出，逐案差分，批量出报告.

规格来源（PROP-0001 v1.6 §6 / v1.7 §6；oracle-suite 记录器本体归 PROP-0006，
本仓只留 Case / diff / runner / 报告形状接口，供记录器后续喂入）:

- :class:`OracleCase`：input（给被测对象的输入）/ expected（oracle 基线期望）/
  normalizer（比较前的规范化，默认恒等——时间戳、排序、空白等噪声在规范化层消掉，
  不在比较层特判）；
- :func:`diff`：规范化后递归比较，产出差异路径列表（结构化，可入 badcase evidence）；
- :class:`OracleRunner`：批量执行 ``invoke(case.input)`` → 差分 → 报告。

判定三态（与 L3 聚合语义一致，fail-closed）：
- 差分一致 → ``PASS``；
- 差分不一致 → ``BLOCKED``（**确定性证据**：基线在，产出偏了）；
- 调用抛异常 → ``UNKNOWN``（无法完成评测 = 证据缺失，不静默放行）；
- 空用例集 → 报告 ``UNKNOWN``（无证据不放行）。
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .gate import BLOCKED, PASS, UNKNOWN

Invokable = Callable[[Any], Any]
Normalizer = Callable[[Any], Any]


def _identity(value: Any) -> Any:
    return value


@dataclass(frozen=True)
class OracleCase:
    """一条 oracle 用例。``normalizer`` 在比较前分别作用于 expected 与 actual。"""

    case_id: str
    input: Any
    expected: Any
    normalizer: Normalizer = _identity
    description: str = ""
    tags: Tuple[str, ...] = ()


@dataclass(frozen=True)
class DiffResult:
    """单案差分结果（verdict 三态；error 非空时必为 UNKNOWN）。"""

    case_id: str
    verdict: str
    matched: bool = False
    normalized_expected: Any = None
    normalized_actual: Any = None
    differences: Tuple[str, ...] = ()   # 结构化差异路径，如 "steps[2].action"
    error: Optional[str] = None         # invoke 抛异常时的类型+消息快照

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id, "verdict": self.verdict, "matched": self.matched,
            "differences": list(self.differences), "error": self.error,
        }


# ── 递归差分 ─────────────────────────────────────────────────────────────────


def _diff_paths(expected: Any, actual: Any, path: str, out: List[str], depth: int) -> None:
    if depth > 32:  # 防环：超过深度的引用只按相等性处理，不再下钻
        try:
            if expected == actual:
                return
        except Exception:  # noqa: BLE001 — 不可比较类型视为不等
            pass
        out.append(path or "<root>")
        return
    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        for key in sorted(set(expected) | set(actual), key=repr):
            child = f"{path}.{key}" if path else str(key)
            if key not in expected:
                out.append(f"{child} (unexpected key, actual={actual[key]!r})")
            elif key not in actual:
                out.append(f"{child} (missing key, expected={expected[key]!r})")
            else:
                _diff_paths(expected[key], actual[key], child, out, depth + 1)
        return
    if isinstance(expected, (list, tuple)) and isinstance(actual, (list, tuple)):
        if len(expected) != len(actual):
            out.append(f"{path or '<root>'} (length {len(expected)} != {len(actual)})")
        for i in range(min(len(expected), len(actual))):
            _diff_paths(expected[i], actual[i], f"{path}[{i}]" if path else f"[{i}]",
                        out, depth + 1)
        return
    try:
        equal = expected == actual
    except Exception:  # noqa: BLE001
        equal = False
    if not equal:
        out.append(f"{path or '<root>'} (expected={expected!r}, actual={actual!r})")


def diff(case: OracleCase, actual: Any) -> DiffResult:
    """规范化后差分单个产出。本函数不调用被测对象——调用发生在 runner。"""
    try:
        norm_expected = case.normalizer(case.expected)
        norm_actual = case.normalizer(actual)
        paths: List[str] = []
        _diff_paths(norm_expected, norm_actual, "", paths, 0)
        matched = not paths
        return DiffResult(case_id=case.case_id, verdict=PASS if matched else BLOCKED,
                          matched=matched, normalized_expected=norm_expected,
                          normalized_actual=norm_actual, differences=tuple(paths))
    except Exception as exc:  # noqa: BLE001 — normalizer 故障 = 证据缺失，fail-closed
        return DiffResult(case_id=case.case_id, verdict=UNKNOWN, matched=False,
                          error=f"normalizer failed: {type(exc).__name__}: {exc}")


@dataclass(frozen=True)
class OracleReport:
    """批量差分报告（形状固定，oracle-suite 记录器 PROP-0006 后续按此喂入）。"""

    run_id: str
    total: int
    matched: int
    mismatched: int
    errored: int
    verdict: str                       # 三态聚合，语义同 gate.aggregate
    items: Tuple[DiffResult, ...] = ()
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "total": self.total, "matched": self.matched,
            "mismatched": self.mismatched, "errored": self.errored,
            "verdict": self.verdict,
            "items": [i.to_dict() for i in self.items],
            "created_at": self.created_at,
        }


def _aggregate(items: Sequence[DiffResult]) -> str:
    verdicts = [i.verdict for i in items]
    if BLOCKED in verdicts:
        return BLOCKED
    if UNKNOWN in verdicts or not verdicts:
        return UNKNOWN
    return PASS


class OracleRunner:
    """批量 runner：逐案 ``actual = invoke(case.input)`` → :func:`diff` → 报告。

    单案 invoke 异常被捕获记 UNKNOWN，**不中断批量**（失败现场保留在报告 items 里）。
    """

    def __init__(self, cases: Sequence[OracleCase], invoke: Invokable,
                 *, run_id: Optional[str] = None) -> None:
        ids = [c.case_id for c in cases]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate case_id in oracle cases: {dupes}")
        self._cases: Tuple[OracleCase, ...] = tuple(cases)
        self._invoke = invoke
        self._run_id = run_id or uuid.uuid4().hex

    def run(self) -> OracleReport:
        items: List[DiffResult] = []
        for case in self._cases:
            try:
                actual = self._invoke(case.input)
            except Exception as exc:  # noqa: BLE001 — 调用失败 ≠ 差分失败，fail-closed
                items.append(DiffResult(case_id=case.case_id, verdict=UNKNOWN,
                                        matched=False,
                                        error=f"invoke failed: {type(exc).__name__}: {exc}"))
                continue
            items.append(diff(case, actual))
        return OracleReport(run_id=self._run_id, total=len(items),
                            matched=sum(1 for i in items if i.verdict == PASS),
                            mismatched=sum(1 for i in items if i.verdict == BLOCKED),
                            errored=sum(1 for i in items if i.verdict == UNKNOWN),
                            verdict=_aggregate(items), items=tuple(items))
