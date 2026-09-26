# coding: utf-8
"""差异矩阵骨架 — 两次录制批次按 case_id 配对逐字段 diff（PROP-0006 月更机制雏形）.

规格来源（PROP-0001 v1.7 §14 PROP-0006"差异矩阵月更"；v1.6 §6 L2 oracle 差分）:

- :func:`DiffMatrix.build`：对批次 A / 批次 B 的交互记录按 ``metadata.case_id``
  配对（缺省回退 ``record_id``），对配对成功的记录**逐字段 diff**——直接复用
  ``eval_gate.oracle.diff``（差异路径形状完全一致，如 ``response.body.choices``）；
- 噪声治理与 oracle 同一哲学：**规范化层消噪声，比较层不特判**——易变字段
  （created_at / latency_ms / tokens / record_id 等，见 :data:`DEFAULT_IGNORE_PATHS`）
  在比较前剥掉，可传 ``ignore_paths`` 覆盖；
- 判定三态沿用 L2 语义（fail-closed）：配对且一致 = ``PASS``；配对但不一致 =
  ``BLOCKED``（确定性证据）；单侧缺失 / 空批次 = ``UNKNOWN``（证据缺失，不放行）；
- :meth:`DiffMatrix.to_markdown`：月更报告的表格形状（run 标题 + 汇总 + 逐案行）。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from eval_gate.gate import BLOCKED, PASS, UNKNOWN
from eval_gate.oracle import OracleCase, diff as oracle_diff

# 比较前剥掉的易变字段（点路径）。ts 与 created_at 同源；latency/tokens 逐次必变；
# record_id 每次录制必然不同——它们不是"行为差异"。
DEFAULT_IGNORE_PATHS: Tuple[str, ...] = (
    "record_id",
    "created_at",
    "metadata.latency_ms",
    "metadata.tokens",
    "metadata.ts",
)

_ROW_STATUS_MATCH = "match"
_ROW_STATUS_DIFF = "diff"
_ROW_STATUS_MISSING_IN_A = "missing_in_a"
_ROW_STATUS_MISSING_IN_B = "missing_in_b"


def _to_dict(record: Any) -> Dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)
    if hasattr(record, "to_dict"):
        return record.to_dict()
    raise TypeError(f"cannot use {type(record).__name__} as an interaction record")


def _strip_paths(node: Dict[str, Any], ignore_paths: Sequence[str]) -> Dict[str, Any]:
    """剥掉点路径指定的字段（返回浅拷贝链上的新结构，只拷贝被剥离的分支）."""
    out: Dict[str, Any] = dict(node)
    for path in ignore_paths:
        parts = path.split(".")
        cursor: Any = out
        for i, part in enumerate(parts[:-1]):
            if not isinstance(cursor, Mapping) or part not in cursor:
                cursor = None
                break
            cursor = cursor[part]
        if isinstance(cursor, Mapping) and parts[-1] in cursor:
            cursor.pop(parts[-1])
    return out


def _case_id_of(rec: Mapping[str, Any]) -> str:
    metadata = rec.get("metadata")
    if isinstance(metadata, Mapping):
        cid = metadata.get("case_id")
        if isinstance(cid, str) and cid:
            return cid
    rid = rec.get("record_id")
    return rid if isinstance(rid, str) and rid else "<unknown>"


@dataclass(frozen=True)
class MatrixRow:
    """矩阵单行：一个 case_id 的配对结论（verdict 三态，语义同 eval_gate.gate）。"""

    case_id: str
    status: str                       # match / diff / missing_in_a / missing_in_b
    verdict: str                      # PASS / BLOCKED / UNKNOWN
    differences: Tuple[str, ...] = () # oracle diff 差异路径（仅 diff 行非空）

    def to_dict(self) -> Dict[str, Any]:
        return {"case_id": self.case_id, "status": self.status,
                "verdict": self.verdict, "differences": list(self.differences)}


@dataclass
class DiffMatrix:
    """两次录制批次的差异矩阵（月更机制雏形：build → to_markdown 存档）。"""

    run_id: str
    rows: Tuple[MatrixRow, ...] = ()
    count_a: int = 0
    count_b: int = 0
    ignore_paths: Tuple[str, ...] = DEFAULT_IGNORE_PATHS
    created_at: Optional[str] = field(default=None)

    # ── 汇总 ──────────────────────────────────────────────────────────────

    @property
    def matched(self) -> int:
        return sum(1 for r in self.rows if r.verdict == PASS)

    @property
    def mismatched(self) -> int:
        return sum(1 for r in self.rows if r.verdict == BLOCKED)

    @property
    def missing(self) -> int:
        return sum(1 for r in self.rows if r.verdict == UNKNOWN)

    @property
    def verdict(self) -> str:
        """三态聚合（同 eval_gate.gate：一票否决 BLOCKED，缺证据 UNKNOWN）。"""
        verdicts = [r.verdict for r in self.rows]
        if BLOCKED in verdicts:
            return BLOCKED
        if UNKNOWN in verdicts or not verdicts:
            return UNKNOWN
        return PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "verdict": self.verdict,
            "count_a": self.count_a, "count_b": self.count_b,
            "matched": self.matched, "mismatched": self.mismatched,
            "missing": self.missing, "ignore_paths": list(self.ignore_paths),
            "rows": [r.to_dict() for r in self.rows],
        }

    # ── 月更报告形状 ──────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        lines = [
            f"# 差异矩阵（run `{self.run_id}`）",
            "",
            f"- 批次 A 共 {self.count_a} 条 / 批次 B 共 {self.count_b} 条"
            f"（配对 {self.matched + self.mismatched}，"
            f"仅 A {sum(1 for r in self.rows if r.status == _ROW_STATUS_MISSING_IN_B)}，"
            f"仅 B {sum(1 for r in self.rows if r.status == _ROW_STATUS_MISSING_IN_A)}）",
            f"- 比较剥除字段：`{', '.join(self.ignore_paths)}`",
            f"- 汇总：matched={self.matched} mismatched={self.mismatched} "
            f"missing={self.missing} → **verdict={self.verdict}**",
            "",
            "| case_id | status | verdict | differences |",
            "| --- | --- | --- | --- |",
        ]
        for row in self.rows:
            diffs = "; ".join(row.differences) if row.differences else "—"
            lines.append(f"| {row.case_id} | {row.status} | {row.verdict} "
                         f"| {_md_escape(diffs)} |")
        return "\n".join(lines) + "\n"

    # ── 构建 ──────────────────────────────────────────────────────────────

    @classmethod
    def build(cls, records_a: Sequence[Any], records_b: Sequence[Any], *,
              ignore_paths: Optional[Sequence[str]] = None,
              run_id: Optional[str] = None) -> "DiffMatrix":
        """按 case_id 配对两批记录并逐字段 diff（复用 ``eval_gate.oracle.diff``）.

        配对规则：``metadata.case_id`` 优先，回退 ``record_id``；两边都配上的做
        diff，单侧独有的记 missing（UNKNOWN，fail-closed）。输入可为
        InteractionRecord 或其 dict 形状。
        """
        paths = tuple(ignore_paths) if ignore_paths is not None else DEFAULT_IGNORE_PATHS
        dict_a = [_to_dict(r) for r in records_a]
        dict_b = [_to_dict(r) for r in records_b]
        map_a = {_case_id_of(r): r for r in dict_a}
        map_b = {_case_id_of(r): r for r in dict_b}

        rows: List[MatrixRow] = []
        for cid in sorted(set(map_a) | set(map_b)):
            if cid not in map_b:
                rows.append(MatrixRow(case_id=cid, status=_ROW_STATUS_MISSING_IN_B,
                                      verdict=UNKNOWN,
                                      differences=(f"case {cid!r} 只在批次 A 中",)))
                continue
            if cid not in map_a:
                rows.append(MatrixRow(case_id=cid, status=_ROW_STATUS_MISSING_IN_A,
                                      verdict=UNKNOWN,
                                      differences=(f"case {cid!r} 只在批次 B 中",)))
                continue
            content_a = _strip_paths(map_a[cid], paths)
            content_b = _strip_paths(map_b[cid], paths)
            case = OracleCase(case_id=cid, input=None, expected=content_a)
            result = oracle_diff(case, content_b)
            if result.verdict == PASS:
                rows.append(MatrixRow(case_id=cid, status=_ROW_STATUS_MATCH,
                                      verdict=PASS))
            elif result.verdict == BLOCKED:
                rows.append(MatrixRow(case_id=cid, status=_ROW_STATUS_DIFF,
                                      verdict=BLOCKED,
                                      differences=tuple(result.differences)))
            else:  # UNKNOWN（normalizer 故障等，fail-closed 透传）
                rows.append(MatrixRow(case_id=cid, status=_ROW_STATUS_DIFF,
                                      verdict=UNKNOWN,
                                      differences=(result.error or "unknown",)))
        return cls(run_id=run_id or uuid.uuid4().hex, rows=tuple(rows),
                   count_a=len(dict_a), count_b=len(dict_b), ignore_paths=paths)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
