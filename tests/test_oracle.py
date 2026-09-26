# coding: utf-8
"""L2 oracle 差分：Case / diff / 批量 runner / 报告形状."""
from __future__ import annotations

import pytest

from eval_gate.gate import BLOCKED, PASS, UNKNOWN
from eval_gate.oracle import OracleCase, OracleReport, OracleRunner, diff


def test_exact_match_passes():
    case = OracleCase(case_id="case-1", input={"x": 1}, expected={"y": 2})
    result = diff(case, {"y": 2})
    assert result.verdict == PASS and result.matched and result.differences == ()


def test_mismatch_blocks_with_structured_paths():
    case = OracleCase(case_id="case-2", input="deploy",
                      expected={"steps": [{"action": "a"}, {"action": "b"}], "ok": True})
    result = diff(case, {"steps": [{"action": "a"}, {"action": "X"}], "ok": False})
    assert result.verdict == BLOCKED
    joined = "\n".join(result.differences)
    assert "steps[1].action" in joined
    assert "ok" in joined


def test_length_and_key_differences():
    case = OracleCase(case_id="case-3", input=1, expected={"a": 1, "b": [1, 2]})
    result = diff(case, {"a": 1, "b": [1]})
    joined = "\n".join(result.differences)
    assert "length 2 != 1" in joined
    # 非确定性顺序：b 列表长度差 + a 相等
    assert result.verdict == BLOCKED


def test_missing_and_unexpected_keys():
    case = OracleCase(case_id="case-4", input=1, expected={"a": 1})
    result = diff(case, {"b": 2})
    joined = "\n".join(result.differences)
    assert "a (missing key" in joined
    assert "b (unexpected key" in joined


def test_normalizer_applied_to_both_sides():
    """规范化层消噪：时间戳/空白差异不应产生差分."""
    def norm(value):
        if isinstance(value, dict):
            return {k: norm(v) for k, v in value.items() if k != "ts"}
        return str(value).strip().lower()

    case = OracleCase(case_id="case-5", input="x", expected={"out": "  Hello ", "ts": 1},
                      normalizer=norm)
    result = diff(case, {"out": "hello", "ts": 999})
    assert result.verdict == PASS


def test_normalizer_failure_is_unknown_fail_closed():
    def broken(_):
        raise RuntimeError("boom")

    case = OracleCase(case_id="case-6", input=1, expected={"a": 1}, normalizer=broken)
    assert diff(case, {"a": 1}).verdict == UNKNOWN


def test_runner_invocation_error_is_unknown_not_interrupting_batch():
    """单案 invoke 抛异常 → 该案 UNKNOWN，批量继续（失败现场保留）."""

    def invoke(inp):
        if inp == "boom":
            raise ValueError("kaboom")
        return {"ok": True}

    report = OracleRunner([
        OracleCase(case_id="a", input="fine", expected={"ok": True}),
        OracleCase(case_id="b", input="boom", expected={"ok": True}),
        OracleCase(case_id="c", input="also-fine", expected={"ok": True}),
    ], invoke).run()
    assert (report.matched, report.errored) == (2, 1)
    assert report.verdict == UNKNOWN          # 证据缺失 → 整体 UNKNOWN
    assert report.items[1].error and "kaboom" in report.items[1].error


def test_report_verdict_blocked_wins_over_unknown():
    """差分不一致是确定性证据：BLOCKED 优先于 UNKNOWN（与 L3 聚合同语义）."""
    def invoke(inp):
        return {"v": "wrong"}

    report = OracleRunner([
        OracleCase(case_id="mismatch", input=1, expected={"v": "right"}),
        OracleCase(case_id="err", input=2, expected={"v": "right"}),
    ], invoke).run()
    assert report.verdict == BLOCKED


def test_empty_case_set_is_unknown_fail_closed():
    report = OracleRunner([], lambda i: i).run()
    assert report.verdict == UNKNOWN and report.total == 0


def test_report_shape_and_roundtrip():
    report = OracleRunner([OracleCase(case_id="a", input=1, expected={"x": 1})],
                          lambda i: {"x": 1}).run()
    data = report.to_dict()
    for key in ("run_id", "total", "matched", "mismatched", "errored", "verdict",
                "items", "created_at"):
        assert key in data
    assert data["verdict"] == PASS and data["total"] == 1
    assert data["items"][0]["case_id"] == "a"
    assert isinstance(report, OracleReport)


def test_duplicate_case_id_rejected():
    with pytest.raises(ValueError, match="duplicate case_id"):
        OracleRunner([OracleCase(case_id="a", input=1, expected=1),
                      OracleCase(case_id="a", input=2, expected=2)], lambda i: i)
