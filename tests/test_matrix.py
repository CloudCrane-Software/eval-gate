# coding: utf-8
"""oracle_suite.matrix 测试 — 配对 / 缺失 case / 空输入 / markdown 形状（全离线）."""
import pytest

from eval_gate.gate import BLOCKED, PASS, UNKNOWN

from oracle_suite.matrix import DEFAULT_IGNORE_PATHS, DiffMatrix
from oracle_suite.recorder import InteractionRecorder


def _rec(case_id: str, content: str, **metadata_overrides):
    """造一条记录：两次批次的内容差异只应来自 content 参数。"""
    recorder = InteractionRecorder(tenant_id="t")
    return recorder.record(
        {"method": "POST", "url": "https://example.invalid/v1", "headers": {},
         "body": {"prompt": case_id}},
        {"status": 200, "body": {"content": content}},
        model="step-3.5-flash", endpoint_ref="https://example.invalid/v1",
        latency_ms=metadata_overrides.get("latency_ms", 100.0),
        tokens=metadata_overrides.get("tokens"),
        case_id=case_id,
    )


def test_identical_records_match_pass():
    a = [_rec("c1", "same")]
    b = [_rec("c1", "same", latency_ms=999.0)]  # latency 属剥除字段，不影响
    matrix = DiffMatrix.build(a, b, run_id="run-test")
    assert matrix.verdict == PASS
    assert matrix.matched == 1 and matrix.mismatched == 0 and matrix.missing == 0
    row = matrix.rows[0]
    assert (row.case_id, row.status, row.verdict) == ("c1", "match", PASS)
    assert row.differences == ()


def test_response_diff_blocked_with_oracle_shape_paths():
    a = [_rec("c1", "answer-v1")]
    b = [_rec("c1", "answer-v2")]
    matrix = DiffMatrix.build(a, b)
    assert matrix.verdict == BLOCKED
    row = matrix.rows[0]
    assert row.status == "diff" and row.verdict == BLOCKED
    assert any("response" in d and "body" in d and "content" in d
               for d in row.differences)  # 差异路径形状同 eval_gate.oracle


def test_missing_cases_unknown_fail_closed():
    a = [_rec("only-a", "x"), _rec("both", "y")]
    b = [_rec("only-b", "z"), _rec("both", "y")]
    matrix = DiffMatrix.build(a, b)
    statuses = {r.case_id: (r.status, r.verdict) for r in matrix.rows}
    assert statuses["only-a"] == ("missing_in_b", UNKNOWN)
    assert statuses["only-b"] == ("missing_in_a", UNKNOWN)
    assert statuses["both"] == ("match", PASS)
    assert matrix.verdict == UNKNOWN  # 有缺失=证据不全，fail-closed 不放行


def test_diff_beats_unknown_in_aggregation():
    a = [_rec("c1", "v1"), _rec("only-a", "x")]
    b = [_rec("c1", "v2"), _rec("only-b", "y")]
    matrix = DiffMatrix.build(a, b)
    assert matrix.mismatched == 1 and matrix.missing == 2
    assert matrix.verdict == BLOCKED  # 一票否决优先于 UNKNOWN（聚合语义同 L3）


def test_empty_batches_unknown():
    matrix = DiffMatrix.build([], [])
    assert matrix.rows == () and matrix.verdict == UNKNOWN
    assert matrix.count_a == 0 and matrix.count_b == 0


def test_case_id_fallback_to_record_id_and_unpairable():
    rec = InteractionRecorder(tenant_id="t").record(
        {"headers": {}}, {"status": 200}, model="m")
    other = dict(rec.to_dict())
    other["record_id"] = "different-id"
    matrix = DiffMatrix.build([rec], [other])
    assert matrix.missing == 2
    assert matrix.verdict == UNKNOWN


def test_volatile_fields_do_not_produce_diff():
    a = [_rec("c1", "same", latency_ms=50.0, tokens={"total_tokens": 10})]
    b = [_rec("c1", "same", latency_ms=5000.0, tokens={"total_tokens": 99})]
    matrix = DiffMatrix.build(a, b)
    assert matrix.verdict == PASS
    assert "metadata.latency_ms" in DEFAULT_IGNORE_PATHS
    assert "metadata.tokens" in DEFAULT_IGNORE_PATHS


def test_accepts_dict_records_too():
    a = [_rec("c1", "same").to_dict()]
    b = [{"record_id": "r2", "interaction_schema": "v1",
          "created_at": "2026-09-26T08:00:00+00:00",
          "request": {"method": "POST", "url": "https://example.invalid/v1",
                      "headers": {}, "body": {"prompt": "c1"}},
          "response": {"status": 200, "body": {"content": "same"}},
          "metadata": {"case_id": "c1", "model": "step-3.5-flash",
                       "endpoint_ref": "https://example.invalid/v1",
                       "latency_ms": 1.0, "ts": "2026-09-26T08:00:00+00:00",
                       "tenant_id": "t", "labels": []}}]
    matrix = DiffMatrix.build(a, b)
    assert matrix.verdict == PASS


def test_to_markdown_shape_and_escaping():
    a = [_rec("c-ok", "same"), _rec("c-bad", "v1")]
    b = [_rec("c-ok", "same"), _rec("c-bad", "v2"), _rec("c-extra", "only-b")]
    matrix = DiffMatrix.build(a, b, run_id="run-2026-09")
    md = matrix.to_markdown()
    assert md.startswith("# 差异矩阵（run `run-2026-09`）")
    assert "| case_id | status | verdict | differences |" in md
    assert "c-bad | diff | BLOCKED" in md
    assert "c-extra | missing_in_a | UNKNOWN" in md
    assert "verdict=" + matrix.verdict in md
    assert matrix.count_a == 2 and matrix.count_b == 3


def test_to_dict_shape():
    matrix = DiffMatrix.build([_rec("c1", "x")], [_rec("c1", "x")], run_id="r1")
    d = matrix.to_dict()
    assert d["run_id"] == "r1" and d["verdict"] == PASS
    assert d["rows"][0]["differences"] == []
    assert "matched" in d and "mismatched" in d and "missing" in d
