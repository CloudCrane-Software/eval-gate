# coding: utf-8
"""L1 级联漏斗：级联顺序与短路语义（写死，见 funnel.py 模块文档）."""
from __future__ import annotations

import pytest

from eval_gate.funnel import (
    Candidate,
    CascadeFunnel,
    GrayZoneConfig,
    Rule,
    load_rule_table,
)
from eval_gate.gate import BLOCKED, PASS, UNKNOWN


def make_candidate(**payload) -> Candidate:
    return Candidate(candidate_id="c-1", kind="code_change", payload=payload or {"x": 1})


# ── 第 1 层：规则命中即短路 ───────────────────────────────────────────────────


def test_rule_hit_blocked_short_circuits_before_score():
    """规则判 BLOCKED → 短路，Score 层与深分析都不得被调用."""
    score_calls, deep_calls = [], []

    def score_fn(c):
        score_calls.append(c)
        return 0.0

    def deep(c):
        deep_calls.append(c)
        return PASS

    funnel = CascadeFunnel(
        rules=[Rule("deny-raw-secret", lambda c: "secret" in c.payload, BLOCKED)],
        score_fn=score_fn, deep_analyzer=deep)
    result = funnel.evaluate(make_candidate(secret="AKIA..."))
    assert result.verdict == BLOCKED
    assert result.decided_by == "rule:deny-raw-secret"
    assert result.matched_rule == "deny-raw-secret"
    assert score_calls == [] and deep_calls == []


def test_rule_hit_pass_short_circuits_remaining_rules():
    """规则判 PASS → 短路：后续规则（哪怕也会命中）不再求值."""
    evaluated = []

    def r1(c):
        evaluated.append("r1")
        return True

    def r2(c):
        evaluated.append("r2")
        return True

    funnel = CascadeFunnel(rules=[
        Rule("allow-docs", r1, PASS),
        Rule("deny-all", r2, BLOCKED),
    ])
    result = funnel.evaluate(make_candidate())
    assert result.verdict == PASS
    assert evaluated == ["r1"]  # r2 未被求值（短路）


def test_first_match_wins_by_declared_order():
    """同时候中多条规则：声明顺序即优先级，第一条胜出."""
    funnel = CascadeFunnel(rules=[
        Rule("rule-a", lambda c: True, PASS),
        Rule("rule-b", lambda c: True, BLOCKED),
    ])
    assert funnel.evaluate(make_candidate()).verdict == PASS
    funnel_reversed = CascadeFunnel(rules=[
        Rule("rule-b", lambda c: True, BLOCKED),
        Rule("rule-a", lambda c: True, PASS),
    ])
    assert funnel_reversed.evaluate(make_candidate()).verdict == BLOCKED


# ── 第 2 层：决策层 Score 灰区 ────────────────────────────────────────────────


def test_no_rule_score_below_pass_threshold_passes():
    deep_calls = []

    funnel = CascadeFunnel(
        rules=[Rule("never", lambda c: False, BLOCKED)],
        score_fn=lambda c: 0.1,
        deep_analyzer=lambda c: deep_calls.append(c) or BLOCKED)
    result = funnel.evaluate(make_candidate())
    assert (result.verdict, result.decided_by, result.score) == (PASS, "score", 0.1)
    assert deep_calls == []  # 未进灰区，不升级


def test_no_rule_score_above_block_threshold_blocks():
    funnel = CascadeFunnel(rules=[], score_fn=lambda c: 0.95)
    result = funnel.evaluate(make_candidate())
    assert (result.verdict, result.decided_by, result.score) == (BLOCKED, "score", 0.95)


def test_gray_zone_escalates_to_deep_analyzer():
    funnel = CascadeFunnel(
        rules=[],
        score_fn=lambda c: 0.5,                      # 灰区内（0.3 < 0.5 < 0.7）
        deep_analyzer=lambda c: BLOCKED)
    result = funnel.evaluate(make_candidate())
    assert (result.verdict, result.decided_by) == (BLOCKED, "deep")
    assert result.score == 0.5
    layers = [s.layer for s in result.trace]
    assert layers == ["score", "deep"]


def test_gray_zone_without_deep_analyzer_is_unknown_fail_closed():
    """灰区 + 未注入深分析器 → UNKNOWN（fail-closed，不静默放行）."""
    funnel = CascadeFunnel(rules=[], score_fn=lambda c: 0.5)
    result = funnel.evaluate(make_candidate())
    assert result.verdict == UNKNOWN
    assert result.decided_by == "fail_closed"


# ── fail-closed 汇总 ─────────────────────────────────────────────────────────


def test_no_rule_no_score_fn_is_unknown():
    funnel = CascadeFunnel(rules=[Rule("never", lambda c: False, BLOCKED)])
    result = funnel.evaluate(make_candidate())
    assert result.verdict == UNKNOWN and result.decided_by == "fail_closed"


def test_non_finite_score_is_unknown():
    for bad in (float("nan"), float("inf"), "0.5", None, True):
        funnel = CascadeFunnel(rules=[], score_fn=lambda c, b=bad: b)
        assert funnel.evaluate(make_candidate()).verdict == UNKNOWN, bad


def test_deep_analyzer_noncanonical_verdict_coerced_to_unknown():
    """深分析返回奇怪字符串 → 收敛 UNKNOWN（非法值不得解释为放行）."""
    for weird in ("ok", "pass", " blocked", "", None):
        funnel = CascadeFunnel(rules=[], score_fn=lambda c: 0.5,
                               deep_analyzer=lambda c, w=weird: w)
        assert funnel.evaluate(make_candidate()).verdict == UNKNOWN, weird


def test_rule_with_unknown_verdict_short_circuits_fail_closed():
    funnel = CascadeFunnel(rules=[Rule("cant-inspect", lambda c: True, UNKNOWN)])
    assert funnel.evaluate(make_candidate()).verdict == UNKNOWN
    assert funnel.evaluate(make_candidate()).decided_by.startswith("rule:")


def test_rule_verdict_must_be_canonical():
    with pytest.raises(ValueError):
        Rule("bad", lambda c: True, "ok")


def test_gray_zone_config_validation():
    with pytest.raises(ValueError):
        GrayZoneConfig(pass_below=0.9, block_above=0.1)
    with pytest.raises(ValueError):
        GrayZoneConfig(pass_below=float("nan"), block_above=0.7)
    assert GrayZoneConfig(pass_below=0.5, block_above=0.5).pass_below == 0.5  # 相等合法


def test_duplicate_rule_id_rejected():
    with pytest.raises(ValueError, match="duplicate rule_id"):
        CascadeFunnel(rules=[Rule("x", lambda c: False, PASS),
                             Rule("x", lambda c: False, BLOCKED)])


# ── 声明式规则表（配置驱动） ──────────────────────────────────────────────────


def test_load_rule_table_declarative_ops():
    table = load_rule_table([
        {"rule_id": "deny-known-bad", "verdict": BLOCKED,
         "match": {"field": "file", "op": "in", "value": ["secrets.yaml", "id_rsa"]}},
        {"rule_id": "deny-sql-string", "verdict": BLOCKED,
         "match": {"field": "diff", "op": "regex", "value": r"(?i)execute\(f"}},
        {"rule_id": "deny-mention", "verdict": BLOCKED,
         "match": {"field": "note", "op": "contains", "value": "hardcoded"}},
        {"rule_id": "allow-tests", "verdict": PASS,
         "match": {"field": "kind", "op": "equals", "value": "test"}},
        {"rule_id": "require-review", "verdict": UNKNOWN,
         "match": {"field": "reviewed", "op": "exists", "value": False}},
    ])
    funnel = CascadeFunnel(rules=table)

    assert funnel.evaluate(make_candidate(file="id_rsa")).verdict == BLOCKED
    assert funnel.evaluate(make_candidate(diff="cur.execute(f'...')")).verdict == BLOCKED
    assert funnel.evaluate(make_candidate(note="this has hardcoded value")).verdict == BLOCKED
    assert funnel.evaluate(make_candidate(kind="test")).verdict == PASS
    # reviewed 字段缺失 → require-review 规则命中 → UNKNOWN（fail-closed 由规则声明）
    assert funnel.evaluate(make_candidate(other=1)).decided_by == "rule:require-review"
    assert funnel.evaluate(make_candidate(other=1)).verdict == UNKNOWN


def test_load_rule_table_requires_field_and_op():
    with pytest.raises(ValueError):
        load_rule_table([{"rule_id": "x", "verdict": BLOCKED, "match": {"op": "equals"}}])
    with pytest.raises(ValueError):
        load_rule_table([{"rule_id": "x", "verdict": BLOCKED,
                          "match": {"field": "a", "op": "fuzzy"}}])
