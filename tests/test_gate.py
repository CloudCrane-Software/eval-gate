# coding: utf-8
"""L3 门禁：三态聚合 fail-closed + GuardrailRun 协议形状兼容."""
from __future__ import annotations

import pytest

from eval_gate.gate import (
    BLOCKED,
    PASS,
    UNKNOWN,
    CheckResult,
    CheckSpec,
    GateSpec,
    aggregate,
    aggregate_reason,
    coerce_verdict,
    run_gate,
    to_protocol_dict,
)

PROTOCOL_KEYS = {"action", "resource", "agent_identity_ref", "env_ref",
                 "tenant_id", "checks", "verdict"}


def make_spec(**overrides) -> GateSpec:
    fields = dict(action="merge_pr", resource="repo://eval-gate#main",
                  agent_identity_ref="agent://dev-core/inst-1",
                  env_ref="env://dev-2026-09-26", tenant_id="tenant-default",
                  checks=())
    fields.update(overrides)
    return GateSpec(**fields)


def check(vid, verdict=PASS, reason=None):
    return CheckResult(check_id=vid, verdict=verdict, tool="t", reason=reason)


# ── 聚合三态（与 glue GuardrailRun 同语义） ──────────────────────────────────


def test_aggregate_all_pass():
    assert aggregate([check("1"), check("2")]) == PASS


def test_aggregate_any_blocked_wins():
    assert aggregate([check("1"), check("2", BLOCKED), check("3", UNKNOWN)]) == BLOCKED


def test_aggregate_any_unknown_without_blocked():
    assert aggregate([check("1"), check("3", UNKNOWN)]) == UNKNOWN


def test_aggregate_empty_is_unknown_fail_closed():
    assert aggregate([]) == UNKNOWN
    assert "no checks" in (aggregate_reason([]) or "")


def test_aggregate_coerces_noncanonical_verdicts():
    weird = CheckResult(check_id="w", verdict="ok")   # 非法值
    assert weird.verdict == UNKNOWN                   # 构造时已收敛
    assert aggregate([check("1"), weird]) == UNKNOWN


def test_aggregate_reason_lists_blocked_and_unknown():
    reason = aggregate_reason([check("a", BLOCKED), check("b", UNKNOWN)])
    assert "a" in reason and "b" in reason


def test_coerce_verdict():
    assert coerce_verdict(PASS) == PASS
    assert coerce_verdict("pass") == UNKNOWN
    assert coerce_verdict(None) == UNKNOWN
    assert coerce_verdict(" BLOCKED") == UNKNOWN


# ── run_gate：执行器崩溃不外抛，fail-closed ───────────────────────────────────


def test_run_gate_happy_path():
    spec = make_spec(checks=(CheckSpec("c1", "static", "ruff"),
                             CheckSpec("c2", "light", "gitleaks")))

    def executor(cs: CheckSpec) -> CheckResult:
        return check(cs.check_id, PASS)

    result = run_gate(spec, executor)
    assert result.verdict == PASS and result.reason is None
    assert len(result.checks) == 2
    assert all(c.duration_ms is not None for c in result.checks)


def test_run_gate_executor_crash_becomes_unknown_not_exception():
    spec = make_spec(checks=(CheckSpec("c1", "deep", "semgrep"),))

    def executor(_):
        raise RuntimeError("semgrep exploded")

    result = run_gate(spec, executor)
    assert result.verdict == UNKNOWN
    assert "semgrep exploded" in result.checks[0].reason
    assert "fail" in (result.reason or "").lower() or "insufficient" in (result.reason or "")


def test_run_gate_executor_returning_garbage_is_unknown():
    spec = make_spec(checks=(CheckSpec("c1", "deep", "llm_review"),))
    result = run_gate(spec, lambda _: "looks fine")
    assert result.verdict == UNKNOWN
    assert "non-CheckResult" in result.checks[0].reason


def test_run_gate_empty_spec_is_unknown():
    result = run_gate(make_spec(), lambda _: check("x"))
    assert result.verdict == UNKNOWN


# ── 协议形状兼容（glue GuardrailRun 字段名） ─────────────────────────────────


def test_protocol_dict_has_glue_guardrailrun_shape():
    spec = make_spec(checks=(CheckSpec("c1", "static", "ruff"),))
    result = run_gate(spec, lambda cs: check(cs.check_id, BLOCKED, "leak"))
    data = to_protocol_dict(result)
    assert PROTOCOL_KEYS <= set(data)                      # 协议键齐全
    assert data["verdict"] == BLOCKED
    assert data["checks"][0]["check_id"] == "c1"
    # 与 spec 同键同值（动作上下文固化后回传）
    assert (data["action"], data["resource"], data["agent_identity_ref"],
            data["env_ref"], data["tenant_id"]) == (
        spec.action, spec.resource, spec.agent_identity_ref,
        spec.env_ref, spec.tenant_id)


def test_gate_spec_dict_roundtrip_fields():
    data = make_spec().to_dict()
    # Spec 承载动作上下文 + 检查清单（verdict 只出现在 Result 侧）
    assert (PROTOCOL_KEYS - {"verdict"}) <= set(data) and data["checks"] == []
    assert {"gate_id", "created_at"} <= set(data)
