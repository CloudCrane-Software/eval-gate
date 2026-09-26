# coding: utf-8
"""oracle_suite.consistency 测试 — 不变式三态 / 泄漏残留 / badcase 契约（全离线）."""
import pytest

from eval_gate.badcase import BadCaseCandidate
from eval_gate.gate import BLOCKED, PASS, UNKNOWN

from oracle_suite.consistency import (
    Invariant,
    check,
    has_model_field,
    latency_under,
    no_redact_residue,
    response_nonempty,
    schema_is_v1,
    to_badcase_candidates,
)
from oracle_suite.recorder import InteractionRecorder

SK_VALUE = "sk" + "-" + "abcd" * 6  # 运行期拼装的假密钥（形态匹配，非真实凭据）

ALL_INVARIANTS = [schema_is_v1(), has_model_field(), latency_under(60000),
                  no_redact_residue(), response_nonempty()]


def _good_record(**overrides):
    kwargs = dict(model="step-3.5-flash", latency_ms=1234.0)
    kwargs.update(overrides)
    return InteractionRecorder(tenant_id="prop-0006").record(
        {"method": "POST", "url": "https://example.invalid/v1", "headers": {},
         "body": {"model": "step-3.5-flash"}},
        {"status": 200, "body": {"content": "幂等性：执行多次与一次效果相同。"}},
        endpoint_ref="https://example.invalid/v1",
        case_id="case-001", **kwargs)


def violation_of(report, name):
    matches = [v for v in report.violations if v.invariant == name]
    assert len(matches) == 1, report.to_dict()
    return matches[0]


# ── 1. 全过 / 各违规路径 ──────────────────────────────────────────────────────

def test_good_record_passes_all_invariants():
    report = check(_good_record(), ALL_INVARIANTS)
    assert report.verdict == PASS
    assert report.total == 5 and report.passed == 5
    assert report.violations == ()


def test_missing_model_blocked():
    record = _good_record(model="")
    report = check(record, [has_model_field()])
    assert report.verdict == BLOCKED
    assert violation_of(report, "metadata.has_model").detail == \
        "metadata.model is missing or empty"


def test_latency_over_threshold_blocked_and_missing_latency_blocked():
    report = check(_good_record(latency_ms=61000.0), [latency_under(60000)])
    v = violation_of(report, "metadata.latency_under_60000ms")
    assert v.verdict == BLOCKED and "61000.0 >= threshold 60000" in v.detail
    report2 = check({"metadata": {}}, [latency_under(60000)])
    assert report2.verdict == BLOCKED
    assert "missing" in violation_of(report2, "metadata.latency_under_60000ms").detail


def test_empty_response_blocked():
    report = check({"response": {}}, [response_nonempty()])
    assert report.verdict == BLOCKED


def test_wrong_schema_blocked():
    report = check({"interaction_schema": "v0"}, [schema_is_v1()])
    assert report.verdict == BLOCKED


# ── 2. 泄漏残留与三态 ─────────────────────────────────────────────────────────

def test_no_redact_residue_detects_raw_secret_without_echoing_it():
    record = _good_record().to_dict()
    record["response"]["body"]["note"] = "raw key: " + SK_VALUE
    report = check(record, [no_redact_residue()])
    assert report.verdict == BLOCKED
    detail = violation_of(report, "security.no_redact_residue").detail
    assert "KEY" in detail
    assert SK_VALUE not in detail           # 违规描述不回显敏感值
    # 已脱敏记录应当通过
    assert check(_good_record(), [no_redact_residue()]).verdict == PASS


def test_invariant_exception_yields_unknown():
    def boom(_rec):
        raise RuntimeError("checker exploded")
    report = check(_good_record(), [Invariant(name="x.boom", check=boom)])
    assert report.verdict == UNKNOWN
    assert report.errored == 1 and report.failed == 0


def test_empty_invariants_unknown_and_aggregate_blocked_wins():
    assert check(_good_record(), []).verdict == UNKNOWN      # 无证据不放行
    def bad(_rec):
        return "violated"
    def boom(_rec):
        raise ValueError("x")
    report = check(_good_record(), [Invariant(name="a.bad", check=bad),
                                    Invariant(name="b.boom", check=boom)])
    assert report.verdict == BLOCKED  # 一票否决优先
    assert report.failed == 1 and report.errored == 1


def test_check_accepts_interaction_record_and_dict_alike():
    record = _good_record()
    assert check(record, ALL_INVARIANTS).verdict == \
        check(record.to_dict(), ALL_INVARIANTS).verdict
    with pytest.raises(TypeError):
        check("not-a-record", ALL_INVARIANTS)


# ── 3. badcase 候选契约对齐 ───────────────────────────────────────────────────

def test_to_badcase_candidates_contract():
    record = _good_record()
    record_dict = record.to_dict()
    record_dict["metadata"].pop("model")
    record_dict["response"]["body"]["leak"] = SK_VALUE
    report = check(record_dict, ALL_INVARIANTS)
    assert report.verdict == BLOCKED

    candidates = to_badcase_candidates(report, record=record_dict, domain="ops")
    assert len(candidates) == report.failed
    for candidate in candidates:
        candidate.validate()  # 契约自检（BadCaseCandidate 最小校验器）
        assert isinstance(candidate, BadCaseCandidate)
        assert candidate.source == "l2_oracle"
        assert candidate.domain == "ops"
        assert candidate.verdict in (BLOCKED, UNKNOWN)
        assert candidate.labels and candidate.labels[0].startswith(
            "oracle-suite/consistency/")
        assert candidate.evidence["record_ref"] == record.record_id
        assert candidate.evidence["suite"] == "oracle-suite/consistency"
        assert candidate.input["record_id"] == record.record_id
        assert SK_VALUE not in candidate.to_json()  # 候选不复制记录正文
    ids = [c.candidate_id for c in candidates]
    assert len(ids) == len(set(ids))               # 不变式不同 → 候选 id 不同
    assert to_badcase_candidates(check(_good_record(), ALL_INVARIANTS)) == []


def test_report_markdown_shape():
    report = check(_good_record(), ALL_INVARIANTS)
    md = report.to_markdown()
    assert md.startswith("# 语义一致性报告")
    assert "verdict=" + PASS in md
    report_bad = check({"metadata": {}}, ALL_INVARIANTS)
    md_bad = report_bad.to_markdown()
    assert "| invariant | verdict | detail |" in md_bad
    assert "verdict=" + BLOCKED in md_bad
