# coding: utf-8
"""badcase 候选：数据契约校验 / 序列化 / JSON Schema / 与漏斗衔接."""
from __future__ import annotations

import json

import pytest

from eval_gate.badcase import (
    SCHEMA_VERSION,
    BadCaseCandidate,
    BadCaseValidationError,
)
from eval_gate.gate import BLOCKED, UNKNOWN


def valid_candidate(**overrides) -> BadCaseCandidate:
    fields = dict(
        candidate_id="bc-20260926-deadbeef",
        created_at="2026-09-26T08:30:00+00:00",
        source="l2_oracle",
        domain="code",
        verdict=BLOCKED,
        labels=["security/secret-leak"],
        input={"task": "t"},
        expected={"ok": True},
        actual={"ok": False},
        evidence={"oracle_run_id": "run-1"},
        notes="n",
    )
    fields.update(overrides)
    return BadCaseCandidate(**fields)


def test_valid_candidate_passes_validation():
    valid_candidate().validate()  # 不抛


def test_invalid_candidates_report_all_errors():
    bad = valid_candidate(candidate_id="bad id!", created_at="not-a-date",
                          source="wherever", domain="Code_Domain", verdict="ok",
                          labels=["Bad Label", "ok/path"], input="not-a-dict",
                          evidence="not-a-dict", schema_version="9.9")
    with pytest.raises(BadCaseValidationError) as exc:
        bad.validate()
    messages = "; ".join(exc.value.errors)
    for fragment in ("candidate_id", "created_at", "source", "domain", "verdict",
                     "label", "input", "evidence", "schema_version"):
        assert fragment in messages, fragment


def test_roundtrip_dict_json_and_from_dict():
    c = valid_candidate()
    assert BadCaseCandidate.from_dict(json.loads(c.to_json())).to_dict() == c.to_dict()
    assert BadCaseCandidate.from_dict(c.to_dict()).validate() is None


def test_from_dict_ignores_unknown_keys():
    data = valid_candidate().to_dict()
    data["future_field"] = 1          # 向前兼容：未知字段被忽略（契约只允许加可选字段）
    assert "future_field" not in BadCaseCandidate.from_dict(data).to_dict()


def test_json_schema_structure():
    schema = BadCaseCandidate.to_json_schema()
    assert schema["$schema"].startswith("https://json-schema.org/draft/")
    assert set(schema["required"]) == {
        "schema_version", "candidate_id", "created_at", "source", "domain",
        "verdict", "labels", "input"}
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert schema["properties"]["source"]["enum"] == [
        "l1_funnel", "l2_oracle", "l3_gate", "human", "external"]
    assert schema["properties"]["verdict"]["enum"] == ["BLOCKED", "PASS", "UNKNOWN"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["labels"]["items"]["pattern"].startswith("^")


def test_json_schema_accepts_valid_instance_minimal():
    """手写校验器与 schema 必填集一致：最小合法实例两者都过."""
    minimal = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": "bc-1",
        "created_at": "2026-09-26T00:00:00Z",
        "source": "human",
        "domain": "video",
        "verdict": UNKNOWN,
        "labels": [],
        "input": {},
    }
    BadCaseCandidate.from_dict(minimal).validate()
    schema = BadCaseCandidate.to_json_schema()
    for key in schema["required"]:
        assert key in minimal
    assert minimal["schema_version"] == schema["properties"]["schema_version"]["const"]
    assert minimal["source"] in schema["properties"]["source"]["enum"]
    assert minimal["verdict"] in schema["properties"]["verdict"]["enum"]


def test_to_funnel_candidate_payload_roundtrip():
    c = valid_candidate()
    fc = c.to_funnel_candidate()
    assert fc.kind == "badcase"
    assert fc.payload["candidate_id"] == c.candidate_id
    assert fc.metadata["domain"] == "code"
    # 漏斗可按 payload 字段声明规则命中该候选
    from eval_gate.funnel import CascadeFunnel, Rule, load_rule_table
    funnel = CascadeFunnel(rules=load_rule_table([
        {"rule_id": "deny-secret-leak", "verdict": BLOCKED,
         "match": {"field": "labels", "op": "contains", "value": "security/secret-leak"}},
    ]))
    assert funnel.evaluate(fc).verdict == BLOCKED


def test_label_path_patterns():
    valid_candidate(labels=["a", "security/secret-leak", "video/frame-quality"]).validate()
    with pytest.raises(BadCaseValidationError):
        valid_candidate(labels=["Security/Secret"]).validate()
    with pytest.raises(BadCaseValidationError):
        valid_candidate(labels=["/leading-slash"]).validate()
