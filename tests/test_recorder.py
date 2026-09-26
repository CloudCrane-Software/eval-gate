# coding: utf-8
"""oracle_suite.recorder 测试 — schema / 脱敏 / 注入 redactor（全离线）.

注意：测试夹具中的"密钥"全部运行期拼装（``"sk" + "-" + ...``），字面量不命中
推送前密钥扫描模式（执行协议红线 4）。
"""
import hashlib
import json
import re
from datetime import datetime, timezone

import pytest

from oracle_suite.recorder import (
    INTERACTION_SCHEMA,
    InteractionRecord,
    InteractionRecorder,
    InteractionValidationError,
    SecretRedactor,
    default_redact_string,
    redact_tree,
    scan_for_secrets,
)

# ── 夹具：运行期拼装的假密钥（非真实凭据，仅形态匹配） ─────────────────────────
SK_VALUE = "sk" + "-" + "abcd" * 6                     # 命中 KEY 形态
GHP_VALUE = "gh" + "p_" + "0123456789abcdef012345"     # 命中 KEY 形态
PHONE_VALUE = "13812345678"                            # 命中 PHONE 形态
BEARER_TEXT = "Bear" + "er " + "AbCdEf0123456789xyz"   # 命中 TOKEN 形态（自由文本中）


def _hash8(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _fixed_clock():
    return lambda: datetime(2026, 9, 26, 8, 30, 0, tzinfo=timezone.utc)


def _recorder(**kwargs):
    kwargs.setdefault("clock", _fixed_clock())
    kwargs.setdefault("id_fn", lambda: "rec" + "0123456789abcdef")
    return InteractionRecorder(**kwargs)


def _sample_request():
    return {
        "method": "POST",
        "url": "https://example.invalid/v1/chat/completions",
        "headers": {"Content-Type": "application/json",
                    "Authorization": "Bearer " + SK_VALUE},
        "body": {"model": "step-3.5-flash",
                 "messages": [{"role": "user", "content": "用一句话说明什么是幂等性"}]},
    }


def _sample_response():
    return {"status": 200, "body": {"id": "chatcmpl-x",
                                    "choices": [{"message": {"role": "assistant",
                                                             "content": "幂等性：同一操作执行多次与执行一次效果相同。"}}]}}


# ── 1. 记录形状与 schema ──────────────────────────────────────────────────────

def test_record_shape_and_schema():
    rec = _recorder(tenant_id="prop-0006").record(
        _sample_request(), _sample_response(),
        model="step-3.5-flash", endpoint_ref="https://example.invalid/v1/chat/completions",
        latency_ms=123.4, labels=["oracle-suite/test"], case_id="case-001")
    d = rec.to_dict()
    assert d["interaction_schema"] == INTERACTION_SCHEMA == "v1"
    assert d["record_id"].startswith("rec")
    datetime.fromisoformat(d["created_at"])  # 可解析
    assert set(d) == {"record_id", "interaction_schema", "created_at",
                      "request", "response", "metadata"}
    m = d["metadata"]
    for key in ("model", "endpoint_ref", "latency_ms", "ts", "tenant_id",
                "labels", "case_id"):
        assert key in m, key
    assert m["model"] == "step-3.5-flash"
    assert m["tenant_id"] == "prop-0006"
    assert m["labels"] == ["oracle-suite/test"]
    assert m["case_id"] == "case-001"
    rec.validate()


def test_from_dict_roundtrip_and_validation_error():
    rec = _recorder().record(_sample_request(), _sample_response(), model="m")
    d = rec.to_dict()
    rec2 = InteractionRecord.from_dict(json.loads(rec.to_json()))
    assert rec2.to_dict() == d
    bad = InteractionRecord(record_id="r", interaction_schema="v2",
                            created_at="2026-09-26T00:00:00+00:00")
    with pytest.raises(InteractionValidationError) as exc:
        bad.validate()
    assert any("interaction_schema" in e for e in exc.value.errors)
    with pytest.raises(InteractionValidationError):
        InteractionRecord.from_dict({**d, "interaction_schema": "v9"})


# ── 2. 字段名层：Authorization 整体脱敏 ───────────────────────────────────────

def test_authorization_header_whole_value_redacted():
    rec = _recorder().record(_sample_request(), _sample_response(), model="m")
    auth = rec.request["headers"]["Authorization"]
    assert auth.startswith("<REDACT-FIELD:") and auth.endswith(">")
    assert _hash8("Bearer " + SK_VALUE) in auth        # 占位哈希=原整体值的 sha256 前 8 位
    assert SK_VALUE not in json.dumps(rec.to_dict())   # 原值零残留
    assert "Bear" + "er" not in auth                   # 整体替换，连 scheme 一起消失


def test_sensitive_field_names_case_insensitive_and_nested():
    tree = {"Headers": {"authorization": "x" * 5, "X-API-KEY": "y" * 5},
            "nested": [{"Token": "z" * 5, "plain": "hello"}]}
    out = redact_tree(tree)
    assert out["Headers"]["authorization"].startswith("<REDACT-FIELD:")
    assert out["Headers"]["X-API-KEY"].startswith("<REDACT-FIELD:")
    assert out["nested"][0]["Token"].startswith("<REDACT-FIELD:")
    assert out["nested"][0]["plain"] == "hello"        # 非敏感字段不受影响
    assert tree["Headers"]["authorization"] == "x" * 5  # 原树不被修改


# ── 3. 值内模式层：key / 手机号 / 自由文本 token ─────────────────────────────

def test_pattern_key_redacted_in_text():
    response = {"status": 200, "body": {"error": "invalid key: " + SK_VALUE
                                        + " / alt: " + GHP_VALUE}}
    rec = _recorder().record({"headers": {}}, response, model="m")
    text = json.dumps(rec.to_dict(), ensure_ascii=False)
    assert SK_VALUE not in text and GHP_VALUE not in text
    assert f"<REDACT-KEY:{_hash8(SK_VALUE)}>" in text
    assert f"<REDACT-KEY:{_hash8(GHP_VALUE)}>" in text


def test_phone_and_bearer_token_redacted_in_text():
    response = {"status": 200, "body": {"log": f"call 13812345678 failed; "
                                               f"retry with {BEARER_TEXT} later"}}
    rec = _recorder().record({"headers": {}}, response, model="m")
    text = json.dumps(rec.to_dict(), ensure_ascii=False)
    assert PHONE_VALUE not in text
    assert "13812345678" not in text
    assert f"<REDACT-PHONE:{_hash8(PHONE_VALUE)}>" in text
    assert f"<REDACT-TOKEN:{_hash8(BEARER_TEXT)}>" in text


def test_placeholder_is_deterministic_and_value_specific():
    a = default_redact_string("leak " + SK_VALUE + " end")
    b = default_redact_string("leak " + SK_VALUE + " end")
    c = default_redact_string("leak " + GHP_VALUE + " end")
    assert a == b                                       # 同值同占位
    assert a != c                                       # 不同值不同占位
    assert scan_for_secrets(a) == ()                    # 脱敏产物不再命中形态


def test_scan_for_secrets_categories():
    hits = scan_for_secrets(f"k={SK_VALUE} t={BEARER_TEXT} p={PHONE_VALUE} clean")
    categories = sorted(c for c, _v in hits)
    assert categories == ["KEY", "PHONE", "TOKEN"]
    assert scan_for_secrets("nothing sensitive here") == ()


# ── 4. 注入自定义 redactor ────────────────────────────────────────────────────

def test_custom_redactor_replaces_pattern_layer_but_field_layer_stays():
    def censor(value: str) -> str:
        return value.replace("secret-word", "[[CENSORED]]")

    request = {"headers": {"Authorization": "Bearer " + SK_VALUE},
               "body": {"note": "a secret-word here"}}
    rec = InteractionRecorder(redactor=censor).record(request, {"status": 200},
                                                      model="m")
    assert rec.request["body"]["note"] == "a [[CENSORED]] here"   # 模式层已接管
    assert rec.request["headers"]["Authorization"].startswith("<REDACT-FIELD:")
    assert SK_VALUE not in json.dumps(rec.to_dict())              # 字段层仍强制


def test_secret_redactor_wrapper_with_extra_patterns():
    red = SecretRedactor(extra_patterns=((re.compile(r"[A-Z]{3}-\d{4}"), "TICKET"),))
    assert red("see ABC-1234") == "see " + f"<REDACT-TICKET:{_hash8('ABC-1234')}>"
    assert red("key " + SK_VALUE) == "key " + f"<REDACT-KEY:{_hash8(SK_VALUE)}>"


# ── 5. metadata 承载与深层结构 ────────────────────────────────────────────────

def test_tokens_and_extra_metadata_carried():
    tokens = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    rec = _recorder().record(_sample_request(), _sample_response(), model="m",
                             tokens=tokens, env="test")
    assert rec.metadata["tokens"] == tokens
    assert rec.metadata["env"] == "test"


def test_redaction_deep_and_non_mutating():
    request = {"headers": {"Authorization": "Bearer " + SK_VALUE},
               "body": {"messages": [{"role": "user",
                                      "content": "phone " + PHONE_VALUE}]}}
    original = json.dumps(request)
    rec = _recorder().record(request, {"status": 200}, model="m")
    assert json.dumps(request) == original                       # 入参不变
    text = json.dumps(rec.to_dict(), ensure_ascii=False)
    assert SK_VALUE not in text and PHONE_VALUE not in text
    assert "<REDACT-FIELD:" in text and "<REDACT-PHONE:" in text


def test_validate_requires_iso_created_at():
    bad = InteractionRecord(record_id="r", interaction_schema="v1",
                            created_at="not-a-date")
    with pytest.raises(InteractionValidationError) as exc:
        bad.validate()
    assert any("created_at" in e for e in exc.value.errors)
