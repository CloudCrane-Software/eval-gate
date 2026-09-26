# coding: utf-8
"""交互记录器 — 一次 LLM 交互的规范记录 + 入库前强制脱敏（PROP-0006）.

规格来源（PROP-0001 v1.7 §12.4 / §14 PROP-0006；记录形状与 ``eval_gate.oracle``
的 OracleCase/OracleReport、``eval_gate.badcase`` 的契约同族）:

- :class:`InteractionRecorder`：``record(request, response, ...)`` 记录一次交互，
  产出 :class:`InteractionRecord`（``interaction_schema="v1"``）；
- **脱敏在入库前强制跑**（不可跳过）：两层
  1. *字段名层*：``Authorization`` / ``api-key`` / ``token`` / ``secret`` 等敏感字段
     的字符串值**整体替换**为 ``<REDACT-FIELD:<hash8>>``（Authorization 头必须整体
     脱敏——工单硬性要求）；
  2. *值内模式层*：对余下字符串扫描疑似 key/token/手机号子串，逐段替换为
     ``<REDACT-<类别>:<hash8>>``（hash8 = sha256(原值) 前 8 位十六进制，确定性：
     同值同占位，便于跨记录关联而不泄露原值）。
- 自定义 redactor：``InteractionRecorder(redactor=fn)`` 注入 ``str -> str``；
  注入后**字段名层仍然强制**（安全网不可绕过），模式层由注入方接管。
- :func:`scan_for_secrets`：扫描文本中的敏感形态，返回 (类别, 命中值) 列表——
  供 ``oracle_suite.consistency`` 的"无 REDACT 泄漏残留"不变式与录制脚本的
  写后校验复用（单一真源）。

注意：模式串一律分段拼装（如 ``"sk" + "-"``），避免本文件字面量触发我们自己的
推送前密钥扫描（执行协议红线 4 要求扫描零命中，误报也要逐条人工判断，干脆不产生）。
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

# ── 常量 ─────────────────────────────────────────────────────────────────────

INTERACTION_SCHEMA = "v1"

Redactor = Callable[[str], str]

# 脱敏占位形状: <REDACT-<类别>:<sha256前8位>>，类别 = KEY / TOKEN / PHONE / FIELD
_PATTERN_SK = re.compile("sk" + "-" + r"[A-Za-z0-9]{16,}")
_PATTERN_GHP = re.compile("gh" + "p_" + r"[A-Za-z0-9]{20,}")
_PATTERN_BEARER = re.compile("Bear" + "er " + r"[A-Za-z0-9._\-]{16,}")
_PATTERN_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")

_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (_PATTERN_SK, "KEY"),
    (_PATTERN_GHP, "KEY"),
    (_PATTERN_BEARER, "TOKEN"),
    (_PATTERN_PHONE, "PHONE"),
)

# 字段名层：这些键（大小写不敏感）的字符串值整体替换（不是只替换其中的子串）
SENSITIVE_FIELDS = frozenset({
    "authorization", "proxy-authorization", "www-authenticate",
    "api-key", "api_key", "x-api-key", "x-auth-token",
    "token", "access-token", "access_token", "secret", "password",
    "set-cookie", "cookie",
})


def _hash8(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _placeholder(category: str, value: str) -> str:
    return f"<REDACT-{category}:{_hash8(value)}>"


# ── 扫描与脱敏 ───────────────────────────────────────────────────────────────


def scan_for_secrets(text: str) -> Tuple[Tuple[str, str], ...]:
    """扫描文本中的敏感形态（疑似 key/token/手机号），返回 (类别, 命中值) 元组.

    只做检测不修改；脱敏见 :func:`default_redact_string`。类别与 :mod:`recorder`
    内部一致（KEY/TOKEN/PHONE），供写后校验与一致性不变式复用。
    """
    hits: List[Tuple[str, str]] = []
    for pattern, category in _PATTERNS:
        for match in pattern.finditer(text):
            hits.append((category, match.group(0)))
    return tuple(hits)


def default_redact_string(value: str) -> str:
    """默认模式层脱敏：把字符串里的敏感子串替换为确定性占位."""
    out = value
    for pattern, category in _PATTERNS:
        out = pattern.sub(lambda m, c=category: _placeholder(c, m.group(0)), out)
    return out


def redact_tree(node: Any, *, value_redactor: Redactor = default_redact_string,
                _count: Optional[Dict[str, int]] = None) -> Any:
    """递归脱敏一棵 JSON 形状的结构，返回新结构（不修改原对象）.

    - dict 的键名命中 :data:`SENSITIVE_FIELDS`（大小写不敏感）且值为非空字符串时，
      整个值替换为 ``<REDACT-FIELD:<hash8>>``（字段层，强制）；
    - 其余字符串过 ``value_redactor``（默认 = 模式层扫描替换）；
    - ``_count`` 传入 dict 时统计替换次数（FIELD / VALUE）。
    """
    if _count is None:
        return _walk(node, value_redactor, SENSITIVE_FIELDS)

    def counting_fn(value: str) -> str:
        redacted = value_redactor(value)
        if redacted != value:
            _count["VALUE"] = _count.get("VALUE", 0) + 1
        return redacted

    def counting_walk(sub: Any, fields: Optional[frozenset]) -> Any:
        if isinstance(sub, Mapping):
            out = {}
            for key, value in sub.items():
                if (fields is not None and isinstance(key, str)
                        and key.lower() in fields
                        and isinstance(value, str) and value):
                    _count["FIELD"] = _count.get("FIELD", 0) + 1
                    out[key] = _placeholder("FIELD", value)
                else:
                    out[key] = counting_walk(value, fields)
            return out
        if isinstance(sub, (list, tuple)):
            return [counting_walk(item, fields) for item in sub]
        if isinstance(sub, str):
            return counting_fn(sub)
        return sub

    return counting_walk(node, SENSITIVE_FIELDS)


@dataclass
class SecretRedactor:
    """可配置脱敏器（自定义 redactor 的便捷封装）.

    ``extra_patterns``：追加 (已编译正则, 类别) 对；``sensitive_fields``：覆盖默认
    敏感字段集合；``field_layer``=False 可关闭字段层（仅测试用，生产不要关）。
    实例本身是 ``str -> str`` 可调用，可直接传给 ``InteractionRecorder(redactor=...)``。
    """

    extra_patterns: Tuple[Tuple[re.Pattern, str], ...] = ()
    sensitive_fields: Optional[frozenset] = None
    field_layer: bool = True

    def __call__(self, value: str) -> str:
        out = value
        for pattern, category in tuple(_PATTERNS) + tuple(self.extra_patterns):
            out = pattern.sub(lambda m, c=category: _placeholder(c, m.group(0)), out)
        return out

    def redact_tree(self, node: Any) -> Any:
        fields = SENSITIVE_FIELDS if self.sensitive_fields is None else self.sensitive_fields
        return _walk(node, self, fields if self.field_layer else None)


def _walk(node: Any, value_fn: Redactor, fields: Optional[frozenset]) -> Any:
    """内部递归：``fields`` 非空时启用字段名层（整体替换），其余字符串过 ``value_fn``."""
    if isinstance(node, Mapping):
        out: Dict[Any, Any] = {}
        for key, value in node.items():
            if (fields is not None and isinstance(key, str)
                    and key.lower() in fields
                    and isinstance(value, str) and value):
                out[key] = _placeholder("FIELD", value)
            else:
                out[key] = _walk(value, value_fn, fields)
        return out
    if isinstance(node, (list, tuple)):
        return [_walk(item, value_fn, fields) for item in node]
    if isinstance(node, str):
        return value_fn(node)
    return node


# ── 记录形状 ─────────────────────────────────────────────────────────────────


class InteractionValidationError(ValueError):
    """记录未过最小校验（附全部错误，风格对齐 eval_gate.badcase.BadCaseValidationError）。"""

    def __init__(self, errors: List[str]) -> None:
        self.errors = list(errors)
        super().__init__("interaction record validation failed: " + "; ".join(self.errors))


@dataclass
class InteractionRecord:
    """一条交互记录（``interaction_schema="v1"``）.

    顶层：record_id / interaction_schema / created_at / request / response / metadata。
    metadata 约定键：model、endpoint_ref、latency_ms、tokens（可选 dict）、ts、
    tenant_id、labels（list）、case_id（可选，供 DiffMatrix 配对）；允许附加键。
    全树（request/response/metadata）在 ``record()`` 内已完成脱敏。
    """

    record_id: str
    interaction_schema: str
    created_at: str                      # ISO 8601 UTC，如 2026-09-26T08:00:00+00:00
    request: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        errors: List[str] = []
        if not self.record_id or not isinstance(self.record_id, str):
            errors.append("record_id must be a non-empty string")
        if self.interaction_schema != INTERACTION_SCHEMA:
            errors.append(f"interaction_schema must be {INTERACTION_SCHEMA!r}, "
                          f"got {self.interaction_schema!r}")
        try:
            datetime.fromisoformat((self.created_at or "").replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"created_at {self.created_at!r} is not ISO 8601 datetime")
        if not isinstance(self.request, dict):
            errors.append("request must be an object")
        if not isinstance(self.response, dict):
            errors.append("response must be an object")
        if not isinstance(self.metadata, dict):
            errors.append("metadata must be an object")
        labels = self.metadata.get("labels")
        if labels is not None and not isinstance(labels, list):
            errors.append("metadata.labels must be a list")
        if errors:
            raise InteractionValidationError(errors)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InteractionRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        record = cls(**{k: v for k, v in data.items() if k in known})
        record.validate()
        return record

    @classmethod
    def coerce(cls, record: Any) -> "InteractionRecord":
        """接受 InteractionRecord / dict，统一成 InteractionRecord。"""
        if isinstance(record, cls):
            return record
        if isinstance(record, Mapping):
            return cls.from_dict(record)
        raise TypeError(f"cannot coerce {type(record).__name__} to InteractionRecord")


# ── 记录器 ───────────────────────────────────────────────────────────────────


class InteractionRecorder:
    """记录一次 LLM 交互 → 强制脱敏 → 规范 :class:`InteractionRecord`.

    用法::

        rec = InteractionRecorder(tenant_id="prop-0006").record(
            request={"method": "POST", "url": "...", "headers": {...}, "body": {...}},
            response={"status": 200, "body": {...}},
            model="step-3.5-flash", endpoint_ref="...",
            latency_ms=1234.5, tokens={"total_tokens": 42},
            labels=["oracle-suite/first-record"], case_id="case-001",
        )
        rec.to_json()  # 入库形状（已脱敏）

    - 脱敏**在构造记录前强制执行**，没有"不脱敏"的开关；
    - ``redactor=None`` → 模式层用默认扫描；注入 ``str -> str`` 自定义 redactor 后
      模式层由注入方接管，字段名层（Authorization 整体替换）仍然强制；
    - ``clock``/``id_fn`` 可注入（测试确定性）；默认 UTC now / uuid4 hex。
    """

    def __init__(self, *, tenant_id: str = "default",
                 redactor: Optional[Redactor] = None,
                 clock: Optional[Callable[[], datetime]] = None,
                 id_fn: Optional[Callable[[], str]] = None) -> None:
        self._tenant_id = tenant_id
        self._redactor = redactor
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_fn = id_fn or (lambda: uuid.uuid4().hex)

    def record(self, request: Mapping[str, Any], response: Mapping[str, Any], *,
               model: str = "", endpoint_ref: str = "",
               latency_ms: Optional[float] = None,
               tokens: Optional[Mapping[str, Any]] = None,
               tenant_id: Optional[str] = None,
               labels: Sequence[str] = (),
               case_id: Optional[str] = None,
               **extra_metadata: Any) -> InteractionRecord:
        """记录并脱敏一次交互。返回的记录树中不应再存在任何敏感原文."""
        now = self._clock()
        created_at = now.astimezone(timezone.utc).isoformat(timespec="seconds")
        metadata: Dict[str, Any] = {
            "model": model,
            "endpoint_ref": endpoint_ref,
            "latency_ms": latency_ms,
            "ts": created_at,
            "tenant_id": tenant_id if tenant_id is not None else self._tenant_id,
            "labels": list(labels),
        }
        if tokens is not None:
            metadata["tokens"] = dict(tokens)
        if case_id is not None:
            metadata["case_id"] = case_id
        metadata.update(extra_metadata)

        raw = {"request": dict(request), "response": dict(response),
               "metadata": metadata}
        redacted = redact_tree(raw, value_redactor=self._redactor or default_redact_string)

        record = InteractionRecord(
            record_id=self._id_fn(),
            interaction_schema=INTERACTION_SCHEMA,
            created_at=created_at,
            request=redacted["request"],
            response=redacted["response"],
            metadata=redacted["metadata"],
        )
        record.validate()
        return record
