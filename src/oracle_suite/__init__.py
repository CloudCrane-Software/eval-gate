# coding: utf-8
"""oracle-suite — 阿里体系为 oracle 的配套记录器（PROP-0006，M2 起步）.

规格来源（PROP-0001 v1.7 §12.4 存储自建 / §14 PROP-0006；v1.6 §6 L2 oracle 差分与
eval-assets 数据循环；与本仓 ``eval_gate.oracle`` 的 Case / diff / OracleReport 形状
以及 ``eval_gate.badcase`` 的 BadCaseCandidate 契约对齐）:

- :mod:`oracle_suite.recorder` —— :class:`InteractionRecorder`：记录一次 LLM 交互
  （request / response / metadata），序列化为 ``interaction_schema=v1`` 规范记录；
  **脱敏在入库前强制执行**（Authorization 等敏感字段整体替换 + key/token/手机号
  模式扫描，占位形状 ``<REDACT-<类别>:<sha256前8位>>``，可注入自定义 redactor）。
- :mod:`oracle_suite.matrix` —— :class:`DiffMatrix`：两次录制批次按 case_id 配对
  逐字段 diff（直接复用 ``eval_gate.oracle.diff`` 的差异路径形状），``to_markdown()``
  是差异矩阵月更机制的雏形。
- :mod:`oracle_suite.consistency` —— :func:`check`：交互记录不变式（语义一致性测试
  骨架），违规产出对齐 ``BadCaseCandidate`` 的 badcase 候选（落 eval-assets 私有仓）。

边界：本包**不发真实网络请求**（录制动作由调用方/scripts 完成，本包只负责"记录什么
与如何脱敏"）；Eval 资产（黄金集/badcase/oracle 交互记录）只落 eval-assets（CNB 私有
仓，v1.7 §12.4"Eval 资产必须自建，黄金集=专属资产核心"），永不进公开仓。
"""
from .recorder import (
    INTERACTION_SCHEMA,
    InteractionRecord,
    InteractionRecorder,
    InteractionValidationError,
    SecretRedactor,
    default_redact_string,
    redact_tree,
    scan_for_secrets,
)
from .matrix import DiffMatrix, MatrixRow
from .consistency import (
    Invariant,
    ConsistencyReport,
    Violation,
    check,
    has_model_field,
    latency_under,
    no_redact_residue,
    response_nonempty,
    schema_is_v1,
    to_badcase_candidates,
)

__all__ = [
    "INTERACTION_SCHEMA",
    "InteractionRecord",
    "InteractionRecorder",
    "InteractionValidationError",
    "SecretRedactor",
    "default_redact_string",
    "redact_tree",
    "scan_for_secrets",
    "DiffMatrix",
    "MatrixRow",
    "Invariant",
    "ConsistencyReport",
    "Violation",
    "check",
    "has_model_field",
    "latency_under",
    "no_redact_residue",
    "response_nonempty",
    "schema_is_v1",
    "to_badcase_candidates",
]
