# 数据契约：eval-gate ↔ agent_evolving（badcase 候选）

> 依据 PROP-0001 v1.6 §6（L1↔agent_evolving 数据循环）与 §4.9 #8（准入严格：
> 一切产出物过 eval-gate 才能进 main）。Schema 版本：**1.0**
> （`eval_gate.badcase.SCHEMA_VERSION`，与本文件同步演进）。

## 1. 循环总览："评测产数据、优化吃数据、门禁管准入"

```
┌────────────────────────────  eval-gate（本仓，公司级门禁）  ───────────────────────────┐
│  L1 级联漏斗（规则→Score 灰区→深分析）   L2 oracle 差分   L3 GuardrailRun 三态聚合        │
└───────────────┬────────────────────────────────────────────────────────────────────────┘
                │  评测侧发现失败 → 产出 BadCaseCandidate（本契约）
                ▼
   eval-assets（CNB 私有仓，落库：黄金集 / badcase 库 / 归因标签树快照）
                │  gpumachine 拉取（agent_evolving：evaluator/optimizer/trainer 消费）
                ▼
   gpumachine 执行面内优化（tune / agent_evolving 自由跑，不设限）
                │  优化产出物（新 skill / 新权重产物 / 新经验）
                ▼
   回 eval-gate 过 L1/L2/L3 —— 只有 PASS 才允许进 main（4.9 #8）
```

要点：

- **单向数据流，准入归 eval-gate**：badcase 候选只落 eval-assets（私有），
  永不直接进 main；进 main 的是优化产出物过完门禁之后的版本。
- **引用不复制**：候选的 `evidence` 只存 trace/guardrail_run/oracle_run 的 ID 引用
  （Langfuse 只查询展示、不当中间层——v1.6 §4.9 #6 同构约束）。
- **labels = PROP-0011 生长接口**：归因标签树路径，见 `packs/README.md`。

## 2. JSON Schema（draft 2020-12，权威由 `BadCaseCandidate.to_json_schema()` 生成）

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://raw.githubusercontent.com/CloudCrane-Software/eval-gate/main/docs/schemas/badcase-candidate-1.0.json",
  "title": "BadCaseCandidate",
  "description": "eval-gate ↔ agent_evolving 的 badcase 候选契约 v1.0（评测产数据、优化吃数据、门禁管准入；PROP-0001 v1.6 §6）",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "candidate_id", "created_at", "source", "domain", "verdict", "labels", "input"],
  "properties": {
    "schema_version": { "const": "1.0" },
    "candidate_id": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" },
    "created_at": { "type": "string", "format": "date-time" },
    "source": { "enum": ["l1_funnel", "l2_oracle", "l3_gate", "human", "external"] },
    "domain": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*$", "examples": ["code", "video", "ops"] },
    "verdict": { "enum": ["BLOCKED", "PASS", "UNKNOWN"] },
    "labels": {
      "type": "array",
      "items": { "type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$" },
      "description": "归因标签树路径（PROP-0011 生长接口），如 security/secret-leak"
    },
    "input": { "type": "object", "description": "触发失败的输入/上下文（脱敏后）" },
    "expected": {},
    "actual": {},
    "evidence": {
      "type": "object",
      "description": "引用而非复制：trace_ref/guardrail_run_id/oracle_run_id/diff_paths"
    },
    "notes": { "type": "string" }
  }
}
```

## 3. 示例

```json
{
  "schema_version": "1.0",
  "candidate_id": "bc-20260926-0a1b2c3d",
  "created_at": "2026-09-26T08:30:00+00:00",
  "source": "l2_oracle",
  "domain": "code",
  "verdict": "BLOCKED",
  "labels": ["security/secret-leak"],
  "input": {
    "task": "为上传接口补充单元测试",
    "artifact_ref": "git://eval-gate@<sha>#tests/test_upload.py"
  },
  "expected": { "diff_contains_secret": false },
  "actual": { "diff_contains_secret": true, "match_kind": "aws_access_key_id" },
  "evidence": {
    "oracle_run_id": "<OracleReport.run_id>",
    "guardrail_run_id": "<GateResult.gate_id>",
    "diff_paths": ["diff_contains_secret"],
    "tool": "gitleaks",
    "note": "工具输出经 --redact，原文不入库"
  },
  "notes": "diff 中出现访问密钥形态字符串；优化目标：产出物生成前过 L1 规则层"
}
```

## 4. 与 eval-assets（CNB 私有仓）的关系

| 资产 | 落点 | 写入方 | 消费方 |
| --- | --- | --- | --- |
| BadCaseCandidate（本契约） | `eval-assets/badcases/<domain>/<yyyy-mm>/` | eval-gate 各层 / 人 | gpumachine（agent_evolving） |
| 归因标签树快照 | `eval-assets/tag-tree.json` | evolution-keeper 维护 | eval-gate 规则准入（L1） |
| 黄金集 / 带毒集 | `eval-assets/golden/` `eval-assets/poisoned/` | oracle-suite 记录器（PROP-0006） | 新扫描规则的 L1 准入回归 |
| 优化产出物 | 不落 eval-assets——走正常 PR | gpumachine | eval-gate L1/L2/L3 → main |

- eval-assets 是**私有仓**：badcase 可能含任务上下文，公开仓（本仓）只放契约与机制，不放数据。
- gpumachine 消费按批拉取（数据主权：自建存储为主，v1.7 §12.4；Eval 资产无托管等价物）。
- 契约演进：`schema_version` 递增 + 本文件同步更新；只允许加可选字段，
  收紧已有字段语义视为 breaking，需过提案流程（PROP-0001 §5.1）。
