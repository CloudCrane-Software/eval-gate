# packs/ —— 扫描规则库（PROP-0011 security-scan-pack）

> **规则不是拍脑袋写的，是从 badcase 归因标签树长出来的。**
> 本目录当前只有 5 条示例种子（`semgrep/seed-rules.yaml`），用于打通
> "semgrep 深扫档"的执行链路，不构成覆盖声明。

## 1. 归因标签树（badcase 的 labels 字段）

每条 :class:`eval_gate.badcase.BadCaseCandidate` 携带 `labels`（标签树路径，
如 `security/secret-leak`）。标签树是开放的，但节点必须先注册再使用：

```json
{
  "tag_tree": [
    {
      "tag": "security/secret-leak",
      "description": "凭据/密钥进入代码、日志或产物",
      "min_cases_to_grow_rule": 3,
      "examples": ["<BadCaseCandidate.candidate_id, 引用不复制>"],
      "rules": ["eval-gate.security.hardcoded-credential"]
    },
    {
      "tag": "security/dangerous-call",
      "description": "动态执行/shell 注入面",
      "min_cases_to_grow_rule": 3,
      "examples": [],
      "rules": ["eval-gate.security.dynamic-execution",
                 "eval-gate.security.subprocess-shell-true"]
    }
  ]
}
```

- 路径格式与 badcase JSON Schema 的 `labels` 一致：`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`；
- `examples` 只存候选 ID **引用**（状态不复制，跨层只传引用——v1.6 §4.9 #10）；
- 树本体登记在 eval-assets（CNB 私有仓），本仓只存被准入规则引用的标签快照。

## 2. 规则生长过程（标签 → 规则草案 → 准入 → 打版）

```
badcase 累计（同标签 ≥ min_cases_to_grow_rule 条，且 L2/L3 证据齐全）
  → 写规则草案（semgrep yaml，rule_id = eval-gate.<标签slug>.<规则slug>）
  → 新规则本身过 eval-gate 自身的 L1 准入（见 §3）
  → 准入通过：规则文件入库本目录，头部注释登记来源标签与候选 ID 引用
  → 打版本 tag（security-pack-vN），深扫档按 tag 锁定版本
```

规则文件头部必须写：来源标签、依据的候选 ID 列表、准入 GuardrailRun 的 gate_id。

## 3. 新规则的准入 = eval-gate 自身 L1（吃自己的狗粮）

新规则草案作为一条 `Candidate(kind="rule_draft")` 过级联漏斗
（:mod:`eval_gate.funnel`，声明式规则表 `load_rule_table`）：

| 优先级 | 准入规则（match → verdict） | 语义 |
| --- | --- | --- |
| 1 | 黄金 PASS 集命中 → **BLOCKED** | 规则在"应当干净"的语料上有误报，直接否决 |
| 2 | 带毒集未命中 → **BLOCKED** | 规则抓不住依据它的那些 badcase，等于没写 |
| 3 | 标签未注册 / 头部元数据缺失 → **BLOCKED** | 无来源的规则不得入库 |
| 4 | 黄金集/带毒集本体缺失 → **UNKNOWN** | fail-closed：没有回归语料就不准入 |

黄金集/带毒集由 oracle-suite 记录器（PROP-0006，后续工单）与 eval-assets 供给；
本体不在本仓（本仓只留 L2 Case/接口，见 README 边界节）。

## 4. 目录约定

```
packs/
├── README.md            # 本文件：生长过程 + 标签树 schema
└── semgrep/
    └── seed-rules.yaml  # 5 条示例种子（深扫档经 scan.py 以 --config 挂载）
```

深扫档定位规则包的顺序（`scan._default_semgrep_pack`）：环境变量
`EVAL_GATE_SEMGREP_PACK` > 当前目录 `packs/semgrep` > 仓根 `packs/semgrep`；
找不到时 semgrep Check 判 **UNKNOWN**（fail-closed，不静默跳过）。
