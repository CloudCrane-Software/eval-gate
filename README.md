# eval-gate

公司级评测门禁（company-level evaluation gate）。一句话：**一切 Agent Release 产出物过 eval-gate 才能进 main。**

## 定位

本仓是公司级**门禁与协议聚合层**，不是检查器集合。依据《建设方案》（PROP-0001）：

- **§4.9 #8（v1.6）**：执行面内优化自由（`dev_tools/tune`、`agent_evolving` 直接在 gpumachine 跑），**准入严格**——一切产出物过本门禁才能进 main。
- **§6（v1.6/v1.7）CI 三层**：
  - **L1 级联漏斗**（`eval_gate.funnel`）：规则（便宜）→ 决策层 Score 灰区（中等）→ 大模型深分析（贵）；级联顺序与短路语义写死并有测试。
  - **L2 oracle 差分测试**（`eval_gate.oracle`）：oracle 基线 vs 被测产出，逐案差分、批量出报告。
  - **L3 GuardrailRun 门禁**（`eval_gate.gate`）：三态聚合 `PASS / BLOCKED / UNKNOWN`，**fail-closed**——空证据、工具缺失、超时、执行器崩溃、非法判定值一律 UNKNOWN，不静默放行。
- **§12.9（v1.7）扫描三档**（`eval_gate.scan`）→ L3 Spec 的三档 Check：
  - **static**：ruff / mypy / eslint；
  - **light**：gitleaks（强制 `--redact`）/ pip-audit / npm audit / license；
  - **deep**：semgrep 自定义规则（`packs/semgrep`，PROP-0011）+ `llm_review` 注入点。
- **§4.9 #2（v1.6）边界**：原生 `core.security.guardrail` 管"检查执行"（检查器本体），本仓只做**协议聚合与公司级门禁**；L3 数据形状与 jiuwen-glue 的 GuardrailRun 协议对齐（action / resource / agent_identity_ref / env_ref / tenant_id / checks / verdict）。
- **数据循环（v1.6 §6）**："评测产数据、优化吃数据、门禁管准入"——badcase 候选契约见 `eval_gate.badcase` 与 `docs/data-contract-agent-evolving.md`：候选落 eval-assets（CNB 私有仓）→ gpumachine（agent_evolving）消费 → 产出物回本门禁。

## 边界（写死，勿越）

| 事项 | 边界 |
| --- | --- |
| 检查器本体 | **不做**。第三方扫描器只经 `subprocess` 调用其 CLI，本包 import 零第三方依赖；工具链由 CI 环境的 env YAML 保证装齐（§12.2） |
| 决策层 Score | **只留注入点**（`score_fn: Callable[[Candidate], float]` + 灰区阈值）；本体在 jiuwen-glue 侧（WO-0010） |
| 大模型调用 | **不内置**。深分析的 `deep_analyzer` / 深扫的 `llm_review` 都是注入接口；模型流量一律经 Higress 唯一入口（§4.9 #7） |
| oracle-suite 记录器 | **不在本仓**（PROP-0006 后续工单）；本仓只留 L2 的 Case / diff / runner / 报告形状接口，记录器后续按 `OracleReport` 形状喂入 |
| Langfuse | 只查询展示，不当中间层（§4.9 #6）；badcase 的 evidence 只存 trace **引用** |
| EvalScope | 只做模型级基准（L1），不替代本门禁 |
| CI workflow | 本仓**不写 GitHub Actions**；CI 由 CNB 流水线统一覆盖（后续工单） |
| 规则库 | 扫描规则从 badcase 归因标签树生长（PROP-0011），新规则本身要过本门禁 L1 准入，见 `packs/README.md` |

## 模块地图

```
src/eval_gate/
├── funnel.py    # L1 级联漏斗：Candidate / 声明式规则表 / 灰区 Score 注入 / 深分析注入
├── oracle.py    # L2 差分：OracleCase / diff() / OracleRunner / OracleReport
├── gate.py      # L3 门禁：CheckSpec/CheckResult/GateSpec/GateResult + aggregate() 三态
├── scan.py      # 扫描三档：TIERS + 每工具一个 runner（subprocess 调 CLI）
├── badcase.py   # 数据契约：BadCaseCandidate + to_json_schema()
└── cli.py       # python -m eval_gate scan <tier> <dir>
packs/
├── README.md            # 规则生长过程 + 归因标签树 schema（PROP-0011）
└── semgrep/seed-rules.yaml  # 5 条示例种子（密钥泄漏/危险调用/注入/越权最小种子）
ci/run-tier.sh            # 入口：run-tier.sh static|light|deep <dir>
docs/data-contract-agent-evolving.md  # badcase JSON Schema 全文 + 示例 + eval-assets 关系
```

## 使用

```bash
# 三档扫描入口（工具缺失的 Check 判 UNKNOWN，整体按三态聚合）
ci/run-tier.sh static path/to/repo
ci/run-tier.sh light  path/to/repo
ci/run-tier.sh deep   path/to/repo
# 末行输出： 【L3结论】verdict=PASS|BLOCKED|UNKNOWN

# 或直接走模块（等价）
PYTHONPATH=src python -m eval_gate scan deep path/to/repo
```

退出码：`0=PASS`，`1=BLOCKED`，`2=UNKNOWN`（**UNKNOWN 同样非零**——CI 不得放行）。

库用法：

```python
from eval_gate import CascadeFunnel, load_rule_table, OracleRunner, OracleCase, run_tier, aggregate

# L1：声明式规则表 + 注入点
funnel = CascadeFunnel(
    rules=load_rule_table([...]),          # match(field,op,value) → verdict
    score_fn=my_decision_layer_score,      # 决策层注入（WO-0010），灰区阈值默认 0.3/0.7
    deep_analyzer=my_llm_review,           # 大模型注入，不配则灰区判 UNKNOWN
)
result = funnel.evaluate(candidate)

# L2：oracle 差分
report = OracleRunner(cases, invoke=my_tool_under_test).run()
report.verdict   # PASS / BLOCKED / UNKNOWN（同三态语义）

# L3：任一档结果 → 门禁结论
verdict = aggregate(run_tier("light", "path/to/repo"))
```

深扫档 semgrep 规则包定位顺序：环境变量 `EVAL_GATE_SEMGREP_PACK` > 当前目录
`packs/semgrep` > 仓根 `packs/semgrep`；找不到 → 该 Check 判 UNKNOWN。

## 三态语义（与 glue GuardrailRun 对齐，决策点唯一）

| 结果 | 语义 | 门控行为 |
| --- | --- | --- |
| `PASS` | 证据齐全且全部通过 | 放行 |
| `BLOCKED` | 有确定性失败证据 | 拒绝 |
| `UNKNOWN` | 证据缺失（工具不可用/超时/崩溃/非法判定/空集） | **拒绝（fail-closed）** |

## 当前状态（如实）

- ✅ M0 骨架 → **WO-0004（M2 前置）已交付**：上述五模块 + 三档 runner + PROP-0011 规则库骨架 + badcase 契约 + `ci/run-tier.sh` + pytest 74 用例全绿（subprocess 全 mock，本机不装真工具）。
- ⚠️ **未在真实扫描器上验证**：本机未安装 ruff/gitleaks/semgrep 等（按工单要求不真装）；各 runner 的退出码语义按各工具公开文档实现，待 CI 环境（env YAML 装齐工具链）首跑核对。`packs/semgrep/seed-rules.yaml` 只做了 YAML 语法校验（pyyaml），**未经 semgrep 引擎实测**。
- ⚠️ 冒烟记录：`run-tier.sh static` 在本机全部判 UNKNOWN（工具缺失，fail-closed 符合设计）；本机恰好存在 npx，eslint 档曾实际启动并因 npx 缺包退出码 1 被判 BLOCKED——npx 介导的"缺包退出 1"与"lint 问题退出 1"不可区分，CI 环境装齐工具链后方可消除该歧义。
- ⏳ 后续工单：CNB 流水线接入、决策层 Score 本体（WO-0010）、oracle-suite 记录器（PROP-0006）、规则库从 badcase 实际生长。

## License

Apache-2.0
