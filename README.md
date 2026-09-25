# eval-gate

公司级评测门禁（company-level evaluation gate）。一句话：**一切 Agent Release 产出物过 eval-gate 才能进 main。**

## 定位

- 依据《建设方案-多Agent系统与GitOps》（PROP-0001）第 4.9 节 #8：执行面内优化自由（`dev_tools/tune`、`agent_evolving` 直接在 gpumachine 跑），**准入严格**——一切产出物过本门禁才能进 main。
- 对应 CI 三层设计（PROP-0001 第 6 节）：
  - **L1** 级联漏斗：规则 → 决策层 Score 灰区 → 大模型深度分析；
  - **L2** oracle 差分测试；
  - **L3** GuardrailRun 门禁。
- 数据循环："评测产数据、优化吃数据、门禁管准入"——L1 的 badcase 候选经 `eval-assets` 进 gpumachine 优化，产出物回本门禁。
- EvalScope 只做模型级基准（L1），不替代本门禁。
- 开源化节点：M2 / WO-0004。

## 状态

M0 骨架（README / LICENSE / .gitignore）。规则集与门禁程序随 WO-0004 落地。

## License

Apache-2.0
