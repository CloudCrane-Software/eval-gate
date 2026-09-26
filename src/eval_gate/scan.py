# coding: utf-8
"""安全扫描三档 — 静态 / 轻扫 / 深扫，映射为 L3 GuardrailRun Spec 的三档 Check.

规格来源（PROP-0001 v1.7 §12.9；WO-0004）:

- **static**（静态）: ruff / mypy / eslint —— 便宜、每次 PR 必跑；
- **light**（轻扫）: gitleaks（密钥泄漏，含 ``--redact``）/ pip-audit / npm audit /
  license（许可合规）；
- **deep**（深扫）: semgrep 自定义规则（packs/semgrep，PROP-0011 规则库从 badcase
  归因标签树生长）+ ``llm_review`` 注入点（LLM Review Agent 接口，本仓不内置调用）。

**边界（写死）**：本仓不做检查器本体（4.9 #2：原生 guardrail 管"检查执行"）——
第三方扫描器只经 ``subprocess`` 调用其 CLI，import 依赖为零；工具不可用/输入缺失/
超时/解析失败一律 ``UNKNOWN``（fail-closed，不静默放行）。真工具由 CI 环境的
env YAML 保证装齐（v1.7 §12.2）。

Evidence 纪律：工具 stdout/stderr 只截尾保留前 2000 字符入 evidence；gitleaks
命令行强制 ``--redact``，防止命中的密钥原文进入报告。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .gate import BLOCKED, PASS, UNKNOWN, CheckResult, aggregate, aggregate_reason, coerce_verdict

Interpret = Callable[[int, str, str], Tuple[str, Optional[str]]]
ArgvBuilder = Callable[[str], Optional[Sequence[str]]]

_EVIDENCE_TAIL = 2000  # evidence 里 stdout/stderr 各保留的最大字符数（截尾）


# ── subprocess 隔离（测试 monkeypatch 点：不真装工具） ────────────────────────


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _subprocess_run(argv: Sequence[str], cwd: str,
                    timeout: float) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False)


def _tail(text: str) -> str:
    text = text or ""
    return text[-_EVIDENCE_TAIL:]


# ── 通用 CLI runner ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CliToolRunner:
    """一个工具 = 一个 runner：build_argv(目标目录) → subprocess → interpret。

    统一 fail-closed 语义（在 :meth:`run` 里写死，interpret 只负责"成功执行后
    怎么判"）：
    - build_argv 返回 None（缺输入文件/规则包）→ UNKNOWN；
    - CLI 不在 PATH → UNKNOWN（原因注明工具名）；
    - 超时 / OSError → UNKNOWN；
    - interpret 抛异常 / 返回非法 verdict → UNKNOWN。
    """

    name: str                       # 工具名，如 "ruff"
    tier: str                       # "static" / "light" / "deep"
    build_argv: ArgvBuilder
    interpret: Interpret
    timeout_s: float = 600.0
    binary: Optional[str] = None    # 缺省取 argv[0]

    def run(self, target: str) -> CheckResult:
        check_id = f"{self.tier}/{self.name}"
        built = self.build_argv(target)
        if not built:
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"{self.name}: required input not found for "
                                      f"target {target!r} (fail-closed)")
        argv = list(built)
        binary = self.binary or argv[0]
        resolved = _which(binary)
        if resolved is None:
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"{self.name}: tool not available on PATH: "
                                      f"{binary!r} (fail-closed; install in CI env per env YAML)")
        # 用解析后的绝对路径启动（Windows 上 npx 等是 .cmd shim，裸名会 spawn 失败）
        argv[0] = resolved
        try:
            proc = _subprocess_run(argv, cwd=target, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"{self.name}: timed out after {self.timeout_s}s "
                                      f"(fail-closed)")
        except OSError as exc:
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"{self.name}: failed to launch: "
                                      f"{type(exc).__name__}: {exc} (fail-closed)")
        try:
            verdict, reason = self.interpret(proc.returncode, proc.stdout or "",
                                             proc.stderr or "")
        except Exception as exc:  # noqa: BLE001 — 解析失败不放行
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"{self.name}: output parse failed: "
                                      f"{type(exc).__name__}: {exc} (fail-closed)")
        return CheckResult(check_id=check_id, verdict=coerce_verdict(verdict),
                           tool=self.name, reason=reason,
                           evidence={"returncode": proc.returncode,
                                     "argv": argv,
                                     "stdout_tail": _tail(proc.stdout or ""),
                                     "stderr_tail": _tail(proc.stderr or "")})


def _exit_code_map(tool: str, mapping: Mapping[int, Tuple[str, Optional[str]]],
                   default: Tuple[str, Optional[str]]
                   = (UNKNOWN, "unexpected exit code (fail-closed)")) -> Interpret:
    def interpret(returncode: int, stdout: str, stderr: str) -> Tuple[str, Optional[str]]:
        return mapping.get(returncode, default)

    return interpret


# ── static 档 ────────────────────────────────────────────────────────────────


def _ruff_runner() -> CliToolRunner:
    return CliToolRunner(
        name="ruff", tier="static",
        build_argv=lambda d: ["ruff", "check", "--no-fix", "."],
        interpret=_exit_code_map("ruff", {
            0: (PASS, None),
            1: (BLOCKED, "ruff reported lint violations (exit 1)"),
            # ruff 以 2 表示配置/调用错误——不是代码问题，证据不足
            2: (UNKNOWN, "ruff exited with 2 (configuration/invocation error)"),
        }))


def _mypy_runner() -> CliToolRunner:
    return CliToolRunner(
        name="mypy", tier="static",
        build_argv=lambda d: ["mypy", "."],
        interpret=_exit_code_map("mypy", {
            0: (PASS, None),
            1: (BLOCKED, "mypy reported type errors (exit 1)"),
            2: (UNKNOWN, "mypy exited with 2 (fatal/usage error)"),
        }))


def _eslint_runner() -> CliToolRunner:
    # eslint 约定：0=干净，1=有 lint 问题，2=fatal（含配置缺失）
    return CliToolRunner(
        name="eslint", tier="static",
        build_argv=lambda d: ["npx", "--no-install", "eslint", "."],
        binary="npx",
        interpret=_exit_code_map("eslint", {
            0: (PASS, None),
            1: (BLOCKED, "eslint reported problems (exit 1)"),
            2: (UNKNOWN, "eslint exited with 2 (fatal error, e.g. missing config)"),
        }))


# ── light 档 ─────────────────────────────────────────────────────────────────


def _gitleaks_runner() -> CliToolRunner:
    # --redact 强制：命中的密钥原文不得进入报告（红线 3）
    return CliToolRunner(
        name="gitleaks", tier="light",
        build_argv=lambda d: ["gitleaks", "detect", "--source", d, "--no-git",
                              "--redact", "-v"],
        interpret=_exit_code_map("gitleaks", {
            0: (PASS, None),
            1: (BLOCKED, "gitleaks found secret leaks (exit 1)"),
        }, default=(UNKNOWN, "gitleaks unexpected exit code (fail-closed)")))


def _pip_audit_runner() -> CliToolRunner:
    def build_argv(target: str) -> Optional[Sequence[str]]:
        req = os.path.join(target, "requirements.txt")
        if not os.path.isfile(req):
            return None  # 缺输入 → UNKNOWN（fail-closed）
        return ["pip-audit", "-r", req, "--progress-spinner", "off"]

    return CliToolRunner(
        name="pip-audit", tier="light",
        build_argv=build_argv,
        interpret=_exit_code_map("pip-audit", {
            0: (PASS, None),
            1: (BLOCKED, "pip-audit found vulnerable dependencies (exit 1)"),
        }, default=(UNKNOWN, "pip-audit unexpected exit code (fail-closed)")))


def _npm_audit_runner() -> CliToolRunner:
    def build_argv(target: str) -> Optional[Sequence[str]]:
        if not os.path.isfile(os.path.join(target, "package.json")):
            return None
        return ["npm", "audit", "--json"]

    def interpret(returncode: int, stdout: str, stderr: str) -> Tuple[str, Optional[str]]:
        # npm v7+：发现漏洞时 exit 1；JSON 里有权威的漏洞计数
        try:
            data = json.loads(stdout)
            total = int(data.get("metadata", {}).get("vulnerabilities", {}).get("total", -1))
        except (ValueError, AttributeError, TypeError):
            total = -1
        if total is not None and total > 0:
            return BLOCKED, f"npm audit reported {total} vulnerabilities"
        if returncode == 0:
            return PASS, None
        if returncode == 1:
            if total == 0:
                return PASS, None
            return UNKNOWN, "npm audit exited 1 but vulnerability count unreadable (fail-closed)"
        return UNKNOWN, f"npm audit unexpected exit code {returncode} (fail-closed)"

    return CliToolRunner(name="npm-audit", tier="light",
                         build_argv=build_argv, interpret=interpret)


_DEFAULT_LICENSE_ALLOWLIST = (
    "MIT", "MIT License", "Apache Software License", "Apache-2.0", "Apache 2.0",
    "BSD", "BSD License", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "ISC License (ISCL)", "Python Software Foundation License", "Python-2.0",
    "Unlicense", "CC0 1.0 Universal", "Mozilla Public License 2.0 (MPL 2.0)",
)


def _license_runner(allowlist: Sequence[str] = _DEFAULT_LICENSE_ALLOWLIST) -> CliToolRunner:
    """许可合规：当前对 Python 环境元数据生效（pip-licenses）；node 侧
    license-checker 后续以同接口接入（README 已如实声明）。"""
    allowed = {a.lower() for a in allowlist}

    def interpret(returncode: int, stdout: str, stderr: str) -> Tuple[str, Optional[str]]:
        if returncode != 0:
            return UNKNOWN, f"pip-licenses unexpected exit code {returncode} (fail-closed)"
        data = json.loads(stdout)
        disallowed: List[str] = []
        for row in data:
            lic = str(row.get("License", "")).strip()
            if lic and lic.lower() not in allowed and lic.lower() != "unknown":
                disallowed.append(f"{row.get('Name', '?')}({lic})")
        if disallowed:
            return BLOCKED, "licenses outside allowlist: " + ", ".join(sorted(disallowed)[:10])
        return PASS, None

    return CliToolRunner(name="license", tier="light",
                         build_argv=lambda d: ["pip-licenses", "--format=json",
                                               "--from=mixed"],
                         interpret=interpret)


# ── deep 档 ──────────────────────────────────────────────────────────────────


def _default_semgrep_pack() -> Optional[str]:
    """semgrep 规则包（PROP-0011）定位：env 覆盖 > CWD > 仓根。找不到 → None。"""
    env = os.environ.get("EVAL_GATE_SEMGREP_PACK")
    if env and os.path.isdir(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))           # src/eval_gate
    repo_root = os.path.dirname(os.path.dirname(here))          # 仓根（src 布局）
    for base in (os.getcwd(), repo_root):
        cand = os.path.join(base, "packs", "semgrep")
        if os.path.isdir(cand):
            return cand
    return None


def _semgrep_runner(rules_path: Optional[str] = None) -> CliToolRunner:
    # --error：有命中即 exit 1；JSON 输出取命中数做 evidence
    def build_argv(target: str) -> Optional[Sequence[str]]:
        pack = rules_path or _default_semgrep_pack()
        if not pack:
            return None
        return ["semgrep", "scan", "--error", "--config", pack, "--json", target]

    def interpret(returncode: int, stdout: str, stderr: str) -> Tuple[str, Optional[str]]:
        findings = -1
        try:
            data = json.loads(stdout)
            findings = len(data.get("results", []))
            if data.get("errors"):
                return UNKNOWN, f"semgrep reported {len(data['errors'])} scan errors (fail-closed)"
        except ValueError:
            pass
        if returncode == 0:
            return PASS, None
        if returncode == 1:
            if findings > 0:
                return BLOCKED, f"semgrep rules matched {findings} finding(s)"
            return UNKNOWN, "semgrep exited 1 but findings unreadable (fail-closed)"
        return UNKNOWN, f"semgrep unexpected exit code {returncode} (fail-closed)"

    return CliToolRunner(name="semgrep", tier="deep",
                         build_argv=build_argv, interpret=interpret)


ReviewFn = Callable[[str], Tuple[str, Optional[str]]]


@dataclass(frozen=True)
class LlmReviewRunner:
    """深扫的 LLM Review Agent 注入点（**本仓不内置任何模型调用**）.

    ``review_fn(target) -> (verdict, reason)`` 由部署方注入（经 Higress 唯一入口）；
    未注入 → ``UNKNOWN``（fail-closed）。返回非法 verdict 一律收敛为 UNKNOWN。
    """

    name: str = "llm_review"
    tier: str = "deep"
    review_fn: Optional[ReviewFn] = None

    def run(self, target: str) -> CheckResult:
        check_id = f"{self.tier}/{self.name}"
        if self.review_fn is None:
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason="llm_review not configured (fail-closed); "
                                      "inject review_fn via Higress-only model entry")
        try:
            verdict, reason = self.review_fn(target)
        except Exception as exc:  # noqa: BLE001
            return CheckResult(check_id=check_id, verdict=UNKNOWN, tool=self.name,
                               reason=f"llm_review crashed: {type(exc).__name__}: {exc} "
                                      f"(fail-closed)")
        return CheckResult(check_id=check_id, verdict=coerce_verdict(verdict),
                           tool=self.name, reason=reason)


# ── 三档目录（§12.9 映射）与入口 ─────────────────────────────────────────────


def build_default_runners(*, semgrep_pack: Optional[str] = None,
                          license_allowlist: Sequence[str] = _DEFAULT_LICENSE_ALLOWLIST,
                          llm_review: Optional[ReviewFn] = None) -> Dict[str, List[Any]]:
    """构造三档默认 runner 集（测试可注入假工具/假 review）。"""
    return {
        "static": [_ruff_runner(), _mypy_runner(), _eslint_runner()],
        "light": [_gitleaks_runner(), _pip_audit_runner(), _npm_audit_runner(),
                  _license_runner(license_allowlist)],
        "deep": [_semgrep_runner(semgrep_pack), LlmReviewRunner(review_fn=llm_review)],
    }


TIERS: Dict[str, List[Any]] = build_default_runners()


def run_tier(tier: str, target: str,
             runners: Optional[Sequence[Any]] = None) -> List[CheckResult]:
    """执行一档扫描，返回 CheckResult 列表（整体判定由 L3 aggregate 决定）。"""
    if runners is None:
        if tier not in TIERS:
            raise ValueError(f"unknown tier {tier!r}; valid tiers: {sorted(TIERS)}")
        runners = TIERS[tier]
    return [runner.run(target) for runner in runners]


def tier_verdict(results: Sequence[CheckResult]) -> Tuple[str, Optional[str]]:
    """一档结果的 L3 结论（aggregate + reason）。"""
    return aggregate(results), aggregate_reason(results)
