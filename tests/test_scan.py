# coding: utf-8
"""三档扫描：全部 mock subprocess（本机不装真工具），验证 fail-closed 语义."""
from __future__ import annotations

import os
import subprocess

import pytest

from eval_gate import cli, scan
from eval_gate.gate import BLOCKED, PASS, UNKNOWN, aggregate
from eval_gate.scan import CliToolRunner, LlmReviewRunner, run_tier

# ── mock 基建 ────────────────────────────────────────────────────────────────


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def tool_env(monkeypatch):
    """返回 (set_tool, proc_registry)：set_tool 决定哪些 CLI '已安装'。"""
    state = {"available": set(), "procs": {}, "calls": []}

    def set_tool(binary, proc=None):
        state["available"].add(binary)
        if proc is not None:
            state["procs"][binary] = proc

    def fake_which(binary):
        return f"/usr/bin/{binary}" if binary in state["available"] else None

    def fake_run(argv, cwd, timeout):
        state["calls"].append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        # runner 会把 argv[0] 替换为 which() 解析出的绝对路径，按裸名回退查找
        proc = state["procs"].get(argv[0])
        if proc is None:
            proc = state["procs"].get(os.path.basename(argv[0]), FakeProc(0, "", ""))
        if isinstance(proc, Exception):
            raise proc
        return proc

    monkeypatch.setattr(scan, "_which", fake_which)
    monkeypatch.setattr(scan, "_subprocess_run", fake_run)
    state["set_tool"] = set_tool
    return state


def expect(argv0, proc, state):
    state["set_tool"](argv0, proc)


# ── 三档目录结构 ─────────────────────────────────────────────────────────────


def test_tiers_structure():
    assert set(scan.TIERS) == {"static", "light", "deep"}
    by_tool = {tier: [r.name for r in runners] for tier, runners in scan.TIERS.items()}
    assert by_tool["static"] == ["ruff", "mypy", "eslint"]
    assert by_tool["light"] == ["gitleaks", "pip-audit", "npm-audit", "license"]
    assert by_tool["deep"] == ["semgrep", "llm_review"]


def test_run_tier_unknown_tier_raises():
    with pytest.raises(ValueError, match="unknown tier"):
        run_tier("heavy", "/tmp")


# ── static 档（工具在 / 工具缺 / 异常码 / 超时） ──────────────────────────────


def test_static_ruff_clean_pass(tmp_path, tool_env):
    expect("ruff", FakeProc(0), tool_env)
    results = {r.check_id: r for r in run_tier("static", str(tmp_path))}
    assert results["static/ruff"].verdict == PASS
    assert tool_env["calls"][0]["cwd"] == str(tmp_path)   # 以目标目录为 cwd 执行


def test_static_ruff_violations_block_and_mypy_fatal_unknown(tmp_path, tool_env):
    expect("ruff", FakeProc(1, stdout="F401 unused import"), tool_env)
    expect("mypy", FakeProc(2, stderr="mypy: usage error"), tool_env)
    expect("npx", FakeProc(0), tool_env)                  # eslint 经 npx 启动
    results = {r.check_id: r for r in run_tier("static", str(tmp_path))}
    assert results["static/ruff"].verdict == BLOCKED
    assert "exit 1" in results["static/ruff"].reason
    assert results["static/mypy"].verdict == UNKNOWN      # 2=fatal → 证据不足
    assert results["static/eslint"].verdict == PASS


def test_static_tool_missing_is_unknown_fail_closed(tmp_path, tool_env):
    # 不注册任何工具
    results = {r.check_id: r for r in run_tier("static", str(tmp_path))}
    assert all(r.verdict == UNKNOWN for r in results.values())
    assert "not available" in results["static/ruff"].reason
    assert tool_env["calls"] == []                        # 缺工具根本不该 spawn


def test_static_timeout_is_unknown_fail_closed(tmp_path, tool_env):
    expect("ruff", subprocess.TimeoutExpired(cmd="ruff", timeout=600), tool_env)
    expect("mypy", FakeProc(0), tool_env)
    expect("npx", FakeProc(0), tool_env)
    results = {r.check_id: r for r in run_tier("static", str(tmp_path))}
    assert results["static/ruff"].verdict == UNKNOWN
    assert "timed out" in results["static/ruff"].reason
    assert aggregate(list(results.values())) == UNKNOWN


def test_static_evidence_captured(tmp_path, tool_env):
    expect("ruff", FakeProc(1, stdout="x" * 5000), tool_env)
    expect("mypy", FakeProc(0), tool_env)
    expect("eslint", FakeProc(0), tool_env)
    results = {r.check_id: r for r in run_tier("static", str(tmp_path))}
    ev = results["static/ruff"].evidence
    assert ev["returncode"] == 1
    assert len(ev["stdout_tail"]) <= 2000                 # evidence 截尾


# ── light 档 ─────────────────────────────────────────────────────────────────


def test_light_gitleaks_leak_blocked_and_redact_flag(tmp_path, tool_env):
    expect("gitleaks", FakeProc(1, stdout="Finding: ***REDACTED***"), tool_env)
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert results["light/gitleaks"].verdict == BLOCKED
    argv = tool_env["calls"][0]["argv"]
    assert "--redact" in argv                             # 命中原文不得进报告


def test_light_gitleaks_clean_pass(tmp_path, tool_env):
    expect("gitleaks", FakeProc(0), tool_env)
    expect("pip-audit", FakeProc(0), tool_env)
    expect("npm", FakeProc(0, stdout='{"metadata":{"vulnerabilities":{"total":0}}}'), tool_env)
    expect("pip-licenses", FakeProc(0, stdout='[{"Name":"py","License":"MIT"}]'), tool_env)
    (tmp_path / "requirements.txt").write_text("py\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert {r.verdict for r in results.values()} == {PASS}


def test_light_pip_audit_missing_requirements_is_unknown(tmp_path, tool_env):
    expect("pip-audit", FakeProc(0), tool_env)
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert results["light/pip-audit"].verdict == UNKNOWN
    assert "required input not found" in results["light/pip-audit"].reason


def test_light_npm_audit_json_counts(tmp_path, tool_env):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    expect("gitleaks", FakeProc(0), tool_env)
    expect("pip-audit", FakeProc(0), tool_env)
    expect("pip-licenses", FakeProc(0, stdout="[]"), tool_env)
    expect("npm", FakeProc(1, stdout='{"metadata":{"vulnerabilities":{"total":3}}}'), tool_env)
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert results["light/npm-audit"].verdict == BLOCKED
    assert "3 vulnerabilities" in results["light/npm-audit"].reason


def test_light_npm_audit_exit1_unreadable_json_is_unknown(tmp_path, tool_env):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    expect("npm", FakeProc(1, stdout="not-json"), tool_env)
    npm = [r for r in run_tier("light", str(tmp_path)) if r.check_id == "light/npm-audit"][0]
    assert npm.verdict == UNKNOWN


def test_light_license_disallowed_blocked(tmp_path, tool_env):
    expect("pip-licenses",
           FakeProc(0, stdout='[{"Name":"a","License":"GPL-3.0"},'
                              '{"Name":"b","License":"MIT"}]'), tool_env)
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert results["light/license"].verdict == BLOCKED
    assert "GPL-3.0" in results["light/license"].reason


def test_light_tools_missing_all_unknown(tmp_path, tool_env):
    results = run_tier("light", str(tmp_path))
    assert len(results) == 4
    assert all(r.verdict == UNKNOWN for r in results)


def test_light_timeout_is_unknown(tmp_path, tool_env):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    expect("gitleaks", subprocess.TimeoutExpired(cmd="gitleaks", timeout=600), tool_env)
    expect("pip-audit", FakeProc(0), tool_env)
    expect("npm", FakeProc(0, stdout='{"metadata":{"vulnerabilities":{"total":0}}}'), tool_env)
    expect("pip-licenses", FakeProc(0, stdout="[]"), tool_env)
    results = {r.check_id: r for r in run_tier("light", str(tmp_path))}
    assert results["light/gitleaks"].verdict == UNKNOWN


# ── deep 档 ──────────────────────────────────────────────────────────────────


SEMGREP_JSON = '{"results": [{"check_id": "eval-gate.security.hardcoded-credential"}], "errors": []}'


def test_deep_semgrep_findings_blocked(tmp_path, tool_env):
    expect("semgrep", FakeProc(1, stdout=SEMGREP_JSON), tool_env)
    results = {r.check_id: r for r in run_tier("deep", str(tmp_path))}
    assert results["deep/semgrep"].verdict == BLOCKED
    assert "1 finding" in results["deep/semgrep"].reason


def test_deep_semgrep_scan_errors_unknown(tmp_path, tool_env):
    expect("semgrep",
           FakeProc(2, stdout='{"results": [], "errors": [{"msg": "bad rule"}]}'), tool_env)
    results = {r.check_id: r for r in run_tier("deep", str(tmp_path))}
    assert results["deep/semgrep"].verdict == UNKNOWN


def test_deep_llm_review_default_unknown(tmp_path, tool_env):
    results = {r.check_id: r for r in run_tier("deep", str(tmp_path))}
    assert results["deep/llm_review"].verdict == UNKNOWN
    assert "not configured" in results["deep/llm_review"].reason


def test_deep_llm_review_injected(tmp_path):
    runner = LlmReviewRunner(review_fn=lambda t: (BLOCKED, "reviewer flagged x"))
    assert runner.run(str(tmp_path)).verdict == BLOCKED
    garbage = LlmReviewRunner(review_fn=lambda t: "nope")
    assert garbage.run(str(tmp_path)).verdict == UNKNOWN  # 非法判定收敛
    crash = LlmReviewRunner(review_fn=lambda t: 1 / 0)
    assert crash.run(str(tmp_path)).verdict == UNKNOWN


def test_deep_semgrep_pack_missing_is_unknown(tmp_path, tool_env, monkeypatch):
    # 隔离仓根回退：把 scan.__file__ 指向 tmp_path 下的假模块位置
    monkeypatch.setattr(scan, "__file__", str(tmp_path / "src" / "eval_gate" / "scan.py"))
    monkeypatch.delenv("EVAL_GATE_SEMGREP_PACK", raising=False)
    monkeypatch.chdir(tmp_path)                           # CWD 下也没有 packs/semgrep
    result = scan._semgrep_runner().run(str(tmp_path))
    assert result.verdict == UNKNOWN
    assert "required input not found" in result.reason


def test_deep_semgrep_pack_via_env(tmp_path, tool_env, monkeypatch):
    pack = tmp_path / "mypack"
    pack.mkdir()
    monkeypatch.setenv("EVAL_GATE_SEMGREP_PACK", str(pack))
    expect("semgrep", FakeProc(0, stdout='{"results": [], "errors": []}'), tool_env)
    results = {r.check_id: r for r in run_tier("deep", str(tmp_path))}
    assert results["deep/semgrep"].verdict == PASS
    argv = [c for c in tool_env["calls"]
            if os.path.basename(c["argv"][0]) == "semgrep"][0]["argv"]
    assert "--config" in argv and str(pack) in argv


# ── 自定义 runner 的统一 fail-closed 语义 ────────────────────────────────────


def test_cli_runner_contract_with_custom_tool(tmp_path, tool_env):
    runner = CliToolRunner(
        name="mytool", tier="static",
        build_argv=lambda d: ["mytool", "check", d],
        interpret=lambda code, out, err: (PASS, None) if code == 0 else (BLOCKED, "bad"))
    assert runner.run(str(tmp_path)).verdict == UNKNOWN     # 工具缺
    tool_env["set_tool"]("mytool", subprocess.TimeoutExpired(cmd="mytool", timeout=600))
    assert runner.run(str(tmp_path)).verdict == UNKNOWN     # 超时
    tool_env["set_tool"]("mytool", FakeProc(0))
    assert runner.run(str(tmp_path)).verdict == PASS        # 工具在且干净
    tool_env["set_tool"]("mytool", FakeProc(3))
    assert runner.run(str(tmp_path)).verdict == BLOCKED


def test_cli_runner_build_argv_none_is_unknown(tmp_path):
    runner = CliToolRunner(name="x", tier="light",
                           build_argv=lambda d: None,
                           interpret=lambda *a: (PASS, None))
    result = runner.run(str(tmp_path))
    assert result.verdict == UNKNOWN and "fail-closed" in result.reason


def test_cli_runner_interpret_crash_is_unknown(tmp_path, tool_env):
    def boom(*a):
        raise KeyError("parse")
    runner = CliToolRunner(name="y", tier="static",
                           build_argv=lambda d: ["y", d], interpret=boom)
    tool_env["set_tool"]("y", FakeProc(0))
    assert runner.run(str(tmp_path)).verdict == UNKNOWN


# ── 一档结论 = L3 聚合 ───────────────────────────────────────────────────────


def test_tier_verdict_uses_l3_aggregation(tmp_path, tool_env):
    expect("gitleaks", FakeProc(1), tool_env)
    expect("pip-audit", FakeProc(0), tool_env)
    expect("npm", FakeProc(0, stdout='{"metadata":{"vulnerabilities":{"total":0}}}'), tool_env)
    expect("pip-licenses", FakeProc(0, stdout="[]"), tool_env)
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    results = run_tier("light", str(tmp_path))
    verdict, reason = scan.tier_verdict(results)
    assert verdict == BLOCKED and "gitleaks" in reason


# ── CLI（ci/run-tier.sh 调用形态） ───────────────────────────────────────────


def test_cli_conclusion_line_and_exit_codes(tmp_path, tool_env, capsys):
    expect("gitleaks", FakeProc(0), tool_env)
    expect("pip-audit", FakeProc(0), tool_env)
    expect("npm", FakeProc(0, stdout='{"metadata":{"vulnerabilities":{"total":0}}}'), tool_env)
    expect("pip-licenses", FakeProc(0, stdout="[]"), tool_env)
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert cli.main(["scan", "light", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "【L3结论】verdict=PASS" in out

    expect("gitleaks", FakeProc(1), tool_env)
    assert cli.main(["scan", "light", str(tmp_path)]) == 1
    assert "【L3结论】verdict=BLOCKED" in capsys.readouterr().out

    expect("gitleaks", subprocess.TimeoutExpired(cmd="gitleaks", timeout=600), tool_env)
    assert cli.main(["scan", "light", str(tmp_path)]) == 2
    assert "【L3结论】verdict=UNKNOWN" in capsys.readouterr().out
