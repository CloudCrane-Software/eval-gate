#!/usr/bin/env bash
# ci/run-tier.sh —— 扫描三档统一入口（WO-0004 / PROP-0001 v1.7 §12.9）
#
# 用法:  ci/run-tier.sh static|light|deep <被扫目录>
#
# 行为:  调 eval_gate.scan 执行该档全部 Check，逐条打印结果，
#        末行输出 L3 结论行:  【L3结论】verdict=PASS|BLOCKED|UNKNOWN
# 退出码: 0=PASS  1=BLOCKED  2=UNKNOWN（fail-closed 同样非零，CI 不得放行）
#
# 说明:  本脚本不安装任何扫描工具（真工具由 CI 环境的 env YAML 保证装齐）；
#        工具缺失时对应 Check 判 UNKNOWN，整体结论按 L3 三态聚合。
set -euo pipefail

TIER="${1:-}"
TARGET="${2:-}"

if [[ -z "$TIER" || -z "$TARGET" ]]; then
  echo "usage: $0 static|light|deep <dir>" >&2
  exit 64
fi

case "$TIER" in
  static|light|deep) ;;
  *) echo "unknown tier: $TIER (valid: static|light|deep)" >&2; exit 64 ;;
esac

if [[ ! -d "$TARGET" ]]; then
  echo "target is not a directory: $TARGET" >&2
  exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || PYTHON_BIN=python

PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
  exec "$PYTHON_BIN" -m eval_gate scan "$TIER" "$TARGET"
