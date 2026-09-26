# coding: utf-8
"""命令行入口：``python -m eval_gate scan <tier> <dir>``.

ci/run-tier.sh 调用本模块。输出逐条 Check 结果，末行给出 L3 结论行：
``【L3结论】verdict=PASS|BLOCKED|UNKNOWN``。
退出码：0=PASS，1=BLOCKED，2=UNKNOWN（fail-closed 也非零，CI 不得放行）。
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import scan
from .gate import BLOCKED, PASS, UNKNOWN, aggregate, aggregate_reason


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="eval_gate",
                                     description="公司级评测门禁（扫描三档 CLI）")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", help="执行一档安全扫描（static/light/deep）")
    p_scan.add_argument("tier", choices=sorted(scan.TIERS))
    p_scan.add_argument("target", help="被扫目录")
    args = parser.parse_args(argv)

    if args.command != "scan":  # pragma: no cover — argparse 已兜底
        parser.error(f"unknown command: {args.command}")

    results = scan.run_tier(args.tier, args.target)
    for r in results:
        line = f"[{r.check_id}] tool={r.tool} verdict={r.verdict}"
        if r.reason:
            line += f" reason={r.reason}"
        print(line)
    verdict = aggregate(results)
    reason = aggregate_reason(results)
    if reason:
        print(f"reason: {reason}")
    print(f"【L3结论】verdict={verdict}")
    if verdict == PASS:
        return 0
    if verdict == BLOCKED:
        return 1
    return 2  # UNKNOWN — fail-closed，CI 同样不得放行


if __name__ == "__main__":
    sys.exit(main())
