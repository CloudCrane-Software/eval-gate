#!/usr/bin/env python3
# coding: utf-8
"""PROP-0006 首条真实交互录制脚本（record_first）.

安全纪律（执行协议红线 3 / 工单 A5）：
- consumer key **只经环境变量进入内存**（``STEPFUN_CONSUMER_KEY``），本脚本
  不打印、不落盘、不写入记录；命令行参数里也不许出现 key；
- 录制经 :class:`oracle_suite.recorder.InteractionRecorder` 强制脱敏：
  Authorization 头整体替换 + 值内 key/token/手机号模式扫描；
- **写后校验**：落盘前重读文件，要求 (a) 不含 key 原值 (b) 无敏感形态残留
  (c) 已含 REDACT 占位（证明字段层脱敏生效）。任一不满足 → 删文件、非零退出。

用法::

    STEPFUN_CONSUMER_KEY=... python scripts/record_first.py --out <path.json>

输出（stdout）只含：HTTP 状态码、record_id、顶层/元数据字段清单、REDACT 统计。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))

from oracle_suite.recorder import (  # noqa: E402
    InteractionRecorder,
    redact_tree,
    scan_for_secrets,
)

DEFAULT_ENDPOINT = "https://ai.hkmingdajiaoyu.com/v1/chat/completions"
DEFAULT_MODEL = "step-3.5-flash"
DEFAULT_PROMPT = "用一句话说明什么是幂等性"


def _fail(msg: str, code: int = 2) -> int:
    print(f"[record_first] FAIL: {msg}", file=sys.stderr)
    return code


def do_call(endpoint: str, model: str, prompt: str, key: str, timeout: float):
    """发一次真实请求。返回 (status, latency_ms, response_payload 或 None, raw_text)。

    本函数把 key 放进 Authorization 头后即刻使用，不保存到任何结构（除请求头
    本身，头会在 recorder 里被整体脱敏后才进记录）。
    """
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:   # 4xx/5xx 也记录（状态码是证据）
        status = exc.code
        raw = exc.read().decode("utf-8", errors="replace")
    latency_ms = (time.perf_counter() - started) * 1000.0
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None
    return status, latency_ms, payload, raw


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="PROP-0006 首条真实交互录制")
    parser.add_argument("--out", required=True, help="脱敏后 interaction record JSON 输出路径")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--case-id", default="oracle-first-real-2026-09")
    parser.add_argument("--tenant", default="prop-0006")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)

    key = os.environ.get("STEPFUN_CONSUMER_KEY", "")
    if not key:
        return _fail("STEPFUN_CONSUMER_KEY not set; key must come from env, "
                     "never from argv/files/stdout")
    if len(key) < 16:
        return _fail("env key looks too short to be a consumer key "
                     f"(len={len(key)}); refusing")

    status, latency_ms, payload, raw = do_call(
        args.endpoint, args.model, args.prompt, key, args.timeout)

    # 组装"待记录"形状：Authorization 头原样交给 recorder（入库前整体脱敏）。
    request_shape = {
        "method": "POST",
        "url": args.endpoint,
        "headers": {"Content-Type": "application/json",
                    "Authorization": "Bearer " + key},
        "body": {"model": args.model,
                 "messages": [{"role": "user", "content": args.prompt}],
                 "stream": False},
    }
    response_shape: dict = {"status": status}
    if payload is not None:
        response_shape["body"] = payload
    else:
        response_shape["body_text_truncated"] = raw[:500]

    recorder = InteractionRecorder(tenant_id=args.tenant)
    record = recorder.record(
        request_shape, response_shape,
        model=args.model,
        endpoint_ref=args.endpoint,
        latency_ms=round(latency_ms, 1),
        tokens=payload.get("usage") if isinstance(payload, dict) else None,
        labels=["oracle-suite/first-record"],
        case_id=args.case_id,
        capture="record_first.py@PROP-0006",
    )

    # ── 写后校验（落盘前，零泄漏门槛） ────────────────────────────────────
    out_json = record.to_json()
    hits = scan_for_secrets(out_json)
    has_redact = "<REDACT-" in out_json
    key_leak = key in out_json
    if key_leak or hits or not has_redact:
        return _fail(f"leak gate failed (key_leak={key_leak}, "
                     f"pattern_hits={[c for c, _ in hits]}, "
                     f"redact_placeholder={has_redact}); nothing written", code=3)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out_json + "\n")
    # 落盘后复读回验（防编码/写出层意外）
    with open(args.out, encoding="utf-8") as fh:
        written = fh.read()
    if key in written or scan_for_secrets(written):
        os.remove(args.out)
        return _fail("post-write verification failed; file removed", code=3)

    # ── 只打印非敏感摘要 ─────────────────────────────────────────────────
    print(f"http_status={status}")
    print(f"record_id={record.record_id}")
    print(f"interaction_schema={record.interaction_schema}")
    print("top_level_fields=" + ",".join(sorted(record.to_dict())))
    print("metadata_fields=" + ",".join(sorted(record.metadata)))
    print(f"out_path={os.path.abspath(args.out)}")
    count = {"FIELD": 0, "VALUE": 0}
    redact_tree(record.to_dict(), _count=count)
    print("redaction_demo=Authorization header wholly replaced; "
          f"field_layer_count={count['FIELD']}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
