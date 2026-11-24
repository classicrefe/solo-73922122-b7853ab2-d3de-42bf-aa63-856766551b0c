#!/usr/bin/env python3
"""种子数据脚本：通过 HTTP 接口灌入示例底片并发布首版。

用法（服务启动后）：
    python3 scripts/seed_demo.py [BASE_URL]
默认 BASE_URL=http://127.0.0.1:8000
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
import json


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def main(base_url: str) -> int:
    # 示例底片：编号故意留空号，便于演示“该段无记录验空”
    demo = [
        (100, "frame-0100"),
        (101, "frame-0101"),
        (102, "frame-0102"),
        (200, "frame-0200"),
        (201, "frame-0201"),
        (300, "frame-0300"),
    ]
    for negative_id, seed in demo:
        post(f"{base_url}/admin/working",
             {"negative_id": negative_id, "sha256": sha(seed)})
    result = post(f"{base_url}/admin/publish", {"note": "种子首版"})
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n请留存版号 {result['version']} 与根摘要 {result['root_sha256']}")
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    raise SystemExit(main(base.rstrip("/")))
