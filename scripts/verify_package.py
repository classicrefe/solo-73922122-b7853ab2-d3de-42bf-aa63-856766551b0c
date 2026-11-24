#!/usr/bin/env python3
"""离线验包 CLI（仅依赖 Python 标准库）。

用法
====
    python3 verify_package.py <交付包.json> <版号> <根摘要hex> <lo> <hi>

退出码 0 表示验包通过；非 0 表示失败，stderr 给出原因。
修复组可把本文件与交付包一并拷入无网环境使用。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# 允许直接以脚本方式运行（同目录 import）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.merkle import VerificationError, verify_manifest  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    package_path, version_s, root_hex, lo_s, hi_s = argv[1:]
    try:
        version, lo, hi = int(version_s), int(lo_s), int(hi_s)
    except ValueError:
        print("版号与区间端点必须为整数", file=sys.stderr)
        return 2
    try:
        pkg = json.loads(Path(package_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"交付包读取/解析失败: {exc}", file=sys.stderr)
        return 2
    try:
        verify_manifest(
            pkg,
            expected_version=version,
            expected_root_hex=root_hex,
            lo=lo,
            hi=hi,
        )
    except VerificationError as exc:
        print(f"验包失败: {exc}", file=sys.stderr)
        return 1
    count = len(pkg.get("entries", []))
    print(f"验包通过: 版号 {version}，区间 [{lo}, {hi}]，明细 {count} 条，"
          f"根摘要 {pkg['root_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
