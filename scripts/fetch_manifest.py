#!/usr/bin/env python3
"""领清单并落盘为交付包（仅用标准库，便于在隔离网内使用）。

用法：
    python3 scripts/fetch_manifest.py BASE_URL VERSION LO HI OUT.json
例如：
    python3 scripts/fetch_manifest.py http://127.0.0.1:8000 1 100 201 pkg.json
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    base, version, lo, hi, out = argv[1:]
    url = f"{base.rstrip('/')}/versions/{version}/manifests/{lo}/{hi}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        pkg = json.loads(resp.read())
    Path(out).write_text(json.dumps(pkg, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已保存交付包: {out}")
    print(f"版号={pkg['version']} 根摘要={pkg['root_sha256']} "
          f"区间=[{lo},{hi}] 明细={len(pkg['entries'])} 条 证明节点={len(pkg['proof'])} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
