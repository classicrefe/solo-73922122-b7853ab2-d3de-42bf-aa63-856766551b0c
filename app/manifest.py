"""按版号与编号闭区间构造交付包（只含区间内明细 + 必要证明信息）。"""

from __future__ import annotations

import sqlite3
from typing import Optional

from .merkle import (
    DOMAIN_VERSION,
    make_empty_range_proof,
    make_range_proof,
)

PACKAGE_DOMAIN = "film-catalog-manifest-v1"


def build_manifest(
    conn: sqlite3.Connection,
    version: int,
    lo: int,
    hi: int,
    levels: list,
    leaf_count: int,
    root_hex: Optional[str],
) -> dict:
    """构造可离线验证的区间交付包。

    包内 entries 严格限定为 [lo, hi] 内的记录；区间外只出现 proof 哈希
    节点和 boundary 中紧邻边界的编号（无摘要），不附任何区间外明细。
    """
    from .db import boundary_records, records_in_range

    entries_rows = records_in_range(conn, version, lo, hi)
    pred, succ = boundary_records(conn, version, lo, hi)

    if entries_rows:
        lo_idx = int(entries_rows[0]["leaf_index"])
        hi_idx = int(entries_rows[-1]["leaf_index"])
        proof, pred_idx, succ_idx = make_range_proof(levels, lo_idx, hi_idx, leaf_count)
    else:
        # 空区间：插入位置 = 后继叶子的叶序（无后继则插到末尾）
        insert_before = int(succ["leaf_index"]) if succ is not None else leaf_count
        proof, pred_idx, succ_idx = make_empty_range_proof(levels, insert_before, leaf_count)

    package = {
        "domain": PACKAGE_DOMAIN,
        "hash_alg": "SHA-256",
        "merkle_domain": DOMAIN_VERSION,
        "version": version,
        "root_sha256": root_hex,
        "leaf_count": leaf_count,
        "requested_range": {"lo": lo, "hi": hi},
        "entries": [
            {
                "negative_id": int(r["negative_id"]),
                "index": int(r["leaf_index"]),
                "sha256": r["sha256"],
            }
            for r in entries_rows
        ],
        "boundary": {
            "predecessor_index": pred_idx,
            "predecessor_id": int(pred["negative_id"]) if pred is not None and pred_idx is not None else None,
            "successor_index": succ_idx,
            "successor_id": int(succ["negative_id"]) if succ is not None and succ_idx is not None else None,
        },
        "proof": [p.to_dict() for p in proof],
    }
    return package
