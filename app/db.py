"""SQLite 持久化：工作区 + 不可变版本快照 + 版本 Merkle 节点。

发版在单个事务内完成：写版本行 -> 复制快照 -> 建树写节点 -> 更新工作区指针。
事务中途任何失败都会整体回滚，已发布的旧版明细与证明始终可读、不变。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional, Tuple

from .merkle import build_levels, leaf_hash

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 工作区：尚未发布的当前草稿，negative_id 唯一
CREATE TABLE IF NOT EXISTS working_records (
    negative_id INTEGER PRIMARY KEY CHECK (negative_id BETWEEN 0 AND 4294967295),
    sha256      TEXT NOT NULL
);

-- 已发布版本的不可变明细快照
CREATE TABLE IF NOT EXISTS versions (
    version     INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    leaf_count  INTEGER NOT NULL,
    root_sha256 TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS version_records (
    version     INTEGER NOT NULL REFERENCES versions(version),
    negative_id INTEGER NOT NULL CHECK (negative_id BETWEEN 0 AND 4294967295),
    leaf_index  INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (version, negative_id)
);
CREATE INDEX IF NOT EXISTS idx_vr_version_index
    ON version_records(version, leaf_index);

-- 每版 Merkle 树节点哈希（供 O(log n) 生成区间证明，无需重算整树）
CREATE TABLE IF NOT EXISTS version_nodes (
    version  INTEGER NOT NULL REFERENCES versions(version),
    level    INTEGER NOT NULL,
    position INTEGER NOT NULL,
    hash     TEXT NOT NULL,
    PRIMARY KEY (version, level, position)
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    # check_same_thread=False：连接按线程隔离创建，关闭由 lifespan 统一进行
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# 工作区草稿维护（勘误：更正摘要 = upsert，删记录 = delete）
# ---------------------------------------------------------------------------


def upsert_working(conn: sqlite3.Connection, negative_id: int, sha256_hex: str) -> None:
    conn.execute(
        """INSERT INTO working_records(negative_id, sha256) VALUES(?, ?)
           ON CONFLICT(negative_id) DO UPDATE SET sha256=excluded.sha256""",
        (negative_id, sha256_hex),
    )


def delete_working(conn: sqlite3.Connection, negative_id: int) -> bool:
    cur = conn.execute("DELETE FROM working_records WHERE negative_id=?", (negative_id,))
    return cur.rowcount > 0


def list_working(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return list(conn.execute(
        "SELECT negative_id, sha256 FROM working_records ORDER BY negative_id"))


# ---------------------------------------------------------------------------
# 发布新版本
# ---------------------------------------------------------------------------


def _next_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(MAX(version), 0) + 1 AS v FROM versions").fetchone()
    return int(row["v"])


def publish_version(conn: sqlite3.Connection, note: Optional[str] = None) -> dict:
    """把当前工作区快照发布为新版本。全程单事务，失败回滚，旧版不受影响。"""
    with transaction(conn):
        records = list_working(conn)
        leaves = [leaf_hash(int(r["negative_id"]), r["sha256"]) for r in records]
        levels = build_levels(leaves)
        root = levels[-1][0] if leaves else None
        version = _next_version(conn)

        conn.execute(
            "INSERT INTO versions(version, leaf_count, root_sha256, note) VALUES(?, ?, ?, ?)",
            (version, len(leaves), root.hex() if root else "", note),
        )
        conn.executemany(
            "INSERT INTO version_records(version, negative_id, leaf_index, sha256) VALUES(?, ?, ?, ?)",
            [(version, int(r["negative_id"]), idx, r["sha256"]) for idx, r in enumerate(records)],
        )
        node_rows = []
        for level, nodes in enumerate(levels):
            for pos, h in enumerate(nodes):
                node_rows.append((version, level, pos, h.hex()))
        conn.executemany(
            "INSERT INTO version_nodes(version, level, position, hash) VALUES(?, ?, ?, ?)",
            node_rows,
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('current_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(version),),
        )
        return {
            "version": version,
            "leaf_count": len(leaves),
            "root_sha256": root.hex() if root else None,
            "note": note,
        }


def current_version(conn: sqlite3.Connection) -> Optional[int]:
    row = conn.execute("SELECT value FROM meta WHERE key='current_version'").fetchone()
    return int(row["value"]) if row else None


def get_version(conn: sqlite3.Connection, version: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM versions WHERE version=?", (version,)).fetchone()


def list_versions(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM versions ORDER BY version"))


def version_exists(conn: sqlite3.Connection, version: int) -> bool:
    return get_version(conn, version) is not None


# ---------------------------------------------------------------------------
# 只读查询：按版号 + 编号闭区间
# ---------------------------------------------------------------------------


def records_in_range(
    conn: sqlite3.Connection, version: int, lo: int, hi: int
) -> List[sqlite3.Row]:
    return list(conn.execute(
        """SELECT negative_id, leaf_index, sha256 FROM version_records
           WHERE version=? AND negative_id BETWEEN ? AND ?
           ORDER BY negative_id""",
        (version, lo, hi),
    ))


def boundary_records(
    conn: sqlite3.Connection, version: int, lo: int, hi: int
) -> Tuple[Optional[sqlite3.Row], Optional[sqlite3.Row]]:
    """返回区间紧邻的前驱、后继记录（只取编号与叶序，不进交付明细）。"""
    pred = conn.execute(
        """SELECT negative_id, leaf_index FROM version_records
           WHERE version=? AND negative_id < ? ORDER BY negative_id DESC LIMIT 1""",
        (version, lo),
    ).fetchone()
    succ = conn.execute(
        """SELECT negative_id, leaf_index FROM version_records
           WHERE version=? AND negative_id > ? ORDER BY negative_id ASC LIMIT 1""",
        (version, hi),
    ).fetchone()
    return pred, succ


def all_level_hashes(conn: sqlite3.Connection, version: int) -> List[List[bytes]]:
    rows = list(conn.execute(
        "SELECT level, position, hash FROM version_nodes WHERE version=? ORDER BY level, position",
        (version,),
    ))
    levels: List[List[bytes]] = []
    for r in rows:
        lvl = int(r["level"])
        while len(levels) <= lvl:
            levels.append([])
        levels[lvl].append(bytes.fromhex(r["hash"]))
    return levels
