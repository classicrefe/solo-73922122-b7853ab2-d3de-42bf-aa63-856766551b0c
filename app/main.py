"""底片目录发布服务（FastAPI）。

接口
====
GET  /health 健康检查
GET  /versions                                        版本列表（含可留存版号、根摘要）
GET  /versions/{version}                              单版元信息
GET  /versions/{version}/manifests/{lo}/{hi}          按闭区间领清单与证明
POST /admin/working                                   草稿 upsert（更正摘要）
DELETE /admin/working/{negative_id}                   草稿删记录
POST /admin/publish                                   发新版（单事务，失败旧版继续可用）
GET  /docs                                            Swagger 试领清单
"""

from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator

from . import db
from .manifest import build_manifest
from .merkle import EMPTY_ROOT, verify_manifest

DB_PATH = os.environ.get("FILM_DB_PATH", "/data/film_catalog.db")
UINT32_MAX = 0xFFFFFFFF
HEX32 = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class WorkingRecordIn(BaseModel):
    negative_id: int = Field(..., ge=0, le=UINT32_MAX)
    sha256: str = HEX32

    @field_validator("sha256")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class PublishIn(BaseModel):
    note: Optional[str] = Field(default=None, max_length=500)


def _init_state() -> None:
    """初始化/重置连接状态（测试可在新库路径后调用）。"""
    app.state._local = threading.local()
    app.state._all_conns = []
    app.state._conn_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 每个工作线程独立连接（SQLite 连接不能跨线程共用事务状态）
    _init_state()
    yield
    with app.state._conn_lock:
        for conn in app.state._all_conns:
            conn.close()
        app.state._all_conns.clear()


app = FastAPI(
    title="底片目录发布服务",
    version="1.0.0",
    description="按版号与编号闭区间领取底片清单及 Merkle 证明，支持离线验包。",
    lifespan=lifespan,
)


def _conn():
    local = app.state._local
    conn = getattr(local, "conn", None)
    if conn is None:
        conn = db.connect(DB_PATH)
        local.conn = conn
        with app.state._conn_lock:
            app.state._all_conns.append(conn)
    return conn


def _require_version(version: int):
    row = db.get_version(_conn(), version)
    if row is None:
        raise HTTPException(status_code=404, detail=f"版本 {version} 不存在")
    return row


@app.get("/health")
def health():
    return {"status": "ok", "current_version": db.current_version(_conn())}


@app.get("/versions")
def versions():
    rows = db.list_versions(_conn())
    return {
        "current_version": db.current_version(_conn()),
        "versions": [
            {
                "version": int(r["version"]),
                "created_at": r["created_at"],
                "leaf_count": int(r["leaf_count"]),
                "root_sha256": r["root_sha256"] or None,
                "note": r["note"],
            }
            for r in rows
        ],
    }


@app.get("/versions/{version}")
def version_meta(version: int = Path(..., ge=1)):
    r = _require_version(version)
    return {
        "version": int(r["version"]),
        "created_at": r["created_at"],
        "leaf_count": int(r["leaf_count"]),
        # 空目录版本也给出确定的可留存根摘要
        "root_sha256": r["root_sha256"] or EMPTY_ROOT.hex(),
        "note": r["note"],
    }


@app.get("/versions/{version}/manifests/{lo}/{hi}")
def get_manifest(
    version: int = Path(..., ge=1),
    lo: int = Path(..., ge=0, le=UINT32_MAX),
    hi: int = Path(..., ge=0, le=UINT32_MAX),
):
    if lo > hi:
        raise HTTPException(status_code=422, detail="闭区间下界 lo 不得大于上界 hi")
    row = _require_version(version)
    leaf_count = int(row["leaf_count"])
    root_hex = row["root_sha256"] or EMPTY_ROOT.hex()
    levels = db.all_level_hashes(_conn(), version)
    return build_manifest(_conn(), version, lo, hi, levels, leaf_count, root_hex)


# ---------------------------------------------------------------------------
# 管理端：勘误（更正摘要 / 删记录）后发新版
# ---------------------------------------------------------------------------


@app.post("/admin/working", status_code=200)
def upsert_working(record: WorkingRecordIn):
    with db.transaction(_conn()):
        db.upsert_working(_conn(), record.negative_id, record.sha256)
    return {"status": "ok", "working_records": len(db.list_working(_conn()))}


@app.delete("/admin/working/{negative_id}", status_code=200)
def delete_working(negative_id: int = Path(..., ge=0, le=UINT32_MAX)):
    with db.transaction(_conn()):
        existed = db.delete_working(_conn(), negative_id)
    if not existed:
        raise HTTPException(status_code=404, detail=f"工作区中无编号 {negative_id}")
    return {"status": "deleted", "negative_id": negative_id}


@app.get("/admin/working")
def show_working():
    return {"working_records": [dict(r) for r in db.list_working(_conn())]}


@app.post("/admin/publish", status_code=201)
def publish(body: PublishIn = PublishIn()):
    try:
        result = db.publish_version(_conn(), note=body.note)
    except Exception as exc:  # 发版失败：事务回滚，旧版继续提供
        raise HTTPException(status_code=500, detail=f"发版失败，已回滚: {exc}")
    # 空目录版本同样给出可留存根摘要
    if result["root_sha256"] is None:
        result["root_sha256"] = EMPTY_ROOT.hex()
    return result


@app.post("/admin/verify")
def verify_online(
    package: dict,
    lo: int = Query(..., ge=0, le=UINT32_MAX),
    hi: int = Query(..., ge=0, le=UINT32_MAX),
):
    """服务端自测入口；离线场景请直接使用 app.merkle.verify_manifest。"""
    try:
        version = int(package["version"])
        root = str(package["root_sha256"])
        verify_manifest(package, expected_version=version, expected_root_hex=root, lo=lo, hi=hi)
    except KeyError:
        raise HTTPException(status_code=422, detail="包内缺少 version/root_sha256")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"验包失败: {exc}")
    return {"status": "valid", "version": version, "range": [lo, hi],
            "entries": len(package.get("entries", []))}
