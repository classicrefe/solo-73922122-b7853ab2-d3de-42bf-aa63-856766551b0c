"""SQLite 版本化与 FastAPI 接口端到端测试。"""

import hashlib

import pytest
from fastapi.testclient import TestClient


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("FILM_DB_PATH", db_path)
    # 延迟导入以读取环境变量；新库路径 + 重置连接状态，保证测试隔离
    from app import main as main_mod

    main_mod.DB_PATH = db_path
    main_mod._init_state()
    with TestClient(main_mod.app) as c:
        yield c


def _upsert(client, nid, digest):
    r = client.post("/admin/working", json={"negative_id": nid, "sha256": digest})
    assert r.status_code == 200, r.text


def test_full_lifecycle_publish_claim_verify(client):
    from app.merkle import verify_manifest

    # 初始发布 v1：5 条
    for i in range(5):
        _upsert(client, 1000 + i, sha(f"v1-{i}"))
    r = client.post("/admin/publish", json={"note": "初版"})
    assert r.status_code == 201
    v1 = r.json()
    assert v1["version"] == 1 and v1["leaf_count"] == 5
    root1 = v1["root_sha256"]
    assert len(root1) == 64

    # 领全区间
    r = client.get("/versions/1/manifests/1000/1004")
    assert r.status_code == 200
    pkg = r.json()
    assert len(pkg["entries"]) == 5
    assert all(1000 <= e["negative_id"] <= 1004 for e in pkg["entries"])
    verify_manifest(pkg, expected_version=1, expected_root_hex=root1, lo=1000, hi=1004)

    # 领子区间，包内不含区间外明细
    r = client.get("/versions/1/manifests/1001/1002")
    sub = r.json()
    assert [e["negative_id"] for e in sub["entries"]] == [1001, 1002]
    # proof/boundary 中不出现区间外摘要
    assert all("sha256" not in p for p in sub["proof"])
    verify_manifest(sub, expected_version=1, expected_root_hex=root1, lo=1001, hi=1002)

    # 空区间也能验
    r = client.get("/versions/1/manifests/2000/3000")
    empty_pkg = r.json()
    assert empty_pkg["entries"] == []
    verify_manifest(empty_pkg, expected_version=1, expected_root_hex=root1, lo=2000, hi=3000)


def test_correction_and_delete_create_new_version(client):
    from app.merkle import verify_manifest

    for i in range(4):
        _upsert(client, 500 + i, sha(f"old-{i}"))
    v1 = client.post("/admin/publish").json()

    # 勘误：更正一条摘要 + 删一条记录 -> 新版
    _upsert(client, 501, sha("corrected-501"))
    r = client.request("DELETE", "/admin/working/503")
    assert r.status_code == 200
    v2 = client.post("/admin/publish", json={"note": "勘误"}).json()
    assert v2["version"] == 2 and v2["leaf_count"] == 3
    assert v2["root_sha256"] != v1["root_sha256"]

    # 旧版照常领取，明细与证明仍对应旧版
    old = client.get("/versions/1/manifests/500/503").json()
    assert len(old["entries"]) == 4
    verify_manifest(old, expected_version=1, expected_root_hex=v1["root_sha256"], lo=500, hi=503)

    new = client.get("/versions/2/manifests/500/503").json()
    assert sorted(e["negative_id"] for e in new["entries"]) == [500, 501, 502]
    assert next(e for e in new["entries"] if e["negative_id"] == 501)["sha256"] == sha("corrected-501")
    verify_manifest(new, expected_version=2, expected_root_hex=v2["root_sha256"], lo=500, hi=503)

    # 版本列表都在
    versions = client.get("/versions").json()
    assert [v["version"] for v in versions["versions"]] == [1, 2]
    assert versions["current_version"] == 2


def test_missing_one_entry_fails(client):
    from app.merkle import VerificationError, verify_manifest

    for i in range(6):
        _upsert(client, 10 + i, sha(f"x-{i}"))
    v1 = client.post("/admin/publish").json()
    pkg = client.get("/versions/1/manifests/10/15").json()
    pkg["entries"].pop(2)  # 抽走一件
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=1, expected_root_hex=v1["root_sha256"], lo=10, hi=15)


def test_empty_catalog_version(client):
    from app.merkle import EMPTY_ROOT, verify_manifest

    # 工作区为空也发版（空目录版本）
    v1 = client.post("/admin/publish").json()
    assert v1["leaf_count"] == 0
    assert v1["root_sha256"] == EMPTY_ROOT.hex()

    pkg = client.get("/versions/1/manifests/0/4294967295").json()
    assert pkg["entries"] == [] and pkg["proof"] == []
    verify_manifest(pkg, expected_version=1, expected_root_hex=EMPTY_ROOT.hex(),
                    lo=0, hi=4294967295)

    # 之后再发有数据的新版，两版都可领
    _upsert(client, 7, sha("seven"))
    v2 = client.post("/admin/publish").json()
    assert v2["leaf_count"] == 1
    assert client.get("/versions/1/manifests/0/100").status_code == 200
    assert client.get("/versions/2/manifests/0/100").status_code == 200


def test_publish_failure_keeps_old_version(client, monkeypatch):
    # v1 正常发布
    _upsert(client, 1, sha("a"))
    v1 = client.post("/admin/publish").json()

    # 让发版在建树后、提交前抛错 -> 回滚；旧版继续可用，版本号不增加
    from app import db as db_mod

    real_next = db_mod._next_version

    def boom(conn):
        real_next(conn)  # 模拟走到分配版号阶段后故障
        raise RuntimeError("模拟磁盘故障")

    monkeypatch.setattr(db_mod, "_next_version", boom)
    r = client.post("/admin/publish")
    assert r.status_code == 500
    monkeypatch.setattr(db_mod, "_next_version", real_next)

    versions = client.get("/versions").json()["versions"]
    assert [v["version"] for v in versions] == [1]
    # 旧版仍可领取且可验
    pkg = client.get("/versions/1/manifests/1/1").json()
    from app.merkle import verify_manifest
    verify_manifest(pkg, expected_version=1, expected_root_hex=v1["root_sha256"], lo=1, hi=1)

    # 故障恢复后可正常发下一版（版号仍是 2，没有被失败事务占用）
    v2 = client.post("/admin/publish").json()
    assert v2["version"] == 2


def test_validation_errors(client):
    # 摘要格式错误
    r = client.post("/admin/working", json={"negative_id": 1, "sha256": "zz"})
    assert r.status_code == 422
    # 编号越界
    r = client.post("/admin/working", json={"negative_id": 2 ** 32, "sha256": sha("z")})
    assert r.status_code == 422
    # 不存在的版本
    assert client.get("/versions/99/manifests/0/1").status_code == 404
    # 非法区间
    _upsert(client, 1, sha("a"))
    client.post("/admin/publish")
    assert client.get("/versions/1/manifests/10/5").status_code == 422


def test_uint32_boundary_ids(client):
    from app.merkle import verify_manifest

    _upsert(client, 0, sha("zero"))
    _upsert(client, 0xFFFFFFFF, sha("max"))
    v1 = client.post("/admin/publish").json()
    pkg = client.get("/versions/1/manifests/0/4294967295").json()
    assert [e["negative_id"] for e in pkg["entries"]] == [0, 0xFFFFFFFF]
    verify_manifest(pkg, expected_version=1, expected_root_hex=v1["root_sha256"],
                    lo=0, hi=0xFFFFFFFF)
