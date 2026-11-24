"""核心 Merkle 证明与离线验包测试（标准库 + pytest）。"""

import hashlib
import itertools

import pytest

from app.merkle import (
    EMPTY_ROOT,
    ProofNode,
    VerificationError,
    _parent,
    build_levels,
    leaf_hash,
    make_empty_range_proof,
    make_range_proof,
    root_hash,
    verify_manifest,
)


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def make_tree(n: int, id_gap: int = 100):
    ids = [id_gap * (i + 1) for i in range(n)]
    digests = [sha(f"neg-{i}") for i in ids]
    leaves = [leaf_hash(i, d) for i, d in zip(ids, digests)]
    levels = build_levels(leaves)
    return ids, digests, leaves, levels


def pkg_skeleton(version, root_hex, leaf_count, lo, hi, entries, proof, boundary):
    return {
        "domain": "film-catalog-manifest-v1",
        "hash_alg": "SHA-256",
        "merkle_domain": 1,
        "version": version,
        "root_sha256": root_hex,
        "leaf_count": leaf_count,
        "requested_range": {"lo": lo, "hi": hi},
        "entries": entries,
        "boundary": boundary,
        "proof": proof,
    }


def build_pkg(ids, digests, levels, lo_id, hi_id):
    """模拟服务端按编号闭区间出包。"""
    n = len(ids)
    in_range = [(i, ids[i], digests[i]) for i in range(n) if lo_id <= ids[i] <= hi_id]
    if in_range:
        lo_idx, hi_idx = in_range[0][0], in_range[-1][0]
        proof, pred_idx, succ_idx = make_range_proof(levels, lo_idx, hi_idx, n)
    else:
        insert = next((i for i, x in enumerate(ids) if x > hi_id), n)
        proof, pred_idx, succ_idx = make_empty_range_proof(levels, insert, n)
    entries = [
        {"negative_id": nid, "index": idx, "sha256": dg}
        for idx, nid, dg in in_range
    ]
    boundary = {
        "predecessor_index": pred_idx,
        "predecessor_id": ids[pred_idx] if pred_idx is not None else None,
        "successor_index": succ_idx,
        "successor_id": ids[succ_idx] if succ_idx is not None else None,
    }
    root = levels[-1][0].hex()
    return pkg_skeleton(3, root, n, lo_id, hi_id, entries,
                        [p.to_dict() for p in proof], boundary)


@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 257])
def test_root_with_bruteforce(n):
    ids, digests, leaves, levels = make_tree(n)
    if n == 0:
        assert root_hash(leaves) == EMPTY_ROOT
        return
    # 暴力重算根
    cur = leaves[:]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            nxt.append(_parent(cur[i], cur[i + 1] if i + 1 < len(cur) else None))
        cur = nxt
    assert levels[-1][0] == cur[0]


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 32, 64])
def test_all_ranges_verify(n):
    ids, digests, leaves, levels = make_tree(n)
    root = levels[-1][0].hex()
    # 所有闭区间（含越界空区间）
    points = [ids[0] - 10] + ids + [ids[-1] + 10]
    for lo, hi in itertools.combinations(points, 2):
        pkg = build_pkg(ids, digests, levels, lo, hi)
        verify_manifest(pkg, expected_version=3, expected_root_hex=root, lo=lo, hi=hi)
    # 单点区间
    for nid in ids:
        pkg = build_pkg(ids, digests, levels, nid, nid)
        verify_manifest(pkg, expected_version=3, expected_root_hex=root, lo=nid, hi=nid)


def test_empty_tree_empty_segment():
    # 整册无记录（leaf_count=0），领任意区间都能验空
    pkg = pkg_skeleton(1, EMPTY_ROOT.hex(), 0, 10, 20, [], [],
                       {"predecessor_index": None, "predecessor_id": None,
                        "successor_index": None, "successor_id": None})
    verify_manifest(pkg, expected_version=1, expected_root_hex=EMPTY_ROOT.hex(), lo=10, hi=20)


@pytest.mark.parametrize("n", [1, 2, 5, 10])
def test_empty_segment_within_tree(n):
    ids, digests, leaves, levels = make_tree(n)
    root = levels[-1][0].hex()
    # 头部空、中间空（编号之间留 50 个空号）、尾部空
    ranges = [
        (ids[0] - 5, ids[0] - 1),
        (ids[0] + 1, ids[0] + 49),
        (ids[-1] + 1, ids[-1] + 9),
    ]
    for lo, hi in ranges:
        pkg = build_pkg(ids, digests, levels, lo, hi)
        assert pkg["entries"] == []
        verify_manifest(pkg, expected_version=3, expected_root_hex=root, lo=lo, hi=hi)
        # 空区间证明里不得夹带任何明细摘要
        assert all(set(e.keys()) == {"level", "position", "hash"} for e in pkg["proof"])


def test_empty_segment_between_every_gap():
    # 每个相邻编号之间的空号段都能验空，且伪造“有记录却报空”必失败
    ids, digests, leaves, levels = make_tree(6)
    root = levels[-1][0].hex()
    for a, b in zip(ids, ids[1:]):
        if b - a <= 1:
            continue
        lo, hi = a + 1, b - 1
        pkg = build_pkg(ids, digests, levels, lo, hi)
        assert pkg["entries"] == []
        verify_manifest(pkg, expected_version=3, expected_root_hex=root, lo=lo, hi=hi)

    # 该段实际有记录时，空包必须失败
    lo, hi = ids[1], ids[2]
    pkg = build_pkg(ids, digests, levels, lo, hi)
    pkg["entries"] = []
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root, lo=lo, hi=hi)


def test_missing_entry_is_failure():
    ids, digests, leaves, levels = make_tree(6)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[0], ids[-1])
    assert len(pkg["entries"]) == 6
    # 删掉中间一条（模拟少一件）
    pkg["entries"].pop(3)
    with pytest.raises(VerificationError, match="不连续|衔接|证明节点覆盖"):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[0], hi=ids[-1])


def test_tampered_digest_fails():
    ids, digests, leaves, levels = make_tree(4)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[1], ids[2])
    pkg["entries"][0]["sha256"] = sha("forged")
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[1], hi=ids[2])


def test_tampered_id_fails():
    ids, digests, leaves, levels = make_tree(4)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[1], ids[2])
    pkg["entries"][0]["negative_id"] += 1
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[1], hi=ids[2])


def test_wrong_root_fails():
    ids, digests, leaves, levels = make_tree(4)
    pkg = build_pkg(ids, digests, levels, ids[0], ids[-1])
    with pytest.raises(VerificationError, match="根摘要与留存值不一致"):
        verify_manifest(pkg, expected_version=3, expected_root_hex=sha("other"),
                        lo=ids[0], hi=ids[-1])


def test_wrong_version_fails():
    ids, digests, leaves, levels = make_tree(4)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[0], ids[-1])
    with pytest.raises(VerificationError, match="版号不符"):
        verify_manifest(pkg, expected_version=9, expected_root_hex=root,
                        lo=ids[0], hi=ids[-1])


def test_wrong_range_fails():
    ids, digests, leaves, levels = make_tree(4)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[0], ids[2])
    with pytest.raises(VerificationError, match="区间"):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[0], hi=ids[3])


def test_proof_hash_tamper_fails():
    ids, digests, leaves, levels = make_tree(7)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[2], ids[3])
    assert pkg["proof"], "该区间应存在外部证明节点"
    pkg["proof"][0]["hash"] = sha("forged-node")
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[2], hi=ids[3])


def test_out_of_range_entry_rejected():
    ids, digests, leaves, levels = make_tree(5)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[1], ids[2])
    # 夹带区间外明细
    pkg["entries"].append({"negative_id": ids[4], "index": 4, "sha256": digests[4]})
    with pytest.raises(VerificationError, match="不在请求闭区间内"):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[1], hi=ids[2])


def test_empty_segment_hides_existing_record():
    # 目录在该段其实有记录，伪空包必须失败
    ids, digests, leaves, levels = make_tree(5)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[1], ids[2])  # 本应有 2 条
    pkg["entries"] = []
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[1], hi=ids[2])


def test_boundary_id_tamper_fails():
    ids, digests, leaves, levels = make_tree(6)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[2], ids[3])
    pkg["boundary"]["predecessor_id"] = ids[2]  # 伪造前驱落到区间内
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[2], hi=ids[3])


def test_proof_node_covering_entry_rejected():
    ids, digests, leaves, levels = make_tree(8)
    root = levels[-1][0].hex()
    pkg = build_pkg(ids, digests, levels, ids[2], ids[5])
    # 用一个覆盖区间内叶子的证明节点替换，并删掉对应明细
    forged = ProofNode(1, 1, levels[1][1]).to_dict()
    pkg["proof"].append(forged)
    pkg["entries"] = [e for e in pkg["entries"] if e["index"] not in (2, 3)]
    with pytest.raises(VerificationError):
        verify_manifest(pkg, expected_version=3, expected_root_hex=root,
                        lo=ids[2], hi=ids[5])


def test_leaf_hash_domain_separation():
    h1 = leaf_hash(1, sha("a"))
    h2 = leaf_hash(1, sha("a"))
    assert h1 == h2
    assert h1 != leaf_hash(2, sha("a"))
    assert h1 != leaf_hash(1, sha("b"))
    with pytest.raises(ValueError):
        leaf_hash(0, "abc")
