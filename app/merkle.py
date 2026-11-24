"""Merkle 树构造、区间证明与离线验证（仅依赖标准库）。

设计要点
========
* 叶子按底片编号（uint32）升序排列，叶序位置记为 index（从 0 起）。
* 哈希全部使用 SHA-256，并以单字节域前缀区分节点类型，防止类型混淆：
    - 叶子:  b"\\x00" + 32 字节编号（大端） + sha256(摘要 hex)
    - 内部:  b"\\x01" + 左孩子哈希 + 右孩子哈希
* 非满二叉树：缺失的右兄弟复制左节点（duplicate last node），复制只在
  哈希计算时进行，不会产生新的可索引节点。
* 空树（该版无任何记录）的根摘要为 SHA256(b"FILM-EMPTY-ROOT-v1")。
* 区间证明只暴露请求闭区间 [lo, hi] 内的明细；区间外只给哈希节点和
  紧邻边界的编号（用于空区间/边界完整性判断），不含区间外摘要明细。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"FILM-EMPTY-ROOT-v1").digest()
DOMAIN_VERSION = 1  # 算法版本，写入证明包，验包时核对


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(negative_id: int, sha256_hex: str) -> bytes:
    """计算叶子哈希。sha256_hex 为小写十六进制原件摘要。"""
    if not 0 <= negative_id <= 0xFFFFFFFF:
        raise ValueError("negative_id 超出 uint32 范围")
    digest = bytes.fromhex(sha256_hex)
    if len(digest) != 32:
        raise VerificationValueError("sha256 摘要必须为 32 字节")
    return _h(LEAF_PREFIX + negative_id.to_bytes(4, "big") + digest)


class VerificationValueError(ValueError):
    pass


def _parent(left: bytes, right: Optional[bytes]) -> bytes:
    # 右兄弟缺失时复制左节点，保证树结构确定
    if right is None:
        right = left
    return _h(NODE_PREFIX + left + right)


def build_levels(leaves: Sequence[bytes]) -> List[List[bytes]]:
    """从叶子层开始逐层向上构造完整层级，levels[0] 为叶子层。"""
    levels: List[List[bytes]] = [list(leaves)]
    if not leaves:
        return levels
    current = list(leaves)
    while len(current) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else None
            nxt.append(_parent(left, right))
        levels.append(nxt)
        current = nxt
    return levels


def root_hash(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    return build_levels(leaves)[-1][0]


@dataclass(frozen=True)
class ProofNode:
    """证明节点：位于 level 层、位置 position，只含哈希，不含任何明细。"""

    level: int
    position: int
    hash: bytes

    def to_dict(self) -> dict:
        return {"level": self.level, "position": self.position, "hash": self.hash.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> "ProofNode":
        return cls(level=int(d["level"]), position=int(d["position"]), hash=bytes.fromhex(d["hash"]))


def _max_level(n: int) -> int:
    return 0 if n <= 1 else (n - 1).bit_length()


def _level_sizes(n: int) -> List[int]:
    """各层真实节点数（与 build_levels 的落盘规模一致）。"""
    sizes = [n]
    cur = n
    while cur > 1:
        cur = (cur + 1) // 2
        sizes.append(cur)
    return sizes


def _collect_decomposition(
    levels: Sequence[Sequence[bytes]],
    span_lo: Optional[int],
    span_hi: Optional[int],
    n: int,
) -> List[ProofNode]:
    """自顶向下分解根节点。

    子树完全落在目标叶序区间 [span_lo, span_hi] 内 -> 不需要证明
    （其叶子由明细提供）；完全在区间外 -> 整体作为证明节点；
    部分相交 -> 继续向下分解。空区间时 span_lo/span_hi 为 None，
    全部子树都在“区间外”，按插入位置切分后收集两侧证明。
    """
    proof: List[ProofNode] = []
    seen: set[Tuple[int, int]] = set()
    max_level = _max_level(n)

    def in_target_raw(lo: int, hi: int) -> Optional[bool]:
        """按给定跨度判断与目标区间关系。"""
        if span_lo is None:
            return False
        if span_lo <= lo and hi <= span_hi:
            return True
        if hi < span_lo or lo > span_hi:
            return False
        return None

    def add_node(level: int, pos: int) -> None:
        key = (level, pos)
        if key not in seen:
            seen.add(key)
            proof.append(ProofNode(level, pos, levels[level][pos]))

    def walk(level: int, pos: int, lo: int, hi: int) -> None:
        # 虚拟位置不落盘、也不作为证明：其哈希由重算方按“复制左兄弟”规则推出
        if pos >= len(levels[level]):
            return
        # 与目标区间的关系按真实叶子跨度判断（叶子层 lo==hi，天然已裁剪）
        relation = in_target_raw(lo, hi) if level == 0 else in_target_raw(lo, min(hi, n - 1))
        if relation is True:
            return
        if relation is False:
            add_node(level, pos)
            return
        # 部分相交：叶子层不可能部分相交（单点），直接防御
        if level == 0:
            add_node(0, pos)
            return
        mid = (lo + hi) // 2
        walk(level - 1, pos * 2, lo, mid)
        walk(level - 1, pos * 2 + 1, mid + 1, hi)

    full_span = (1 << max_level) - 1
    walk(max_level, 0, 0, full_span)
    proof.sort(key=lambda p: (p.level, p.position))
    return proof


def make_range_proof(
    levels: Sequence[Sequence[bytes]],
    lo_idx: int,
    hi_idx: int,
    n: int,
) -> Tuple[List[ProofNode], Optional[int], Optional[int]]:
    """构造覆盖叶子闭区间 [lo_idx, hi_idx] 的最小证明及前后驱叶序。"""
    if n == 0 or not (0 <= lo_idx <= hi_idx < n):
        raise ValueError("证明区间越界")
    proof = _collect_decomposition(levels, lo_idx, hi_idx, n)
    predecessor = lo_idx - 1 if lo_idx > 0 else None
    successor = hi_idx + 1 if hi_idx + 1 < n else None
    return proof, predecessor, successor


def make_empty_range_proof(
    levels: Sequence[Sequence[bytes]],
    insert_before: int,
    n: int,
) -> Tuple[List[ProofNode], Optional[int], Optional[int]]:
    """空区间证明。insert_before 为区间在叶序中的插入位置（0..n）。"""
    if n == 0:
        return [], None, None
    if not 0 <= insert_before <= n:
        raise ValueError("插入位置越界")
    # 空区间：目标区间不覆盖任何叶子，全树分解后即为两侧边界证明
    proof = _collect_decomposition(levels, None, None, n)
    predecessor = insert_before - 1 if insert_before > 0 else None
    successor = insert_before if insert_before < n else None
    return proof, predecessor, successor


# ---------------------------------------------------------------------------
# 离线验包
# ---------------------------------------------------------------------------


class VerificationError(Exception):
    """验包失败。"""


def _recompute_root(
    entries: Sequence[Tuple[int, bytes]],
    proof: Sequence[ProofNode],
    n: int,
) -> bytes:
    """由区间内叶子 + 证明哈希节点重算根。

    entries 为 (leaf_index, leaf_hash)，须按 index 升序连续；
    空区间时 entries 为空。
    """
    if n == 0:
        if proof or entries:
            raise VerificationError("空目录版本不应包含证明节点或明细")
        return EMPTY_ROOT

    max_level = _max_level(n)
    node_map: dict[Tuple[int, int], bytes] = {}
    for p in proof:
        if not (0 <= p.level <= max_level and p.position >= 0):
            raise VerificationError(f"证明节点坐标越界: level={p.level} pos={p.position}")
        if (p.level, p.position) in node_map:
            raise VerificationError("证明节点坐标重复")
        node_map[(p.level, p.position)] = p.hash
    for idx, lh in entries:
        if (0, idx) in node_map:
            raise VerificationError(f"证明节点与明细在叶子 {idx} 处重叠")
        node_map[(0, idx)] = lh

    def node_at(level: int, pos: int) -> bytes:
        key = (level, pos)
        if key in node_map:
            return node_map[key]
        if level == 0:
            raise VerificationError(f"缺少叶子 {pos} 的哈希/证明")
        # 满树位置上界检查（防御伪造坐标）
        if pos >= 1 << (_max_level(n) - level):
            raise VerificationError(f"level {level} 节点位置 {pos} 越界")
        # 内部节点未直接给出时继续向下递归：能从更低层证明/明细推出即可。
        # 仅当右兄弟是“虚拟位”（非满树）时按复制左兄弟规则处理。
        left = node_at(level - 1, pos * 2)
        right_key = (level - 1, pos * 2 + 1)
        if right_key in node_map:
            right = node_map[right_key]
        elif pos * 2 + 1 >= level_sizes[level - 1]:
            right = None  # 虚拟右兄弟：复制左节点
        else:
            right = node_at(level - 1, pos * 2 + 1)
        value = _parent(left, right)
        node_map[key] = value
        return value

    level_sizes = _level_sizes(n)
    return node_at(max_level, 0)


def verify_manifest(pkg: dict, *, expected_version: int, expected_root_hex: str,
                    lo: int, hi: int) -> None:
    """离线验包：成功返回 None，失败抛 VerificationError。

    参数
    ----
    pkg: 交付包（已解析的 dict）。
    expected_version / expected_root_hex: 留存的版号与根摘要。
    lo, hi: 当初请求的编号闭区间。
    """
    if not isinstance(pkg, dict):
        raise VerificationError("交付包不是 JSON 对象")
    if pkg.get("domain") != "film-catalog-manifest-v1":
        raise VerificationError("交付包域标识不正确")
    if pkg.get("hash_alg") != "SHA-256":
        raise VerificationError("仅支持 SHA-256")
    if pkg.get("merkle_domain") != DOMAIN_VERSION:
        raise VerificationError("Merkle 算法域版本不匹配")

    version = pkg.get("version")
    if version != expected_version:
        raise VerificationError(f"版号不符: 包内 {version!r}，留存 {expected_version}")
    root_hex = pkg.get("root_sha256")
    if not isinstance(root_hex, str) or len(root_hex) == 0 or root_hex.lower() != expected_root_hex.lower():
        raise VerificationError("根摘要与留存值不一致")

    req = pkg.get("requested_range") or {}
    try:
        pkg_lo, pkg_hi = int(req["lo"]), int(req["hi"])
    except (KeyError, TypeError, ValueError):
        raise VerificationError("请求区间字段缺失或非法")
    if (pkg_lo, pkg_hi) != (lo, hi):
        raise VerificationError("交付包区间与所请求区间不一致")
    if not (0 <= lo <= hi <= 0xFFFFFFFF):
        raise VerificationError("请求区间不是合法 uint32 闭区间")

    n = pkg.get("leaf_count")
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise VerificationError("leaf_count 非法")

    raw_entries = pkg.get("entries", [])
    if not isinstance(raw_entries, list):
        raise VerificationError("entries 必须为数组")

    # 1) 逐条重算叶子哈希，检查编号严格升序、全部落在闭区间内
    entries: List[Tuple[int, bytes]] = []
    prev_id = None
    for e in raw_entries:
        if not isinstance(e, dict):
            raise VerificationError("明细条目格式非法")
        try:
            nid = int(e["negative_id"])
            idx = int(e["index"])
            digest_hex = str(e["sha256"])
        except (KeyError, TypeError, ValueError):
            raise VerificationError("明细字段缺失或非法")
        if not (0 <= nid <= 0xFFFFFFFF):
            raise VerificationError("明细编号越界")
        if n > 0 and not (0 <= idx < n):
            raise VerificationError(f"明细 {nid} 叶序越界")
        if n == 0:
            raise VerificationError("空目录版本不应包含明细")
        if not (lo <= nid <= hi):
            raise VerificationError(f"编号 {nid} 不在请求闭区间内")
        if prev_id is not None and nid <= prev_id:
            raise VerificationError("明细编号必须严格升序且唯一")
        prev_id = nid
        try:
            bytes.fromhex(digest_hex)
            entries.append((idx, leaf_hash(nid, digest_hex)))
        except (VerificationValueError, ValueError) as exc:
            raise VerificationError(f"明细 {nid} 摘要非法: {exc}")

    indices = sorted(idx for idx, _ in entries)
    if len(set(indices)) != len(indices):
        raise VerificationError("叶序 index 重复")

    first_index = indices[0] if indices else None
    last_index = indices[-1] if indices else None
    if indices and indices != list(range(first_index, last_index + 1)):
        raise VerificationError("区间内叶序不连续，可能遗漏明细")

    # 2) 边界信息
    bnd = pkg.get("boundary") or {}
    if not isinstance(bnd, dict):
        raise VerificationError("boundary 必须为对象")

    def _opt_int(v, name: str):
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int):
            raise VerificationError(f"边界字段 {name} 必须为整数或 null")
        return v

    pred_idx = _opt_int(bnd.get("predecessor_index"), "predecessor_index")
    succ_idx = _opt_int(bnd.get("successor_index"), "successor_index")
    pred_id = _opt_int(bnd.get("predecessor_id"), "predecessor_id")
    succ_id = _opt_int(bnd.get("successor_id"), "successor_id")

    def check_id(v, name: str) -> None:
        if v is not None and not (0 <= v <= 0xFFFFFFFF):
            raise VerificationError(f"边界编号 {name} 越界")

    check_id(pred_id, "predecessor_id")
    check_id(succ_id, "successor_id")

    # 3) index 连续性与边界一致性（防“少一件”）
    if entries:
        if first_index == 0:
            if pred_idx is not None or pred_id is not None:
                raise VerificationError("区间已从头开始，不应存在前驱")
        else:
            if pred_idx != first_index - 1:
                raise VerificationError("前驱叶序与首批明细不衔接")
            if pred_id is None or pred_id >= lo:
                raise VerificationError("前驱编号缺失或落在请求区间内")
        if last_index == n - 1:
            if succ_idx is not None or succ_id is not None:
                raise VerificationError("区间已到叶序末尾，不应存在后继")
        else:
            if succ_idx != last_index + 1:
                raise VerificationError("后继叶序与末批明细不衔接")
            if succ_id is None or succ_id <= hi:
                raise VerificationError("后继编号缺失或落在请求区间内")
    else:
        # 空区间：两侧边界都必须自洽
        if pred_idx is None and pred_id is None:
            if not (n == 0 or succ_idx == 0):
                raise VerificationError("空区间缺少前驱边界信息")
        else:
            if pred_idx is None or pred_id is None or pred_idx < 0:
                raise VerificationError("空区间前驱边界不完整")
            if pred_id >= lo:
                raise VerificationError("空区间前驱编号必须位于区间左侧")
        if succ_idx is None and succ_id is None:
            if not (n == 0 or pred_idx == n - 1):
                raise VerificationError("空区间缺少后继边界信息")
        else:
            if succ_idx is None or succ_id is None or not (0 <= succ_idx < n):
                raise VerificationError("空区间后继边界不完整")
            if succ_id <= hi:
                raise VerificationError("空区间后继编号必须位于区间右侧")
        if pred_idx is not None and succ_idx is not None and succ_idx != pred_idx + 1:
            raise VerificationError("空区间前后驱叶序不相邻，区间内存在被隐瞒的记录")

    # 4) 证明节点重算根
    raw_proof = pkg.get("proof", [])
    if not isinstance(raw_proof, list):
        raise VerificationError("proof 必须为数组")
    try:
        proof = [ProofNode.from_dict(p) for p in raw_proof]
    except (KeyError, TypeError, ValueError):
        raise VerificationError("proof 节点格式非法")

    computed = _recompute_root(sorted(entries, key=lambda x: x[0]), proof, n)
    if computed.hex() != root_hex.lower():
        raise VerificationError("重算根摘要与留存根不一致，证明无效")

    # 5) 证明节点不得覆盖任何区间内叶子（防止以哈希冒充明细导致漏件）
    covered: set[int] = set()
    for p in proof:
        span = 1 << p.level
        for leaf in range(p.position * span, min((p.position + 1) * span, n)):
            covered.add(leaf)
    overlap = covered & set(indices)
    if overlap:
        raise VerificationError(f"证明节点覆盖了区间内叶子 {sorted(overlap)}，存在以证明替代明细的漏件")
