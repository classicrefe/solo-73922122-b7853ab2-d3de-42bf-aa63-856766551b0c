# 底片目录发布服务

修复组只接收自己负责的编号区间。本服务用 **FastAPI + SQLite** 发布底片目录，
按**版号 + 编号闭区间**领取清单与 Merkle 证明，并提供**纯标准库的离线验包函数**，
凭留存的版号、根摘要、请求区间即可核对该段所有编号与摘要；少一件即判失败，
该段无记录时也能验空。

## 1. 数据模型与安全性质

| 项目 | 说明 |
| --- | --- |
| 编号 | 32 位无符号整数（0 ~ 4294967295），全册唯一 |
| 摘要 | 每条记录附原件 SHA-256（小写十六进制） |
| 版号 | 单调递增整数，发版即生成，可长期留存 |
| 根摘要 | 该版全部叶子的 Merkle 根（SHA-256），随版号一并留存 |
| 空目录 | 根摘要为常量 `SHA256("FILM-EMPTY-ROOT-v1")`，空段照样可验 |

### Merkle 树约定

* 叶子按编号升序排列，叶序 `index` 从 0 起。
* 域前缀防类型混淆：
  * 叶子 `SHA256(0x00 || uint32_be(编号) || 原件摘要)`
  * 内部节点 `SHA256(0x01 || 左哈希 || 右哈希)`
* 非满二叉树缺失的右兄弟复制左节点（duplicate-last），复制只在哈希计算时发生。
* 区间证明只包含：区间内明细 + 区间外的哈希节点 + 紧邻边界的编号（**不含区间外摘要**）。
* 验包除重算根外，还强制检查：
  1. 明细编号严格升序且全部落在请求闭区间内；
  2. 区间内叶序连续，前后驱边界与明细衔接（**少一件必失败**）；
  3. 空区间时前后驱叶序必须相邻，防止“有记录却报空”；
  4. 证明节点不得覆盖任何区间内叶子，防止用哈希节点冒充明细漏件。

### 版本化与勘误

* 工作区草稿支持 upsert（更正摘要）与 delete（删记录）。
* 发版在**单个 SQLite 事务**内完成：写版本行 → 复制不可变明细快照 → 建树落节点 →
  更新当前版指针。任何步骤失败整体回滚，**已发布旧版的明细与证明始终可读、不变**。
* 更正一条摘要或删一条记录即发新版，历史版本快照独立保留，无需重写整册。

## 2. 启动（Docker Compose）

```bash
docker compose up -d --build
# 浏览器打开 http://localhost:8000/docs 即可交互式试领清单
```

数据保存在命名卷 `film-data`（容器内 `/data/film_catalog.db`）。
本地无 Docker 时等价启动方式：

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
FILM_DB_PATH=./data/film_catalog.db uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 3. 接口一览（/docs 可试）

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/health` | 健康检查、当前版号 |
| GET | `/versions` | 版本列表（版号、根摘要、叶数、时间） |
| GET | `/versions/{version}` | 单版元信息（含可留存根摘要） |
| GET | `/versions/{version}/manifests/{lo}/{hi}` | **按闭区间领清单与证明** |
| POST | `/admin/working` | 草稿 upsert（更正摘要） |
| DELETE | `/admin/working/{negative_id}` | 草稿删记录 |
| GET | `/admin/working` | 查看草稿 |
| POST | `/admin/publish` | 发新版（失败回滚，旧版继续供） |
| POST | `/admin/verify?lo=&hi=` | 服务端验包自测 |

## 4. 典型流程

```bash
# 4.1 灌入示例数据并发布首版
python scripts/seed_demo.py http://127.0.0.1:8000

# 4.2 留存版号与根摘要（输出示例）
#   版号 1 / 根摘要 e01dc090...e7d20

# 4.3 修复组按负责区间领包（只含区间内明细与必要证明）
python scripts/fetch_manifest.py http://127.0.0.1:8000 1 100 201 pkg.json

# 4.4 离线验包（只需 Python 标准库，可在无网环境运行）
python scripts/verify_package.py pkg.json 1 <留存根摘要> 100 201
```

验包也可作为库函数嵌入修复组自有工具：

```python
from app.merkle import verify_manifest, VerificationError

try:
    verify_manifest(pkg_dict,
                    expected_version=1,
                    expected_root_hex="<留存根摘要>",
                    lo=100, hi=201)
except VerificationError as e:
    ...  # 少件、篡改、错版、错区间等均在此报错
```

### 交付包结构

```json
{
  "domain": "film-catalog-manifest-v1",
  "hash_alg": "SHA-256",
  "merkle_domain": 1,
  "version": 1,
  "root_sha256": "...",
  "leaf_count": 6,
  "requested_range": {"lo": 100, "hi": 201},
  "entries": [
    {"negative_id": 100, "index": 0, "sha256": "..."}
  ],
  "boundary": {
    "predecessor_index": null, "predecessor_id": null,
    "successor_index": 5, "successor_id": 300
  },
  "proof": [
    {"level": 2, "position": 1, "hash": "..."}
  ]
}
```

`boundary` 只给紧邻边界的编号与叶序，`proof` 只有哈希，均不含区间外明细摘要。

## 5. 测试

```bash
pip install pytest
python -m pytest          # 50 个用例：树构造、全区间枚举、篡改/漏件、空段、版本勘误、回滚
```

## 6. 目录结构

```
app/
  merkle.py     # Merkle 构造、区间证明、离线 verify_manifest（纯标准库）
  db.py         # SQLite 版本化快照、单事务发版
  manifest.py   # 交付包组装（只含区间内明细）
  main.py       # FastAPI 路由
scripts/
  seed_demo.py        # 示例数据与首版发布
  fetch_manifest.py   # 领清单落盘
  verify_package.py   # 离线验包 CLI（标准库）
tests/          # pytest 测试
Dockerfile, docker-compose.yml, requirements.txt
```
