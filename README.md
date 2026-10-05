# pollux-lock-audit

飞控冗余控制器主节点切换前的**安全审计服务**：复核一段捕获的受限视图锁定投票轨迹，
确保验证者不会在未获得更高证明解锁的情况下为冲突分支投票，导致两条链同时被封存。

纯 Node.js（≥ 20，使用内置 `node:crypto` 的 Ed25519），**零第三方依赖**。

## 安全模型

- 调用方提交 **4 或 7 个** Ed25519 验证者公钥（去重）、创世块、以及**按捕获顺序**
  出现的至多 **64** 个事件。事件类型：
  - `proposal` —— 提案，只能引用**已达到 2f+1 名不同签名者**的阈值证明（QC），
    且父块必须与该证明封存的块一致（高度、哈希均一致）；首个高度引用 `GENESIS`。
  - `attestation` —— 对某高度某块的证明观察（签名份额），同一验证者同一视图
    不得为两个不同块出具证明。
  - `vote` —— 投票；同一验证者同一视图不得二投。
- 每名验证者根据**自己已观察到的最高证明**维持锁定块：其签署的提案/投票中引用
  的 QC 即视为其个人已观察。只有在以下任一条件成立时才允许投票：
  1. 候选块延伸（或本身就是）其当前锁定块；
  2. 候选块携带的证明视图**严格高于**其锁定视图（更高证明解锁）。
- 阈值证明在第 `2f+1` 名**不同**验证者证明到达的那个捕获索引形成
  （4 节点阈值 3；7 节点阈值 5）。
- 连续三个阈值证明构成三链 `QC(B_h) → QC(B_{h-1}) → QC(B_{h-2})` 且父链相连时，
  封存 `B_{h-2}`。
- **冻结在最早违规事件**：未见证明、签名无效、重复身份、悬空父块、父块/证明不一致、
  同视图二投、不安全投票等都会立即冻结，`frozen_at.event_index` 指出位置，
  之后事件一律不产生任何结论（即使此前已有证明形成，也不返回封存）。
- 轨迹内部安全但未形成三链时，裁决为 `REJECTED` 且 `frozen_at` 为 `null`，
  `reason` 为 `insufficient_quorum_chain`。

## 签名载荷（规范 UTF-8，`\n` 分隔）

```
POLLUX-LOCK-AUDIT/v1
<audit_id>
<validator_pubkey_base64>
proposal|attestation|vote
<height>
<block_hash_base64>
... proposal/vote: <parent_hash_base64>; proposal 另有 <qc 或 GENESIS>
... vote 另有 <证明视图号>（GENESIS 为 0），服务端从已形成的 QC 推导后验签
```

- proposal: `PROTOCOL_TAG \n audit_id \n validator \n proposal \n height \n block \n parent \n qc`
- attestation: `… \n attestation \n height \n block`
- vote: `… \n vote \n height \n block \n parent \n proofView`

公钥与块哈希均为 32 字节的 base64（接受标准/base64url），签名为 64 字节 base64。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康响应 `{"status":"ok",...}` |
| `POST` | `/v1/audits` | 提交轨迹并取得裁决 |
| `GET` | `/v1/audits/:audit_id` | 取回该稳定标识的原裁决 |

同一 `audit_id`、**语义完全相同**的重传：回放原裁决（`replayed: true`，HTTP 200）。
同一 `audit_id` 但内容不同：明确冲突（HTTP 409 `AUDIT_ID_CONFLICT`，附双方指纹）。
非法载荷：HTTP 400；未知标识：HTTP 404。

### 提交体

```json
{
  "audit_id": "flight-switch-2026-10-05-01",
  "validators": ["<32B b64>", "..."],
  "genesis": { "hash": "<32B b64>" },
  "events": [
    { "type": "proposal", "validator": "...", "height": 1,
      "block": "...", "parent": "...", "qc": "GENESIS", "signature": "..." },
    { "type": "attestation", "validator": "...", "height": 1,
      "block": "...", "signature": "..." },
    { "type": "vote", "validator": "...", "height": 2,
      "block": "...", "parent": "...", "signature": "..." }
  ]
}
```

裁决包含 `verdict`（`COMMITTED`/`REJECTED`）、`reason`、`frozen_at`、
`quorum_certificates`（各证明的视图/块/签名者/形成位置）、`committed_blocks`
（被封存块及三链签名者）和 `lock_changes`（每名验证者的锁定变化轨迹）。

## 本地运行

```bash
PORT=8080 node src/server.js
curl -s localhost:8080/healthz
```

## 测试与 Compose 验证

一次性复核（锁定规则单测 + 提交/拒绝轨迹的 API/HTTP 冒烟），完成即退出并以
状态码给出结果：

```bash
node test/verify.js          # 本地：单测 + 进程内随机端口冒烟，0/1 退出码
```

容器方式（Compose 的 `verify` 一次性服务：先构建 runtime/verify 镜像，
等 `audit` 健康后，在 verify 容器中跑全部锁定规则并对运行中的服务做 HTTP 冒烟）：

```bash
./verify.sh
# 或手动：
docker compose --profile verify up --build --abort-on-container-exit --exit-code-from verify verify
docker compose --profile verify down --remove-orphans
```

服务端口可配置：`AUDIT_PORT=9090 ./verify.sh`（容器内始终监听 `PORT`，默认 8080）。

## 目录

```
src/audit.js    规范编码、Ed25519 验签、阈值证明、锁定/三链规则、冻结
src/store.js    稳定标识裁决存储（重放/冲突，TTL）
src/server.js   HTTP 服务（健康 + 两项操作）
test/helpers.js Ed25519 测试密钥与轨迹构造
test/verify.js  一次性验证（26 项检查，退出码反映结果）
Dockerfile      runtime / verify 多阶段镜像
compose.yaml    audit 服务 + 一次性 verify
```
