# key-rotation-vault-go

本地密钥托管与密文版本管理组件：支持主密钥创建、轮换、停用/撤销，
密钥版本有效期与解密宽限期、存量密文升级（re-encrypt）、旧版本下线回收，
密文自描述版本与完整性校验，以及轮换/到期/下线进行中的并发安全加解密。

## 快速开始

```go
store := vault.NewKeyStore()
v := vault.NewVault(store)

store.CreateKey("payments")          // 创建主密钥（版本 1），缺省长期有效
ct, _ := v.Encrypt("payments", []byte("secret"))

store.Rotate("payments")             // 轮换到版本 2；旧版本仍可解密历史密文
pt, err := v.Decrypt("payments", ct) // 历史密文照常解密

// 存量密文升级到当前版本
up, changed, err := v.ReEncrypt("payments", ct) // 旧版本密文 -> 当前版本密文

// 迁移确认完成后，回收旧版本空间
store.RetireOldVersions("payments")  // 下线并清除除当前版本外的全部旧版本材料

store.Disable("payments")            // 停用：加解密均被拒绝（ErrKeyDisabled）
store.Revoke("payments")             // 撤销：不可恢复（ErrKeyRevoked）
```

## 密钥生命周期

| 状态 | 加密 | 解密 | 说明 |
|------|------|------|------|
| Active   | ✅ | ✅ | 轮换后旧版本保持 Active，仅用于解密历史密文 |
| Disabled | ❌ | ❌ | 停用，可恢复（重新实现时可加 Enable） |
| Revoked  | ❌ | ❌ | 撤销，语义上不可恢复；错误同时命中 `ErrKeyDisabled` |
| Retired  | ❌ | ❌ | 旧版本已下线、材料已清除；解密报 `ErrKeyRetired` |

- `CreateKey(alias, opts...)`：创建版本 1；别名重复报错。
- `Rotate(alias, opts...)`：追加新版本，加密立即切换到新版本；旧版本保留以解密历史密文。
- `Disable/Revoke(alias)`：该别名全部（非墓碑）版本置为对应状态；已下线版本保持墓碑。
- `Retire(alias, version)` / `RetireOldVersions(alias)`：见“旧版本下线回收”。

## 有效期与到期规则

创建或轮换时可用选项给**每个版本**独立设置存活时长与解密宽限期：

```go
store.CreateKey("billing",
    vault.WithTTL(24*time.Hour),        // 存活时长：到期时刻起禁止加密
    vault.WithGracePeriod(time.Hour),   // 到期后的解密宽限期，缺省 24h
)
store.Rotate("billing", vault.WithTTL(12*time.Hour)) // 新版本可带不同 TTL
```

- 不传 `WithTTL`（或传 `<=0`）= **长期有效**，时钟推进多久都不到期。
- 判定一律取**操作发生的那一刻**（内部时钟，测试可替换），时间点规则：

| 时刻关系（相对当前版本） | 加密 | 解密 |
|---|---|---|
| `now < ExpiresAt` | ✅ | ✅ |
| `now == ExpiresAt`（到期当刻） | ❌ `ErrKeyExpired` | ✅（宽限期内） |
| `ExpiresAt < now <= GraceUntil` | ❌ `ErrKeyExpired` | ✅ |
| `now == GraceUntil`（宽限当刻） | ❌ `ErrKeyExpired` | ✅ |
| `now > GraceUntil`（过宽限期） | ❌ `ErrKeyExpired` | ❌ `ErrKeyExpired` |

- 宽限期的意义：版本到期、新数据不再用它加密后，留一个存量数据升级窗口，
  窗口内历史密文仍可解密。`WithGracePeriod` 缺省为 `DefaultGracePeriod = 24h`。
- 到期是**按版本独立**判断的：旧版本到期不影响当前版本加密，
  当前版本到期也不改变旧版本是否还在其自身宽限期内。

## 存量密文升级（Re-encrypt）

```go
out, changed, err := v.ReEncrypt(alias, oldCiphertext)
```

流程：解析信封头 → 同一临界区取“源版本 + 当前版本”快照 →
用源版本解出明文并做 GCM 完整性校验 → 用当前版本生成新 nonce 重新加密。

- 升级前后解出的明文**完全一致**；输出密文头中的版本号即新版本。
- 密文已是当前版本时**原样返回、`changed=false`**，便于反复安全重试。
- 升级失败是**整体失败**：返回 `err` 时 `out == nil`、绝不吐出新密文或半截明文。
  可区分原因包括：`ErrCiphertextMalformed` / `ErrUnsupportedVersion` /
  `ErrKeyNotFound` / `ErrKeyRetired` / `ErrKeyRevoked` / `ErrKeyDisabled` /
  `ErrKeyExpired`（源版本过宽限期，或当前版本不可加密）/
  `ErrCiphertextIntegrity`（源密文被篡改，在校验阶段即失败）。
- **重试稳定**：成功后对结果再升级是 no-op；对同一失败输入重试得到同类错误。
- 与轮换/停用/下线并发时，源版本与当前版本快照在同一读锁内取得，
  结论基于一致视图：要么按当时有效结论成功，要么给出对应拒绝，不出现版本错配。

推荐迁移顺序：先 `Rotate` 出新当前版本 → 分批 `ReEncrypt` 存量密文并落库 →
全部升级并校验完成后再 `RetireOldVersions`。

## 旧版本下线回收

```go
store.Retire("payments", 1)        // 下线指定版本
vers, _ := store.RetireOldVersions("payments") // 批量下线所有旧版本
```

- 下线会把版本置为 `Retired` 墓碑并**清空其密钥材料**，回收占用空间。
- **当前版本不能被下线**：`Retire` 命中当前版本返回 `ErrCannotRetireCurrent`；
  批量接口始终保留切片末尾的当前版本。
- 下线后针对这些旧版本密文的解密返回 **`ErrKeyRetired`**：
  它与 `ErrKeyNotFound`（别名/版本从不存在）、`ErrCiphertextMalformed`（数据损坏）
  都能通过 `errors.Is` 区分，上层可明确知道是“版本被回收”而不是数据坏了。
- 操作幂等：重复下线同一版本成功；批量接口重复调用返回空列表。
- 并发安全：快照在锁内复制密钥材料，解密不会读到“清理到一半”的材料；
  下线与解密并发时，结果只能是“成功解出正确明文”或 `ErrKeyRetired`。

下线后的兼容范围：**仅保留按当前版本解密与加密的能力**；已回收版本的密文
在重新升级前将无法解密，因此务必在确认存量数据全部 `ReEncrypt` 完成后再回收。

## 密文格式与兼容规则

信封格式（自描述）：

```
magic(2B 'KV') | formatVersion(1B) | keyVersion(4B BE) | nonce(12B) | ciphertext+GCM tag(16B)
```

- 当前支持 `formatVersion = 1`，加密算法 AES-256-GCM。
- 解密时按信封头中的 `keyVersion` 选取密钥版本，因此轮换后历史密文可解密。
- 兼容性判定（均可用 `errors.Is` 区分，互不混淆）：

| 情形 | 错误 |
|------|------|
| 别名或密钥版本不存在 | `ErrKeyNotFound` |
| 密钥已停用 | `ErrKeyDisabled` |
| 密钥已撤销（同时命中 `ErrKeyDisabled`） | `ErrKeyRevoked` |
| 版本已到期：加密到期，或解密已过宽限期 | `ErrKeyExpired` |
| 旧版本已下线回收（材料已清除） | `ErrKeyRetired` |
| 试图下线当前正在使用的版本 | `ErrCannotRetireCurrent` |
| 结构非法：过短、截断、magic 错误 | `ErrCiphertextMalformed` |
| 格式版本不受支持 | `ErrUnsupportedVersion` |
| 完整性校验失败（被篡改） | `ErrCiphertextIntegrity` |

任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。

## 并发模型

- `KeyStore` 使用单把 `sync.RWMutex`：加解密/升级取读锁，轮换/停用/撤销/下线取写锁。
- 加解密与升级不直接持有活的 `KeyVersion` 指针，而是在读锁临界区内取出
  **独立拷贝材料的快照**，锁外再做 AEAD 运算。因此：
  - 同一别名上加解密与轮换并发，每条密文头部版本与实际密钥材料一致，无错配/撕裂；
  - 下线清空材料与解密并发时，不会读到被清到一半的材料；
  - 升级的“源版本 + 当前版本”在同一临界区取快照，视图一致。
- 停用/下线与解密并发时，解密结果只会是“成功解出正确明文”或对应哨兵错误之一。
- “能不能用”按操作时刻判断：到期、停用、轮换并发交错时，每个操作要么按当时
  有效结论成功，要么给出对应拒绝，不会出现“一会儿行一会儿不行”的闪烁结论。

## 验证方法

```sh
go build ./...
go vet ./...
go test ./vault/ -race -v            # 带竞态检测跑全部用例
go test ./vault/ -race -count=3      # 并发用例多轮压一遍
```

覆盖范围：

- 有效期：到期前 1ns / 到期当刻 / 宽限期内 / 宽限当刻 / 过宽限期 1ns 的边界判定，
  无 TTL 长期有效，轮换版本独立 TTL 互不影响；
- 存量升级：升级到当前版本且明文一致、已是当前版本幂等、重试稳定、
  损坏/篡改/版本不存在/停用/撤销/过宽限期等失败原因可区分且失败不吐密文；
- 下线回收：旧版本下线后解密报 `ErrKeyRetired` 且与损坏/不存在区分、
  当前版本受保护、幂等、批量回收；
- 并发（`-race`）：升级×轮换、解密×下线回收、加解密×轮换、解密×停用；
- 回归：轮换后历史密文可解密、停用/撤销拒绝、损坏/篡改/不受支持版本被拒绝。

单测日志会打印**所用密钥版本、命中的状态与最终判定依据**，例如
`source keyVersion=1 -> new keyVersion=2`、`时刻 ExpiresAt: encrypt 判定=ErrKeyExpired`、
`旧版本密文解密: 判定=ErrKeyRetired`，便于定位问题。
