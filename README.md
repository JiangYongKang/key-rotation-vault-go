# key-rotation-vault-go

本地密钥托管与密文版本管理组件：支持主密钥创建、轮换、停用/撤销，
密钥版本有效期与解密宽限期，存量密文原子升级到当前版本，旧版本下线回收，
密文自描述版本与完整性校验，以及上述操作并发进行时的一致性。

## 快速开始

```go
store := vault.NewKeyStore()                               // 默认宽限期 24h
v := vault.NewVault(store)

store.CreateKey("payments")                               // 创建主密钥（版本 1，长期有效）
store.CreateKey("payments", 24*time.Hour)                 // 或指定 TTL
ct, _ := v.Encrypt("payments", []byte("secret"))

store.Rotate("payments")                                  // 轮换到版本 2；旧版本仍可解密历史密文
store.Rotate("payments", 12*time.Hour)                    // 轮换也可独立指定 TTL
pt, err := v.Decrypt("payments", ct)                      // 历史密文照常解密

newCT, err := v.Upgrade("payments", ct)                   // 把老密文原子升级为当前版本密文
n, err := store.Retire("payments")                        // 迁移完成后回收所有旧版本（当前版本除外）

store.Disable("payments")                                 // 停用：加解密均被拒绝（ErrKeyDisabled）
store.Revoke("payments")                                  // 撤销：语义同上，表示不可恢复（ErrKeyRevoked）
```

## 密钥生命周期

| 状态 | 加密 | 解密 | 说明 |
|------|------|------|------|
| Active   | ✅ | ✅ | 轮换后旧版本保持 Active，仅用于解密历史密文 |
| Expired（到期，宽限内） | ❌ | ✅ | 已过 `ExpiresAt`、未过 `GraceEnd`，只可解密/被升级 |
| GraceEnded（宽限期满） | ❌ | ❌ | 以 `ErrKeyExpired` 拒绝加解密 |
| Disabled | ❌ | ❌ | 停用（`ErrKeyDisabled`） |
| Revoked  | ❌ | ❌ | 撤销，语义上不可恢复（`ErrKeyRevoked`） |
| Retired  | ❌ | ❌ | 版本已下线回收，密钥材料已销毁（`ErrKeyVersionRetired`） |

- `CreateKey(alias [, ttl])`：创建版本 1；别名重复报错；`ttl` 可空（长期有效），负数报 `ErrInvalidArgument`。
- `Rotate(alias [, ttl])`：追加新版本，加密立即切换到新版本；每个版本的 TTL 相互独立。
- `Disable/Revoke(alias)`：该别名全部未回收版本置为对应状态；已 Retired 的版本不会被复活。
- 判定一律按**操作发生时刻**进行（内部通过可注入时钟取值，见“时间注入”）。

### 有效期与宽限期规则

- `ttl > 0` 时记录两个时刻：`ExpiresAt = CreatedAt + ttl`，`GraceEnd = ExpiresAt + grace`。
- 宽限期由 `NewKeyStore(WithGracePeriod(d))` 配置，默认 24h；它对所有带 TTL 的版本生效。
- 边界约定（半开区间，避免临界时刻歧义）：
  - `now < ExpiresAt`：可加解密；
  - `now == ExpiresAt` 即视为**已到期**：加密拒绝（`ErrKeyExpired`），解密仍允许；
  - `ExpiresAt < now <= GraceEnd`：加密拒绝、解密允许（这也是存量密文升级的窗口）；
  - `now > GraceEnd`：加解密均拒绝（同为 `ErrKeyExpired`，错误信息会注明是“已到期”还是“宽限期已过”）。
- 不指定 TTL（零值 `ExpiresAt`）= 长期有效，时间推进不影响它。
- 静态状态优先于时间窗口：已停用/撤销/回收的版本，即使时间上仍有效也按静态状态拒绝。

## 存量密文升级（Upgrade）

`v.Upgrade(alias, oldBlob)` 将老版本密文重新加密为别名当前版本下的密文：

1. 解析信封（损坏 → `ErrCiphertextMalformed`；格式版本不受支持 → `ErrUnsupportedVersion`）；
2. 在密钥库**同一读锁临界区**内取“旧版本 + 当前版本”的同一时刻快照并完成可用性判定；
3. 用旧版本解密并做 GCM 校验（篡改 → `ErrCiphertextIntegrity`，不返回任何明文）；
4. 旧版本即当前版本时，校验通过后**原样返回**（幂等，不重复处理）；
5. 否则用当前版本重新加密，返回新信封密文。

保证：

- 升级前后解出的明文完全一致；
- 与轮换、停用、撤销、到期、回收并发时不会版本错配：两次版本判定来自同一快照；
- 任何失败都只返回错误（密文为 nil），**绝不会在报错的同时吐出新密文或半截明文**；
- Upgrade 是只读操作、不改状态，同一输入失败后重试，结论稳定（损坏永远损坏，可升级则可升级）。

注意：旧版本处于“到期但宽限期内”仍可升级；宽限期结束后升级以 `ErrKeyExpired` 失败。
因此推荐在旧版本宽限期结束前完成存量升级。

## 旧版本下线回收（Retire）

`store.Retire(alias)` 下线别名下**除当前版本外的所有旧版本**：标记为 Retired 并销毁内存中的
密钥材料，返回本次新回收的版本数。

- 当前版本永远不会被回收（即使只有一个版本也安全，返回 0）。
- 回收幂等：已 Retired 的版本不重复计数；之后又轮换产生新的旧版本时，只回收新增的。
- 回收后针对这些版本的密文解密/升级返回 `ErrKeyVersionRetired`——与 `ErrCiphertextMalformed`
  （数据损坏）、`ErrKeyNotFound`（别名/版本不存在）都不同，上层可据此判定“版本已被回收”。
- 建议顺序：先 `Rotate` → 用 `Upgrade` 迁移全部存量密文并核验 → 再 `Retire`。
  Retire 不会检查是否还有未迁移密文，请在上层确认迁移完成后调用。
- 与加解密/升级并发时结论一致：进行中的操作使用快照内复制的密钥材料完成，
  新进入的操作则得到 `ErrKeyVersionRetired`，不存在“清理到一半被读走材料”的情况。

## 时间注入（测试与确定性验证）

```go
var now time.Time
clk := func() time.Time { return now }
store := vault.NewKeyStore(vault.WithClock(clk), vault.WithGracePeriod(30*time.Minute))
```

生产环境默认使用 `time.Now`；测试里注入可控时钟即可精确验证到期边界。

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
| 版本已到期：加密时，或解密时宽限期已过 | `ErrKeyExpired` |
| 密钥已停用 | `ErrKeyDisabled` |
| 密钥已撤销 | `ErrKeyRevoked` |
| 密钥版本已被下线回收 | `ErrKeyVersionRetired` |
| 参数非法（如负 TTL） | `ErrInvalidArgument` |
| 结构非法：过短、截断、magic 错误 | `ErrCiphertextMalformed` |
| 格式版本不受支持 | `ErrUnsupportedVersion` |
| 完整性校验失败（被篡改） | `ErrCiphertextIntegrity` |

任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。
到期、停用、撤销、版本不存在、密文损坏各自对应不同哨兵，调用方无需靠错误字符串猜测。

## 并发模型

- `KeyStore` 使用单把 `sync.RWMutex`：加解密/升级取读锁，轮换/停用/撤销/回收取写锁。
- 加解密与升级先在读锁内取**单一时刻快照**（含复制出的密钥材料与到期判定），
  再在锁外做 AEAD 运算：同一别名上与轮换、到期、停用、回收并发时，
  密文头版本号与实际密钥材料必然一致，不会错配、丢失或撕裂读取。
- 停用/回收与解密并发时，解密结果只会是“成功”或对应哨兵错误之一。
- Upgrade 中旧版本与当前版本的判定来自同一次快照，并发轮换无法插入两步之间。

## 验证方法

```sh
go build ./...
go vet ./...
go test ./vault/ -race -v           # 竞态检测 + 详细日志
go test ./vault/ -race -count=10    # 重复压测并发用例
```

测试覆盖：

- **有效期**：`now == ExpiresAt`（到期即拒加密、仍可解密）、宽限期内、
  `now == GraceEnd`（末端仍可解密）、超过一纳秒即拒绝解密、不指定 TTL 长期有效、
  各版本 TTL 独立、负 TTL 被拒；
- **存量升级**：多老版本升级到当前版本且明文一致、已是当前版本幂等返回、
  损坏/篡改/格式不受支持/版本与别名不存在/停用等失败路径只返回错误且可区分、
  宽限期内可升级而宽限期满失败、失败重试结论稳定、与轮换并发（race）；
- **下线回收**：旧版本回收后解密为 `ErrKeyVersionRetired` 且与损坏/不存在可区分、
  当前版本受保护、回收幂等、停用/撤销不复活、与解密和升级并发（race）；
- **不回归**：轮换后历史密文可解密、停用/撤销分别拒绝、非法/截断/篡改/
  版本不受支持的密文被拒绝且原因可区分、并发轮换与读写。

单测日志会打印密钥版本、命中状态与最终判定依据（例如
`key version 1 -> 3`、`at ... (=ExpiresAt): encrypt -> ErrKeyExpired`、
`判定=ErrKeyVersionRetired`），便于定位问题。
