# key-rotation-vault-go

本地密钥托管与密文版本管理组件：支持主密钥创建、轮换、停用/撤销，
密文自描述版本与完整性校验，以及轮换进行中的并发安全加解密。

## 快速开始

```go
store := vault.NewKeyStore()
v := vault.NewVault(store)

store.CreateKey("payments")          // 创建主密钥（版本 1）
ct, _ := v.Encrypt("payments", []byte("secret"))

store.Rotate("payments")             // 轮换到版本 2；旧版本仍可解密历史密文
pt, err := v.Decrypt("payments", ct) // 历史密文照常解密

store.Disable("payments")            // 停用：加解密均被拒绝（ErrKeyDisabled）
store.Revoke("payments")             // 撤销：语义同上，表示不可恢复
```

## 密钥生命周期

| 状态 | 加密 | 解密 | 说明 |
|------|------|------|------|
| Active   | ✅ | ✅ | 轮换后旧版本保持 Active，仅用于解密历史密文 |
| Disabled | ❌ | ❌ | 停用，可恢复（重新实现时可加 Enable） |
| Revoked  | ❌ | ❌ | 撤销，语义上不可恢复 |

- `CreateKey(alias)`：创建版本 1；别名重复报错。
- `Rotate(alias)`：追加新版本，加密立即切换到新版本；旧版本保留以解密历史密文。
- `Disable/Revoke(alias)`：该别名全部版本置为对应状态。

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
| 密钥已停用/撤销 | `ErrKeyDisabled` |
| 结构非法：过短、截断、magic 错误 | `ErrCiphertextMalformed` |
| 格式版本不受支持 | `ErrUnsupportedVersion` |
| 完整性校验失败（被篡改） | `ErrCiphertextIntegrity` |

任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。

## 并发模型

- `KeyStore` 使用单把 `sync.RWMutex`：加解密取读锁，轮换/停用/撤销取写锁。
- 同一别名上加解密与轮换并发执行时，每条密文头部记录的密钥版本
  与实际加密所用密钥材料一致，不会出现错配、丢失或撕裂读取。
- 停用与解密并发时，解密结果只会是“成功”或 `ErrKeyDisabled` 之一。

## 验证方法

```sh
go build ./...
go test ./vault/ -race -v
```

测试覆盖：轮换后历史密文可解密、停用/撤销后拒绝解密、非法/截断/
篡改/版本不受支持的密文被拒绝且原因可区分、并发轮换与读写（race detector）。
单测日志会打印密钥版本与判定依据（如 `encrypted with key version=1`、
`判定=ErrCiphertextIntegrity`）。
