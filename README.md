# key-rotation-vault-go

本地密钥托管与密文版本管理组件。提供主密钥的创建、轮换、停用，
以及带自描述版本与完整性校验的密文封装，保证密钥轮换、并发访问
与密文兼容性在各种失败路径下都有一致且可解释的结论。

## 密钥生命周期

每个密钥别名（alias）下挂一串递增的版本，每个版本处于以下状态之一：

| 状态 | 加密 | 解密 | 说明 |
|------|------|------|------|
| `active` | ✅ | ✅ | 当前版本，`Encrypt` 只使用它 |
| `decrypt-only` | ❌ | ✅ | 轮换后的旧版本，历史密文仍可解密 |
| `disabled` | ❌ | ❌ | 已停用/撤销，任何加解密请求均被拒绝 |

状态流转：

```
CreateKey(alias)            -> v1: active
RotateKey(alias)            -> v1: decrypt-only, v2: active
RotateKey(alias)            -> v2: decrypt-only, v3: active
DisableKey(alias)           -> 全部版本: disabled（不可逆）
```

- 轮换只追加新版本、降级旧版本，**不删除密钥材料**，因此历史密文永远可解密。
- 停用作用于别名下的全部版本，停用后该别名的加密与解密都返回 `ErrKeyDisabled`。

## 密文格式与兼容规则

密文为自描述信封（大端字节序）：

```
[0:2]   魔数 "KV"
[2]     格式版本（当前为 1）
[3:5]   密钥别名长度 (uint16)
[5:7]   加密所用密钥版本 (uint16)
[7:19]  AES-GCM nonce (12 字节)
[19:..] 密钥别名 || AEAD 输出（密文 || 16 字节认证标签）
```

- 头部整体作为 AEAD 的附加认证数据（AAD）：篡改别名、版本号或 nonce
  都会使完整性校验失败。
- 解密时按信封内嵌的别名与版本选钥，密文与密钥版本严格一一对应。
- 格式版本不受支持的密文直接拒绝，不尝试猜测解析。

## 失败语义（可用 errors.Is 区分）

| 错误 | 触发条件 |
|------|----------|
| `ErrKeyNotFound` | 别名不存在，或密文引用的密钥版本不存在 |
| `ErrKeyDisabled` | 密钥已停用/撤销，拒绝加解密 |
| `ErrNoActiveKey` | 别名存在但没有可加密版本 |
| `ErrCiphertextMalformed` | 密文过短、截断、魔数错误、字段不完整 |
| `ErrCiphertextIntegrity` | AEAD 认证失败（密文或头部被篡改） |
| `ErrUnsupportedVersion` | 信封格式版本不受支持 |

任何解密失败都不会返回部分明文；底层加密库的错误一律映射为
`ErrCiphertextIntegrity`，不向调用方透出。

## 并发模型

`Vault` 内部以一把 `sync.RWMutex` 保护全部密钥状态：

- `Encrypt`/`Decrypt` 持读锁，可并发执行；
- `CreateKey`/`RotateKey`/`DisableKey` 持写锁，与读写互斥；
- 加密在同一临界区内完成“选钥 + 封印”，密文内嵌版本与实际所用
  密钥材料始终一致，轮换进行中不会出现数据丢失、错配或撕裂读取。

## 验证方法

```sh
go build ./...
go vet ./...
go test ./... -race -v
```

测试覆盖（`vault/vault_test.go`）：

- `TestRotateKeepsOldCiphertextDecryptable`：轮换后历史密文可解密，
  旧版本降级为 decrypt-only，新密文使用新版本；
- `TestDisableKeyRejectsDecryptAndEncrypt`：停用后加解密均返回
  `ErrKeyDisabled`；
- `TestFailureReasonsAreDistinguishable`：密钥不存在、密文篡改、
  截断、版本不受支持等失败原因逐一可区分，且完好密文不受误伤；
- `TestConcurrentEncryptDecryptRotate`：8 个写者与轮换并发执行，
  400 条消息全部往返一致，在 `-race` 下验证无数据竞争。

测试日志中以 `判定依据:` 前缀打印每步涉及的密钥版本、状态与判定结论。
