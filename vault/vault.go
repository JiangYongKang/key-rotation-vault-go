package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
)

// Vault 是本地密钥托管与密文版本管理组件。
//
// 并发模型：一把 sync.RWMutex 保护全部密钥状态。
// Encrypt/Decrypt 持读锁，Rotate/Disable/Create 持写锁；
// 加密时在同一临界区内完成“选钥 + 封印”，因此密文内嵌的
// 密钥版本始终与实际所用密钥材料一致，不会出现撕裂读取或错配。
type Vault struct {
	mu    sync.RWMutex
	store *keyStore
}

// New 创建一个空的 Vault。
func New() *Vault {
	return &Vault{store: newKeyStore()}
}

// CreateKey 为别名创建首个主密钥版本（版本号从 1 开始，状态 Active）。
func (v *Vault) CreateKey(alias string) (Key, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.store.latest(alias) != nil {
		return Key{}, fmt.Errorf("vault: key alias %q already exists", alias)
	}
	e, err := v.store.add(alias)
	if err != nil {
		return Key{}, fmt.Errorf("vault: generate key material: %w", err)
	}
	return Key{Alias: alias, Version: e.version, Status: e.status}, nil
}

// RotateKey 轮换别名下的主密钥：生成新的 Active 版本，
// 既有 Active 版本降级为 DecryptOnly（历史密文仍可解密）。
func (v *Vault) RotateKey(alias string) (Key, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	latest := v.store.latest(alias)
	if latest == nil {
		return Key{}, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if latest.status == StatusDisabled {
		return Key{}, fmt.Errorf("%w: alias %q", ErrKeyDisabled, alias)
	}
	latest.status = StatusDecryptOnly
	e, err := v.store.add(alias)
	if err != nil {
		return Key{}, fmt.Errorf("vault: generate key material: %w", err)
	}
	return Key{Alias: alias, Version: e.version, Status: e.status}, nil
}

// DisableKey 停用（撤销）别名下的全部密钥版本：
// 之后该别名的加密与解密请求都会被拒绝。
func (v *Vault) DisableKey(alias string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	versions := v.store.byAlias[alias]
	if len(versions) == 0 {
		return fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	for _, e := range versions {
		e.status = StatusDisabled
	}
	return nil
}

// Encrypt 使用别名当前 Active 版本加密，输出自描述密文。
func (v *Vault) Encrypt(alias string, plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	latest := v.store.latest(alias)
	if latest == nil {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	switch latest.status {
	case StatusActive:
		// 可加密
	case StatusDisabled:
		return nil, fmt.Errorf("%w: alias %q version %d", ErrKeyDisabled, alias, latest.version)
	default:
		return nil, fmt.Errorf("%w: alias %q latest version %d is %s",
			ErrNoActiveKey, alias, latest.version, latest.status)
	}

	aead, err := newAEAD(latest.material)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	// AAD 绑定头部（含别名与版本），先搭头部再封印，保证密文与密钥版本一致。
	head := encodeEnvelope(alias, latest.version, nonce, nil)
	sealed := aead.Seal(nil, nonce, plaintext, head)
	return encodeEnvelope(alias, latest.version, nonce, sealed), nil
}

// Decrypt 解密自描述密文，依据密文内嵌的别名与版本选择密钥。
// 任何失败都不会返回部分明文，底层加密库错误一律映射为
// ErrCiphertextIntegrity，不外泄。
func (v *Vault) Decrypt(blob []byte) ([]byte, error) {
	alias, keyVersion, nonce, sealed, aad, err := decodeEnvelope(blob)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if _, ok := v.store.byAlias[alias]; !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	e := v.store.get(alias, keyVersion)
	if e == nil {
		return nil, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, keyVersion)
	}
	if e.status == StatusDisabled {
		return nil, fmt.Errorf("%w: alias %q version %d", ErrKeyDisabled, alias, keyVersion)
	}

	aead, err := newAEAD(e.material)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		// 认证失败：密文被篡改或截断，统一映射，不透出底层错误。
		return nil, fmt.Errorf("%w: alias %q version %d", ErrCiphertextIntegrity, alias, keyVersion)
	}
	return plain, nil
}

// KeyInfo 返回别名指定版本（version<=0 表示最新版本）的密钥元信息。
func (v *Vault) KeyInfo(alias string, version int) (Key, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var e *keyEntry
	if version <= 0 {
		e = v.store.latest(alias)
	} else {
		e = v.store.get(alias, version)
	}
	if e == nil {
		return Key{}, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, version)
	}
	return Key{Alias: alias, Version: e.version, Status: e.status}, nil
}

// newAEAD 由 32 字节密钥材料构造 AES-256-GCM。
// 密钥材料长度在 keyStore.add 中固定为 32，此处出错属于内部不变量破坏。
func newAEAD(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("vault: internal: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: internal: %w", err)
	}
	return aead, nil
}
