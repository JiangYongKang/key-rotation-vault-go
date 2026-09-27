package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Vault 组合密钥库与信封加解密，对外提供线程安全的加解密接口。
type Vault struct {
	store *KeyStore
}

// NewVault 创建基于给定密钥库的 Vault。
func NewVault(store *KeyStore) *Vault { return &Vault{store: store} }

// Store 返回底层密钥库（用于轮换/停用等管理操作）。
func (v *Vault) Store() *KeyStore { return v.store }

// Encrypt 使用别名当前版本加密明文，返回自描述信封密文。
// 取密钥与加密在同一读锁临界区内完成，保证密文头中的版本号
// 与实际使用的密钥材料一致，轮换并发时不会错配。
func (v *Vault) Encrypt(alias string, plaintext []byte) ([]byte, error) {
	kv, err := v.store.current(alias)
	if err != nil {
		return nil, err
	}
	if kv.Status != StatusActive {
		return nil, fmt.Errorf("%w: alias %q version %d is %s",
			ErrKeyDisabled, alias, kv.Version, kv.Status)
	}
	aead, err := newAEAD(kv)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return encode(kv.Version, nonce, ct), nil
}

// Decrypt 解密信封密文；失败原因可通过 errors.Is 区分：
//   - ErrCiphertextMalformed  结构非法/截断
//   - ErrUnsupportedVersion   格式版本不受支持
//   - ErrKeyNotFound          别名或密钥版本不存在
//   - ErrKeyDisabled          密钥已停用或撤销
//   - ErrCiphertextIntegrity  完整性校验失败（被篡改）
//
// 任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。
func (v *Vault) Decrypt(alias string, blob []byte) ([]byte, error) {
	keyVersion, nonce, ct, err := decode(blob)
	if err != nil {
		return nil, err
	}
	kv, err := v.store.get(alias, keyVersion)
	if err != nil {
		return nil, err
	}
	if kv.Status != StatusActive {
		return nil, fmt.Errorf("%w: alias %q version %d is %s",
			ErrKeyDisabled, alias, kv.Version, kv.Status)
	}
	aead, err := newAEAD(kv)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		// AEAD 打开失败即完整性校验失败；不向外泄露库错误原文。
		return nil, fmt.Errorf("%w: alias %q version %d", ErrCiphertextIntegrity, alias, keyVersion)
	}
	return pt, nil
}

func newAEAD(kv *KeyVersion) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kv.material)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init gcm")
	}
	return aead, nil
}
