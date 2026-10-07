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

// Store 返回底层密钥库（用于轮换/停用/下线等管理操作）。
func (v *Vault) Store() *KeyStore { return v.store }

// denyFor 把可用性结论翻译为可区分的哨兵错误。
// encrypt=true 时“已到期但宽限期内”也拒绝加密。
func denyFor(vw *keyView, encrypt bool) error {
	switch vw.avail {
	case availOK:
		return nil
	case availExpired:
		if encrypt {
			return fmt.Errorf("%w: alias %q version %d expired at %s (now %s)",
				ErrKeyExpired, vw.alias, vw.version,
				vw.expires.Format(timeFmt), vw.now.Format(timeFmt))
		}
		return nil // 宽限期内允许解密
	case availGraceEnded:
		return fmt.Errorf("%w: alias %q version %d grace ended at %s (now %s)",
			ErrKeyExpired, vw.alias, vw.version,
			vw.graceEnd.Format(timeFmt), vw.now.Format(timeFmt))
	case availDisabled:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyDisabled, vw.alias, vw.version)
	case availRevoked:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyRevoked, vw.alias, vw.version)
	case availRetired:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyVersionRetired, vw.alias, vw.version)
	default:
		return fmt.Errorf("%w: unknown state", ErrDecryptFailed)
	}
}

const timeFmt = "2006-01-02T15:04:05.000Z07:00"

// Encrypt 使用别名当前版本加密明文，返回自描述信封密文。
// 取快照与可用性判定在同一读锁临界区内完成；密钥材料复制到快照，
// 因此轮换、到期、停用、回收并发时，密文头版本号与实际材料必然一致。
func (v *Vault) Encrypt(alias string, plaintext []byte) ([]byte, error) {
	vw, err := v.store.snapshotCurrent(alias)
	if err != nil {
		return nil, err
	}
	if err := denyFor(vw, true); err != nil {
		return nil, err
	}
	aead, err := newAEAD(vw.material)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return encode(vw.version, nonce, ct), nil
}

// Decrypt 解密信封密文；失败原因可通过 errors.Is 区分：
//   - ErrCiphertextMalformed  结构非法/截断
//   - ErrUnsupportedVersion   格式版本不受支持
//   - ErrKeyNotFound          别名或密钥版本不存在
//   - ErrKeyExpired           版本已到期且宽限期已过
//   - ErrKeyDisabled          密钥已停用
//   - ErrKeyRevoked           密钥已撤销
//   - ErrKeyVersionRetired    版本已被下线回收
//   - ErrCiphertextIntegrity  完整性校验失败（被篡改）
//
// 任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。
func (v *Vault) Decrypt(alias string, blob []byte) ([]byte, error) {
	keyVersion, nonce, ct, err := decode(blob)
	if err != nil {
		return nil, err
	}
	vw, err := v.store.snapshotVersion(alias, keyVersion)
	if err != nil {
		return nil, err
	}
	if err := denyFor(vw, false); err != nil {
		return nil, err
	}
	pt, err := openAEAD(vw.material, nonce, ct)
	if err != nil {
		// AEAD 打开失败即完整性校验失败；不向外泄露库错误原文。
		return nil, fmt.Errorf("%w: alias %q version %d", ErrCiphertextIntegrity, alias, keyVersion)
	}
	return pt, nil
}

// Upgrade 把老版本密钥加密的密文原子地重新加密为当前密钥版本下的密文。
// “取旧版本+当前版本同一时刻快照 -> 校验 -> 解出明文 -> 重新加密”
// 所需的密钥判定来自同一读锁临界区，轮换/停用/到期/下线无法插入：
//   - 成功：返回新密文；新旧密文解出的明文完全一致；
//   - 密文本身已是当前版本且校验通过：原样返回（不重复处理）；
//   - 任何失败只返回错误（nil 密文），绝不吐出新密文或半截明文；
//     损坏/篡改/版本不受支持与密钥侧原因各自可区分；
//   - 操作只读密钥库、不修改任何状态，因此失败后原样重试结果稳定。
func (v *Vault) Upgrade(alias string, blob []byte) ([]byte, error) {
	keyVersion, nonce, ct, err := decode(blob)
	if err != nil {
		return nil, err
	}
	oldV, curV, err := v.store.snapshotPair(alias, keyVersion)
	if err != nil {
		return nil, err
	}
	// 旧版本必须此刻可解密（到期宽限内仍允许升级）。
	if err := denyFor(oldV, false); err != nil {
		return nil, err
	}
	pt, err := openAEAD(oldV.material, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("%w: alias %q version %d", ErrCiphertextIntegrity, alias, keyVersion)
	}
	// 已经是当前版本：校验通过即幂等返回原密文，不重新封装。
	if oldV.version == curV.version {
		return blob, nil
	}
	// 当前版本必须此刻可加密。
	if err := denyFor(curV, true); err != nil {
		return nil, err
	}
	aead, err := newAEAD(curV.material)
	if err != nil {
		return nil, err
	}
	newNonce := make([]byte, nonceLen)
	if _, err := rand.Read(newNonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	newCT := aead.Seal(nil, newNonce, pt, nil)
	return encode(curV.version, newNonce, newCT), nil
}

func newAEAD(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init gcm")
	}
	return aead, nil
}

// openAEAD 用给定材料解出明文；底层错误细节不向上透出。
func openAEAD(material, nonce, ct []byte) ([]byte, error) {
	aead, err := newAEAD(material)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, nil)
}
