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
// 取版本快照、按操作时刻做可用性判定都在读锁临界区内完成；
// 快照材料独立拷贝，锁外加密期间即使并发轮换/下线也不会读到
// 半更新状态，密文头版本号与实际密钥材料必然一致。
func (v *Vault) Encrypt(alias string, plaintext []byte) ([]byte, error) {
	now := v.store.now()
	snap, err := v.store.snapshotCurrent(alias)
	if err != nil {
		return nil, err
	}
	if err := snap.asKeyVersion().encryptDenied(now); err != nil {
		return nil, err
	}
	aead, err := newAEADFromSnapshot(snap)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return encode(snap.version, nonce, ct), nil
}

// Decrypt 解密信封密文；失败原因可通过 errors.Is 区分：
//   - ErrCiphertextMalformed  结构非法/截断
//   - ErrUnsupportedVersion   格式版本不受支持
//   - ErrKeyNotFound          别名或密钥版本不存在
//   - ErrKeyRetired           版本已被下线回收
//   - ErrKeyRevoked           密钥已撤销（同时也命中 ErrKeyDisabled）
//   - ErrKeyDisabled          密钥已停用
//   - ErrKeyExpired           版本已到期且过了解密宽限期
//   - ErrCiphertextIntegrity  完整性校验失败（被篡改）
//
// 可用性一律按解密操作发生的时刻判定。
// 任何失败路径都不返回部分明文，也不透出底层加密库的错误细节。
func (v *Vault) Decrypt(alias string, blob []byte) ([]byte, error) {
	keyVersion, nonce, ct, err := decode(blob)
	if err != nil {
		return nil, err
	}
	now := v.store.now()
	snap, err := v.store.snapshotVersion(alias, keyVersion)
	if err != nil {
		return nil, err
	}
	if err := snap.asKeyVersion().decryptDenied(now); err != nil {
		return nil, err
	}
	pt, err := openSnapshot(snap, nonce, ct, alias)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// ReEncrypt 把存量密文升级到别名当前密钥版本：先按信封头中的源版本
// 解出明文，再用当前版本重新加密。升级前后明文完全一致。
//
// 源版本与当前版本的快照在同一读锁临界区内取得，因此并发轮换/停用/
// 下线时，升级判定基于一致视图：要么按当时有效的结论成功，
// 要么给出对应拒绝，不会版本错配或读到半更新状态。
//
// 失败语义（任一成立即整体失败，绝不吐出新密文或半截明文）：
//   - 密文损坏 -> ErrCiphertextMalformed；格式版本不受支持 -> ErrUnsupportedVersion；
//   - 源版本不存在/已下线/停用/撤销/过宽限期 -> 对应哨兵错误；
//   - 源密文被篡改 -> ErrCiphertextIntegrity（在重加密之前校验失败）；
//   - 当前版本不可加密（到期/停用/撤销/已下线）-> 对应哨兵错误。
//
// 幂等稳定：密文已是当前版本时原样返回 changed=false；同一输入
// 无论重试多少次，结论稳定（成功恒为当前版本且明文一致，失败恒同类原因）。
func (v *Vault) ReEncrypt(alias string, blob []byte) (out []byte, changed bool, err error) {
	sourceVersion, nonce, ct, err := decode(blob)
	if err != nil {
		return nil, false, err // 损坏/版本不受支持：先于一切密钥操作，稳定可重试
	}
	now := v.store.now()
	src, cur, err := v.store.snapshotPairForReEncrypt(alias, sourceVersion)
	if err != nil {
		return nil, false, err
	}
	// 已经是当前版本：无需升级。原样返回，保证重试稳定，
	// 且不会对一条可能损坏的当前版本密文做无谓重加密。
	if src.version == cur.version {
		return blob, false, nil
	}
	// 源版本必须在“此刻”仍可解密（到期宽限期内也可以）。
	if err := src.asKeyVersion().decryptDenied(now); err != nil {
		return nil, false, err
	}
	// 当前版本必须在“此刻”可加密。
	if err := cur.asKeyVersion().encryptDenied(now); err != nil {
		return nil, false, err
	}
	// 先解开旧密文并校验完整性；篡改在此暴露，绝不在此之后产出新密文。
	pt, err := openSnapshot(src, nonce, ct, alias)
	if err != nil {
		return nil, false, err
	}
	aead, err := newAEADFromSnapshot(cur)
	if err != nil {
		return nil, false, err
	}
	newNonce := make([]byte, nonceLen)
	if _, err := rand.Read(newNonce); err != nil {
		return nil, false, fmt.Errorf("vault: generate nonce: %w", err)
	}
	newCT := aead.Seal(nil, newNonce, pt, nil)
	return encode(cur.version, newNonce, newCT), true, nil
}

// openSnapshot 用快照材料执行 GCM 打开；失败统一映射为 ErrCiphertextIntegrity，
// 不向外泄露加密库错误原文，也绝不返回部分明文。
func openSnapshot(snap keySnapshot, nonce, ct []byte, alias string) ([]byte, error) {
	aead, err := newAEADFromSnapshot(snap)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: alias %q version %d",
			ErrCiphertextIntegrity, alias, snap.version)
	}
	return pt, nil
}

func newAEADFromSnapshot(snap keySnapshot) (cipher.AEAD, error) {
	block, err := aes.NewCipher(snap.material)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, "init gcm")
	}
	return aead, nil
}
