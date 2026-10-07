package vault

import (
	"fmt"
	"time"
)

// KeyStatus 密钥生命周期状态。
type KeyStatus int

const (
	// StatusActive 可用于加密与解密。
	StatusActive KeyStatus = iota
	// StatusDisabled 已停用：不可加密也不可解密。
	StatusDisabled
	// StatusRevoked 已撤销：同 Disabled，但语义上表示不可恢复。
	StatusRevoked
	// StatusRetired 已下线回收：版本元数据保留为墓碑，但密钥材料已清除，
	// 既不可加密也不可解密（报 ErrKeyRetired，可与“不存在”“密文损坏”区分）。
	StatusRetired
)

func (s KeyStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDisabled:
		return "disabled"
	case StatusRevoked:
		return "revoked"
	case StatusRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// KeyVersion 一个密钥别名的单个版本。
type KeyVersion struct {
	Alias     string
	Version   int
	Status    KeyStatus
	CreatedAt time.Time
	// ExpiresAt 加密有效期截止时刻；零值表示长期有效（仅用于加密的到期判定）。
	ExpiresAt time.Time
	// GraceUntil 解密宽限期截止时刻：ExpiresAt 之后、GraceUntil 之前
	// 仍允许解密但禁止加密；零值表示到期后无解密宽限期。
	// 若 ExpiresAt 为零值，本字段无意义。
	GraceUntil time.Time

	material []byte // 主密钥材料，32 字节，AES-256；retired 后为 nil
}

// encryptDenied 在时刻 now 判断该版本能否用于加密；可以用时返回 nil，
// 否则返回可区分原因的哨兵错误（ErrKeyDisabled/ErrKeyRevoked/
// ErrKeyExpired/ErrKeyRetired）。
func (kv *KeyVersion) encryptDenied(now time.Time) error {
	switch kv.Status {
	case StatusRetired:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyRetired, kv.Alias, kv.Version)
	case StatusRevoked:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyRevoked, kv.Alias, kv.Version)
	case StatusDisabled:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyDisabled, kv.Alias, kv.Version)
	case StatusActive:
		if kv.expiredAt(now) {
			return fmt.Errorf("%w: alias %q version %d expired at %s (now %s)",
				ErrKeyExpired, kv.Alias, kv.Version, kv.ExpiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		}
		return nil
	default:
		return fmt.Errorf("%w: alias %q version %d unknown status", ErrKeyDisabled, kv.Alias, kv.Version)
	}
}

// decryptDenied 在时刻 now 判断该版本能否用于解密。
// 与 encryptDenied 的区别：到期但仍处于解密宽限期内时允许解密。
func (kv *KeyVersion) decryptDenied(now time.Time) error {
	switch kv.Status {
	case StatusRetired:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyRetired, kv.Alias, kv.Version)
	case StatusRevoked:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyRevoked, kv.Alias, kv.Version)
	case StatusDisabled:
		return fmt.Errorf("%w: alias %q version %d", ErrKeyDisabled, kv.Alias, kv.Version)
	case StatusActive:
		// 未到期：正常解密。
		if !kv.expiredAt(now) {
			return nil
		}
		// 已到期但仍在宽限期内：禁止加密、允许解密。
		if !kv.pastGraceAt(now) {
			return nil
		}
		return fmt.Errorf("%w: alias %q version %d grace ended at %s (now %s)",
			ErrKeyExpired, kv.Alias, kv.Version, kv.GraceUntil.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	default:
		return fmt.Errorf("%w: alias %q version %d unknown status", ErrKeyDisabled, kv.Alias, kv.Version)
	}
}

// expiredAt 报告版本在时刻 now 是否已过加密有效期（零值永不到期）。
// 边界语义：now < ExpiresAt 仍可加密；now == ExpiresAt 即到期。
func (kv *KeyVersion) expiredAt(now time.Time) bool {
	if kv.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(kv.ExpiresAt)
}

// pastGraceAt 报告版本在时刻 now 是否已过解密宽限期。
// 边界语义：now <= GraceUntil 仍可解密；now > GraceUntil 拒绝解密。
func (kv *KeyVersion) pastGraceAt(now time.Time) bool {
	if kv.GraceUntil.IsZero() {
		// 未配置宽限期：到期即拒绝解密。
		return true
	}
	return now.After(kv.GraceUntil)
}
