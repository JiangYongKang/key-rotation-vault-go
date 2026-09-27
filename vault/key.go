package vault

import "time"

// KeyStatus 密钥生命周期状态。
type KeyStatus int

const (
	// StatusActive 可用于加密与解密。
	StatusActive KeyStatus = iota
	// StatusDisabled 已停用：不可加密也不可解密。
	StatusDisabled
	// StatusRevoked 已撤销：同 Disabled，但语义上表示不可恢复。
	StatusRevoked
)

func (s KeyStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDisabled:
		return "disabled"
	case StatusRevoked:
		return "revoked"
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

	material []byte // 主密钥材料，32 字节，AES-256
}
