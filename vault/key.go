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
	// StatusRetired 版本已被下线回收：密钥材料已销毁，加解密均不可用。
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
	// ExpiresAt 加密有效期截止时刻；零值表示长期有效。
	ExpiresAt time.Time
	// GraceEnd 解密宽限期截止时刻；在 (ExpiresAt, GraceEnd] 之间
	// 该版本不可加密但仍可解密；零值表示长期有效。
	GraceEnd time.Time

	material []byte // 主密钥材料，32 字节，AES-256
}

// timeState 描述某个观察时刻下版本的时间有效性。
type timeState int

const (
	timeValid      timeState = iota // 在有效期内（可加解密）
	timeExpired                     // 已过 ExpiresAt 但未过 GraceEnd（仅可解密）
	timeGraceEnded                  // 已过 GraceEnd（加解密均不可用）
)

// availabilityAt 综合静态状态与观察时刻，描述某操作时刻版本是否可用。
type availability int

const (
	availOK         availability = iota // 在有效期内，可加解密
	availExpired                        // 已过 ExpiresAt、未过 GraceEnd：不可加密，仍可解密
	availGraceEnded                     // 已过 GraceEnd：加解密均不可用
	availDisabled                       // 已停用
	availRevoked                        // 已撤销
	availRetired                        // 已下线回收，密钥材料不存在
)

// availabilityAt 按观察时刻 now 给出版本的可用性结论。
// 静态状态（停用/撤销/下线）优先于时间窗口：一旦人工处置，
// 即使仍在有效期内也按静态状态拒绝。
func (kv *KeyVersion) availabilityAt(now time.Time) availability {
	switch kv.Status {
	case StatusRetired:
		return availRetired
	case StatusDisabled:
		return availDisabled
	case StatusRevoked:
		return availRevoked
	}
	switch kv.timeStateAt(now) {
	case timeValid:
		return availOK
	case timeExpired:
		return availExpired
	default:
		return availGraceEnded
	}
}

// timeStateAt 返回观察时刻下的时间有效性。
// 边界约定：now == ExpiresAt 即视为已到期（加密被拒）；
// now == GraceEnd 仍在宽限期内（可解密），超过才拒绝解密。
func (kv *KeyVersion) timeStateAt(now time.Time) timeState {
	if kv.ExpiresAt.IsZero() {
		return timeValid // 长期有效
	}
	if now.Before(kv.ExpiresAt) {
		return timeValid
	}
	if !now.After(kv.GraceEnd) {
		return timeExpired
	}
	return timeGraceEnded
}
