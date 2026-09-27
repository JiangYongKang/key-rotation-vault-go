package vault

import "crypto/rand"

// KeyStatus 表示密钥版本的生命周期状态。
type KeyStatus int

const (
	// StatusActive 可用于加密与解密。
	StatusActive KeyStatus = iota
	// StatusDecryptOnly 仅可用于解密历史密文（轮换后的旧版本）。
	StatusDecryptOnly
	// StatusDisabled 已停用/撤销，不得再用于解密。
	StatusDisabled
)

// String 返回状态的可读名称，用于日志打印判定依据。
func (s KeyStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDecryptOnly:
		return "decrypt-only"
	case StatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// Key 是主密钥一个版本的对外元信息（不含密钥材料）。
type Key struct {
	Alias   string
	Version int
	Status  KeyStatus
}

// keyEntry 是内部持有的密钥版本，包含密钥材料。
type keyEntry struct {
	version  int
	status   KeyStatus
	material []byte // 32 字节 AES-256 密钥材料
}

// keyStore 是别名 -> 版本列表（按版本升序）的内存托管结构。
// 所有访问必须由 Vault 的互斥锁保护，本结构自身不加锁。
type keyStore struct {
	byAlias map[string][]*keyEntry
}

func newKeyStore() *keyStore {
	return &keyStore{byAlias: make(map[string][]*keyEntry)}
}

// latest 返回别名下最新版本，不存在时返回 nil。
func (s *keyStore) latest(alias string) *keyEntry {
	versions := s.byAlias[alias]
	if len(versions) == 0 {
		return nil
	}
	return versions[len(versions)-1]
}

// get 返回别名指定版本的条目，不存在时返回 nil。
func (s *keyStore) get(alias string, version int) *keyEntry {
	for _, e := range s.byAlias[alias] {
		if e.version == version {
			return e
		}
	}
	return nil
}

// add 追加一个新版本，密钥材料由 crypto/rand 生成。
func (s *keyStore) add(alias string) (*keyEntry, error) {
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}
	e := &keyEntry{
		version:  len(s.byAlias[alias]) + 1,
		status:   StatusActive,
		material: material,
	}
	s.byAlias[alias] = append(s.byAlias[alias], e)
	return e, nil
}
