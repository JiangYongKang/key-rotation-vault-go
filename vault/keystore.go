package vault

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// keyMaterialLen 主密钥材料长度（AES-256）。
const keyMaterialLen = 32

// KeyStore 管理密钥别名到版本列表的映射，并发安全。
// 所有读写共用一把 RWMutex：加解密持读锁，轮换/停用持写锁，
// 保证同一别名上的并发操作不会出现撕裂读取或版本错配。
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string][]*KeyVersion // 版本按递增顺序追加
}

// NewKeyStore 创建空密钥库。
func NewKeyStore() *KeyStore { return &KeyStore{keys: make(map[string][]*KeyVersion)} }

// CreateKey 为别名创建首个版本；别名已存在时返回错误。
func (s *KeyStore) CreateKey(alias string) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[alias]; ok {
		return nil, fmt.Errorf("vault: alias %q already exists", alias)
	}
	kv, err := newKeyVersion(alias, 1)
	if err != nil {
		return nil, err
	}
	s.keys[alias] = []*KeyVersion{kv}
	return kv, nil
}

// Rotate 为别名追加新版本并返回；旧版本保持 Active 以允许解密历史密文。
func (s *KeyStore) Rotate(alias string) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	kv, err := newKeyVersion(alias, len(versions)+1)
	if err != nil {
		return nil, err
	}
	s.keys[alias] = append(versions, kv)
	return kv, nil
}

// Disable 停用指定别名的全部版本。
func (s *KeyStore) Disable(alias string) error {
	return s.setStatus(alias, StatusDisabled)
}

// Revoke 撤销指定别名的全部版本。
func (s *KeyStore) Revoke(alias string) error {
	return s.setStatus(alias, StatusRevoked)
}

func (s *KeyStore) setStatus(alias string, st KeyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	for _, kv := range versions {
		kv.Status = st
	}
	return nil
}

// current 返回别名当前（最新）版本。
func (s *KeyStore) current(alias string) (*KeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	return versions[len(versions)-1], nil
}

// get 返回别名指定版本。
func (s *KeyStore) get(alias string, version int) (*KeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if version < 1 || version > len(versions) {
		return nil, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, version)
	}
	return versions[version-1], nil
}

// newKeyVersion 生成一个带随机密钥材料的新版本。
func newKeyVersion(alias string, version int) (*KeyVersion, error) {
	material := make([]byte, keyMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("vault: generate key material: %w", err)
	}
	return &KeyVersion{
		Alias:     alias,
		Version:   version,
		Status:    StatusActive,
		CreatedAt: time.Now(),
		material:  material,
	}, nil
}
