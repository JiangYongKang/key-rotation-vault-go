package vault

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// keyMaterialLen 主密钥材料长度（AES-256）。
const keyMaterialLen = 32

// Clock 返回当前时刻，抽象出来便于在测试中控制时间。
type Clock func() time.Time

// KeyStore 管理密钥别名到版本列表的映射，并发安全。
// 所有读写共用一把 RWMutex：加解密持读锁，轮换/停用/下线持写锁，
// 保证同一别名上的并发操作不会出现撕裂读取或版本错配。
type KeyStore struct {
	mu    sync.RWMutex
	keys  map[string][]*KeyVersion // 版本按递增顺序追加
	now   Clock                    // 观察时刻来源
	grace time.Duration            // 到期后的解密宽限期（TTL 版本）
}

// Option 配置 KeyStore。
type Option func(*KeyStore)

// WithClock 注入时钟（测试用）。
func WithClock(c Clock) Option {
	return func(s *KeyStore) { s.now = c }
}

// WithGracePeriod 设置默认解密宽限期：版本到期后仍可解密的时长。
func WithGracePeriod(d time.Duration) Option {
	return func(s *KeyStore) { s.grace = d }
}

// defaultGracePeriod 未显式配置时的宽限期。
const defaultGracePeriod = 24 * time.Hour

// NewKeyStore 创建空密钥库。
func NewKeyStore(opts ...Option) *KeyStore {
	s := &KeyStore{
		keys:  make(map[string][]*KeyVersion),
		now:   time.Now,
		grace: defaultGracePeriod,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// CreateKey 为别名创建首个版本；别名已存在时返回错误。
// ttl 可空（长期有效）；负数返回 ErrInvalidArgument。
func (s *KeyStore) CreateKey(alias string, ttl ...time.Duration) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[alias]; ok {
		return nil, fmt.Errorf("vault: alias %q already exists", alias)
	}
	d, err := optionalTTL(ttl)
	if err != nil {
		return nil, err
	}
	kv, err := s.newKeyVersion(alias, 1, d)
	if err != nil {
		return nil, err
	}
	s.keys[alias] = []*KeyVersion{kv}
	return kv, nil
}

// Rotate 为别名追加新版本并返回；旧版本保留以允许解密历史密文。
// ttl 可空（长期有效）；每个版本的有效期独立。
func (s *KeyStore) Rotate(alias string, ttl ...time.Duration) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	d, err := optionalTTL(ttl)
	if err != nil {
		return nil, err
	}
	kv, err := s.newKeyVersion(alias, len(versions)+1, d)
	if err != nil {
		return nil, err
	}
	s.keys[alias] = append(versions, kv)
	return kv, nil
}

// Retire 下线并回收别名下除当前版本外的所有旧版本：销毁密钥材料并
// 标记为 retired，返回被回收的版本数。当前版本永远不会被下线。
// 回收后，针对这些版本的密文解密返回 ErrKeyVersionRetired。
// 已下线的版本保持下线（幂等，不重复计数）。
func (s *KeyStore) Retire(alias string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return 0, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	current := len(versions)
	retired := 0
	for i, kv := range versions {
		if i+1 == current {
			continue // 当前版本永不回收
		}
		if kv.Status == StatusRetired {
			continue
		}
		kv.Status = StatusRetired
		kv.material = nil // 销毁密钥材料
		retired++
	}
	return retired, nil
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
		// 已下线回收的版本不会被停用/撤销“复活”。
		if kv.Status == StatusRetired {
			continue
		}
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

// keyView 是某版本在单一观察时刻下的不可变快照。
// material 复制出来，即使随后版本被 Retire 回收，快照仍可完成
// 已授权的本次操作，保证临界区内做出的判定不会半途失效。
type keyView struct {
	alias    string
	version  int
	avail    availability
	now      time.Time
	expires  time.Time
	graceEnd time.Time
	material []byte
}

// snapshotCurrent 在同一读锁临界区内取当前版本快照并给出时刻判定。
func (s *KeyStore) snapshotCurrent(alias string) (*keyView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	return s.snapshotLocked(versions[len(versions)-1]), nil
}

// snapshotVersion 在同一读锁临界区内取指定版本快照并给出时刻判定。
func (s *KeyStore) snapshotVersion(alias string, version int) (*keyView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if version < 1 || version > len(versions) {
		return nil, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, version)
	}
	return s.snapshotLocked(versions[version-1]), nil
}

// snapshotPair 在同一读锁临界区内同时取旧版本与当前版本快照，
// 供 Upgrade 使用：两次判定基于同一时刻、同一状态，
// 期间轮换/停用/到期/下线都无法插入。
func (s *KeyStore) snapshotPair(alias string, oldVersion int) (old, cur *keyView, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if oldVersion < 1 || oldVersion > len(versions) {
		return nil, nil, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, oldVersion)
	}
	return s.snapshotLocked(versions[oldVersion-1]),
		s.snapshotLocked(versions[len(versions)-1]), nil
}

// snapshotLocked 必须在持锁状态下调用。
func (s *KeyStore) snapshotLocked(kv *KeyVersion) *keyView {
	now := s.now()
	v := &keyView{
		alias:    kv.Alias,
		version:  kv.Version,
		avail:    kv.availabilityAt(now),
		now:      now,
		expires:  kv.ExpiresAt,
		graceEnd: kv.GraceEnd,
	}
	if len(kv.material) > 0 {
		v.material = bytes.Clone(kv.material)
	}
	return v
}

// newKeyVersion 生成一个带随机密钥材料的新版本（调用方持锁）。
func (s *KeyStore) newKeyVersion(alias string, version int, ttl time.Duration) (*KeyVersion, error) {
	material := make([]byte, keyMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("vault: generate key material: %w", err)
	}
	now := s.now()
	kv := &KeyVersion{
		Alias:     alias,
		Version:   version,
		Status:    StatusActive,
		CreatedAt: now,
		material:  material,
	}
	if ttl > 0 {
		kv.ExpiresAt = now.Add(ttl)
		kv.GraceEnd = kv.ExpiresAt.Add(s.grace)
	}
	return kv, nil
}

// optionalTTL 校验并取出可选 TTL：零个=长期有效，一个=指定时长。
func optionalTTL(ttl []time.Duration) (time.Duration, error) {
	switch len(ttl) {
	case 0:
		return 0, nil
	case 1:
		if ttl[0] < 0 {
			return 0, fmt.Errorf("%w: ttl must be >= 0", ErrInvalidArgument)
		}
		return ttl[0], nil
	default:
		return 0, fmt.Errorf("%w: at most one ttl allowed", ErrInvalidArgument)
	}
}
