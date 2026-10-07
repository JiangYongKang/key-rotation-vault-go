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

// DefaultGracePeriod 轮换/创建时未显式指定宽限期时使用的默认解密宽限期：
// 版本到期、加密被拒后的这段时间内历史密文仍可解密，留给存量升级窗口。
const DefaultGracePeriod = 24 * time.Hour

// KeyOption 创建或轮换密钥版本时的可选参数。
type KeyOption func(*keyOptions)

type keyOptions struct {
	ttl         time.Duration // <=0 表示长期有效
	gracePeriod time.Duration // 到期后的解密宽限期
}

// WithTTL 指定新版本的存活时长：从创建时刻起 ttl 后到期，到期即禁止加密。
// 不传或传入 <=0 表示长期有效。
func WithTTL(ttl time.Duration) KeyOption {
	return func(o *keyOptions) { o.ttl = ttl }
}

// WithGracePeriod 指定到期后的解密宽限期；需配合 WithTTL 使用，缺省为 DefaultGracePeriod。
func WithGracePeriod(d time.Duration) KeyOption {
	return func(o *keyOptions) { o.gracePeriod = d }
}

// KeyStore 管理密钥别名到版本列表的映射，并发安全。
// 所有读写共用一把 RWMutex：加解密持读锁，轮换/停用持写锁，
// 保证同一别名上的并发操作不会出现撕裂读取或版本错配。
type KeyStore struct {
	mu    sync.RWMutex
	keys  map[string][]*KeyVersion // 版本按递增顺序追加；retired 版本保留为墓碑
	nowFn func() time.Time         // 时钟，测试可替换
}

// NewKeyStore 创建空密钥库。
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string][]*KeyVersion), nowFn: time.Now}
}

// now 返回当前判定时刻（“能不能用”一律按操作发生的这一刻判断）。
func (s *KeyStore) now() time.Time { return s.nowFn() }

// setClock 替换判定时钟（包内测试用，用于精确驱动到期/宽限期边界）。
func (s *KeyStore) setClock(fn func() time.Time) {
	if fn == nil {
		fn = time.Now
	}
	s.nowFn = fn
}

// parseOptions 归一化创建/轮换选项。
func parseOptions(opts []KeyOption) *keyOptions {
	o := &keyOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// CreateKey 为别名创建首个版本；别名已存在时返回错误。
// 可用 WithTTL / WithGracePeriod 指定有效期与解密宽限期，缺省为长期有效。
func (s *KeyStore) CreateKey(alias string, opts ...KeyOption) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[alias]; ok {
		return nil, fmt.Errorf("vault: alias %q already exists", alias)
	}
	kv, err := newKeyVersion(alias, 1, s.now(), parseOptions(opts))
	if err != nil {
		return nil, err
	}
	s.keys[alias] = []*KeyVersion{kv}
	return kv, nil
}

// Rotate 为别名追加新版本并返回；旧版本保留以允许解密历史密文。
// 新版本可用 WithTTL/WithGracePeriod 指定有效期（包括每次轮换独立的 TTL），
// 缺省为长期有效。
func (s *KeyStore) Rotate(alias string, opts ...KeyOption) (*KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	kv, err := newKeyVersion(alias, len(versions)+1, s.now(), parseOptions(opts))
	if err != nil {
		return nil, err
	}
	s.keys[alias] = append(versions, kv)
	return kv, nil
}

// Retire 下线别名下指定版本并清除其密钥材料（回收空间）。
// 下线后该版本密文解密返回 ErrKeyRetired；当前版本不允许下线
// （返回 ErrCannotRetireCurrent）；重复下线同一版本幂等成功；
// 已停用/撤销的旧版本同样可以回收。
func (s *KeyStore) Retire(alias string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if version < 1 || version > len(versions) {
		return fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, version)
	}
	if version == len(versions) {
		return fmt.Errorf("%w: alias %q version %d", ErrCannotRetireCurrent, alias, version)
	}
	kv := versions[version-1]
	if kv.Status == StatusRetired {
		return nil // 幂等：已经下线，直接成功
	}
	kv.Status = StatusRetired
	kv.material = nil // 清除材料，回收占用
	return nil
}

// RetireOldVersions 下线别名下除当前版本外、所有未下线的旧版本，
// 返回本次新下线的版本号列表（按版本号升序）。幂等，重复调用返回空切片。
func (s *KeyStore) RetireOldVersions(alias string) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.keys[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	retired := make([]int, 0)
	// 当前版本（切片末尾）绝不回收。
	for _, kv := range versions[:len(versions)-1] {
		if kv.Status == StatusRetired {
			continue
		}
		kv.Status = StatusRetired
		kv.material = nil
		retired = append(retired, kv.Version)
	}
	return retired, nil
}

// snapshotCurrent 在同一读锁临界区内返回当前版本的不可变快照
// （版本号、状态、到期时刻与密钥材料拷贝），供加密使用，
// 杜绝并发轮换/下线读到半更新状态。
func (s *KeyStore) snapshotCurrent(alias string) (keySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return keySnapshot{}, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	return toSnapshot(versions[len(versions)-1]), nil
}

// snapshotVersion 与 snapshotCurrent 同理，按信封头版本号取快照，供解密/升级使用。
// 已下线版本返回的快照中状态为 retired、material 为 nil，由调用方据此报 ErrKeyRetired。
func (s *KeyStore) snapshotVersion(alias string, version int) (keySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return keySnapshot{}, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if version < 1 || version > len(versions) {
		return keySnapshot{}, fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, version)
	}
	return toSnapshot(versions[version-1]), nil
}

// snapshotPairForReEncrypt 在同一读锁临界区内同时取出
// 源版本（信封头记录的版本）与当前版本两个快照，保证升级判定
// 基于同一时刻的密钥库视图：并发轮换/下线期间，两个版本要么都拿到
// 一致状态，要么整体重试/拒绝，不会读到半更新状态。
func (s *KeyStore) snapshotPairForReEncrypt(alias string, sourceVersion int) (src, cur keySnapshot, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.keys[alias]
	if !ok {
		return keySnapshot{}, keySnapshot{}, fmt.Errorf("%w: alias %q", ErrKeyNotFound, alias)
	}
	if sourceVersion < 1 || sourceVersion > len(versions) {
		return keySnapshot{}, keySnapshot{},
			fmt.Errorf("%w: alias %q version %d", ErrKeyNotFound, alias, sourceVersion)
	}
	return toSnapshot(versions[sourceVersion-1]), toSnapshot(versions[len(versions)-1]), nil
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
		if kv.Status == StatusRetired {
			continue // 墓碑不参与停用/撤销
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

// toSnapshot 必须在持锁状态下调用：拷贝出一份独立材料，
// 保证快照在锁外使用时与后续下线/轮换互不影响。
func toSnapshot(kv *KeyVersion) keySnapshot {
	snap := keySnapshot{
		alias:      kv.Alias,
		version:    kv.Version,
		status:     kv.Status,
		expiresAt:  kv.ExpiresAt,
		graceUntil: kv.GraceUntil,
	}
	if kv.material != nil {
		snap.material = bytes.Clone(kv.material)
	}
	return snap
}

// asKeyVersion 仅供 newKeyVersion 之外、需要复用 key.go 判定逻辑时使用：
// 快照转成临时 KeyVersion（material 为同一份拷贝，调用方不得修改）。
func (s keySnapshot) asKeyVersion() *KeyVersion {
	return &KeyVersion{
		Alias:      s.alias,
		Version:    s.version,
		Status:     s.status,
		ExpiresAt:  s.expiresAt,
		GraceUntil: s.graceUntil,
		material:   s.material,
	}
}

// newKeyVersion 生成一个带随机密钥材料的新版本。
// now 为创建时刻；opts 为 nil 时生成长期有效版本。
func newKeyVersion(alias string, version int, now time.Time, opts *keyOptions) (*KeyVersion, error) {
	material := make([]byte, keyMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("vault: generate key material: %w", err)
	}
	kv := &KeyVersion{
		Alias:     alias,
		Version:   version,
		Status:    StatusActive,
		CreatedAt: now,
		material:  material,
	}
	if opts != nil && opts.ttl > 0 {
		kv.ExpiresAt = now.Add(opts.ttl)
		grace := opts.gracePeriod
		if grace == 0 {
			grace = DefaultGracePeriod
		}
		if grace > 0 {
			kv.GraceUntil = kv.ExpiresAt.Add(grace)
		}
	}
	return kv, nil
}

// keySnapshot 是一次读锁临界区内取出的不可变密钥视图：
// material 是独立拷贝，之后即使版本被轮换/下线也不会影响本快照。
type keySnapshot struct {
	alias      string
	version    int
	status     KeyStatus
	expiresAt  time.Time
	graceUntil time.Time
	material   []byte
}
