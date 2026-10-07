package vault

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock 可控时钟，用于确定性地验证到期边界。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newVaultWithClock 创建使用假时钟的 Vault，时间起点固定。
func newVaultWithClock(t *testing.T, grace time.Duration) (*Vault, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)}
	store := NewKeyStore(WithClock(clk.now), WithGracePeriod(grace))
	return NewVault(store), clk
}

func TestVersionExpiryBoundaries(t *testing.T) {
	const ttl = time.Hour
	const grace = 30 * time.Minute
	v, clk := newVaultWithClock(t, grace)

	kv, err := v.Store().CreateKey("orders", ttl)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	t.Logf("created version=%d createdAt=%s expiresAt=%s graceEnd=%s (判定依据: TTL=%v grace=%v)",
		kv.Version, kv.CreatedAt.Format(timeFmt), kv.ExpiresAt.Format(timeFmt),
		kv.GraceEnd.Format(timeFmt), ttl, grace)

	ct, err := v.Encrypt("orders", []byte("border-data"))
	if err != nil {
		t.Fatalf("encrypt while fresh: %v", err)
	}

	// 1) now == ExpiresAt：恰好到期 -> 加密被拒，解密仍允许（宽限期含起点）
	clk.set(kv.ExpiresAt)
	if got := kv.timeStateAt(clk.t); got != timeExpired {
		t.Fatalf("at expiry instant expected timeExpired, got %v", got)
	}
	if _, err := v.Encrypt("orders", []byte("x")); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("encrypt at expiry instant: expected ErrKeyExpired, got %v", err)
	}
	t.Logf("at %s (=ExpiresAt): encrypt -> ErrKeyExpired（边界: 到期时刻不可加密）",
		clk.t.Format(timeFmt))

	if pt, err := v.Decrypt("orders", ct); err != nil || string(pt) != "border-data" {
		t.Fatalf("decrypt at expiry instant should be in grace: pt=%q err=%v", pt, err)
	}
	t.Logf("at %s (=ExpiresAt): decrypt OK（状态=expired, 宽限内仍可解密）", clk.t.Format(timeFmt))

	// 2) 有效期与宽限期之间：加密拒、解密允许
	clk.advance(ttl / 2)
	if _, err := v.Encrypt("orders", []byte("x")); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("encrypt during grace: expected ErrKeyExpired, got %v", err)
	}
	if _, err := v.Decrypt("orders", ct); err != nil {
		t.Fatalf("decrypt during grace: %v", err)
	}
	t.Logf("at %s (ExpiresAt,GraceEnd]: encrypt=ErrKeyExpired, decrypt=OK", clk.t.Format(timeFmt))

	// 3) now == GraceEnd：宽限期末刻仍可解密（边界含端点）
	clk.set(kv.GraceEnd)
	if pt, err := v.Decrypt("orders", ct); err != nil || string(pt) != "border-data" {
		t.Fatalf("decrypt at grace-end instant must still work: pt=%q err=%v", pt, err)
	}
	t.Logf("at %s (=GraceEnd): decrypt OK（边界: 宽限期含末端）", clk.t.Format(timeFmt))

	// 4) 超过 GraceEnd 一纳秒：解密也被拒
	clk.advance(time.Nanosecond)
	if _, err := v.Encrypt("orders", []byte("x")); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("encrypt after grace: expected ErrKeyExpired, got %v", err)
	}
	_, err = v.Decrypt("orders", ct)
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("decrypt after grace: expected ErrKeyExpired, got %v", err)
	}
	t.Logf("at %s (>GraceEnd): decrypt -> ErrKeyExpired（判定依据: now.After(GraceEnd)）",
		clk.t.Format(timeFmt))
}

func TestNoTTLMeansLongLived(t *testing.T) {
	v, clk := newVaultWithClock(t, time.Hour)
	if _, err := v.Store().CreateKey("eternal"); err != nil {
		t.Fatal(err)
	}
	ct, err := v.Encrypt("eternal", []byte("forever"))
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(24 * 365 * 10 * time.Hour) // 十年后
	if _, err := v.Decrypt("eternal", ct); err != nil {
		t.Fatalf("long-lived key must not expire, got %v", err)
	}
	if _, err := v.Encrypt("eternal", []byte("x")); err != nil {
		t.Fatalf("long-lived key must still encrypt, got %v", err)
	}
	t.Logf("未指定 TTL: 推进 %v 后加解密仍 OK（ExpiresAt 零值=长期有效）", clk.t)
}

func TestRotateWithIndependentTTL(t *testing.T) {
	v, clk := newVaultWithClock(t, time.Hour)
	v1, _ := v.Store().CreateKey("mix", time.Hour)
	ct1, _ := v.Encrypt("mix", []byte("old"))

	clk.advance(30 * time.Minute)
	v2, err := v.Store().Rotate("mix", 0) // 新版本长期有效
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("v1 expiresAt=%s; v2 ExpiresAt 零值(长期)", v1.ExpiresAt.Format(timeFmt))

	// v1 到期进入宽限期：v2 不受影响
	clk.set(v1.ExpiresAt.Add(30 * time.Minute))
	if _, err := v.Encrypt("mix", []byte("new")); err != nil {
		t.Fatalf("current v2 long-lived must encrypt: %v", err)
	}
	if _, err := v.Decrypt("mix", ct1); err != nil {
		t.Fatalf("v1 within grace must decrypt: %v", err)
	}
	// v1 宽限期过：历史密文被拒，v2 正常
	clk.set(v1.GraceEnd.Add(time.Second))
	_, err = v.Decrypt("mix", ct1)
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("expected v1 ErrKeyExpired after grace, got %v", err)
	}
	ct2, err := v.Encrypt("mix", []byte("new"))
	if err != nil {
		t.Fatalf("v2 must still encrypt after v1 fully expired: %v", err)
	}
	if _, err := v.Decrypt("mix", ct2); err != nil {
		t.Fatalf("v2 decrypt: %v", err)
	}
	t.Logf("版本 TTL 独立: v1 版本=%d 过期拒绝, v2 版本=%d 长期有效 (最终判定=%s)",
		v1.Version, v2.Version, classify(t, err))
}

func TestNegativeTTLRejected(t *testing.T) {
	store := NewKeyStore()
	if _, err := store.CreateKey("bad", -time.Second); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	store.CreateKey("ok")
	if _, err := store.Rotate("ok", -1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("rotate negative ttl: expected ErrInvalidArgument, got %v", err)
	}
}
