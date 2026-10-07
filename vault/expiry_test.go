package vault

import (
	"errors"
	"testing"
	"time"
)

// fixedClock 返回可控的“当前时刻”，用于精确测试到期/宽限期边界。
type fixedClock struct{ t time.Time }

func (c *fixedClock) get() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newVaultWithClock(t *testing.T, alias string) (*Vault, *fixedClock) {
	t.Helper()
	store := NewKeyStore()
	clk := &fixedClock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	store.setClock(clk.get)
	v := NewVault(store)
	if _, err := store.CreateKey(alias); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return v, clk
}

// TestTTLBoundaries 精确覆盖：到期前一刻可加解密、到期当刻不可加密但可解密、
// 宽限期内可解密、宽限期当刻仍可解密（边界）、过了宽限期不可解密。
func TestTTLBoundaries(t *testing.T) {
	store := NewKeyStore()
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	clk := &fixedClock{t: base}
	store.setClock(clk.get)
	v := NewVault(store)

	const ttl = 1 * time.Hour
	const grace = 30 * time.Minute
	kv, err := store.CreateKey("billing", WithTTL(ttl), WithGracePeriod(grace))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	t.Logf("created version=%d createdAt=%s expiresAt=%s graceUntil=%s (ttl=%v grace=%v)",
		kv.Version, kv.CreatedAt.Format(time.RFC3339), kv.ExpiresAt.Format(time.RFC3339),
		kv.GraceUntil.Format(time.RFC3339), ttl, grace)

	ct, err := v.Encrypt("billing", []byte("edge"))
	if err != nil {
		t.Fatalf("encrypt before expiry: %v", err)
	}

	// 到期前 1ns：仍可加密、可解密。
	clk.t = kv.ExpiresAt.Add(-1)
	if _, err := v.Encrypt("billing", []byte("before")); err != nil {
		t.Fatalf("1ns before expiry encrypt: %v", err)
	}
	if pt, err := v.Decrypt("billing", ct); err != nil || string(pt) != "edge" {
		t.Fatalf("1ns before expiry decrypt: pt=%q err=%v", pt, err)
	}
	t.Logf("时刻 ExpiresAt-1ns: encrypt=OK decrypt=OK (判定依据 now<ExpiresAt)")

	// 到期当刻（now == ExpiresAt）：加密被拒 ErrKeyExpired；宽限期内解密仍成功。
	clk.t = kv.ExpiresAt
	_, err = v.Encrypt("billing", []byte("at"))
	t.Logf("时刻 ExpiresAt: encrypt err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("at expiry encrypt: expected ErrKeyExpired, got %v", err)
	}
	if pt, err := v.Decrypt("billing", ct); err != nil || string(pt) != "edge" {
		t.Fatalf("at expiry decrypt should still work in grace: pt=%q err=%v", pt, err)
	}
	t.Log("时刻 ExpiresAt: decrypt=OK (判定依据 ExpiresAt<=now<=GraceUntil 宽限期内)")

	// 宽限期中间：加密拒、解密成。
	clk.t = kv.ExpiresAt.Add(grace / 2)
	if _, err := v.Encrypt("billing", []byte("mid")); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("in grace encrypt: expected ErrKeyExpired, got %v", err)
	}
	if pt, err := v.Decrypt("billing", ct); err != nil || string(pt) != "edge" {
		t.Fatalf("in grace decrypt: pt=%q err=%v", pt, err)
	}

	// 宽限期当刻（now == GraceUntil）：边界上仍可解密，加密仍是 ErrKeyExpired。
	clk.t = kv.GraceUntil
	if pt, err := v.Decrypt("billing", ct); err != nil || string(pt) != "edge" {
		t.Fatalf("at grace boundary decrypt must still work: pt=%q err=%v", pt, err)
	}
	if _, err := v.Encrypt("billing", []byte("at-grace")); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("at grace boundary encrypt: expected ErrKeyExpired, got %v", err)
	}
	t.Log("时刻 GraceUntil: decrypt=OK(now<=GraceUntil) 且 encrypt 拒绝(ErrKeyExpired)")

	// 过了宽限期 1ns：解密也被拒，且原因仍是 ErrKeyExpired（可与损坏/停用区分）。
	clk.t = kv.GraceUntil.Add(1)
	_, err = v.Decrypt("billing", ct)
	t.Logf("时刻 GraceUntil+1ns: decrypt err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("after grace decrypt: expected ErrKeyExpired, got %v", err)
	}
	if errors.Is(err, ErrCiphertextMalformed) || errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("expiry must be distinguishable from malformed/disabled")
	}
}

// TestNoTTLMeansLongLived 不指定 TTL 时无论时钟推进多久都长期有效。
func TestNoTTLMeansLongLived(t *testing.T) {
	v, clk := newVaultWithClock(t, "forever")
	ct, err := v.Encrypt("forever", []byte("durable"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	clk.advance(24 * 365 * 10 * time.Hour) // 十年后
	if pt, err := v.Decrypt("forever", ct); err != nil || string(pt) != "durable" {
		t.Fatalf("long-lived key: pt=%q err=%v", pt, err)
	}
	if _, err := v.Encrypt("forever", []byte("still")); err != nil {
		t.Fatalf("long-lived key encrypt after years: %v", err)
	}
	t.Log("无 TTL 版本：时钟推进 10 年后 encrypt/decrypt 均 OK（ExpiresAt 零值永不到期）")
}

// TestRotateWithIndependentTTL 轮换出的新版本可带独立 TTL；旧版本到期规则
// 与新版本互不影响，历史密文按旧版本时刻判定。
func TestRotateWithIndependentTTL(t *testing.T) {
	store := NewKeyStore()
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	clk := &fixedClock{t: base}
	store.setClock(clk.get)
	v := NewVault(store)

	k1, err := store.CreateKey("mix", WithTTL(1*time.Hour), WithGracePeriod(time.Hour))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	ct1, _ := v.Encrypt("mix", []byte("old-data"))

	clk.advance(30 * time.Minute)
	k2, err := store.Rotate("mix", WithTTL(2*time.Hour), WithGracePeriod(time.Hour))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	t.Logf("v1 expiresAt=%s graceUntil=%s | v2 expiresAt=%s graceUntil=%s",
		k1.ExpiresAt.Format(time.RFC3339), k1.GraceUntil.Format(time.RFC3339),
		k2.ExpiresAt.Format(time.RFC3339), k2.GraceUntil.Format(time.RFC3339))
	ct2, _ := v.Encrypt("mix", []byte("new-data"))

	// v1 到期（t0+1h）但 v2 未到期：当前加密走 v2 成功。
	clk.t = k1.ExpiresAt
	if cur, _ := store.current("mix"); cur.Version != 2 {
		t.Fatalf("expected current version 2")
	}
	if _, err := v.Encrypt("mix", []byte("x")); err != nil {
		t.Fatalf("v2 still valid when v1 expired: %v", err)
	}
	// 旧密文 v1 处于宽限期内仍可解密。
	if pt, err := v.Decrypt("mix", ct1); err != nil || string(pt) != "old-data" {
		t.Fatalf("v1 in grace: pt=%q err=%v", pt, err)
	}
	// 新密文 v2 正常解密。
	if pt, err := v.Decrypt("mix", ct2); err != nil || string(pt) != "new-data" {
		t.Fatalf("v2 decrypt: pt=%q err=%v", pt, err)
	}
	t.Log("轮换版本独立 TTL：v1 到期后当前加密走 v2，v1 宽限期内旧密文照解")

	// v1 宽限期结束后（t0+2h+1ns）：v1 旧密文被拒；此时 v2 仍在自身宽限期可解密。
	clk.t = k1.GraceUntil.Add(1)
	_, err = v.Decrypt("mix", ct1)
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("v1 past grace: expected ErrKeyExpired, got %v", err)
	}
	if pt, err2 := v.Decrypt("mix", ct2); err2 != nil || string(pt) != "new-data" {
		t.Fatalf("v2 still in grace at this point: pt=%q err=%v", pt, err2)
	}
	t.Logf("v1 过宽限期拒绝(判定=%s)，v2 仍在自身宽限期可解", classify(t, err))
}
