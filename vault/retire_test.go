package vault

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestRetireReclaimsOldVersions 正常路径：旧版本回收后解密明确失败
// （ErrKeyVersionRetired，区别于损坏/不存在），当前版本不受影响。
func TestRetireReclaimsOldVersions(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("k")
	ct1, _ := v.Encrypt("k", []byte("v1-data"))
	v.Store().Rotate("k")
	ct2, _ := v.Encrypt("k", []byte("v2-data"))
	v.Store().Rotate("k") // 当前版本 v3

	n, err := v.Store().Retire("k")
	if err != nil || n != 2 {
		t.Fatalf("Retire count=%d err=%v, want 2", n, err)
	}
	t.Logf("Retire 回收版本数=%d（判定: 当前版本 v3 永不回收）", n)

	for name, c := range map[string]struct {
		blob []byte
	}{"v1": {ct1}, "v2": {ct2}} {
		pt, err := v.Decrypt("k", c.blob)
		ver, _, _, _ := decode(c.blob)
		t.Logf("decrypt retired %s (key version=%d): err=%v 判定=%s",
			name, ver, err, classify(t, err))
		if !errors.Is(err, ErrKeyVersionRetired) {
			t.Fatalf("%s: want ErrKeyVersionRetired, got %v", name, err)
		}
		if pt != nil {
			t.Fatalf("%s: must not return plaintext", name)
		}
		// 与“密文损坏”“密钥/版本不存在”区分
		if errors.Is(err, ErrCiphertextMalformed) || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("retired must be distinguishable from malformed/notfound")
		}
	}

	// 当前版本照常工作
	ct3, err := v.Encrypt("k", []byte("v3-data"))
	if err != nil {
		t.Fatalf("current version encrypt after retire: %v", err)
	}
	if pt, err := v.Decrypt("k", ct3); err != nil || string(pt) != "v3-data" {
		t.Fatalf("current version decrypt after retire: pt=%q err=%v", pt, err)
	}
	// 升级一个已回收版本的密文也必须明确失败，且无新密文
	out, err := v.Upgrade("k", ct1)
	if !errors.Is(err, ErrKeyVersionRetired) || out != nil {
		t.Fatalf("upgrade retired: err=%v out=%v", err, out)
	}
	t.Log("当前版本 v3 加解密正常；升级已回收版本 -> ErrKeyVersionRetired，无新密文")
}

// TestRetireCurrentVersionProtected 只有当前版本时 Retire 不回收任何版本。
func TestRetireCurrentVersionProtected(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("only")
	ct, _ := v.Encrypt("only", []byte("live"))

	n, err := v.Store().Retire("only")
	if err != nil || n != 0 {
		t.Fatalf("Retire n=%d err=%v, want 0", n, err)
	}
	if pt, err := v.Decrypt("only", ct); err != nil || string(pt) != "live" {
		t.Fatalf("current version must survive retire: pt=%q err=%v", pt, err)
	}
	t.Log("无旧版本时 Retire 回收数=0，当前版本保持可用")
}

// TestRetireIdempotentAndNotFound 重复下线幂等；别名不存在报 ErrKeyNotFound。
func TestRetireIdempotentAndNotFound(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("x")
	v.Encrypt("x", []byte("old"))
	v.Store().Rotate("x")

	if n, _ := v.Store().Retire("x"); n != 1 {
		t.Fatalf("first retire want 1, got %d", n)
	}
	if n, _ := v.Store().Retire("x"); n != 0 {
		t.Fatalf("second retire must be idempotent 0, got %d", n)
	}
	if _, err := v.Store().Retire("ghost"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing alias: want ErrKeyNotFound, got %v", err)
	}
	// 轮换产生 v3 后再回收：只回收 v2（v1 已 retired），当前 v3 保留
	v.Store().Rotate("x")
	if n, _ := v.Store().Retire("x"); n != 1 {
		t.Fatalf("retire after new rotation want 1 newly retired, got %d", n)
	}
	t.Log("Retire 幂等：已回收不重复计数；新轮换后只回收新增旧版本")
}

// TestDisableRevokeDoesNotResurrectRetired 停用/撤销不能复活已回收版本。
func TestDisableRevokeDoesNotResurrectRetired(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("d")
	old, _ := v.Encrypt("d", []byte("old"))
	v.Store().Rotate("d")
	v.Store().Retire("d")

	if err := v.Store().Disable("d"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Decrypt("d", old); !errors.Is(err, ErrKeyVersionRetired) {
		t.Fatalf("retired must stay retired after disable, got %v", err)
	}
	if err := v.Store().Revoke("d"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Decrypt("d", old); !errors.Is(err, ErrKeyVersionRetired) {
		t.Fatalf("retired must stay retired after revoke, got %v", err)
	}
	t.Log("停用/撤销不复活已回收版本，判定恒为 ErrKeyVersionRetired")
}

// TestConcurrentRetireAndDecrypt 回收与解密并发：解密结果只能是
// 成功 或 ErrKeyVersionRetired，绝不出现撕裂读取或其他错误。
func TestConcurrentRetireAndDecrypt(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("c")
	old, _ := v.Encrypt("c", []byte("old"))
	v.Store().Rotate("c")
	curCT, _ := v.Encrypt("c", []byte("current"))

	var wg sync.WaitGroup
	errCh := make(chan error, 2000)

	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// 旧版本：成功或 retired 二选一
				if pt, err := v.Decrypt("c", old); err != nil {
					if !errors.Is(err, ErrKeyVersionRetired) {
						errCh <- fmt.Errorf("old decrypt unexpected: %v", err)
					}
				} else if string(pt) != "old" {
					errCh <- fmt.Errorf("old torn read: %q", pt)
				}
				// 当前版本：任何时刻都必须可解
				if pt, err := v.Decrypt("c", curCT); err != nil || string(pt) != "current" {
					errCh <- fmt.Errorf("current decrypt: pt=%q err=%v", pt, err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := v.Store().Retire("c"); err != nil {
			errCh <- fmt.Errorf("retire: %v", err)
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	t.Log("并发回收+解密：旧版本结果仅为成功或 ErrKeyVersionRetired；当前版本全程可解")
}

// TestConcurrentRetireAndUpgrade 回收与升级并发：升级要么成功且明文一致，
// 要么以 ErrKeyVersionRetired 等明确原因失败，绝不吐出半截新密文。
func TestConcurrentRetireAndUpgrade(t *testing.T) {
	v := NewVault(NewKeyStore())
	v.Store().CreateKey("u")
	old, _ := v.Encrypt("u", []byte("payload"))
	v.Store().Rotate("u")

	var wg sync.WaitGroup
	errCh := make(chan error, 2000)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				out, err := v.Upgrade("u", old)
				if err != nil {
					if out != nil {
						errCh <- fmt.Errorf("error path emitted ciphertext: %v", err)
					}
					continue
				}
				pt, derr := v.Decrypt("u", out)
				if derr != nil || string(pt) != "payload" {
					errCh <- fmt.Errorf("upgraded mismatch: pt=%q err=%v", pt, derr)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		v.Store().Retire("u")
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	t.Log("并发回收+升级：成功路径明文一致，失败路径零输出")
}
