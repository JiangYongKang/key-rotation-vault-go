package vault

import (
	"errors"
	"testing"
)

// TestRetireOldVersion 正常路径：迁移完成后下线旧版本，材料被清除；
// 针对旧版本密文解密明确失败且原因为 ErrKeyRetired。
func TestRetireOldVersion(t *testing.T) {
	v := newVaultWithKey(t, "archive")
	ct1, _ := v.Encrypt("archive", []byte("old"))
	_, _ = v.Store().Rotate("archive")
	ct2, _ := v.Encrypt("archive", []byte("new"))

	if err := v.Store().Retire("archive", 1); err != nil {
		t.Fatalf("Retire v1: %v", err)
	}
	t.Log("下线 version=1：状态置 retired，密钥材料清空")

	// 旧密文解密必须失败，原因是 ErrKeyRetired。
	_, err := v.Decrypt("archive", ct1)
	t.Logf("旧版本密文解密: 判定=%s err=%v", classify(t, err), err)
	if !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("expected ErrKeyRetired, got %v", err)
	}
	// 且必须能与“密文损坏”“密钥不存在”区分开。
	if errors.Is(err, ErrCiphertextMalformed) {
		t.Fatal("retired must not be confused with malformed")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatal("retired version existed before; must not be reported as not found")
	}

	// 当前版本密文不受影响。
	if pt, err := v.Decrypt("archive", ct2); err != nil || string(pt) != "new" {
		t.Fatalf("current version must still decrypt: pt=%q err=%v", pt, err)
	}
	if _, err := v.Encrypt("archive", []byte("x")); err != nil {
		t.Fatalf("current version must still encrypt: %v", err)
	}
}

// TestRetireCurrentRejected 当前正在使用的版本不能被下线。
func TestRetireCurrentRejected(t *testing.T) {
	v := newVaultWithKey(t, "cur")
	_, _ = v.Encrypt("cur", []byte("x"))
	_, _ = v.Store().Rotate("cur") // 当前为 v2

	err := v.Store().Retire("cur", 2)
	t.Logf("下线当前版本 v2: 判定=%s", classify(t, err))
	if !errors.Is(err, ErrCannotRetireCurrent) {
		t.Fatalf("expected ErrCannotRetireCurrent, got %v", err)
	}
	// 仅有的一个版本（=当前）也不能下线。
	err = v.Store().Retire("solo", 1)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown alias should be not found, got %v", err)
	}

	vs := newVaultWithKey(t, "solo2")
	if err := vs.Store().Retire("solo2", 1); !errors.Is(err, ErrCannotRetireCurrent) {
		t.Fatalf("only version is current: expected ErrCannotRetireCurrent, got %v", err)
	}
}

// TestRetireIdempotentAndNotFound 重复下线幂等；下线不存在版本报 not found。
func TestRetireIdempotentAndNotFound(t *testing.T) {
	v := newVaultWithKey(t, "idemr")
	_, _ = v.Store().Rotate("idemr")

	if err := v.Store().Retire("idemr", 1); err != nil {
		t.Fatalf("first retire: %v", err)
	}
	if err := v.Store().Retire("idemr", 1); err != nil {
		t.Fatalf("second retire must be idempotent, got %v", err)
	}
	t.Log("重复 Retire(version=1) 两次均成功（幂等）")

	if err := v.Store().Retire("idemr", 99); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("retire nonexistent version: expected not found, got %v", err)
	}
	if err := v.Store().Retire("missing", 1); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("retire missing alias: expected not found, got %v", err)
	}
}

// TestRetireOldVersionsBulk 批量下线所有旧版本、保留当前版本；再次调用为空操作。
func TestRetireOldVersionsBulk(t *testing.T) {
	v := newVaultWithKey(t, "bulk")
	c1, _ := v.Encrypt("bulk", []byte("a"))
	_, _ = v.Store().Rotate("bulk")
	c2, _ := v.Encrypt("bulk", []byte("b"))
	_, _ = v.Store().Rotate("bulk")
	c3, _ := v.Encrypt("bulk", []byte("c"))

	retired, err := v.Store().RetireOldVersions("bulk")
	if err != nil {
		t.Fatalf("RetireOldVersions: %v", err)
	}
	t.Logf("批量下线 versions=%v，当前版本保留", retired)
	if len(retired) != 2 || retired[0] != 1 || retired[1] != 2 {
		t.Fatalf("expected [1 2], got %v", retired)
	}

	for i, ct := range [][]byte{c1, c2} {
		if _, err := v.Decrypt("bulk", ct); !errors.Is(err, ErrKeyRetired) {
			t.Fatalf("c%d expected retired, got %v", i+1, err)
		}
	}
	if pt, err := v.Decrypt("bulk", c3); err != nil || string(pt) != "c" {
		t.Fatalf("current c3 must still decrypt: pt=%q err=%v", pt, err)
	}

	// 再次调用：幂等，无新增下线。
	again, err := v.Store().RetireOldVersions("bulk")
	if err != nil || len(again) != 0 {
		t.Fatalf("second bulk retire should be no-op, got %v err=%v", again, err)
	}
}
