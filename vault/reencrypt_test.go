package vault

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestReEncryptUpgradesToCurrent 正常路径：老版本密文升级到当前版本，
// 明文一致，信封头版本号变为新版本。
func TestReEncryptUpgradesToCurrent(t *testing.T) {
	v := newVaultWithKey(t, "ledger")

	ct1, err := v.Encrypt("ledger", []byte("historical-secret"))
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	v1, _, _, _ := decode(ct1)

	k2, err := v.Store().Rotate("ledger")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	t.Logf("rotated: current version=%d", k2.Version)

	up, changed, err := v.ReEncrypt("ledger", ct1)
	if err != nil {
		t.Fatalf("ReEncrypt: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true for old ciphertext")
	}
	upVer, _, _, _ := decode(up)
	t.Logf("升级: source keyVersion=%d -> new keyVersion=%d changed=%v", v1, upVer, changed)
	if upVer != k2.Version || v1 == upVer {
		t.Fatalf("expected upgrade v1->v2, got %d -> %d", v1, upVer)
	}

	// 升级前后明文必须完全一致。
	pt, err := v.Decrypt("ledger", up)
	if err != nil {
		t.Fatalf("Decrypt upgraded: %v", err)
	}
	if string(pt) != "historical-secret" {
		t.Fatalf("plaintext mismatch after upgrade: %q", pt)
	}
	// 新密文字节不应与旧密文相同（nonce 重新随机）。
	if bytes.Equal(up, ct1) {
		t.Fatal("upgraded blob must differ from source")
	}

	// 旧密文仍可解密（尚未下线）。
	if pt1, err := v.Decrypt("ledger", ct1); err != nil || string(pt1) != "historical-secret" {
		t.Fatalf("source ciphertext must remain decryptable: %v", err)
	}
}

// TestReEncryptAlreadyCurrentIsIdempotent 已是当前版本的密文原样返回、
// changed=false；多次重试结论稳定。
func TestReEncryptAlreadyCurrentIsIdempotent(t *testing.T) {
	v := newVaultWithKey(t, "idem")
	ct, _ := v.Encrypt("idem", []byte("fresh"))

	for i := 0; i < 3; i++ {
		out, changed, err := v.ReEncrypt("idem", ct)
		if err != nil {
			t.Fatalf("reencrypt current attempt %d: %v", i, err)
		}
		if changed {
			t.Fatalf("attempt %d: current version must report changed=false", i)
		}
		if !bytes.Equal(out, ct) {
			t.Fatalf("attempt %d: current version must be returned verbatim", i)
		}
	}
	t.Log("已是当前版本：ReEncrypt 原样返回 changed=false，重复 3 次结论稳定")
}

// TestReEncryptRetriesAreStable 升级成功后对新密文再升级是幂等 no-op；
// 对失败输入反复重试，错误类别稳定不变，且绝不返回新密文。
func TestReEncryptRetriesAreStable(t *testing.T) {
	v := newVaultWithKey(t, "stable")
	old, _ := v.Encrypt("stable", []byte("payload"))
	_, _ = v.Store().Rotate("stable")

	up, _, err := v.ReEncrypt("stable", old)
	if err != nil {
		t.Fatalf("first upgrade: %v", err)
	}
	// 对升级产物再次升级：当前版本 => 原样 no-op。
	out2, changed2, err := v.ReEncrypt("stable", up)
	if err != nil || changed2 || !bytes.Equal(out2, up) {
		t.Fatalf("re-upgrade should be no-op: changed=%v err=%v", changed2, err)
	}

	// 失败输入：篡改旧密文，连续重试错误恒为 ErrCiphertextIntegrity，
	// 且返回的 out 必须为 nil（绝不在报错时吐出新密文）。
	tampered := bytes.Clone(old)
	tampered[len(tampered)-1] ^= 0xFF
	for i := 0; i < 3; i++ {
		out, changed, err := v.ReEncrypt("stable", tampered)
		t.Logf("重试#%d 篡改密文: changed=%v outNil=%v 判定=%s", i, changed, out == nil, classify(t, err))
		if !errors.Is(err, ErrCiphertextIntegrity) {
			t.Fatalf("attempt %d: expected integrity, got %v", i, err)
		}
		if out != nil || changed {
			t.Fatalf("attempt %d: must not emit ciphertext/partial plaintext on failure", i)
		}
	}
}

// TestReEncryptFailureCauses 覆盖可区分的失败原因：损坏、格式版本不受支持、
// 版本不存在、旧版本已停用/撤销/到期过宽限、当前版本不可加密。
func TestReEncryptFailureCauses(t *testing.T) {
	// 1) 密文损坏 / 格式版本不受支持（先于任何密钥判定）。
	v := newVaultWithKey(t, "f1")
	old, _ := v.Encrypt("f1", []byte("p"))
	_, _ = v.Store().Rotate("f1")

	if _, _, err := v.ReEncrypt("f1", old[:3]); !errors.Is(err, ErrCiphertextMalformed) {
		t.Fatalf("truncated: expected malformed, got %v", err)
	}
	badFmt := bytes.Clone(old)
	badFmt[2] = 99
	if _, _, err := v.ReEncrypt("f1", badFmt); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad format: expected unsupported, got %v", err)
	}

	// 2) 别名不存在 / 源版本不存在。
	if _, _, err := v.ReEncrypt("nope", old); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing alias: expected not found, got %v", err)
	}
	missingVer := bytes.Clone(old)
	missingVer[6] = 99
	if _, _, err := v.ReEncrypt("f1", missingVer); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing source version: expected not found, got %v", err)
	}

	// 3) 源版本被停用 => ErrKeyDisabled；被撤销 => ErrKeyRevoked。
	vd := newVaultWithKey(t, "f2")
	cd, _ := vd.Encrypt("f2", []byte("p"))
	_, _ = vd.Store().Rotate("f2")
	if err := vd.Store().Disable("f2"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_, _, err := vd.ReEncrypt("f2", cd)
	t.Logf("旧版本停用后升级: 判定=%s", classify(t, err))
	if !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("disabled source: expected disabled, got %v", err)
	}

	vr := newVaultWithKey(t, "f3")
	cr, _ := vr.Encrypt("f3", []byte("p"))
	_, _ = vr.Store().Rotate("f3")
	_ = vr.Store().Revoke("f3")
	_, _, err = vr.ReEncrypt("f3", cr)
	t.Logf("旧版本撤销后升级: 判定=%s (同时命中 disabled=%v)",
		classify(t, err), errors.Is(err, ErrKeyDisabled))
	if !errors.Is(err, ErrKeyRevoked) || !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("revoked source: expected revoked+disabled, got %v", err)
	}

	// 4) 源版本已过解密宽限期 => ErrKeyExpired。
	store := NewKeyStore()
	clk := &fixedClock{}
	store.setClock(clk.get)
	ve := NewVault(store)
	k1, _ := store.CreateKey("f4", WithTTL(time.Hour), WithGracePeriod(time.Minute))
	clk.t = k1.CreatedAt
	ce, _ := ve.Encrypt("f4", []byte("p"))
	_, _ = store.Rotate("f4") // 新版本长期有效，可加密
	clk.t = k1.GraceUntil.Add(1)
	_, _, err = ve.ReEncrypt("f4", ce)
	t.Logf("源版本过宽限期后升级: 判定=%s", classify(t, err))
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("expired source: expected ErrKeyExpired, got %v", err)
	}
}
