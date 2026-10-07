package vault

import (
	"bytes"
	"errors"
	"testing"
)

// classify 打印判定依据并返回命中的哨兵错误名。
func classify(t *testing.T, err error) string {
	t.Helper()
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, ErrKeyNotFound):
		return "ErrKeyNotFound"
	case errors.Is(err, ErrKeyDisabled):
		return "ErrKeyDisabled"
	case errors.Is(err, ErrKeyRevoked):
		return "ErrKeyRevoked"
	case errors.Is(err, ErrKeyExpired):
		return "ErrKeyExpired"
	case errors.Is(err, ErrKeyVersionRetired):
		return "ErrKeyVersionRetired"
	case errors.Is(err, ErrCiphertextMalformed):
		return "ErrCiphertextMalformed"
	case errors.Is(err, ErrUnsupportedVersion):
		return "ErrUnsupportedVersion"
	case errors.Is(err, ErrCiphertextIntegrity):
		return "ErrCiphertextIntegrity"
	default:
		return "unknown"
	}
}

func newVaultWithKey(t *testing.T, alias string) *Vault {
	t.Helper()
	v := NewVault(NewKeyStore())
	kv, err := v.Store().CreateKey(alias)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	t.Logf("created key alias=%q version=%d status=%s", kv.Alias, kv.Version, kv.Status)
	return v
}

func TestRotateKeepsHistoryDecryptable(t *testing.T) {
	v := newVaultWithKey(t, "payments")

	ct1, err := v.Encrypt("payments", []byte("secret-v1"))
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	ver1, _, _, _ := decode(ct1)
	t.Logf("encrypted with key version=%d (判定依据: 信封头 keyVersion 字段)", ver1)

	kv2, err := v.Store().Rotate("payments")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	t.Logf("rotated to version=%d status=%s", kv2.Version, kv2.Status)

	ct2, err := v.Encrypt("payments", []byte("secret-v2"))
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	ver2, _, _, _ := decode(ct2)
	t.Logf("after rotation encrypted with key version=%d", ver2)
	if ver2 != 2 || ver1 != 1 {
		t.Fatalf("expected versions 1 then 2, got %d then %d", ver1, ver2)
	}

	// 历史密文仍可解密
	pt1, err := v.Decrypt("payments", ct1)
	if err != nil {
		t.Fatalf("Decrypt historical ciphertext: %v", err)
	}
	if string(pt1) != "secret-v1" {
		t.Fatalf("historical plaintext mismatch: %q", pt1)
	}
	t.Logf("historical ciphertext (key version=%d) decrypted OK", ver1)

	pt2, err := v.Decrypt("payments", ct2)
	if err != nil || string(pt2) != "secret-v2" {
		t.Fatalf("Decrypt v2: pt=%q err=%v", pt2, err)
	}
}

func TestDisableAndRevokeBlockDecrypt(t *testing.T) {
	v := newVaultWithKey(t, "tokens")
	ct, err := v.Encrypt("tokens", []byte("session"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := v.Store().Disable("tokens"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_, err = v.Decrypt("tokens", ct)
	t.Logf("decrypt after disable: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("expected ErrKeyDisabled, got %v", err)
	}
	if _, err = v.Encrypt("tokens", []byte("x")); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("encrypt after disable: expected ErrKeyDisabled, got %v", err)
	}

	// 撤销语义同样禁止解密
	v2 := newVaultWithKey(t, "api")
	ct2, _ := v2.Encrypt("api", []byte("k"))
	if err := v2.Store().Revoke("api"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = v2.Decrypt("api", ct2)
	t.Logf("decrypt after revoke: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked after revoke, got %v", err)
	}
	if errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("revoked must be distinguishable from disabled")
	}
}

func TestKeyNotFoundIsDistinguishable(t *testing.T) {
	v := newVaultWithKey(t, "exists")
	ct, _ := v.Encrypt("exists", []byte("data"))

	_, err := v.Decrypt("missing-alias", ct)
	t.Logf("decrypt with unknown alias: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}

	// 篡改版本号为不存在的密钥版本
	bad := bytes.Clone(ct)
	bad[6] = 99 // keyVersion 末字节
	_, err = v.Decrypt("exists", bad)
	t.Logf("decrypt with unknown key version=99: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for unknown version, got %v", err)
	}
}

func TestMalformedCiphertextRejected(t *testing.T) {
	v := newVaultWithKey(t, "m")
	ct, _ := v.Encrypt("m", []byte("payload"))

	cases := map[string][]byte{
		"empty":         {},
		"short-header":  ct[:envelopeHeadLen-1],
		"bad-magic":     append([]byte{0x00, 0x00}, ct[2:]...),
		"truncated-tag": ct[:len(ct)-gcmTagLen],
	}
	for name, blob := range cases {
		_, err := v.Decrypt("m", blob)
		t.Logf("case=%s len=%d: err=%v 判定=%s", name, len(blob), err, classify(t, err))
		if !errors.Is(err, ErrCiphertextMalformed) {
			t.Fatalf("case %s: expected ErrCiphertextMalformed, got %v", name, err)
		}
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	v := newVaultWithKey(t, "u")
	ct, _ := v.Encrypt("u", []byte("payload"))
	ct[2] = 77 // 不受支持的格式版本

	_, err := v.Decrypt("u", ct)
	t.Logf("format version=77: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
	if errors.Is(err, ErrCiphertextMalformed) {
		t.Fatalf("unsupported version must be distinguishable from malformed")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	v := newVaultWithKey(t, "t")
	ct, _ := v.Encrypt("t", []byte("payload"))

	// 翻转密文体最后一个字节（GCM tag 区域内）
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xFF
	pt, err := v.Decrypt("t", tampered)
	t.Logf("tampered body: err=%v 判定=%s", err, classify(t, err))
	if !errors.Is(err, ErrCiphertextIntegrity) {
		t.Fatalf("expected ErrCiphertextIntegrity, got %v", err)
	}
	if pt != nil {
		t.Fatalf("must not return partial plaintext, got %q", pt)
	}

	// 翻转 nonce 一字节
	tampered2 := bytes.Clone(ct)
	tampered2[envelopeHeadLen] ^= 0x01
	if _, err := v.Decrypt("t", tampered2); !errors.Is(err, ErrCiphertextIntegrity) {
		t.Fatalf("tampered nonce: expected ErrCiphertextIntegrity, got %v", err)
	}
}
