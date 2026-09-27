package vault

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// logKey 打印密钥版本与状态，作为测试判定依据。
func logKey(t *testing.T, v *Vault, alias string, version int, note string) Key {
	t.Helper()
	k, err := v.KeyInfo(alias, version)
	if err != nil {
		t.Fatalf("KeyInfo(%q,%d): %v", alias, version, err)
	}
	t.Logf("判定依据: alias=%s version=%d status=%s (%s)", k.Alias, k.Version, k.Status, note)
	return k
}

func TestRotateKeepsOldCiphertextDecryptable(t *testing.T) {
	v := New()
	k1, err := v.CreateKey("payments")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	t.Logf("判定依据: 创建密钥 version=%d status=%s", k1.Version, k1.Status)

	// 轮换前用 v1 加密
	oldPlain := []byte("historical secret")
	oldBlob, err := v.Encrypt("payments", oldPlain)
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}

	k2, err := v.RotateKey("payments")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	t.Logf("判定依据: 轮换后新版本 version=%d status=%s", k2.Version, k2.Status)
	logKey(t, v, "payments", 1, "轮换后旧版本应降级为 decrypt-only")
	logKey(t, v, "payments", 2, "轮换后新版本应为 active")

	// 历史密文仍可解密
	got, err := v.Decrypt(oldBlob)
	if err != nil {
		t.Fatalf("Decrypt old ciphertext after rotation: %v", err)
	}
	if !bytes.Equal(got, oldPlain) {
		t.Fatalf("old ciphertext roundtrip mismatch: got %q", got)
	}
	t.Logf("判定依据: version=1 的历史密文在轮换后解密成功")

	// 新密文应使用 v2
	newBlob, err := v.Encrypt("payments", []byte("fresh secret"))
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	_, ver, _, _, _, err := decodeEnvelope(newBlob)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	if ver != 2 {
		t.Fatalf("new ciphertext should use version 2, got %d", ver)
	}
	t.Logf("判定依据: 新密文内嵌版本=%d，与当前 active 版本一致", ver)
}

func TestDisableKeyRejectsDecryptAndEncrypt(t *testing.T) {
	v := New()
	if _, err := v.CreateKey("api-token"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	blob, err := v.Encrypt("api-token", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := v.DisableKey("api-token"); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	logKey(t, v, "api-token", 1, "停用后应为 disabled")

	if _, err := v.Decrypt(blob); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("Decrypt on disabled key: want ErrKeyDisabled, got %v", err)
	}
	t.Log("判定依据: 停用后解密返回 ErrKeyDisabled")
	if _, err := v.Encrypt("api-token", []byte("x")); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("Encrypt on disabled key: want ErrKeyDisabled, got %v", err)
	}
	t.Log("判定依据: 停用后加密返回 ErrKeyDisabled")
}

func TestFailureReasonsAreDistinguishable(t *testing.T) {
	v := New()
	if _, err := v.CreateKey("db"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	blob, err := v.Encrypt("db", []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 1) 密钥不存在
	if _, err := v.Encrypt("ghost", []byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Encrypt unknown alias: want ErrKeyNotFound, got %v", err)
	}
	t.Log("判定依据: 别名不存在 -> ErrKeyNotFound")

	// 2) 密文被篡改 -> 完整性失败
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := v.Decrypt(tampered); !errors.Is(err, ErrCiphertextIntegrity) {
		t.Fatalf("Decrypt tampered: want ErrCiphertextIntegrity, got %v", err)
	}
	t.Log("判定依据: 密文末字节被翻转 -> ErrCiphertextIntegrity")

	// 3) 篡改头部别名（AAD 保护）-> 完整性失败而非密钥错配
	tamperedHead := bytes.Clone(blob)
	tamperedHead[envelopeHeadSize] ^= 0x01 // 别名首字节
	if _, err := v.Decrypt(tamperedHead); !errors.Is(err, ErrCiphertextIntegrity) &&
		!errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Decrypt tampered header: want integrity/not-found, got %v", err)
	}
	t.Log("判定依据: 头部别名被篡改 -> 完整性校验或别名查找失败，绝不返回明文")

	// 4) 截断 -> 结构非法
	truncated := blob[:len(blob)-gcmTagSize]
	if _, err := v.Decrypt(truncated); !errors.Is(err, ErrCiphertextMalformed) {
		t.Fatalf("Decrypt truncated: want ErrCiphertextMalformed, got %v", err)
	}
	t.Log("判定依据: 密文被截断 -> ErrCiphertextMalformed")

	// 5) 版本不受支持
	badVer := bytes.Clone(blob)
	badVer[2] = formatVersion + 1
	if _, err := v.Decrypt(badVer); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Decrypt bad version: want ErrUnsupportedVersion, got %v", err)
	}
	t.Log("判定依据: 格式版本号不受支持 -> ErrUnsupportedVersion")

	// 6) 密文指向不存在的密钥版本
	badKeyVer := bytes.Clone(blob)
	badKeyVer[6] = 0xFF // keyVersion 高字节
	if _, err := v.Decrypt(badKeyVer); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Decrypt unknown key version: want ErrKeyNotFound, got %v", err)
	}
	t.Log("判定依据: 密文引用的密钥版本不存在 -> ErrKeyNotFound")

	// 7) 完好密文不受影响
	got, err := v.Decrypt(blob)
	if err != nil || !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("Decrypt intact: got %q, err %v", got, err)
	}
	t.Log("判定依据: 完好密文解密成功，上述拒绝均无误伤")
}

func TestConcurrentEncryptDecryptRotate(t *testing.T) {
	v := New()
	if _, err := v.CreateKey("hot"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	const writers = 8
	const perWriter = 50

	var wg sync.WaitGroup
	errCh := make(chan error, writers*perWriter*2+4)

	// 写者：加密后立即解密校验，密文与所用密钥版本必须一致
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				plain := []byte(fmt.Sprintf("writer-%d-msg-%d", id, i))
				blob, err := v.Encrypt("hot", plain)
				if err != nil {
					errCh <- fmt.Errorf("encrypt: %w", err)
					return
				}
				_, ver, _, _, _, err := decodeEnvelope(blob)
				if err != nil {
					errCh <- fmt.Errorf("decode own ciphertext: %w", err)
					return
				}
				got, err := v.Decrypt(blob)
				if err != nil {
					errCh <- fmt.Errorf("decrypt (key version %d): %w", ver, err)
					return
				}
				if !bytes.Equal(got, plain) {
					errCh <- fmt.Errorf("roundtrip mismatch (key version %d)", ver)
					return
				}
			}
		}(w)
	}

	// 轮换者：与读写并发执行
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if _, err := v.RotateKey("hot"); err != nil {
				errCh <- fmt.Errorf("rotate: %w", err)
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	final := logKey(t, v, "hot", 0, "并发结束后最新版本")
	t.Logf("判定依据: 共完成 %d 次轮换，最终版本=%d，全部 %d 条消息往返一致",
		5, final.Version, writers*perWriter)
	if final.Version != 6 { // 1 次创建 + 5 次轮换
		t.Fatalf("final version = %d, want 6", final.Version)
	}
}
