package vault

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentRotateEncryptDecrypt 在同一别名上并发执行轮换、加密与解密，
// 验证：无数据丢失、无错配（每条密文都能解出原始明文）、无撕裂读取，
// 且每条密文头部记录的密钥版本与实际可解密的版本一致。
func TestConcurrentRotateEncryptDecrypt(t *testing.T) {
	v := NewVault(NewKeyStore())
	if _, err := v.Store().CreateKey("hot"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	const workers = 8
	const opsPerWorker = 200

	var wg sync.WaitGroup
	errCh := make(chan error, workers*opsPerWorker*2)

	// 加密者 + 立即自解密校验
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				msg := []byte(fmt.Sprintf("w%d-msg%d", id, i))
				ct, err := v.Encrypt("hot", msg)
				if err != nil {
					errCh <- fmt.Errorf("encrypt: %w", err)
					return
				}
				hdrVer, _, _, derr := decode(ct)
				if derr != nil {
					errCh <- fmt.Errorf("decode header: %w", derr)
					return
				}
				pt, err := v.Decrypt("hot", ct)
				if err != nil {
					errCh <- fmt.Errorf("decrypt (hdr keyVersion=%d): %w", hdrVer, err)
					return
				}
				if string(pt) != string(msg) {
					errCh <- fmt.Errorf("mismatch: got %q want %q (hdr keyVersion=%d)", pt, msg, hdrVer)
					return
				}
			}
		}(w)
	}

	// 轮换者
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, err := v.Store().Rotate("hot"); err != nil {
				errCh <- fmt.Errorf("rotate: %w", err)
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	final, err := v.Store().current("hot")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	t.Logf("final key version=%d status=%s；并发期间所有密文均按信封头版本正确解密，无错配/撕裂",
		final.Version, final.Status)
}

// TestConcurrentDecryptDuringDisable 解密与停用并发时，结果只能是
// “成功解密”或“ErrKeyDisabled”之一，不得出现其他错误或部分明文。
func TestConcurrentDecryptDuringDisable(t *testing.T) {
	v := NewVault(NewKeyStore())
	if _, err := v.Store().CreateKey("flip"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	ct, err := v.Encrypt("flip", []byte("stable"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1000)
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				pt, err := v.Decrypt("flip", ct)
				if err == nil {
					if string(pt) != "stable" {
						errCh <- fmt.Errorf("torn read: %q", pt)
					}
					continue
				}
				if !errors.Is(err, ErrKeyDisabled) {
					errCh <- fmt.Errorf("unexpected error class: %v", err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = v.Store().Disable("flip")
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	t.Log("并发停用期间：解密结果仅为成功或 ErrKeyDisabled，无撕裂读取")
}
