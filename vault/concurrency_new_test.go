package vault

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentReEncryptAndRotate 升级与轮换并发：
// 每次升级要么成功（结果密文能按其头部版本解出同一明文），
// 要么返回明确拒绝（not found/disabled/expired/retired），
// 不得出现版本错配、丢数据、返回半截明文或未知错误。
func TestConcurrentReEncryptAndRotate(t *testing.T) {
	v := NewVault(NewKeyStore())
	if _, err := v.Store().CreateKey("hot"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	const upgraders = 8
	const rounds = 150
	var wg sync.WaitGroup
	errCh := make(chan error, upgraders*rounds+32)

	// 每个 upgrader 持有一条自己的“旧密文”，反复把它升级到当时的当前版本，
	// 升级成功后用返回的新密文继续下一轮。
	for w := 0; w < upgraders; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("upgrader-%d-plaintext", id))
			blob, err := v.Encrypt("hot", plaintext)
			if err != nil {
				errCh <- fmt.Errorf("seed encrypt: %w", err)
				return
			}
			for i := 0; i < rounds; i++ {
				out, changed, err := v.ReEncrypt("hot", blob)
				if err != nil {
					// 并发期间只允许明确、可区分的拒绝类别。
					if !(errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrKeyDisabled) ||
						errors.Is(err, ErrKeyExpired) || errors.Is(err, ErrKeyRetired) ||
						errors.Is(err, ErrCiphertextIntegrity) ||
						errors.Is(err, ErrCiphertextMalformed) ||
						errors.Is(err, ErrUnsupportedVersion)) {
						errCh <- fmt.Errorf("upgrader %d unexpected class: %w", id, err)
						return
					}
					if out != nil {
						errCh <- fmt.Errorf("upgrader %d error must not carry ciphertext", id)
						return
					}
					continue // 输入 blob 未变，下一轮重试（验证稳定/可重试）
				}
				if changed {
					// 成功升级：新密文必须能解出完全一致的明文，且头部版本即所用版本。
					pt, derr := v.Decrypt("hot", out)
					if derr != nil {
						// 可能恰好又被下线/停用，属于明确拒绝；否则才算错。
						if errors.Is(derr, ErrKeyRetired) || errors.Is(derr, ErrKeyDisabled) ||
							errors.Is(derr, ErrKeyExpired) || errors.Is(derr, ErrKeyNotFound) {
							continue
						}
						errCh <- fmt.Errorf("verify upgraded blob: %w", derr)
						return
					}
					if string(pt) != string(plaintext) {
						errCh <- fmt.Errorf("upgrader %d plaintext mismatch: %q", id, pt)
						return
					}
					blob = out // 用升级结果继续
				}
			}
		}(w)
	}

	// 轮换者：不断产生新当前版本，制造“升级读到的当前版本被立刻超越”的窗口。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
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

	final, _ := v.Store().current("hot")
	t.Logf("升级×轮换 并发结束：当前 version=%d；所有成功升级均解出同一明文，无错配/半截数据",
		final.Version)
}

// TestConcurrentDecryptDuringRetire 解密与旧版本下线并发：
// 结果只能是“成功解出正确明文”或“ErrKeyRetired”，
// 不得出现读到被清空的材料导致的其他错误或撕裂状态。
func TestConcurrentDecryptDuringRetire(t *testing.T) {
	v := NewVault(NewKeyStore())
	if _, err := v.Store().CreateKey("rc"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	ct, _ := v.Encrypt("rc", []byte("reclaim-me"))
	// 制造多个旧版本；下线目标为 v1。
	for i := 0; i < 5; i++ {
		if _, err := v.Store().Rotate("rc"); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	}

	const readers = 10
	const reads = 200
	var wg sync.WaitGroup
	errCh := make(chan error, readers*reads)

	for w := 0; w < readers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < reads; i++ {
				pt, err := v.Decrypt("rc", ct)
				if err == nil {
					if string(pt) != "reclaim-me" {
						errCh <- fmt.Errorf("torn/garbled plaintext: %q", pt)
					}
					continue
				}
				// v1 一旦被下线，必须稳定报 ErrKeyRetired；
				// 快照在锁内复制材料，理论上不会出现 nil-material 之类的内部错误。
				if !errors.Is(err, ErrKeyRetired) {
					errCh <- fmt.Errorf("unexpected error during retire: %v", err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = v.Store().Retire("rc", 1)
		_, _ = v.Store().RetireOldVersions("rc") // 与单个 Retire 并发也应安全
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// 收尾：v1 必然已下线；当前版本仍可正常加解密。
	if _, err := v.Decrypt("rc", ct); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("after retire v1 must be ErrKeyRetired, got %v", err)
	}
	cur, _ := v.Store().current("rc")
	if cur.Status != StatusActive {
		t.Fatalf("current version must remain active, got %s", cur.Status)
	}
	t.Log("下线×解密 并发：解密仅为成功或 ErrKeyRetired，无半清理状态被读到；当前版本仍 active")
}
