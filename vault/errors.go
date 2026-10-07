package vault

import (
	"errors"
	"fmt"
)

// 可区分的失败原因，调用方可用 errors.Is 判定。
var (
	// ErrKeyNotFound 密钥别名或版本不存在。
	ErrKeyNotFound = errors.New("vault: key not found")
	// ErrKeyDisabled 密钥已停用，禁止加解密。
	ErrKeyDisabled = errors.New("vault: key disabled")
	// ErrKeyRevoked 密钥已撤销（不可恢复）。它 wrap 了 ErrKeyDisabled，
	// 因此历史调用方用 errors.Is(err, ErrKeyDisabled) 仍能命中，
	// 新调用方可用 errors.Is(err, ErrKeyRevoked) 与“停用”区分。
	ErrKeyRevoked = fmt.Errorf("%w: key revoked", ErrKeyDisabled)
	// ErrKeyExpired 密钥版本已到期：到期时刻起禁止加密，
	// 超过解密宽限期后连解密也一并禁止。
	ErrKeyExpired = errors.New("vault: key version expired")
	// ErrKeyRetired 密钥版本已被下线回收：版本确实存在过，
	// 但密钥材料已清除，与 ErrKeyNotFound / ErrCiphertextMalformed 均可区分。
	ErrKeyRetired = errors.New("vault: key version retired")
	// ErrCannotRetireCurrent 当前正在使用的版本不允许下线。
	ErrCannotRetireCurrent = errors.New("vault: current key version cannot be retired")
	// ErrCiphertextMalformed 密文结构非法（过短、截断、字段无法解析）。
	ErrCiphertextMalformed = errors.New("vault: ciphertext malformed")
	// ErrUnsupportedVersion 密文格式版本不受支持。
	ErrUnsupportedVersion = errors.New("vault: unsupported ciphertext version")
	// ErrCiphertextIntegrity 密文完整性校验失败（被篡改）。
	ErrCiphertextIntegrity = errors.New("vault: ciphertext integrity check failed")
	// ErrDecryptFailed 解密失败（未归类的底层错误，细节不外泄）。
	ErrDecryptFailed = errors.New("vault: decryption failed")
)
