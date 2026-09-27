package vault

import "errors"

// 可区分的失败原因，调用方可用 errors.Is 判定。
var (
	// ErrKeyNotFound 密钥别名或版本不存在。
	ErrKeyNotFound = errors.New("vault: key not found")
	// ErrKeyDisabled 密钥已停用或撤销，禁止用于解密。
	ErrKeyDisabled = errors.New("vault: key disabled or revoked")
	// ErrCiphertextMalformed 密文结构非法（过短、截断、字段无法解析）。
	ErrCiphertextMalformed = errors.New("vault: ciphertext malformed")
	// ErrUnsupportedVersion 密文格式版本不受支持。
	ErrUnsupportedVersion = errors.New("vault: unsupported ciphertext version")
	// ErrCiphertextIntegrity 密文完整性校验失败（被篡改）。
	ErrCiphertextIntegrity = errors.New("vault: ciphertext integrity check failed")
	// ErrDecryptFailed 解密失败（未归类的底层错误，细节不外泄）。
	ErrDecryptFailed = errors.New("vault: decryption failed")
)
