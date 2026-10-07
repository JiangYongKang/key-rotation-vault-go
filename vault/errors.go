package vault

import "errors"

// 可区分的失败原因，调用方可用 errors.Is 判定。
var (
	// ErrKeyNotFound 密钥别名或版本不存在。
	ErrKeyNotFound = errors.New("vault: key not found")
	// ErrKeyDisabled 密钥已停用，禁止用于加解密。
	ErrKeyDisabled = errors.New("vault: key disabled")
	// ErrKeyRevoked 密钥已撤销，语义上不可恢复。
	ErrKeyRevoked = errors.New("vault: key revoked")
	// ErrKeyExpired 密钥版本已超过有效期（加密被拒）；
	// 宽限期结束后解密同样以该错误被拒（错误信息会注明宽限期已过）。
	ErrKeyExpired = errors.New("vault: key version expired")
	// ErrKeyVersionRetired 密钥版本已被下线回收，密钥材料已销毁。
	ErrKeyVersionRetired = errors.New("vault: key version retired")
	// ErrInvalidArgument 调用参数非法（如负的 TTL）。
	ErrInvalidArgument = errors.New("vault: invalid argument")
	// ErrCiphertextMalformed 密文结构非法（过短、截断、字段无法解析）。
	ErrCiphertextMalformed = errors.New("vault: ciphertext malformed")
	// ErrUnsupportedVersion 密文格式版本不受支持。
	ErrUnsupportedVersion = errors.New("vault: unsupported ciphertext version")
	// ErrCiphertextIntegrity 密文完整性校验失败（被篡改）。
	ErrCiphertextIntegrity = errors.New("vault: ciphertext integrity check failed")
	// ErrDecryptFailed 解密失败（未归类的底层错误，细节不外泄）。
	ErrDecryptFailed = errors.New("vault: decryption failed")
)
