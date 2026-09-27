// Package vault 提供本地密钥托管与密文版本管理。
package vault

import "errors"

// 可区分的失败原因，调用方应使用 errors.Is 判定。
var (
	// ErrKeyNotFound 密钥别名不存在。
	ErrKeyNotFound = errors.New("vault: key not found")
	// ErrKeyDisabled 密钥已被停用或撤销，不得再用于加解密。
	ErrKeyDisabled = errors.New("vault: key disabled")
	// ErrCiphertextMalformed 密文结构非法（过短、截断、字段不完整）。
	ErrCiphertextMalformed = errors.New("vault: ciphertext malformed")
	// ErrCiphertextIntegrity 密文完整性校验失败（被篡改）。
	ErrCiphertextIntegrity = errors.New("vault: ciphertext integrity check failed")
	// ErrUnsupportedVersion 密文格式版本不受支持。
	ErrUnsupportedVersion = errors.New("vault: unsupported ciphertext version")
	// ErrNoActiveKey 别名存在但当前没有可用于加密的密钥版本。
	ErrNoActiveKey = errors.New("vault: no active key version")
)
