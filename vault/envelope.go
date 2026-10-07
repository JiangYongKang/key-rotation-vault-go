package vault

import (
	"encoding/binary"
	"fmt"
)

// 密文信封格式（自描述）：
//
//	magic(2) | formatVersion(1) | keyVersion(4, big-endian) | nonce(12) | ciphertext+GCM tag
const (
	envelopeMagic0   = 0x4B // 'K'
	envelopeMagic1   = 0x56 // 'V'
	formatVersion1   = 1
	envelopeHeadLen  = 2 + 1 + 4
	nonceLen         = 12
	gcmTagLen        = 16
	supportedVersion = formatVersion1
)

// encode 将密文各部分序列化为信封字节串。
func encode(keyVersion int, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, envelopeHeadLen+nonceLen+len(ciphertext))
	out = append(out, envelopeMagic0, envelopeMagic1, formatVersion1)
	var vb [4]byte
	binary.BigEndian.PutUint32(vb[:], uint32(keyVersion))
	out = append(out, vb[:]...)
	out = append(out, nonce...)
	return append(out, ciphertext...)
}

// decode 解析并校验信封头部，返回密钥版本、nonce 与密文体。
// 结构非法返回 ErrCiphertextMalformed，版本不受支持返回 ErrUnsupportedVersion，
// 二者可区分；本函数不做完整性校验（由 AEAD 在解密时完成）。
func decode(blob []byte) (keyVersion int, nonce, ciphertext []byte, err error) {
	if len(blob) < envelopeHeadLen {
		return 0, nil, nil, fmt.Errorf("%w: length %d < header %d",
			ErrCiphertextMalformed, len(blob), envelopeHeadLen)
	}
	if blob[0] != envelopeMagic0 || blob[1] != envelopeMagic1 {
		return 0, nil, nil, fmt.Errorf("%w: bad magic", ErrCiphertextMalformed)
	}
	if v := blob[2]; v != supportedVersion {
		return 0, nil, nil, fmt.Errorf("%w: format version %d", ErrUnsupportedVersion, v)
	}
	keyVersion = int(binary.BigEndian.Uint32(blob[3:7]))
	rest := blob[envelopeHeadLen:]
	if len(rest) < nonceLen+gcmTagLen {
		return 0, nil, nil, fmt.Errorf("%w: truncated body (need nonce+tag)", ErrCiphertextMalformed)
	}
	nonce = rest[:nonceLen]
	ciphertext = rest[nonceLen:]
	return keyVersion, nonce, ciphertext, nil
}
