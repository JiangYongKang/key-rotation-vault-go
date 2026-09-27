package vault

import (
	"encoding/binary"
	"fmt"
)

// formatVersion 是当前密文自封包格式版本。
const formatVersion byte = 1

// 信封二进制布局（大端）：
//
//	[0:2]   魔数 "KV"，用于快速识别非本组件产出的数据
//	[2]     格式版本（formatVersion）
//	[3:5]   密钥别名长度 aliasLen (uint16)
//	[5:7]   加密所用密钥版本 (uint16)
//	[7:19]  AEAD nonce (12 字节)
//	[19:19+aliasLen] 密钥别名
//	其余    AEAD 输出（密文 || 认证标签）
//
// 头部 [0:19+aliasLen] 整体作为 AEAD 附加认证数据（AAD），
// 任何对别名、版本号或 nonce 的篡改都会导致完整性校验失败。
const (
	envelopeMagic0   = 'K'
	envelopeMagic1   = 'V'
	nonceSize        = 12
	envelopeHeadSize = 2 + 1 + 2 + 2 + nonceSize
	gcmTagSize       = 16
)

// encodeEnvelope 将密钥标识与 AEAD 输出打包为自描述密文。
func encodeEnvelope(keyAlias string, keyVersion int, nonce, sealed []byte) []byte {
	alias := []byte(keyAlias)
	out := make([]byte, 0, envelopeHeadSize+len(alias)+len(sealed))
	out = append(out, envelopeMagic0, envelopeMagic1, formatVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(alias)))
	out = binary.BigEndian.AppendUint16(out, uint16(keyVersion))
	out = append(out, nonce...)
	out = append(out, alias...)
	out = append(out, sealed...)
	return out
}

// decodeEnvelope 解析并校验自描述密文的结构。
// 返回的 aad 为需作为 AEAD 附加认证数据的头部字节。
// 结构非法返回 ErrCiphertextMalformed，版本不受支持返回 ErrUnsupportedVersion。
func decodeEnvelope(blob []byte) (alias string, keyVersion int, nonce, sealed, aad []byte, err error) {
	if len(blob) < envelopeHeadSize {
		return "", 0, nil, nil, nil, fmt.Errorf("%w: length %d < header %d",
			ErrCiphertextMalformed, len(blob), envelopeHeadSize)
	}
	if blob[0] != envelopeMagic0 || blob[1] != envelopeMagic1 {
		return "", 0, nil, nil, nil, fmt.Errorf("%w: bad magic", ErrCiphertextMalformed)
	}
	if blob[2] != formatVersion {
		return "", 0, nil, nil, nil, fmt.Errorf("%w: got %d, want %d",
			ErrUnsupportedVersion, blob[2], formatVersion)
	}
	aliasLen := int(binary.BigEndian.Uint16(blob[3:5]))
	keyVer := int(binary.BigEndian.Uint16(blob[5:7]))
	headEnd := envelopeHeadSize + aliasLen
	// 至少需要别名 + 一个 GCM 认证标签，否则视为截断。
	if len(blob) < headEnd+gcmTagSize {
		return "", 0, nil, nil, nil, fmt.Errorf("%w: truncated, length %d, need at least %d",
			ErrCiphertextMalformed, len(blob), headEnd+gcmTagSize)
	}
	alias = string(blob[envelopeHeadSize:headEnd])
	nonce = blob[7 : 7+nonceSize]
	sealed = blob[headEnd:]
	aad = blob[:headEnd]
	return alias, keyVer, nonce, sealed, aad, nil
}
